use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

#[macro_use]
extern crate rocket;
pub mod attester;
use attester::Attester;
pub mod secrets_store;
pub mod sev;

use rocket::http::{Cookie, CookieJar};
use rocket::response::status::{BadRequest, Unauthorized};
use rocket::serde::json::{json, Json, Value};
use rocket::State;
use secrets_store::{get_secret_from_vault, SecretStore};

#[derive(Eq, PartialEq)]
pub enum SessionStatus {
    Authorized,
    Unauthorized,
}

pub struct Session {
    id: String,
    workload_id: String,
    attester: Box<dyn Attester>,
    status: SessionStatus,
    expires_on: Instant,
}

// Session will only be accessed through Arc<Mutex<Session>>
unsafe impl Send for Session {}

impl Session {
    pub fn new(id: String, workload_id: String, attester: Box<dyn Attester>) -> Session {
        Session {
            id,
            workload_id,
            attester,
            status: SessionStatus::Unauthorized,
            expires_on: Instant::now() + Duration::from_secs(3 * 60 * 60),
        }
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub fn workload_id(&self) -> String {
        self.workload_id.clone()
    }

    pub fn attester(&mut self) -> &mut Box<dyn Attester> {
        &mut self.attester
    }

    pub fn is_valid(&self) -> bool {
        if self.status != SessionStatus::Authorized {
            println!("Session is not authorized");
        }
        if Instant::now() > self.expires_on {
            println!("Session expired");
        }
        self.status == SessionStatus::Authorized && Instant::now() < self.expires_on
    }

    pub fn approve(&mut self) {
        self.status = SessionStatus::Authorized;
    }
}

pub struct SessionState {
    pub sessions: RwLock<HashMap<String, Arc<Mutex<Session>>>>,
    pub secret_store: RwLock<SecretStore>,
}

#[get("/get")]
pub fn get_secret_store(state: &State<SessionState>) -> Json<SecretStore> {
    let store = state.secret_store.read().unwrap();
    Json(SecretStore::new(&store.get_url(), &store.get_token()))
}

#[post("/update", format = "json", data = "<store>")]
pub fn register_secret_store(state: &State<SessionState>, store: Json<SecretStore>) -> Value {
    let valid = store.validate();
    match valid {
        Ok(_) => {
            let mut s = state.secret_store.write().unwrap();
            s.update(store.get_url(), store.get_token());

            return json!({ "status": "updated"});
        }
        Err(e) => json!({ "status": "error",
                "reason": e.to_string(),
        }),
    }
}

#[get("/key/<key_id>")]
pub async fn key(
    state: &State<SessionState>,
    cookies: &CookieJar<'_>,
    key_id: &str,
) -> Result<Value, Unauthorized<String>> {
    let session_id = cookies
        .get("session_id")
        .ok_or_else(|| Unauthorized(Some("Missing cookie".to_string())))?
        .value();
    // We're just cloning an Arc, looks like a false positive to me...
    #[allow(clippy::significant_drop_in_scrutinee)]
    let session_lock = match state.sessions.read().unwrap().get(session_id) {
        Some(s) => s.clone(),
        None => return Err(Unauthorized(Some("Invalid cookie".to_string()))),
    };

    if !session_lock.lock().unwrap().is_valid() {
        return Err(Unauthorized(Some("Invalid session".to_string())));
    }

    let owned_key_id = key_id.to_string();
    let url = state.secret_store.read().unwrap().get_url();
    let token = state.secret_store.read().unwrap().get_token();
    let secret_clear = get_secret_from_vault(&url, &token, &owned_key_id).await;
    let mut session = session_lock.lock().unwrap();
    let secret = session
        .attester()
        .encrypt_secret(&secret_clear.as_bytes())
        .unwrap();
    Ok(secret)
}

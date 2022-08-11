use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub mod attester;
use attester::Attester;
pub mod sev;
use crate::sev::SevAttester;

use rocket::http::{Cookie, CookieJar};
use rocket::response::status::{BadRequest, Unauthorized};
use rocket::serde::json::{json, Json, Value};
use rocket::State;

#[macro_use]
extern crate rocket;
use rocket::serde::{Deserialize, Serialize};

use kbs_types::{Attestation, Request, SevRequest, Tee};
use uuid::Uuid;

use rocket_sync_db_pools::database;

#[macro_use]
extern crate diesel;

use diesel::prelude::*;

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable)]
#[serde(crate = "rocket::serde")]
#[table_name = "configs"]
struct TeeConfig {
    workload_id: String,
    tee_config: String,
}

table! {
    configs (workload_id) {
        workload_id -> Text,
        tee_config -> Text,
    }
}

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
}

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable)]
#[serde(crate = "rocket::serde")]
#[table_name = "measurements"]
struct Measurement {
    workload_id: String,
    launch_measurement: String,
}

table! {
    measurements (workload_id) {
        workload_id -> Text,
        launch_measurement -> Text,
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable)]
#[serde(crate = "rocket::serde")]
#[table_name = "secrets"]
struct Secret {
    key_id: String,
    secret: String,
}

table! {
    secrets (key_id) {
        key_id -> Text,
        secret -> Text,
    }
}

#[database("diesel")]
pub struct Db(diesel::SqliteConnection);

#[get("/")]
pub fn index() -> Result<String, Unauthorized<String>> {
    Err(Unauthorized(None))
}

#[post("/auth", format = "application/json", data = "<request>")]
pub async fn auth(
    db: Db,
    state: &State<SessionState>,
    cookies: &CookieJar<'_>,
    request: Json<Request>,
) -> Result<Value, BadRequest<String>> {
    let session_id = Uuid::new_v4().to_simple().to_string();

    let workload_id = request.workload_id.clone();
    let tee_config: Option<String> = match db
        .run(move |conn| {
            configs::table
                .filter(configs::workload_id.eq(workload_id))
                .first::<TeeConfig>(conn)
        })
        .await
    {
        Ok(e) => Some(e.tee_config),
        Err(_) => None,
    };

    let mut attester: Box<dyn Attester> = match request.tee {
        Tee::Sev => {
            let sev_request: SevRequest = serde_json::from_str(&request.extra_params)
                .map_err(|e| BadRequest(Some(e.to_string())))?;
            Box::new(SevAttester::new(
                session_id.clone(),
                request.workload_id.clone(),
                sev_request.build,
                sev_request.chain,
                tee_config,
            )) as Box<dyn Attester>
        }
        _ => return Err(BadRequest(Some("Unsupported TEE".to_string()))),
    };

    let challenge = attester
        .challenge()
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    let session = Session::new(session_id, request.workload_id.clone(), attester);
    cookies.add(Cookie::new("session_id", session.id()));

    state
        .sessions
        .write()
        .unwrap()
        .insert(session.id(), Arc::new(Mutex::new(session)));
    Ok(json!(challenge))
}

#[post("/attest", format = "application/json", data = "<attestation>")]
pub async fn attest(
    db: Db,
    state: &State<SessionState>,
    cookies: &CookieJar<'_>,
    attestation: Json<Attestation>,
) -> Result<(), BadRequest<String>> {
    let session_id = cookies
        .get("session_id")
        .ok_or_else(|| BadRequest(Some("Missing cookie".to_string())))?
        .value();

    // We're just cloning an Arc, looks like a false positive to me...
    #[allow(clippy::significant_drop_in_scrutinee)]
    let session_lock = match state.sessions.read().unwrap().get(session_id) {
        Some(s) => s.clone(),
        None => return Err(BadRequest(Some("Invalid cookie".to_string()))),
    };

    let workload_id = session_lock.lock().unwrap().workload_id();

    let measurement_entry: Measurement = db
        .run(move |conn| {
            measurements::table
                .filter(measurements::workload_id.eq(workload_id))
                .first(conn)
        })
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    let mut session = session_lock.lock().unwrap();
    session
        .attester()
        .attest(&attestation, &measurement_entry.launch_measurement)
        .map_err(|e| BadRequest(Some(e.to_string())))?;
    session.approve();

    Ok(())
}

#[get("/key/<key_id>")]
pub async fn key(
    db: Db,
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
    let secrets_entry: Secret = db
        .run(move |conn| {
            secrets::table
                .filter(secrets::key_id.eq(owned_key_id))
                .first(conn)
        })
        .await
        .map_err(|e| Unauthorized(Some(e.to_string())))?;

    let mut session = session_lock.lock().unwrap();
    let secret = session
        .attester()
        .encrypt_secret(secrets_entry.secret.as_bytes())
        .unwrap();
    Ok(secret)
}

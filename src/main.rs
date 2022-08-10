#![feature(option_result_contains)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

#[macro_use]
extern crate rocket;
use rocket::http::{Cookie, CookieJar};
use rocket::response::status::{BadRequest, Unauthorized};
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};
use rocket::State;

use kbs_types::{Attestation, Request, SevRequest, Tee};
use uuid::Uuid;

use reference_kbs::attester::Attester;
use reference_kbs::secrets_store::SecretStore;
use reference_kbs::sev::SevAttester;
use reference_kbs::{get_secret_store, key, register_secret_store, Session, SessionState};

use rocket_sync_db_pools::database;

//use std::thread;

#[macro_use]
extern crate diesel;

use diesel::prelude::*;

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

#[database("diesel")]
struct Db(diesel::SqliteConnection);

#[get("/")]
fn index() -> Result<String, Unauthorized<String>> {
    //Ok("Hello, world!".to_string())
    Err(Unauthorized(None))
}

#[post("/auth", format = "application/json", data = "<request>")]
fn auth(
    state: &State<SessionState>,
    cookies: &CookieJar<'_>,
    request: Json<Request>,
) -> Result<Value, BadRequest<String>> {
    let session_id = Uuid::new_v4().to_simple().to_string();

    let mut attester: Box<dyn Attester> = match request.tee {
        Tee::Sev => {
            let sev_request: SevRequest = serde_json::from_str(&request.extra_params)
                .map_err(|e| BadRequest(Some(e.to_string())))?;
            Box::new(SevAttester::new(
                session_id.clone(),
                request.workload_id.clone(),
                sev_request.build,
                sev_request.chain,
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
async fn attest(
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

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/kbs/v0", routes![index, auth, attest, key])
        .mount(
            "/secret-store",
            routes![register_secret_store, get_secret_store],
        )
        .manage(SessionState {
            sessions: RwLock::new(HashMap::new()),
            secret_store: RwLock::new(SecretStore::new("http://127.0.0.1:8200", "myroot")),
        })
        .attach(Db::fairing())
}

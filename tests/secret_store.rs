#![feature(option_result_contains)]
use rocket::http::{ContentType, Status};
use rocket::local::blocking::Client;
use rocket::routes;

use reference_kbs::attester::AttesterError;
use reference_kbs::secrets_store::{get_secret_from_vault, SecretStore};
use reference_kbs::{get_secret_store, key, register_secret_store, Session, SessionState};
use rocket::http::{Cookie, CookieJar};
use rocket::serde::json::{json, Value};
use serde_json::Result;
use std::collections::HashMap;
use std::env;
use std::str;
use std::sync::{Arc, Mutex, RwLock};

#[actix_rt::test]
async fn get_secret() {
    let url = env::var("VAULT_ADDR").unwrap();
    let token = env::var("VAULT_TOKEN").unwrap();
    println!(
        "Executing test with VAULT_ADDR: {} VAULT_TOKEN: {}",
        url, token
    );
    let secret = get_secret_from_vault(&url, &token, "fakeid").await;
    assert_eq!(secret.secret, "test".to_string());
}

#[test]
fn update_secret_store() {
    let serialized_store =
        serde_json::to_string(&SecretStore::new("http://127.0.0.1:8200", "myroot")).unwrap();
    let state = SessionState {
        sessions: RwLock::new(HashMap::new()),
        secret_store: RwLock::new(SecretStore::new("http://127.0.0.1:8200", "myroot")),
    };
    let rocket = rocket::build()
        .mount("/", routes![register_secret_store, get_secret_store])
        .manage(state);
    let client = Client::new(rocket).expect("valid rocket instance");
    let mut response = client
        .post("/update")
        .header(ContentType::JSON)
        .body(serialized_store.clone())
        .dispatch();
    assert_eq!(response.status(), Status::Ok);
    let mut response = client.get("/get").header(ContentType::JSON).dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string(), serialized_store.into());
}

#[test]
fn test_key() {
    // TODO set env variables
    let mut mockAttester = reference_kbs::attester::MockAttester::new();
    mockAttester
        .expect_encrypt_secret()
        .returning(|x| Ok(json!(str::from_utf8(&x).unwrap())));
    let state = SessionState {
        sessions: RwLock::new(HashMap::new()),
        secret_store: RwLock::new(SecretStore::new("http://127.0.0.1:8200", "myroot")),
    };
    let mut session = Session::new(
        "test-session".to_string(),
        "fakeid".to_string(),
        Box::new(mockAttester),
    );
    session.approve();
    state
        .sessions
        .write()
        .unwrap()
        .insert("test-session".to_string(), Arc::new(Mutex::new(session)));
    let rocket = rocket::build().mount("/", routes![key]).manage(state);
    let client = Client::new(rocket).expect("valid rocket instance");
    let response = client
        .get("/key/fakeid")
        .cookie(Cookie::new("session_id", "test-session"))
        .dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().unwrap().contains("test"), true);
}

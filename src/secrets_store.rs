use rocket::{get, post};

use bincode;
use lazy_static::lazy_static;
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::sync::RwLock;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

lazy_static! {
    static ref SECRET_STORE: RwLock<SecretStore> = RwLock::new(SecretStore::default());
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Secret {
    secret: String,
}

impl Secret {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(crate = "rocket::serde")]
pub struct SecretStore {
    url: String,
    token: String,
}

impl SecretStore {
    pub fn new(url: &str, token: &str) -> SecretStore {
        SecretStore {
            url: url.to_string(),
            token: token.to_string(),
        }
    }
}

pub async fn get_secret_from_vault(path: &str) -> Secret {
    let store = read_secret_store();
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(store.url.clone())
            .token(store.token.clone())
            .build()
            .unwrap(),
    )
    .unwrap();
    kv2::read(&client, "secret", path).await.unwrap()
}

#[derive(Debug, Clone)]
struct InvalidSecretStoreError {
    details: String,
}

impl InvalidSecretStoreError {
    fn new(msg: &str) -> InvalidSecretStoreError {
        InvalidSecretStoreError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for InvalidSecretStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for InvalidSecretStoreError {
    fn description(&self) -> &str {
        &self.details
    }
}

impl SecretStore {
    fn validate(&self) -> Result<(), InvalidSecretStoreError> {
        if self.token.is_empty() {
            Err(InvalidSecretStoreError::new("token cannot be empty"))
        } else if self.url.is_empty() {
            Err(InvalidSecretStoreError::new("url cannot be empty"))
        } else {
            Ok(())
        }
    }
}

pub fn write_secret_store(store: SecretStore) {
    let mut s = SECRET_STORE.write().unwrap();
    *s = store;
}

fn read_secret_store() -> SecretStore {
    let store = SECRET_STORE.read().unwrap();
    SecretStore::new(&store.url, &store.token)
}

#[get("/get")]
pub fn get_secret_store() -> Json<SecretStore> {
    Json(read_secret_store())
}

#[post("/update", format = "json", data = "<store>")]
pub fn register_secret_store(store: Json<SecretStore>) -> Value {
    let valid = store.validate();
    match valid {
        Ok(_) => {
            write_secret_store(store.0);
            return json!({ "status": "updated"});
        }
        Err(e) => json!({ "status": "error",
                "reason": e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;
    use rocket::routes;

    use serde_json::Result;
    use std::env;

    #[test]
    fn set_secret_store() {
        let store = SecretStore::new("http://127.0.0.1:8200", "sfjdksjfksjfkdjskfjskfjd");
        let serialized_store = serde_json::to_string(&store).unwrap();
        let rocket = rocket::build().mount("/", routes![register_secret_store, get_secret_store]);
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

    #[actix_rt::test]
    async fn get_secret() {
        let url = env::var("VAULT_ADDR").unwrap();
        let token = env::var("VAULT_TOKEN").unwrap();
        println!(
            "Executing test with VAULT_ADDR: {} VAULT_TOKEN: {}",
            url, token
        );
        write_secret_store(SecretStore {
            url: url.to_string(),
            token: token.to_string(),
        });
        let secret = get_secret_from_vault("fakeid").await;
        assert_eq!(secret.secret, "test".to_string());
    }
}

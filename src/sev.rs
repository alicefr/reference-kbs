use kbs_types::{Attestation, Challenge, SevChallenge};
use rocket::serde::json::{json, Value};
use sev::certs::Chain;
use sev::launch::sev::{Measurement, Policy};
use sev::session;
use sev::session::{Initialized, Verified};
use sev::Build;

use crate::attester::{Attester, AttesterError};

pub struct SevAttester {
    _workload_id: String,
    nonce: String,
    build: Build,
    chain: Option<Chain>,
    session: Option<session::Session<Initialized>>,
    session_verified: Option<session::Session<Verified>>,
}

impl SevAttester {
    pub fn new(workload_id: String, nonce: String, build: Build, chain: Chain) -> Self {
        SevAttester {
            _workload_id: workload_id,
            nonce,
            build,
            chain: Some(chain),
            session: None,
            session_verified: None,
        }
    }
}

impl Attester for SevAttester {
    fn challenge(&mut self) -> Result<Challenge, AttesterError> {
        // TODO: The policy should be read from a DB using the workload_id as key
        let policy = Policy::default();
        let session = session::Session::try_from(policy).map_err(AttesterError::SevPolicy)?;
        let chain = self.chain.take().ok_or(AttesterError::SevMissingChain)?;
        let start = session.start(chain).map_err(AttesterError::SevSession)?;

        let sev_challenge = SevChallenge {
            id: self.nonce.clone(),
            start,
        };
        let sev_challenge_json =
            serde_json::to_string(&sev_challenge).map_err(AttesterError::SevChallengeJson)?;

        self.session = Some(session);

        Ok(Challenge {
            nonce: self.nonce.clone(),
            extra_params: sev_challenge_json,
        })
    }

    fn attest(
        &mut self,
        attestation: &Attestation,
        launch_measurement: &str,
    ) -> Result<(), AttesterError> {
        let measurement: Measurement = serde_json::from_str(&attestation.tee_evidence)
            .map_err(AttesterError::InvalidAttestation)?;

        let session = self
            .session
            .take()
            .ok_or(AttesterError::SevMissingSession)?;

        let session = session
            .measure()
            .map_err(AttesterError::SevSessionMeasure)?;

        let decoded_lm = hex::decode(launch_measurement).unwrap();

        match session.verify_with_digest(self.build, measurement, &decoded_lm) {
            Err(e) => {
                println!("Launch measurement verification failed: {:?}", e);
                Err(AttesterError::InvalidMeasurement(e))
            }
            Ok(session) => {
                self.session_verified = Some(session);
                Ok(())
            }
        }
    }

    fn encrypt_secret(&self, plain_secret: &[u8]) -> Result<Value, AttesterError> {
        if let Some(session) = &self.session_verified {
            if plain_secret.len() > 4096 {
                return Err(AttesterError::SevSecretTooLong);
            }
            let padding: Vec<u8> = vec![0; 512 - plain_secret.len()];
            let data = [plain_secret, &padding].concat();
            let secret = session
                .secret(sev::launch::sev::HeaderFlags::default(), &data)
                .map_err(AttesterError::SevSecret)?;
            let secret_json = json!(secret);
            Ok(secret_json)
        } else {
            Err(AttesterError::SevMissingVerified)
        }
    }
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{FaunaError, Result, SessionKey};

pub struct ExchangeKeypair {
    secret_key: StaticSecret,
    public_key: PublicKey,
}

impl ExchangeKeypair {
    pub fn generate() -> Self {
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);

        Self {
            secret_key,
            public_key,
        }
    }

    pub fn public_key_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key.as_bytes())
    }

    pub fn derive_session_key(&self, remote_public_key: &str) -> Result<SessionKey> {
        let bytes = URL_SAFE_NO_PAD.decode(remote_public_key)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| FaunaError::InvalidKey)?;
        let remote_public_key = PublicKey::from(bytes);
        let shared_secret = self.secret_key.diffie_hellman(&remote_public_key);

        let digest = Sha256::digest(shared_secret.as_bytes());
        let mut session_key = [0_u8; 32];
        session_key.copy_from_slice(&digest);

        Ok(SessionKey::from_bytes(session_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_derive_the_same_session_key() {
        let alice = ExchangeKeypair::generate();
        let bob = ExchangeKeypair::generate();

        let alice_key = alice
            .derive_session_key(&bob.public_key_base64())
            .unwrap()
            .expose_for_dev_only();
        let bob_key = bob
            .derive_session_key(&alice.public_key_base64())
            .unwrap()
            .expose_for_dev_only();

        assert_eq!(alice_key, bob_key);
    }
}

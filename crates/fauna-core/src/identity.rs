use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{FaunaError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerId(String);

impl PeerId {
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let digest = Sha256::digest(public_key.as_bytes());
        Self(format!("fauna-{}", hex::encode(&digest[..16])))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone)]
pub struct DeviceIdentity {
    signing_key: SigningKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportedIdentity {
    pub peer_id: PeerId,
    pub secret_key: String,
    pub public_key: String,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_secret_key_bytes(secret_key: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&secret_key),
        }
    }

    pub fn from_export(export: &ExportedIdentity) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(&export.secret_key)?;
        let secret_key: [u8; 32] = bytes.try_into().map_err(|_| FaunaError::InvalidKey)?;
        Ok(Self::from_secret_key_bytes(secret_key))
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.public_key())
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key().as_bytes())
    }

    pub fn public_key_from_base64(input: &str) -> Result<VerifyingKey> {
        let bytes = URL_SAFE_NO_PAD.decode(input)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| FaunaError::InvalidKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| FaunaError::InvalidKey)
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }

    pub fn verify(public_key: &VerifyingKey, message: &[u8], signature: &[u8]) -> Result<()> {
        let signature = Signature::from_slice(signature).map_err(|_| FaunaError::Signature)?;
        public_key
            .verify(message, &signature)
            .map_err(|_| FaunaError::Signature)
    }

    pub fn export(&self) -> ExportedIdentity {
        ExportedIdentity {
            peer_id: self.peer_id(),
            secret_key: URL_SAFE_NO_PAD.encode(self.signing_key.to_bytes()),
            public_key: self.public_key_base64(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_can_sign_and_verify() {
        let identity = DeviceIdentity::generate();
        let message = b"hello fauna";
        let signature = identity.sign(message);

        DeviceIdentity::verify(&identity.public_key(), message, &signature).unwrap();
    }

    #[test]
    fn exported_identity_round_trips() {
        let identity = DeviceIdentity::generate();
        let restored = DeviceIdentity::from_export(&identity.export()).unwrap();

        assert_eq!(identity.peer_id(), restored.peer_id());
    }

    #[test]
    fn public_key_decodes_from_base64() {
        let identity = DeviceIdentity::generate();
        let public_key =
            DeviceIdentity::public_key_from_base64(&identity.public_key_base64()).unwrap();

        assert_eq!(PeerId::from_public_key(&public_key), identity.peer_id());
    }
}

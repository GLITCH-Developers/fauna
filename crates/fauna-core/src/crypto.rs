use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{FaunaError, Result};

#[derive(Clone)]
pub struct SessionKey([u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub nonce: String,
    pub ciphertext: String,
}

impl SessionKey {
    pub fn generate() -> Self {
        let mut key = [0_u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn expose_for_dev_only(&self) -> [u8; 32] {
        self.0
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| FaunaError::Crypto)?;

        Ok(EncryptedMessage {
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        let nonce = URL_SAFE_NO_PAD.decode(&message.nonce)?;
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| FaunaError::InvalidKey)?;
        let ciphertext = URL_SAFE_NO_PAD.decode(&message.ciphertext)?;

        let cipher = XChaCha20Poly1305::new((&self.0).into());
        cipher
            .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| FaunaError::Crypto)
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_encrypts_and_decrypts() {
        let key = SessionKey::generate();
        let encrypted = key.encrypt(b"secret message").unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, b"secret message");
    }
}

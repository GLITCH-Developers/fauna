pub mod crypto;
pub mod identity;
pub mod invite;
pub mod key_exchange;

pub use crypto::{EncryptedMessage, SessionKey};
pub use identity::{DeviceIdentity, PeerId};
pub use invite::Invite;
pub use key_exchange::ExchangeKeypair;

#[derive(Debug, thiserror::Error)]
pub enum FaunaError {
    #[error("base64 decode failed")]
    Base64(#[from] base64::DecodeError),

    #[error("crypto operation failed")]
    Crypto,

    #[error("invalid key material")]
    InvalidKey,

    #[error("json serialization failed")]
    Json(#[from] serde_json::Error),

    #[error("signature verification failed")]
    Signature,
}

pub type Result<T> = std::result::Result<T, FaunaError>;

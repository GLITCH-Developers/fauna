use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{DeviceIdentity, PeerId, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub version: u8,
    pub peer_id: PeerId,
    pub display_name: String,
    pub public_key: String,
    pub addresses: Vec<String>,
}

impl Invite {
    pub fn new(identity: &DeviceIdentity, display_name: impl Into<String>) -> Self {
        Self {
            version: 1,
            peer_id: identity.peer_id(),
            display_name: display_name.into(),
            public_key: identity.public_key_base64(),
            addresses: Vec::new(),
        }
    }

    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.addresses.push(address.into());
        self
    }

    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(format!("fauna://join/{}", URL_SAFE_NO_PAD.encode(json)))
    }

    pub fn decode(input: &str) -> Result<Self> {
        let payload = input.strip_prefix("fauna://join/").unwrap_or(input);
        let json = URL_SAFE_NO_PAD.decode(payload)?;
        Ok(serde_json::from_slice(&json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_round_trips() {
        let identity = DeviceIdentity::generate();
        let invite = Invite::new(&identity, "Ada").with_address("/ip4/127.0.0.1/tcp/45123");
        let encoded = invite.encode().unwrap();
        let decoded = Invite::decode(&encoded).unwrap();

        assert_eq!(decoded.peer_id, identity.peer_id());
        assert_eq!(decoded.display_name, "Ada");
        assert_eq!(decoded.addresses, vec!["/ip4/127.0.0.1/tcp/45123"]);
    }
}

//! Local private keys and CSR generation; products own the identity bindings and issuer protocol.
use crate::TransportError;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType, PKCS_ED25519};

pub fn signing_request(names: Vec<SanType>) -> Result<(KeyPair, String), TransportError> {
    let key = KeyPair::generate_for(&PKCS_ED25519).map_err(|_| TransportError::InvalidConfig)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names = names;
    let csr = params
        .serialize_request(&key)
        .and_then(|csr| csr.pem())
        .map_err(|_| TransportError::InvalidConfig)?;
    Ok((key, csr))
}

#[cfg(feature = "plaintext")]
#[derive(Clone)]
pub struct PossessionKey(rsa::RsaPrivateKey);
#[cfg(feature = "plaintext")]
impl PossessionKey {
    pub fn generate() -> Result<Self, TransportError> {
        rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
            .map(Self)
            .map_err(|_| TransportError::InvalidConfig)
    }
    /// Fingerprint for binding in a product's signed identity. Contains no private key.
    pub fn fingerprint(&self) -> Result<String, TransportError> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        use sha2::{Digest, Sha256};
        let der = self
            .0
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|_| TransportError::InvalidConfig)?;
        Ok(format!("{:x}", Sha256::digest(der.as_bytes())))
    }
    /// Secret configuration: never log or send to a server.
    pub fn native_config(&self) -> Result<serde_json::Value, TransportError> {
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
        let public = self
            .0
            .to_public_key()
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|_| TransportError::InvalidConfig)?;
        let private = self
            .0
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|_| TransportError::InvalidConfig)?;
        Ok(
            serde_json::json!({"pubkey":{"public_key_pem":public,"private_key_pem":private.as_str()}}),
        )
    }
}
#[cfg(feature = "plaintext")]
impl std::fmt::Debug for PossessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PossessionKey([REDACTED])")
    }
}

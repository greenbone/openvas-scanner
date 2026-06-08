use scannerlib::models;

use crate::{
    crypt::{self, ChaCha20Crypt, Crypt, Encrypted},
    database::dao::DAOError,
};

impl From<crypt::ParseError> for DAOError {
    fn from(value: crypt::ParseError) -> Self {
        tracing::warn!(%value, "Unable to handle encryption on credentials.");
        Self::Corrupt
    }
}

impl From<serde_json::Error> for DAOError {
    fn from(value: serde_json::Error) -> Self {
        tracing::warn!(%value, "Invalid json stored.");
        Self::Corrupt
    }
}

pub(crate) fn config_to_crypt(key: Option<&str>) -> ChaCha20Crypt {
    key.map(ChaCha20Crypt::new)
        .unwrap_or_else(|| ChaCha20Crypt::new("insecure"))
}

pub(crate) async fn encrypt_credentials<C>(
    crypter: &C,
    credentials: &[models::Credential],
) -> Result<String, DAOError>
where
    C: Crypt + Sync,
{
    let bytes = serde_json::to_vec(credentials)?;
    let encrypted = crypter.encrypt(bytes).await;
    Ok(encrypted.to_string())
}

pub(crate) async fn decrypt_credentials<C>(
    crypter: &C,
    auth_data: &str,
) -> Result<Vec<models::Credential>, DAOError>
where
    C: Crypt + Sync,
{
    if auth_data.is_empty() {
        return Ok(vec![]);
    }
    let encrypted = Encrypted::try_from(auth_data)?;
    let auth_data = crypter.decrypt(encrypted).await;
    Ok(serde_json::from_slice(&auth_data)?)
}

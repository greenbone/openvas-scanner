use ::serde::Deserialize;

#[derive(Deserialize)]
pub struct Auth {
    pub api_key: String,
    pub auth_method: String,
}

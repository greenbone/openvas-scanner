use ::serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub api_key: String,
}

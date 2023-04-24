use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SNMP {
    pub username: String,
    pub password: String,
    pub community: String,
    pub auth_algorithm: String,
    pub privacy_password: String,
    pub privacy_algorithm: String,
}

use serde::{Deserialize, Serialize};

use super::parameter::Parameter;
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VT {
    pub oid: String,
    pub parameters: Option<Vec<Parameter>>,
}

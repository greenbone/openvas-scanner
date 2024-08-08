use nasl_syntax::NaslValue;

use crate::FunctionErrorKind;

use super::FromNaslValue;

/// `Some(string)` if constructed from either a `NaslValue::String`
/// or `NaslValue::Data`.
pub struct StringOrData(pub String);

/// Turn byte data into a string.
pub fn bytes_to_str(bytes: &[u8]) -> String {
    bytes.iter().map(|x| *x as char).collect::<String>()
}

impl<'a> FromNaslValue<'a> for StringOrData {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        match value {
            NaslValue::String(string) => Ok(Self(string.clone())),
            NaslValue::Data(buffer) => Ok(Self(bytes_to_str(buffer))),
            _ => Err(FunctionErrorKind::WrongArgument(
                "Expected string or byte buffer.".to_string(),
            )),
        }
    }
}

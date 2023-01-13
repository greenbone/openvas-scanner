use std::str::FromStr;

use crate::{
    context::{ContextType, Register},
    error::FunctionError,
    interpreter::NaslValue,
    NaslFunction,
};

use sink::nvt::{NVTField, NvtPreference, PreferenceType, TagKey, NvtRef};
use sink::{Sink, SinkError};

impl From<SinkError> for FunctionError {
    fn from(_: SinkError) -> Self {
        Self {
            reason: "something went horrible wrong on a db".to_owned(),
        }
    }
}

/// Makes a storage function based on a very small DSL.
///
/// ```ignore
///make_storage_function! {
///  only_one_unnamed_parameter as_one_unnamed_field => [:1],
///  a_list_of_unnamed_parameter as_list => [:0],
///  name_value_pairs as_pair => (name: value),
///  id_is_optional as_optional_id => (name: type: value) ? (id),
///  combined => [0] (name: type: value) ? (id)
///}
/// ````
/// The first parameter is the name of the function as well as the &str lookup key.
/// Afterwards a method that transform `&[&NaslValue]` to `Result<NVTField, FunctionError>` must be defined.
///
/// Parameter are separated from the definition by a `=>`.
///
/// All parameter groups are optional.
/// The first parameter group are unnamed parameter `[amount]` the amount is the specific 
/// number of expected arguments or 0 for a variadic list.
/// Followed by required named parameter separated by `:` `(field1: field2)`.
/// The third group indicated by `(?field1: field2)` are optional named parameter.
macro_rules! make_storage_function {
    ($($name:ident $transform:expr => $([$len:expr])? $(($($value:ident):+))? $(?($($optional_value:ident):+))?),+) => {
        $(
        $(
        /// Stores
        /// positional values
        #[doc = concat!("(", stringify!($len), ")")]
        )?
        $(
        /// Stores value defined in named_parameter
        $(
        #[doc = concat!("`", stringify!($value), "`")]
        )+
        )?
        $(
        /// Stores optional value defined in named_parameter
        $(
        #[doc = concat!("`", stringify!($optional_value), "`")]
        )+
        )?
        ///
        /// Returns NaslValue::Null on success.
        pub fn $name(
            key: &str,
            storage: &dyn Sink,
            registrat: &Register,
        ) -> Result<NaslValue, FunctionError> {
            let mut variables = vec![];
            $(
            let positional = registrat.positional();
            if $len > 0 && positional.len() != $len{
                return Err(FunctionError::new(
                    format!("expected {} positional arguments but {} were given.", $len, positional.len()),
                ));
            }
            for p in positional {
                variables.push(p);
            }
            )?
            $(
            $(
            let value = get_named_parameter(registrat, stringify!($value), true)?;
            variables.push(value);
            )+
            )?
            $(
            $(
            let value = get_named_parameter(registrat, stringify!($optional_value), false)?;
            if !matches!(value, &NaslValue::Exit(0)) {
               variables.push(value);
            }
            )+
            )?
            let db_arg = $transform(&variables)?;
            storage.dispatch(key, sink::Dispatch::NVT(db_arg))?;
            Ok(NaslValue::Null)
        }
        )*
        /// Returns found function for key or None when not found
        pub fn lookup(key: &str) -> Option<NaslFunction> {
            match key {
                $(
                stringify!($name) => Some($name),
                )*
                _ => None,
            }
        }
    };
}

fn get_named_parameter<'a>(
    registrat: &'a Register,
    key: &'a str,
    required: bool,
) -> Result<&'a NaslValue, FunctionError> {
    match registrat.named(key) {
        None => {
            if required {
                Err(FunctionError::new(format!("expected {} to be set.", key)))
            } else {
                Ok(&NaslValue::Exit(0))
            }
        }
        Some(ct) => match ct {
            ContextType::Value(value) => Ok(value),
            _ => Err(FunctionError::new(format!(
                "expected {} to be a string.",
                key
            ))),
        },
    }
}

fn as_timeout_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    Ok(NVTField::Preference(NvtPreference {
        id: Some(0),
        name: "timeout".to_owned(),
        class: PreferenceType::Entry,
        default: arguments[0].to_string(),
    }))
}

fn as_category_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    match arguments[0] {
        NaslValue::AttackCategory(cat) => Ok(NVTField::Category(*cat)),
        _ => Err(FunctionError {
            reason: "unexpected type for category.".to_owned(),
        }),
    }
}

fn as_name_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    Ok(NVTField::Name(arguments[0].to_string()))
}

fn as_oid_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    Ok(NVTField::Oid(arguments[0].to_string()))
}

fn as_family_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    Ok(NVTField::Family(arguments[0].to_string()))
}

fn as_noop(_arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    Ok(NVTField::NoOp)
}

fn as_dependencies_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(NVTField::Dependencies(values))
}

fn as_exclude_keys_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(NVTField::ExcludedKeys(values))
}

fn as_mandatory_keys_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(NVTField::MandatoryKeys(values))
}

fn as_require_ports_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(NVTField::RequiredPorts(values))
}

fn as_require_udp_ports_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(NVTField::RequiredUdpPorts(values))
}

fn as_require_keys_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    let values: Vec<String> = arguments.iter().map(|x| x.to_string()).collect();
    Ok(NVTField::RequiredKeys(values))
}

fn as_cve_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    Ok(NVTField::Reference(NvtRef {
        class: "cve".to_owned(),
        id: arguments[0].to_string(),
        text: None,
    }))
}

fn as_tag_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    let key: TagKey = arguments[0].to_string().parse()?;
    Ok(NVTField::Tag(key, arguments[1].to_string()))
}

fn as_xref_field(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    if arguments.len() != 2 {
        return Err(FunctionError {
            reason: "expected either name or csv to be set".to_owned(),
        });
    }
    // TODO handle csv correctly
    Ok(NVTField::Reference(NvtRef {
        class: arguments[1].to_string(),
        id: arguments[0].to_string(),
        text: None,
    }))
}

fn as_preference(arguments: &[&NaslValue]) -> Result<NVTField, FunctionError> {
    if arguments.len() < 3 {
        return Err(FunctionError {
            reason: "expected at least name, type and value to be set.".to_owned(),
        });
    }
    let name = arguments[0].to_string();
    let class = arguments[1].to_string();
    let value = arguments[2].to_string();
    let id: Option<i32> = {
        if arguments.len() == 4 {
            match arguments[3].to_string().parse() {
                Ok(id) => Some(id),
                _ => None,
            }
        } else {
            None
        }
    };
    Ok(NVTField::Preference(NvtPreference {
        id,
        class: PreferenceType::from_str(&class)?,
        name,
        default: value,
    }))
}

// creates the actual description functions
make_storage_function! {
  script_timeout as_timeout_field => [1],
  script_category as_category_field => [1],
  script_name as_name_field => [1],
  script_version as_noop => [1],
  script_copyright as_noop => [1],
  script_family as_family_field => [1],
  script_oid as_oid_field => [1],
  script_dependencies as_dependencies_field => [0],
  script_exclude_keys as_exclude_keys_field => [0],
  script_mandatory_keys as_mandatory_keys_field => [ 0],
  script_require_ports as_require_ports_field => [ 0],
  script_require_udp_ports as_require_udp_ports_field => [ 0],
  script_require_keys as_require_keys_field => [ 0],
  script_cve_id as_cve_field => [0],
  script_tag as_tag_field => (name: value),
  script_xref as_xref_field => (name: value),
  script_add_preference as_preference => (name: type: value) ? (id)
}

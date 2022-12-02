use crate::{
    context::{ContextType, NaslContext, Register},
    error::FunctionError,
    interpreter::NaslValue,
    NaslFunction,
};

use sink::{NVTField, NvtPreference, PreferenceType, Sink, SinkError, TagKey};

impl From<SinkError> for FunctionError {
    fn from(_: SinkError) -> Self {
        Self {
            reason: "something went horrible wrong on a db".to_owned(),
        }
    }
}

/// Makes a storage function base on a very small DSL.
///
/// The DSL is defined as
/// function_name => [positional_key: expected_amount_pos_args] (key_named_parameter:value_named_parameter)
/// although the positional block as well as the named_parameter block are optional wen both are omitted a warning 
/// that the storage is unused will pop up informing the developer that this created method is useless.
macro_rules! make_storage_function {
    ($($name:ident $transform:expr => $([$key:ident : $len:expr])? $(($($value:ident):+))? ),+) => {
        $(
        $(
        /// Stores
        /// positional values
        #[doc = concat!("(", stringify!($len), ")")]
        /// as
        #[doc = concat!("`", stringify!($key), "`.")]
        )?
        $(
        /// Stores value defined in named_parameter
            $(
        #[doc = concat!("`", stringify!($value), "`")]
            )+
        )*
        ///
        /// Returns NaslValue::Null on success.
        pub fn $name(
            key: &str,
            storage: &dyn Sink,
            registrat: &Register,
        ) -> Result<NaslValue, FunctionError> {
            let ctx = registrat.last();
            let mut variables = vec![];
            $(
            let positional = ctx.positional(registrat);
            if $len > 0 && positional.len() != $len{
                return Err(FunctionError::new(
                    format!("expected {} positional arguments but {} were given.", $len, positional.len()),
                ));
            }
            for p in positional {
                match p {
                    ContextType::Value(value) => {
                        variables.push(value);
                    },
                    _ => {
                        return Err(FunctionError::new(
                            "argument is a function, string was expected".to_string(),
                        ))
                    }
                }
            }
            )?
            $(
            $(
            let value = get_named_parameter(registrat, ctx, stringify!($value))?;
            variables.push(value);
            )+
            )?
            let db_arg = $transform(&variables)?;
            storage.store(key, sink::StoreType::NVT(db_arg))?;
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
    ctx: &'a NaslContext,
    key: &'a str,
) -> Result<&NaslValue, FunctionError> {
    match ctx.named(registrat, key) {
        None => Err(FunctionError::new(format!("expected {} to be set.", key))),
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
        id: 0,
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
    Ok(NVTField::Reference(sink::NvtRef {
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
    Ok(NVTField::Reference(sink::NvtRef {
        class: arguments[1].to_string(),
        id: arguments[0].to_string(),
        text: None,
    }))
}

// creates the actual description functions
make_storage_function! {
  script_timeout as_timeout_field => [timeout :1],
  script_category as_category_field => [category :1],
  script_name as_name_field => [name :1],
  script_version as_noop => [version :1],
  script_copyright as_noop => [copyright :1],
  script_family as_family_field => [family :1],
  script_oid as_oid_field => [oid :1],
  script_dependencies as_dependencies_field => [dependencies :0],
  script_exclude_keys as_exclude_keys_field => [exclude_keys :0],
  script_mandatory_keys as_mandatory_keys_field => [mandatory_keys: 0],
  script_require_ports as_require_ports_field => [required_ports: 0],
  script_require_udp_ports as_require_udp_ports_field => [require_udp_ports: 0],
  script_require_keys as_require_keys_field => [require_keys: 0],
  script_cve_id as_cve_field => [cve_ids: 0],
  script_tag as_tag_field => (name: value),
  script_xref as_xref_field => (name: value)
}

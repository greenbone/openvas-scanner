use crate::{
    context::{ContextType, NaslContext, Register},
    error::FunctionError,
    interpreter::{NaslValue, Storage},
    NaslFunction,
};

/// Makes a storage function base on a very small DSL.
///
/// The DSL is defined as
/// function_name => [positional_key: expected_amount_pos_args] (key_named_parameter:value_named_parameter)
/// although the positional block as well as the named_parameter block are optional wen both are ommited a warning 
/// that the storage is unused will pop up informing the developer that this created method is useless.
macro_rules! make_storage_function {
    ($($name:ident=> $([$key:ident : $len:expr])? $(($nkey:ident:$value:ident)),* ),+) => {
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
        #[doc = concat!("`", stringify!($value), "`")]
        /// as key defined in 
        #[doc = concat!("`", stringify!($nkey), "`.")]
        )*
        ///
        /// Returns NaslValue::Null on success.
        pub fn $name(
            storage: &mut dyn Storage,
            registrat: &mut Register,
        ) -> Result<NaslValue, FunctionError> {
            let ctx = registrat.last();
            $(
            let positional = ctx.positional(registrat);
            if $len > 0 && positional.len() != $len{
                return Err(FunctionError::new(
                    format!("expected {} possitional arguments but {} were given.", $len, positional.len()),
                ));
            }
            for p in positional {
                match p {
                    ContextType::Value(value) => {
                        storage.write(stringify!($key), &value.to_string());
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
            let key = get_named_parameter(registrat, ctx, stringify!($nkey))?;
            let value = get_named_parameter(registrat, ctx, stringify!($value))?;

            storage.write(key, value);
            )*
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
) -> Result<&str, FunctionError> {
    match ctx.named(registrat, key) {
        None => Err(FunctionError::new(format!("expected {} to be set.", key))),
        Some(ct) => match ct {
            ContextType::Value(NaslValue::String(value)) => Ok(value),
            _ => Err(FunctionError::new(format!(
                "expected {} to be a string.",
                key
            ))),
        },
    }
}

// creates the actual description functions
make_storage_function! {
  script_timeout => [timeout :1],
  script_category => [category :1],
  script_name => [name :1],
  script_version => [version :1],
  script_copyright => [copyright :1],
  script_family => [family :1],
  script_oid => [oid :1],
  script_dependencies => [dependencies :0],
  script_exclude_keys => [exclude_keys :0],
  script_mandatory_keys => [mandatory_keys: 0],
  script_require_ports => [required_ports: 2],
  script_tag => (name: value),
  script_require_udp_ports => [require_udp_ports: 0],
  script_require_keys => [require_keys: 0],
  script_cve_id => [cve_ids: 0],
  script_xref => (name: value)
}

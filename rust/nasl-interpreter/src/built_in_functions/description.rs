use crate::{
    context::{ContextType, NaslContext, Register},
    error::FunctionError,
    interpreter::{NaslValue, Storage},
};

macro_rules! decl_store_first_unnamed_param_fn {
    ($($name:ident=> $key:ident),*) => {
        $(
        /// Stores the first positional value as
        #[doc = concat!(stringify!($key))]
        /// into the storage.
        pub fn $name(
            storage: &mut dyn Storage,
            registrat: &mut Register,
        ) -> Result<NaslValue, FunctionError> {
            match registrat.last().positional(registrat, 0) {
                None => {
                    return Err(FunctionError::new(
                        "expected at least one possitional argument, 0 were given.".to_string(),
                    ))
                }
                Some(ct) => match ct {
                    ContextType::Value(value_type) => match value_type {
                        NaslValue::String(value) => {
                            storage.write(stringify!($key), value.as_str());
                            Ok(NaslValue::Null)
                        }
                        _ => {
                            return Err(FunctionError::new(
                                "argument is of the wrong type, string was expected".to_string(),
                            ))
                        }
                    },
                    _ => {
                        return Err(FunctionError::new(
                            "argument is a function, string was expected".to_string(),
                        ))
                    }
                },
            }
        }
    )*
    };
}

decl_store_first_unnamed_param_fn! {
  nasl_script_timeout => timeout,
  nasl_script_category => category,
  nasl_script_name => name
}

fn get_named_parameter<'a>(
    registrat: &'a Register,
    ctx: &'a NaslContext,
    key: &'a str,
) -> Result<&str, FunctionError> {
    match ctx.named(registrat, key) {
        None => Err(FunctionError::new(format!("expected {} to be set.", key))),
        Some(ct) => match ct {
            ContextType::Value(NaslValue::String(value)) => Ok(&value),
            _ => Err(FunctionError::new(format!(
                "expected {} to be a string.",
                key
            ))),
        },
    }
}

macro_rules! decl_store_named_key_and_val_param_fn {
    ($($name:ident=> ($key:ident,$value:ident)),*) => {
    $(
        /// Stores the named
        #[doc = concat!(stringify!($value))]
        /// parameter as the given
        #[doc = concat!(stringify!($key))]
        /// into the storage.
        pub fn $name(
            storage: &mut dyn Storage,
            registrat: &mut Register,
        ) -> Result<NaslValue, FunctionError> {
            let ctx = registrat.last();
            let key = get_named_parameter(registrat, ctx, stringify!($key))?;
            let value = get_named_parameter(registrat, ctx, stringify!($value))?;

            storage.write(key, value);
            Ok(NaslValue::Null)

        }
    )*
    };
}

decl_store_named_key_and_val_param_fn! {
    nasl_script_tag => (name, value)
}

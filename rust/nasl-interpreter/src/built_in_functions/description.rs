use crate::{
    context::{ContextType, NaslContext, Register},
    error::FunctionError,
    interpreter::{NaslValue, Storage},
    NaslFunction,
};

macro_rules! declare_lookup {
    ($($name:ident=> $key:ident),*) => {
        pub fn lookup(key: &str) -> Option<NaslFunction> {
            match key {
                $(
                   stringify!($key) => Some($name),
                )*
                _ => None,
            }
        }
    }
}

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
        // TODO although I think it is better than manually add it in lib.rs we need to find a way
        // to get rid of the repetion of this lookup_unnamed, lookup_named ...
        // maybe we could use: https://doc.rust-lang.org/reference/procedural-macros.html#function-like-procedural-macros
        // to create an overall macro to either define single unnamed, list unnamed, named ... functions?
        fn lookup_unnamed(key: &str) -> Option<NaslFunction> {
            match key {
                $(
                   stringify!($name) => Some($name),
                )*
                _ => None,
            }
        }
    };
}

decl_store_first_unnamed_param_fn! {
  script_timeout => timeout,
  script_category => category,
  script_name => name,
  script_version => version,
  script_copyright => copyright,
  script_family => family,
  script_oid => oid
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

        // TODO although I think it is better than manually add it in lib.rs we need to find a way
        // to get rid of the repetion of this lookup_unnamed, lookup_named ...
        // maybe we could use: https://doc.rust-lang.org/reference/procedural-macros.html#function-like-procedural-macros
        // to create an overall macro to either define single unnamed, list unnamed, named ... functions?
        fn lookup_named(key: &str) -> Option<NaslFunction> {
            match key {
                $(
                   stringify!($name) => Some($name),
                )*
                _ => None,
            }
        }
    };
}

decl_store_named_key_and_val_param_fn! {
    script_tag => (name, value)
}

pub fn lookup(name: &str) -> Option<NaslFunction> {
    lookup_unnamed(name).or_else(|| lookup_named(name))
}

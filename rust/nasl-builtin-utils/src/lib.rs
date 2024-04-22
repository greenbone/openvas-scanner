// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
pub mod context;
pub mod error;
pub mod lookup_keys;
use std::collections::HashMap;

pub use context::{Context, ContextType, Register};
pub use error::FunctionErrorKind;

/// The result of a function call.
pub type NaslResult = Result<nasl_syntax::NaslValue, FunctionErrorKind>;

/// Is a type definition for built-in functions
///
/// It is mostly used internally when building a NaslFunctionExecuter.
/// The register as well as the context are given by the interpreter that wants either a result or
/// an error back.
pub type NaslFunction<'a, K> =
    fn(&Register, &Context<K>) -> Result<nasl_syntax::NaslValue, FunctionErrorKind>;

/// Looks up functions and executes them. Returns None when no function is found and a result
/// otherwise.
pub trait NaslFunctionExecuter<K> {
    /// Executes function found by name if it registered.
    ///
    /// Usually it is called by the context and not directly from the interpreter. This way it is
    /// ensured that it is using the correct context. To not have to have a context ready on
    /// initialization the context is given via a parameter.
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<NaslResult>;

    /// Returns true when the nasl function is defined otherwise false.
    fn nasl_fn_defined(&self, name: &str) -> bool;

    /// Clears the cache of the nasl function. It will be called on exit of the interpreter.
    ///
    /// This is useful for functions that cache values and need to be cleared on exit.
    /// As an example ssh functions store open sessions.
    fn nasl_fn_cache_clear(&self) -> Option<usize> {
        None
    }
}

/// Resolves positional arguments from the register.
pub fn resolve_positional_arguments(register: &Register) -> Vec<nasl_syntax::NaslValue> {
    match register.named(lookup_keys::FC_ANON_ARGS).cloned() {
        Some(ContextType::Value(nasl_syntax::NaslValue::Array(arr))) => arr,
        Some(unexpected) => {
            tracing::warn!(
                "expected array but got: {:?}. Maybe {} was overridden. Ignoring.",
                unexpected,
                lookup_keys::FC_ANON_ARGS
            );
            vec![]
        }
        None => vec![],
    }
}

/// gets a named parameter
///
/// The function name is required for the error cases that can occur when either the found
/// parameter is a function or when required is set to true and no parameter was found.
///
/// Additionally when a parameter is not required it will return Exit(0) instead of Null. This is
/// done to allow differentiation between a parameter that is set to Null on purpose.
pub fn get_named_parameter<'a>(
    registrat: &'a Register,
    key: &'a str,
    required: bool,
) -> Result<&'a nasl_syntax::NaslValue, FunctionErrorKind> {
    match registrat.named(key) {
        None => {
            if required {
                Err(FunctionErrorKind::MissingArguments(vec![key.to_owned()]))
            } else {
                // we use exit because a named value can be intentionally set to null and may be
                // treated differently when it is not set compared to set but null.
                Ok(&nasl_syntax::NaslValue::Exit(0))
            }
        }
        Some(ct) => match ct {
            ContextType::Value(value) => Ok(value),
            _ => Err((key, "value", "function").into()),
        },
    }
}
/// Holds registered NaslFunctionExecuter and executes them in order of registration.
#[derive(Default)]
pub struct NaslFunctionRegister<K> {
    executor: Vec<Box<dyn NaslFunctionExecuter<K>>>,
}

impl<K> NaslFunctionRegister<K> {
    /// Creates a new NaslFunctionRegister
    pub fn new(executor: Vec<Box<dyn NaslFunctionExecuter<K>>>) -> Self {
        Self { executor }
    }

    /// Pushes a NaslFunctionExecuter to the register
    pub fn push_executer<T>(&mut self, executor: T)
    where
        T: NaslFunctionExecuter<K> + 'static,
    {
        self.executor.push(Box::new(executor));
    }
}

impl<K> NaslFunctionExecuter<K> for NaslFunctionRegister<K> {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &context::Register,
        context: &context::Context<K>,
    ) -> Option<NaslResult> {
        for executor in &self.executor {
            if let Some(r) = executor.nasl_fn_execute(name, register, context) {
                return Some(r);
            }
        }
        None
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        for executor in &self.executor {
            if executor.nasl_fn_defined(name) {
                return true;
            }
        }
        false
    }
}

#[derive(Default)]
/// A builder for NaslFunctionRegister
pub struct NaslfunctionRegisterBuilder<K> {
    executor: Vec<Box<dyn NaslFunctionExecuter<K>>>,
}

impl<K> NaslfunctionRegisterBuilder<K> {
    /// New NaslFunctionRegisterBuilder
    pub fn new() -> Self {
        Self {
            executor: Vec::new(),
        }
    }

    /// Pushes a NaslFunctionExecuter to the register
    pub fn push_register<T>(mut self, executor: T) -> Self
    where
        T: NaslFunctionExecuter<K> + 'static,
    {
        self.executor.push(Box::new(executor));
        self
    }

    /// Builds the NaslFunctionRegister
    pub fn build(self) -> NaslFunctionRegister<K> {
        NaslFunctionRegister::new(self.executor)
    }
}

/// Is a type definition for built-in variables
///
/// It is mostly used internally when building a NaslVarDefiner.
pub type NaslVars<'a> = HashMap<&'a str, nasl_syntax::NaslValue>;

/// Looks for NaslVars.
pub trait NaslVarDefiner {
    /// Returns a NaslVars if it is registered.
    fn nasl_var_define(&self) -> NaslVars;
}

/// Holds registered NaslVarDefiner
#[derive(Default)]
pub struct NaslVarRegister {
    /// Holds all NaslVars definers
    pub definers: Vec<Box<dyn NaslVarDefiner>>,
}

impl NaslVarRegister {
    /// Creates a new NaslVarRegister
    pub fn new(definer: Vec<Box<dyn NaslVarDefiner>>) -> Self {
        Self { definers: definer }
    }
}

/// A builder for NaslVarRegister
#[derive(Default)]
pub struct NaslVarRegisterBuilder {
    definer: Vec<Box<dyn NaslVarDefiner>>,
}

impl NaslVarRegisterBuilder {
    /// Creates a new NaslVarRegister builder
    pub fn new() -> Self {
        Self {
            definer: Vec::new(),
        }
    }
    /// Push a declared NaslVarDefiner into the definer list
    pub fn push_register<T>(mut self, definer: T) -> Self
    where
        T: NaslVarDefiner + 'static,
    {
        self.definer.push(Box::new(definer));
        self
    }

    /// Build a NaslVarRegister with a vector of NaslVarsDefiner
    pub fn build(self) -> NaslVarRegister {
        NaslVarRegister::new(self.definer)
    }
}

#[cfg(test)]
mod test {

    struct Test;
    impl crate::NaslFunctionExecuter<std::string::String> for Test {
        fn nasl_fn_execute(
            &self,
            name: &str,
            register: &crate::Register,
            _context: &crate::Context<String>,
        ) -> Option<crate::NaslResult> {
            match name {
                "test" => {
                    let a: i64 = crate::get_named_parameter(register, "a", true)
                        .unwrap()
                        .into();
                    let b: i64 = crate::get_named_parameter(register, "b", true)
                        .unwrap()
                        .into();
                    Some(Ok((a + b).into()))
                }
                _ => None,
            }
        }

        fn nasl_fn_defined(&self, name: &str) -> bool {
            name == "test"
        }
    }
    #[test]
    fn register_new_function() {
        let key = "test".to_owned();
        let target = "localhost";
        let storage = storage::DefaultDispatcher::default();
        let loader = nasl_syntax::NoOpLoader::default();
        let logger = nasl_syntax::logger::DefaultLogger::default();
        let context =
            crate::Context::new(&key, target, &storage, &storage, &loader, &logger, &Test);
        let mut register = crate::Register::default();
        register.add_local("a", 1.into());
        register.add_local("b", 2.into());

        assert!(context.nasl_fn_defined("test"));
        assert_eq!(
            context.nasl_fn_execute("test", &register),
            Some(Ok(3.into()))
        );
    }
}

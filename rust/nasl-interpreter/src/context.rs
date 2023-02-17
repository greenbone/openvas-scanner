// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use nasl_syntax::Statement;

use crate::{
    error::InterpretError,
    logger::{DefaultLogger, NaslLogger},
    lookup_keys::FC_ANON_ARGS,
    NaslValue,
};

/// Contexts are responsible to locate, add and delete everything that is declared within a NASL plugin

/// Represents a Value within the NaslContext
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextType {
    /// Represents a Function definition
    Function(Vec<String>, Statement),
    /// Represents a Variable or Parameter
    Value(NaslValue),
}

impl ToString for ContextType {
    fn to_string(&self) -> String {
        match self {
            ContextType::Function(_, _) => "".to_owned(),
            ContextType::Value(v) => v.to_string(),
        }
    }
}

impl From<NaslValue> for ContextType {
    fn from(value: NaslValue) -> Self {
        Self::Value(value)
    }
}

impl From<Vec<u8>> for ContextType {
    fn from(s: Vec<u8>) -> Self {
        Self::Value(s.into())
    }
}

impl From<bool> for ContextType {
    fn from(b: bool) -> Self {
        Self::Value(b.into())
    }
}

impl From<&str> for ContextType {
    fn from(s: &str) -> Self {
        Self::Value(s.into())
    }
}

impl From<String> for ContextType {
    fn from(s: String) -> Self {
        Self::Value(s.into())
    }
}

impl From<i32> for ContextType {
    fn from(n: i32) -> Self {
        Self::Value(n.into())
    }
}

impl From<i64> for ContextType {
    fn from(n: i64) -> Self {
        Self::Value(n.into())
    }
}

impl From<usize> for ContextType {
    fn from(n: usize) -> Self {
        Self::Value(n.into())
    }
}

impl From<HashMap<String, NaslValue>> for ContextType {
    fn from(x: HashMap<String, NaslValue>) -> Self {
        Self::Value(x.into())
    }
}
/// Registers all NaslContext
///
/// When creating a new context call a corresponding create method.
/// Warning since those will be stored within a vector each context must be manually
/// deleted by calling drop_last when the context runs out of scope.
pub struct Register {
    blocks: Vec<NaslContext>,
    logger: Box<dyn NaslLogger>,
}

impl Register {
    /// Creates an empty register
    pub fn new() -> Self {
        Self {
            blocks: vec![NaslContext::default()],
            logger: Box::new(DefaultLogger::new()),
        }
    }

    /// Creates a root Register based on the given initial values
    pub fn root_initial(initial: &[(String, ContextType)]) -> Self {
        let mut defined = HashMap::with_capacity(initial.len());
        for (k, v) in initial {
            defined.insert(k.to_owned(), v.to_owned());
        }
        let root = NaslContext {
            defined,
            ..Default::default()
        };
        Self {
            blocks: vec![root],
            logger: Box::<DefaultLogger>::default(),
        }
    }

    /// Get the logger to print messages
    pub fn logger(&self) -> &dyn NaslLogger {
        &*self.logger
    }

    /// Set a new logger
    pub fn set_logger(&mut self, logger: Box<dyn NaslLogger>) {
        self.logger = logger;
    }

    /// Returns the next index
    pub fn index(&self) -> usize {
        self.blocks.len()
    }

    /// Creates a child context
    pub fn create_child(&mut self, parent: &NaslContext, defined: Named) -> &NaslContext {
        let result = NaslContext {
            parent: Some(parent.id),
            id: self.index(),
            defined,
        };
        self.blocks.push(result);
        return self.blocks.last_mut().unwrap();
    }

    /// Creates a child context for the root context.
    ///
    /// This is used to function calls to prevent that the called function can access the
    /// context of the caller.
    pub fn create_root_child(&mut self, defined: Named) -> &NaslContext {
        let result = NaslContext {
            parent: Some(0),
            id: self.index(),
            defined,
        };
        self.blocks.push(result);
        return self.blocks.last_mut().unwrap();
    }

    /// Returns the last created context.
    ///
    /// The idea is that since NASL is an iterative language the last context is also the current
    /// one.
    fn last(&self) -> &NaslContext {
        let last = self.blocks.last();
        last.unwrap()
    }

    /// Finds a named ContextType
    pub fn named<'a>(&'a self, name: &'a str) -> Option<&ContextType> {
        self.last().named(self, name).map(|(_, val)| val)
    }

    /// Finds a named ContextType with index
    pub fn index_named<'a>(&'a self, name: &'a str) -> Option<(usize, &ContextType)> {
        self.last().named(self, name)
    }

    /// Returns a mutable reference of the current context
    pub fn last_mut(&mut self) -> &mut NaslContext {
        let last = self.blocks.last_mut();
        last.unwrap()
    }

    /// Adds a named parameter to the root context
    pub fn add_global(&mut self, name: &str, value: ContextType) {
        let global = &mut self.blocks[0];
        global.add_named(name, value);
    }

    /// Adds a named parameter to the root context
    pub fn add_to_index(
        &mut self,
        idx: usize,
        name: &str,
        value: ContextType,
    ) -> Result<(), InterpretError> {
        if idx >= self.blocks.len() {
            panic!("The given index should be retrieved by named_value. Therefore this should not happen.");
        } else {
            let global = &mut self.blocks[idx];
            global.add_named(name, value);
            Ok(())
        }
    }
    /// Adds a named parameter to the last context
    pub fn add_local(&mut self, name: &str, value: ContextType) {
        let last = &mut self.last_mut();
        last.add_named(name, value);
    }

    /// Retrieves all positional definitions
    pub fn positional(&self) -> &[NaslValue] {
        match self.named(FC_ANON_ARGS) {
            Some(ContextType::Value(NaslValue::Array(arr))) => arr,
            _ => &[],
        }
    }

    /// Destroys the current context.
    ///
    /// This must be called when a context vanishes.
    /// E.g. after a block statement is proceed or a function call is finished.
    pub fn drop_last(&mut self) {
        self.blocks.pop();
    }
}

impl Default for Register {
    fn default() -> Self {
        Self::new()
    }
}
use std::collections::HashMap;
type Named = HashMap<String, ContextType>;

/// NaslContext is a struct to contain variables and if root declared functions
///
/// A context should never be created directly but via a Register.
/// The reason for that is that a Registrat contains all blocks and a block must be registered to ensure that each Block must be created via an Registrat.
#[derive(Default)]
pub struct NaslContext {
    /// Parent id within the register
    parent: Option<usize>,
    /// Own id within the register
    id: usize,
    /// The defined values/ functions.
    defined: Named,
}

impl NaslContext {
    /// Adds a named parameter to the context
    fn add_named(&mut self, name: &str, value: ContextType) {
        self.defined.insert(name.to_owned(), value);
    }

    /// Retrieves a definition by name
    fn named<'a>(
        &'a self,
        registrat: &'a Register,
        name: &'a str,
    ) -> Option<(usize, &ContextType)> {
        // first check local
        match self.defined.get(name) {
            Some(ctx) => Some((self.id, ctx)),
            None => match self.parent {
                Some(parent) => registrat.blocks[parent].named(registrat, name),
                None => None,
            },
        }
    }
}

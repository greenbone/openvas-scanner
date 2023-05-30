// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use nasl_syntax::Statement;
use storage::{DefaultDispatcher, Dispatcher, Retriever};

use crate::{logger::NaslLogger, lookup_keys::FC_ANON_ARGS, sessions::Sessions, Loader, NaslValue};

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

impl From<&ContextType> for i64 {
    fn from(ct: &ContextType) -> i64 {
        match ct {
            ContextType::Value(NaslValue::Number(i)) => *i,
            _ => i64::default(),
        }
    }
}

impl From<&ContextType> for String {
    fn from(ct: &ContextType) -> String {
        match ct {
            ContextType::Value(NaslValue::String(s)) => s.to_string(),
            _ => String::default(),
        }
    }
}

impl From<&ContextType> for bool {
    fn from(ct: &ContextType) -> bool {
        match ct {
            ContextType::Value(NaslValue::Boolean(b)) => *b,
            _ => bool::default(),
        }
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
}

impl Register {
    /// Creates an empty register
    pub fn new() -> Self {
        Self {
            blocks: vec![NaslContext::default()],
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
        Self { blocks: vec![root] }
    }

    /// Returns the next index
    pub fn index(&self) -> usize {
        self.blocks.len()
    }

    /// Creates a child context using the last context as a parent
    pub fn create_child(&mut self, defined: Named) {
        let parent_id = self.blocks.last().map(|x| x.id).unwrap_or_default();
        let result = NaslContext {
            parent: Some(parent_id),
            id: self.index(),
            defined,
        };
        self.blocks.push(result);
    }

    /// Creates a child context for the root context.
    ///
    /// This is used to function calls to prevent that the called function can access the
    /// context of the caller.
    pub fn create_root_child(&mut self, defined: Named) {
        let result = NaslContext {
            parent: Some(0),
            id: self.index(),
            defined,
        };
        self.blocks.push(result);
    }

    /// Finds a named ContextType
    pub fn named<'a>(&'a self, name: &'a str) -> Option<&ContextType> {
        self.blocks
            .last()
            .and_then(|x| x.named(self, name))
            .map(|(_, val)| val)
    }

    /// Finds a named ContextType with index
    pub fn index_named<'a>(&'a self, name: &'a str) -> Option<(usize, &ContextType)> {
        self.blocks.last().and_then(|x| x.named(self, name))
    }

    /// Adds a named parameter to the root context
    pub fn add_global(&mut self, name: &str, value: ContextType) {
        let global = &mut self.blocks[0];
        global.add_named(name, value);
    }

    /// Adds a named parameter to the root context
    pub fn add_to_index(&mut self, idx: usize, name: &str, value: ContextType) {
        if idx >= self.blocks.len() {
            panic!("The given index should be retrieved by named_value. Therefore this should not happen.");
        } else {
            let global = &mut self.blocks[idx];
            global.add_named(name, value);
        }
    }
    /// Adds a named parameter to the last context
    pub fn add_local(&mut self, name: &str, value: ContextType) {
        if let Some(last) = self.blocks.last_mut() {
            last.add_named(name, value);
        }
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

/// Configurations
///
/// This struct includes all objects that a nasl function requires.
/// New objects must be added here in
pub struct Context<'a, K> {
    /// key for this context. A name or an OID
    key: &'a K,
    /// target to run a scan against
    target: &'a str,
    /// Default Dispatcher
    dispatcher: &'a dyn Dispatcher<K>,
    /// Default Retriever
    retriever: &'a dyn Retriever<K>,
    /// Default Loader
    loader: &'a dyn Loader,
    /// Default logger.
    logger: &'a dyn NaslLogger,
    /// Default logger.
    sessions: &'a Sessions,
}

impl<'a, K> Context<'a, K> {
    /// Creates an empty configuration
    pub fn new(
        key: &'a K,
        target: &'a str,
        dispatcher: &'a dyn Dispatcher<K>,
        retriever: &'a dyn Retriever<K>,
        loader: &'a dyn Loader,
        logger: &'a dyn NaslLogger,
        sessions: &'a Sessions,
    ) -> Self {
        Self {
            key,
            target,
            dispatcher,
            retriever,
            loader,
            logger,
            sessions,
        }
    }

    /// Get the logger to print messages
    pub fn logger(&self) -> &dyn NaslLogger {
        self.logger
    }
    /// Get the Key
    pub fn key(&self) -> &K {
        self.key
    }
    /// Get the target host
    pub fn target(&self) -> &str {
        self.target
    }
    /// Get the storage
    pub fn dispatcher(&self) -> &dyn Dispatcher<K> {
        self.dispatcher
    }
    /// Get the storage
    pub fn retriever(&self) -> &dyn Retriever<K> {
        self.retriever
    }
    /// Get the loader
    pub fn loader(&self) -> &dyn Loader {
        self.loader
    }
    /// Get the sessions
    pub fn sessions(&self) -> &Sessions {
        self.sessions
    }
}
/// Can be used as DefaultContext::default().as_context() within tests
#[derive(Default)]
pub struct DefaultContext {
    /// key for the default context. A name or an OID
    pub key: String,
    /// Default target host
    pub target: String,
    /// Default Storage
    pub dispatcher: Box<DefaultDispatcher<String>>,
    /// Default Loader
    pub loader: Box<dyn Loader>,
    /// Default logger
    pub logger: Box<dyn NaslLogger>,
    /// Default logger
    pub sessions: Sessions,
}

impl DefaultContext {
    /// Converts a DefaultContext to Context
    pub fn as_context(&self) -> Context<String> {
        Context {
            key: &self.key,
            target: &self.target,
            dispatcher: &*self.dispatcher,
            retriever: &*self.dispatcher,
            loader: &*self.loader,
            logger: self.logger.as_ref(),
            sessions: &self.sessions,
        }
    }
}


impl From<&ContextType> for NaslValue {
    fn from(value: &ContextType) -> Self {
        match value {
            ContextType::Function(_, _) => NaslValue::Null,
            ContextType::Value(v) => v.to_owned(),
        }
    }
}

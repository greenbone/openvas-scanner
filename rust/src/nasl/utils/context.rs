// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines the context used within the interpreter and utilized by the builtin functions

use itertools::Itertools;

use crate::nasl::builtin::KBError;
use crate::nasl::syntax::{Loader, NaslValue, Statement};
use crate::nasl::{FromNaslValue, WithErrorInfo};
use crate::storage::{ContextKey, Dispatcher, Field, Retrieve, Retriever};

use super::error::ReturnBehavior;
use super::hosts::resolve;
use super::FnError;
use super::{executor::Executor, lookup_keys::FC_ANON_ARGS};

/// Contexts are responsible to locate, add and delete everything that is declared within a NASL plugin
///
/// Represents a Value within the NaslContext
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextType {
    /// Represents a Function definition
    Function(Vec<String>, Statement),
    /// Represents a Variable or Parameter
    Value(NaslValue),
}

impl std::fmt::Display for ContextType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContextType::Function(_, _) => write!(f, ""),
            ContextType::Value(v) => write!(f, "{v}"),
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
#[derive(Clone)]
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
    pub fn named<'a>(&'a self, name: &'a str) -> Option<&'a ContextType> {
        self.blocks
            .last()
            .and_then(|x| x.named(self, name))
            .map(|(_, val)| val)
    }

    /// Finds a named ContextType with index
    pub fn index_named<'a>(&'a self, name: &'a str) -> Option<(usize, &'a ContextType)> {
        self.blocks.last().and_then(|x| x.named(self, name))
    }

    /// Return an iterator over the names of the named arguments.
    pub fn iter_named_args(&self) -> Option<impl Iterator<Item = &str>> {
        self.blocks
            .last()
            .map(|x| x.defined.keys().map(|x| x.as_str()))
    }

    /// Adds a named parameter to the root context
    pub fn add_global(&mut self, name: &str, value: ContextType) {
        let global = &mut self.blocks[0];
        global.add_named(name, value);
    }

    /// Adds a named parameter to a specified context
    pub fn add_to_index(&mut self, idx: usize, name: &str, value: ContextType) {
        if idx >= self.blocks.len() {
            panic!("The given index should be retrieved by named_value. Therefore this should not happen.");
        } else {
            let ctx = &mut self.blocks[idx];
            ctx.add_named(name, value);
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

    /// This function extracts number of positional arguments, available functions and variables
    /// and prints them. This function is used as a debugging tool.
    pub fn dump(&self, index: usize) {
        match self.blocks.get(index) {
            Some(mut current) => {
                let mut vars = vec![];
                let mut funs = vec![];

                // Get number of positional arguments
                let num_pos = match current.named(self, FC_ANON_ARGS).map(|(_, val)| val) {
                    Some(ContextType::Value(NaslValue::Array(arr))) => arr.len(),
                    _ => 0,
                };

                // collect all available functions and variables available in current and parent
                // context recursively
                loop {
                    for (name, ctype) in current.defined.clone() {
                        if vars.contains(&name) || funs.contains(&name) || name == FC_ANON_ARGS {
                            continue;
                        }

                        match ctype {
                            ContextType::Function(_, _) => funs.push(name),
                            ContextType::Value(_) => vars.push(name),
                        };
                    }
                    if let Some(parent) = current.parent {
                        current = &self.blocks[parent];
                    } else {
                        break;
                    }
                }

                // Print all available information
                println!("--------<CTXT>--------");
                println!("number of positional arguments: {}", num_pos);
                println!();
                println!("available functions:");
                for function in funs {
                    print!("{function}\t");
                }
                println!();
                println!();
                println!("available variables:");
                for var in vars {
                    print!("{var}\t");
                }
                println!();
                println!("----------------------");
            }
            None => println!("No context available"),
        };
    }
}

impl Default for Register {
    fn default() -> Self {
        Self::new()
    }
}
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Mutex;

type Named = HashMap<String, ContextType>;

/// NaslContext is a struct to contain variables and if root declared functions
///
/// A context should never be created directly but via a Register.
/// The reason for that is that a Registrat contains all blocks and a block must be registered to ensure that each Block must be created via an Registrat.
#[derive(Default, Clone)]
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
    ) -> Option<(usize, &'a ContextType)> {
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

#[derive(Debug)]
pub struct Target {
    /// The original target. IP or hostname
    target: String,
    /// The IP address. Always has a valid IP. It defaults to 127.0.0.1 if not possible to resolve target.
    ip_addr: IpAddr,
    // The shared state is guarded by a mutex. This is a `std::sync::Mutex` and
    // not a Tokio mutex. This is because there are no asynchronous operations
    // being performed while holding the mutex. Additionally, the critical
    // sections are very small.
    //
    // A Tokio mutex is mostly intended to be used when locks need to be held
    // across `.await` yield points. All other cases are **usually** best
    // served by a std mutex. If the critical section does not include any
    // async operations but is long (CPU intensive or performing blocking
    // operations), then the entire operation, including waiting for the mutex,
    // is considered a "blocking" operation and `tokio::task::spawn_blocking`
    // should be used.
    /// vhost list which resolve to the IP address and their sources.
    vhosts: Mutex<Vec<(String, String)>>,
}

impl Target {
    pub fn set_target(&mut self, target: String) -> &Target {
        // Target can be an ip address or a hostname
        self.target = target;

        // Store the IpAddr if possible, else default to localhost
        self.ip_addr = match resolve(self.target.clone()) {
            Ok(a) => *a.first().unwrap_or(&IpAddr::from_str("127.0.0.1").unwrap()),
            Err(_) => IpAddr::from_str("127.0.0.1").unwrap(),
        };
        self
    }

    pub fn add_hostname(&self, hostname: String, source: String) -> &Target {
        self.vhosts.lock().unwrap().push((hostname, source));
        self
    }
}

impl Default for Target {
    fn default() -> Self {
        Self {
            target: String::new(),
            ip_addr: IpAddr::from_str("127.0.0.1").unwrap(),
            vhosts: Mutex::new(vec![]),
        }
    }
}
/// Configurations
///
/// This struct includes all objects that a nasl function requires.
/// New objects must be added here in
pub struct Context<'a> {
    /// key for this context. A file name or a scan id
    key: ContextKey,
    /// target to run a scan against
    target: Target,
    /// Default Dispatcher
    dispatcher: &'a dyn Dispatcher,
    /// Default Retriever
    retriever: &'a dyn Retriever,
    /// Default Loader
    loader: &'a dyn Loader,
    /// Default function executor.
    executor: &'a Executor,
}

impl<'a> Context<'a> {
    /// Creates an empty configuration
    pub fn new(
        key: ContextKey,
        target: Target,
        dispatcher: &'a dyn Dispatcher,
        retriever: &'a dyn Retriever,
        loader: &'a dyn Loader,
        executor: &'a Executor,
    ) -> Self {
        Self {
            key,
            target,
            dispatcher,
            retriever,
            loader,
            executor,
        }
    }

    /// Executes a function by name
    ///
    /// Returns None when the function was not found.
    pub async fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
    ) -> Option<super::NaslResult> {
        self.executor.exec(name, self, register).await
    }

    /// Checks if a function is defined
    pub fn nasl_fn_defined(&self, name: &str) -> bool {
        self.executor.contains(name)
    }

    /// Get the executor
    pub fn executor(&self) -> &'a Executor {
        self.executor
    }

    /// Get the Key
    pub fn key(&self) -> &ContextKey {
        &self.key
    }

    /// Get the target IP as string
    pub fn target(&self) -> &str {
        &self.target.target
    }

    /// Get the target host as IpAddr enum member
    pub fn target_ip(&self) -> IpAddr {
        self.target.ip_addr
    }

    /// Get the target VHost list
    pub fn target_vhosts(&self) -> Vec<(String, String)> {
        self.target.vhosts.lock().unwrap().clone()
    }

    pub fn set_target(&mut self, target: String) {
        self.target.target = target;
    }

    pub fn add_hostname(&self, hostname: String, source: String) {
        self.target.add_hostname(hostname, source);
    }

    /// Get the storage
    pub fn dispatcher(&self) -> &dyn Dispatcher {
        self.dispatcher
    }

    /// Get the storage
    pub fn retriever(&self) -> &dyn Retriever {
        self.retriever
    }

    /// Get the loader
    pub fn loader(&self) -> &dyn Loader {
        self.loader
    }

    /// Return a single item from the knowledge base.
    /// If multiple entries are found (which would result
    /// in forking the interpreter), return an error.
    /// This function automatically converts the item
    /// to a specific type via its `FromNaslValue` impl
    /// and returns the appropriate error if necessary.
    pub fn get_single_kb_item<T: for<'b> FromNaslValue<'b>>(
        &self,
        name: &str,
    ) -> Result<T, FnError> {
        // If we find multiple or no items at all, return an error that
        // exits the script instead of continuing execution with a return
        // value, since this is most likely an error in the feed.
        let val = self
            .get_single_kb_item_inner(name)
            .map_err(|e| e.with(ReturnBehavior::ExitScript))?;
        T::from_nasl_value(&val)
    }

    fn get_single_kb_item_inner(&self, name: &str) -> Result<NaslValue, FnError> {
        let result = self
            .retriever()
            .retrieve(&self.key, Retrieve::KB(name.to_string()))?;
        let single_item = result
            .filter_map(|field| match field {
                Field::KB(kb) => Some(kb.value.into()),
                _ => None,
            })
            .at_most_one()
            .map_err(|_| KBError::MultipleItemsFound(name.to_string()))?
            .ok_or_else(|| KBError::ItemNotFound(name.to_string()))?;
        Ok(single_item)
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

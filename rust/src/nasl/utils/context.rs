// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines the context used within the interpreter and utilized by the builtin functions

use itertools::Itertools;
use tokio::sync::RwLock;
use rand::seq::SliceRandom;

use crate::models::PortRange;
use crate::nasl::builtin::{KBError, NaslSockets};
use crate::nasl::syntax::{Loader, NaslValue, Statement};
use crate::nasl::{FromNaslValue, WithErrorInfo};
use crate::storage::error::StorageError;
use crate::storage::infisto::json::JsonStorage;
use crate::storage::inmemory::InMemoryStorage;
use crate::storage::items::kb::{self, KbKey};
use crate::storage::items::kb::{GetKbContextKey, KbContextKey, KbItem};
use crate::storage::items::nvt::NvtField;
use crate::storage::items::nvt::{Feed, FeedVersion, FileName, Nvt};
use crate::storage::items::result::{ResultContextKeyAll, ResultContextKeySingle, ResultItem};
use crate::storage::redis::{
    RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper,
};
use crate::storage::{self, ScanID};
use crate::storage::{Dispatcher, Remover, Retriever};

use super::FnError;
use super::error::ReturnBehavior;
use super::hosts::resolve;
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
            panic!(
                "The given index should be retrieved by named_value. Therefore this should not happen."
            );
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
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

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

#[derive(Debug, Clone)]
pub struct VHost {
    source: String,
    hostname: String,
}

impl VHost {
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn source(&self) -> &str {
        &self.source
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
    vhosts: Mutex<Vec<VHost>>,
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
        self.vhosts.lock().unwrap().push(VHost { hostname, source });
        self
    }

    pub fn target(&self) -> &str {
        &self.target
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

pub trait ContextStorage:
    Sync
    + Send
    // kb
    + Dispatcher<KbContextKey, Item = KbItem>
    + Retriever<KbContextKey, Item = Vec<KbItem>>
    + Retriever<GetKbContextKey, Item = Vec<(String, Vec<KbItem>)>>
    + Remover<KbContextKey, Item = Vec<KbItem>>
    // results
    + Dispatcher<ScanID, Item = ResultItem>
    + Retriever<ResultContextKeySingle, Item = ResultItem>
    + Retriever<ResultContextKeyAll, Item = Vec<ResultItem>>
    + Remover<ResultContextKeySingle, Item = ResultItem>
    + Remover<ResultContextKeyAll, Item = Vec<ResultItem>>
    // nvt
    + Dispatcher<FileName, Item = Nvt>
    + Dispatcher<FeedVersion, Item = String>
    + Retriever<FeedVersion, Item = String>
    + Retriever<Feed, Item = Vec<Nvt>>
{
    /// By default the KbKey can hold multiple values. When dispatch is used on an already existing
    /// KbKey, the value is appended to the existing list. This function is used to replace the
    /// existing entry with the new one.
    fn dispatch_replace(&self, key: KbContextKey, item: KbItem) -> Result<(), StorageError> {
        self.remove(&key)?;
        self.dispatch(key, item)
    }

}
impl ContextStorage for InMemoryStorage {}
impl<T: Write + Send> ContextStorage for JsonStorage<T> {}
impl<T> ContextStorage for RedisStorage<T> where
    T: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Send
{
}
impl<T> ContextStorage for Arc<T> where T: ContextStorage {}


/// This struct includes all objects that a nasl function requires.
pub struct Context<'a> {
    /// key for this context. A file name or a scan id
    scan: ScanID,
    /// target to run a scan against
    target: Target,
    /// File Name of the current script
    filename: PathBuf,
    /// Storage
    storage: &'a dyn ContextStorage,
    /// Default Loader
    loader: &'a dyn Loader,
    /// Default function executor.
    executor: &'a Executor,
    /// NVT object, which is put into the storage, when set
    nvt: Mutex<Option<Nvt>>,
    sockets: RwLock<NaslSockets>,
}

impl<'a> Context<'a> {
    /// Creates an empty configuration
    pub fn new(
        scan: ScanID,
        target: Target,
        filename: PathBuf,
        storage: &'a dyn ContextStorage,
        loader: &'a dyn Loader,
        executor: &'a Executor,
    ) -> Self {
        Self {
            scan,
            target,
            filename,
            storage,
            loader,
            executor,
            nvt: Mutex::new(None),
            sockets: RwLock::new(NaslSockets::default()),
        }
    }

    /// Executes a function by name
    ///
    /// Returns None when the function was not found.
    pub async fn execute_builtin_fn(
        &self,
        name: &str,
        register: &Register,
    ) -> Option<super::NaslResult> {
        const NUM_RETRIES_ON_RETRYABLE_ERROR: usize = 5;

        let mut i = 0;
        loop {
            i += 1;
            let result = self.executor.exec(name, self, register).await;
            if let Some(Err(ref e)) = result {
                if e.retryable() && i < NUM_RETRIES_ON_RETRYABLE_ERROR {
                    continue;
                }
            }
            return result;
        }
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
    pub fn scan(&self) -> &ScanID {
        &self.scan
    }

    /// Get the target IP as string
    pub fn target(&self) -> &str {
        &self.target.target
    }

    pub fn filename(&self) -> &PathBuf {
        &self.filename
    }

    /// Get the target host as IpAddr enum member
    pub fn target_ip(&self) -> IpAddr {
        self.target.ip_addr
    }

    /// Get the target VHost list
    pub fn target_vhosts(&self) -> Vec<VHost> {
        self.target.vhosts.lock().unwrap().clone()
    }

    pub fn set_target(&mut self, target: String) {
        self.target.target = target;
    }

    pub fn add_hostname(&self, hostname: String, source: String) {
        self.target.add_hostname(hostname, source);
    }

    pub fn port_range(&self) -> PortRange {
        // TODO Get this from the scan prefs
        PortRange {
            start: 0,
            end: None,
        }
    }

    /// Get the storage
    pub fn storage(&self) -> &dyn ContextStorage {
        self.storage
    }
    /// Get the loader
    pub fn loader(&self) -> &dyn Loader {
        self.loader
    }

    pub fn set_nvt_field(&self, field: NvtField) {
        let mut nvt = self.nvt.lock().unwrap();
        match nvt.as_mut() {
            Some(nvt) => {
                nvt.set_from_field(field);
            }
            _ => {
                let mut new = Nvt {
                    filename: self.filename().to_string_lossy().to_string(),
                    ..Default::default()
                };
                new.set_from_field(field);
                *nvt = Some(new);
            }
        }
    }

    pub fn dispatch_nvt(&self, nvt: Nvt) {
        self.storage
            .dispatch(FileName(self.filename.to_string_lossy().to_string()), nvt)
            .unwrap();
    }

    fn kb_key(&self, key: KbKey) -> KbContextKey {
        KbContextKey(
            (
                self.scan.clone(),
                storage::Target(self.target.target.clone()),
            ),
            key,
        )
    }

    pub fn set_kb_item(&self, key: KbKey, value: KbItem) -> Result<(), FnError> {
        self.storage.dispatch(self.kb_key(key), value)?;
        Ok(())
    }

    pub fn get_kb_item(&self, key: &KbKey) -> Result<Vec<KbItem>, FnError> {
        let result = self
            .storage
            .retrieve(&self.kb_key(key.clone()))?
            .unwrap_or_default();
        Ok(result)
    }

    pub fn get_kb_items_with_keys(
        &self,
        key: &KbKey,
    ) -> Result<Vec<(String, Vec<KbItem>)>, FnError> {
        let result = self
            .storage
            .retrieve(&GetKbContextKey(
                (
                    self.scan.clone(),
                    storage::Target(self.target.target.clone()),
                ),
                key.clone(),
            ))?
            .unwrap_or_default();
        Ok(result)
    }

    pub fn set_single_kb_item<T: Into<KbItem>>(&self, key: KbKey, value: T) -> Result<(), FnError> {
        self.storage
            .dispatch_replace(self.kb_key(key), value.into())?;
        Ok(())
    }

    /// Return a single item from the knowledge base.
    /// If multiple entries are found (which would result
    /// in forking the interpreter), return an error.
    /// This function automatically converts the item
    /// to a specific type via its `FromNaslValue` impl
    /// and returns the appropriate error if necessary.
    pub fn get_single_kb_item<T: for<'b> FromNaslValue<'b>>(
        &self,
        key: &KbKey,
    ) -> Result<T, FnError> {
        // If we find multiple or no items at all, return an error that
        // exits the script instead of continuing execution with a return
        // value, since this is most likely an error in the feed.
        let val = self
            .get_single_kb_item_inner(key)
            .map_err(|e| e.with(ReturnBehavior::ExitScript))?;
        T::from_nasl_value(&val.into())
    }

    fn get_single_kb_item_inner(&self, key: &KbKey) -> Result<KbItem, FnError> {
        let result = self.storage().retrieve(&self.kb_key(key.clone()))?;
        let item = result.ok_or_else(|| KBError::ItemNotFound(key.to_string()))?;

        match item.len() {
            0 => Ok(KbItem::Null),
            1 => Ok(item[0].clone()),
            _ => Err(KBError::MultipleItemsFound(key.to_string()).into()),
        }
    }
    // TODO: Check which KbKey is used for Port Transport
    /// Sets the state of a port
    pub fn set_port_transport(&self, port: u16, transport: usize) -> Result<(), FnError> {
        self.set_single_kb_item(
            KbKey::Port(kb::Port::Tcp(port.to_string())),
            KbItem::Number(transport as i64),
        )
    }

    pub fn get_port_transport(&self, port: u16) -> Result<Option<i64>, FnError> {
        self.get_single_kb_item_inner(&KbKey::Port(kb::Port::Tcp(port.to_string())))
            .map(|x| match x {
                KbItem::Number(n) => Some(n),
                _ => None,
            })
    }

    /// Don't always return the first open port, otherwise
    /// we might get bitten by OSes doing active SYN flood
    /// countermeasures. Also, avoid returning 80 and 21 as
    /// open ports, as many transparent proxies are acting for these...
    pub fn get_host_open_port(&self) -> Result<u16, FnError> {
        let mut open21 = false;
        let mut open80 = false;
        let ports: Vec<u16> = self
            .get_kb_items_with_keys(&KbKey::Port(kb::Port::Tcp("*".to_string())))?
            .iter()
            .filter_map(|x| {
                x.0.split('/').last().and_then(|x| {
                    if x == "21" {
                        open21 = true;
                        None
                    } else if x == "80" {
                        open80 = true;
                        None
                    } else {
                        x.parse::<u16>().ok()
                    }
                })
            })
            .collect();

        let ret = if ports.is_empty() {
            *ports.choose(&mut rand::thread_rng()).unwrap()
        } else if open21 {
            21
        } else if open80 {
            80
        } else {
            0
        };
        Ok(ret)
    }

    pub async fn read_sockets(&self) -> tokio::sync::RwLockReadGuard<'_, NaslSockets> {
        // TODO do not unwrap?
        self.sockets.read().await
    }

    pub async fn write_sockets(&self) -> tokio::sync::RwLockWriteGuard<'_, NaslSockets> {
        // TODO do not unwrap?
        self.sockets.write().await
    }
}

impl Drop for Context<'_> {
    fn drop(&mut self) {
        let mut nvt = self.nvt.lock().unwrap();
        if let Some(nvt) = nvt.take() {
            self.dispatch_nvt(nvt);
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

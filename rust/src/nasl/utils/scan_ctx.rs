// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines the context used within the interpreter and utilized by the builtin functions

use tokio::sync::RwLock;

use crate::models::{AliveTestMethods, Port, PortRange, Protocol, ScanPreference};
use crate::nasl::builtin::{KBError, NaslSockets};
use crate::nasl::syntax::{Loader, NaslValue, Statement};
use crate::nasl::{ArgumentError, FromNaslValue, WithErrorInfo};
use crate::scanner::preferences::preference::ScanPrefs;
use crate::storage::error::StorageError;
use crate::storage::infisto::json::JsonStorage;
use crate::storage::inmemory::InMemoryStorage;
use crate::storage::items::kb::{self, KbKey};
use crate::storage::items::kb::{GetKbContextKey, KbContextKey, KbItem};
use crate::storage::items::nvt::{Feed, FeedVersion, FileName, Nvt};
use crate::storage::items::nvt::{NvtField, Oid};
use crate::storage::items::result::{ResultContextKeySingle, ResultItem};
use crate::storage::redis::{
    RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper,
};
use crate::storage::{self, ScanID};
use crate::storage::{Dispatcher, Remover, Retriever};
use rand::seq::SliceRandom;
use std::sync::MutexGuard;

use super::FnError;
use super::error::ReturnBehavior;
use super::hosts::{LOCALHOST, resolve_hostname};
use super::{
    executor::Executor,
    lookup_keys::{FC_ANON_ARGS, SCRIPT_PARAMS},
};

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
#[derive(Clone, Debug)]
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

    /// Find a named argument and return its value as a variable
    /// or an error otherwise
    pub(crate) fn nasl_value<'a>(&'a self, arg: &'a str) -> Result<&'a NaslValue, ArgumentError> {
        match self.named(arg) {
            Some(ContextType::Value(val)) => Ok(val),
            Some(_) => Err(ArgumentError::WrongArgument(format!(
                "Argument {arg} is a function but should be a value."
            ))),
            None => Err(ArgumentError::MissingNamed(vec![arg.to_string()])),
        }
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

    /// Retrieves a script parameter by id
    pub fn script_param(&self, id: usize) -> Option<NaslValue> {
        match self.named(format!("{SCRIPT_PARAMS}_{id}").as_str()) {
            Some(ContextType::Value(v)) => Some(v.clone()),
            _ => None,
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
                println!("number of positional arguments: {num_pos}");
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
use socket2;
use std::collections::{BTreeSet, HashMap};

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

type Named = HashMap<String, ContextType>;

/// NaslContext is a struct to contain variables and if root declared functions
///
/// A context should never be created directly but via a Register.
/// The reason for that is that a Registrat contains all blocks and a block must be registered to ensure that each Block must be created via an Registrat.
#[derive(Default, Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct Target {
    /// The original target. IP or hostname
    original_target_str: String,
    /// The IP address of the target.
    ip_addr: IpAddr,
    /// Whether the string given to `Target` was a hostname or an ip address.
    kind: TargetKind,
}

#[derive(Clone, Debug, Default)]
pub struct Ports {
    /// The TCP ports to test against.
    pub tcp: BTreeSet<u16>,
    /// The UDP ports to test against.
    pub udp: BTreeSet<u16>,
}

impl From<Vec<Port>> for Ports {
    fn from(ports: Vec<Port>) -> Self {
        let tcp = ports
            .clone()
            .into_iter()
            .filter(|p| p.protocol.unwrap_or(Protocol::TCP) == Protocol::TCP)
            .flat_map(|p| p.range.into_iter())
            .flat_map(|p| p.into_iter())
            .collect();

        let udp = ports
            .clone()
            .into_iter()
            .filter(|p| p.protocol.unwrap_or(Protocol::UDP) == Protocol::UDP)
            .flat_map(|p| p.range.into_iter())
            .flat_map(|p| p.into_iter())
            .collect();

        Self { tcp, udp }
    }
}

/// Specifies whether the string given to `Target` was a hostname
/// or an ip address.
#[derive(Clone, Debug, PartialEq)]
pub enum TargetKind {
    Hostname,
    IpAddr,
}

#[derive(Debug)]
pub struct CtxTarget {
    /// The target
    target: Target,
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
    /// The TCP ports to test against.
    ports_tcp: BTreeSet<u16>,
    /// The UDP ports to test against.
    ports_udp: BTreeSet<u16>,
}

impl Target {
    pub fn localhost() -> Self {
        Self {
            original_target_str: LOCALHOST.to_string(),
            ip_addr: LOCALHOST,
            kind: TargetKind::IpAddr,
        }
    }

    #[cfg(test)]
    pub fn do_not_resolve_hostname(target: impl AsRef<str>) -> Self {
        let (ip_addr, kind) = match target.as_ref().parse::<IpAddr>() {
            Ok(ip_addr) => (ip_addr, TargetKind::IpAddr),
            Err(_) => (LOCALHOST, TargetKind::Hostname),
        };
        Self {
            original_target_str: target.as_ref().into(),
            ip_addr,
            kind,
        }
    }

    pub fn resolve_hostname(target: impl AsRef<str>) -> Option<Self> {
        // Try to parse as IpAddr first
        let (ip_addr, kind) = if let Ok(ip_addr) = target.as_ref().parse::<IpAddr>() {
            (ip_addr, TargetKind::IpAddr)
        } else {
            let ip_addr = resolve_hostname(target.as_ref())
                .ok()
                .and_then(|ip_addrs| ip_addrs.into_iter().next())?;
            (ip_addr, TargetKind::Hostname)
        };
        Some(Self {
            original_target_str: target.as_ref().into(),
            ip_addr,
            kind,
        })
    }

    pub fn original_target_str(&self) -> &str {
        &self.original_target_str
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.ip_addr
    }

    pub fn kind(&self) -> &TargetKind {
        &self.kind
    }
}

impl From<(Target, Ports)> for CtxTarget {
    fn from(value: (Target, Ports)) -> Self {
        CtxTarget {
            target: value.0,
            vhosts: Mutex::new(vec![]),
            ports_tcp: value.1.tcp,
            ports_udp: value.1.udp,
        }
    }
}

impl CtxTarget {
    pub fn add_hostname(&self, hostname: String, source: String) -> &CtxTarget {
        self.vhosts.lock().unwrap().push(VHost { hostname, source });
        self
    }

    pub fn original_target_str(&self) -> &str {
        &self.target.original_target_str
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.target.ip_addr
    }

    pub fn kind(&self) -> &TargetKind {
        &self.target.kind
    }

    /// Return the hostname that this `Target` was constructed with
    /// or None otherwise
    pub fn hostname(&self) -> Option<String> {
        match self.target.kind {
            TargetKind::Hostname => Some(self.target.original_target_str.clone()),
            TargetKind::IpAddr => None,
        }
    }

    pub fn vhosts(&self) -> MutexGuard<'_, Vec<VHost>> {
        self.vhosts.lock().unwrap()
    }

    pub fn ports_tcp(&self) -> &BTreeSet<u16> {
        &self.ports_tcp
    }

    pub fn ports_udp(&self) -> &BTreeSet<u16> {
        &self.ports_udp
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
    + Retriever<ScanID, Item = Vec<ResultItem>>
    + Remover<ScanID, Item = Vec<ResultItem>>
    // nvt
    + Dispatcher<FileName, Item = Nvt>
    + Dispatcher<FeedVersion, Item = String>
    + Retriever<FeedVersion, Item = String>
    + Retriever<Feed, Item = Vec<Nvt>>
    + Retriever<Oid, Item = Nvt> + Retriever<FileName, Item = Nvt>
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

/// NASL execution context.
pub struct ScanCtx<'a> {
    /// The key for this context.
    scan: ScanID,
    /// Target against which the scan is run.
    target: CtxTarget,
    /// Filename of the current script
    filename: PathBuf,
    /// Storage
    storage: &'a dyn ContextStorage,
    /// Loader
    loader: &'a dyn Loader,
    /// Function executor.
    executor: &'a Executor,
    /// NVT object, which is put into the storage, when set
    nvt: Mutex<Option<Nvt>>,
    sockets: RwLock<NaslSockets>,
    /// Scanner preferences
    pub scan_preferences: ScanPrefs,
    /// Alive test methods
    alive_test_methods: Vec<AliveTestMethods>,
}

impl<'a> ScanCtx<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scan: ScanID,
        target: CtxTarget,
        filename: PathBuf,
        storage: &'a dyn ContextStorage,
        loader: &'a dyn Loader,
        executor: &'a Executor,
        scan_preferences: ScanPrefs,
        alive_test_methods: Vec<AliveTestMethods>,
    ) -> Self {
        let mut sockets = NaslSockets::default();
        sockets.with_recv_timeout(scan_preferences.get_preference_int("checks_read_timeout"));

        Self {
            scan,
            target,
            filename,
            storage,
            loader,
            executor,
            nvt: Mutex::new(None),
            sockets: RwLock::new(sockets),
            scan_preferences,
            alive_test_methods,
        }
    }

    /// Executes a function by name
    ///
    /// Returns None when the function was not found.
    pub async fn execute_builtin_fn(
        &self,
        name: &str,
        register: &Register,
        script_ctx: &mut ScriptCtx,
    ) -> Option<super::NaslResult> {
        const NUM_RETRIES_ON_RETRYABLE_ERROR: usize = 5;

        let mut i = 0;
        loop {
            i += 1;
            let result = self.executor.exec(name, self, register, script_ctx).await;
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

    pub fn filename(&self) -> &PathBuf {
        &self.filename
    }

    /// Get the `CtxTarget`
    pub fn target(&self) -> &CtxTarget {
        &self.target
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

    pub fn set_nvt(&self, vt: Nvt) {
        let mut nvt = self.nvt.lock().unwrap();
        *nvt = Some(vt);
    }

    pub fn nvt(&self) -> MutexGuard<'_, Option<Nvt>> {
        self.nvt.lock().unwrap()
    }

    pub fn set_scan_params(&mut self, params: ScanPrefs) {
        self.scan_preferences = params;
    }

    pub fn scan_params(&self) -> impl Iterator<Item = &ScanPreference> {
        self.scan_preferences.iter()
    }

    pub fn set_alive_test_methods(&mut self, methods: Vec<AliveTestMethods>) {
        self.alive_test_methods = methods;
    }

    pub fn alive_test_methods(&self) -> Vec<AliveTestMethods> {
        self.alive_test_methods.clone()
    }

    fn kb_key(&self, key: KbKey) -> KbContextKey {
        KbContextKey(
            (
                self.scan.clone(),
                storage::Target(self.target.original_target_str().to_string()),
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
                    storage::Target(self.target.original_target_str().into()),
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
    /// Sets the state of a port
    pub fn set_port_transport(&self, port: u16, transport: usize) -> Result<(), FnError> {
        self.set_single_kb_item(
            KbKey::Transport(kb::Transport::Tcp(port.to_string())),
            KbItem::Number(transport as i64),
        )
    }

    pub fn get_port_transport(&self, port: u16) -> Option<i64> {
        self.get_single_kb_item_inner(&KbKey::Transport(kb::Transport::Tcp(port.to_string())))
            .ok()
            .and_then(|item| match item {
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
                x.0.split('/').next_back().and_then(|x| {
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

        let ret = if !ports.is_empty() {
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

    pub fn get_preference_bool(&self, key: &str) -> Option<bool> {
        self.scan_preferences
            .iter()
            .find(|x| x.id == key)
            .map(|x| matches!(x.value.as_str(), "true" | "1" | "yes"))
    }

    pub fn get_preference_int(&self, key: &str) -> Option<i64> {
        self.scan_preferences
            .iter()
            .find(|x| x.id == key)
            .and_then(|x| x.value.parse::<i64>().ok())
    }

    pub fn get_preference_string(&self, key: &str) -> Option<String> {
        self.scan_preferences
            .iter()
            .find(|x| x.id == key)
            .map(|x| x.value.clone())
    }

    pub fn get_port_state(&self, port: u16, protocol: Protocol) -> Result<bool, FnError> {
        match protocol {
            Protocol::TCP => {
                if !self.target.ports_tcp.contains(&port)
                    || self.get_kb_item(&KbKey::Host(kb::Host::Tcp))?.is_empty()
                {
                    return Ok(!self.get_preference_bool("unscanned_closed").unwrap_or(true));
                }
                self.get_single_kb_item(&KbKey::Port(kb::Port::Tcp(port.to_string())))
            }
            Protocol::UDP => {
                if !self.target.ports_udp.contains(&port)
                    || self.get_kb_item(&KbKey::Host(kb::Host::Udp))?.is_empty()
                {
                    return Ok(!self
                        .get_preference_bool("unscanned_closed_udp")
                        .unwrap_or(true));
                }
                self.get_single_kb_item(&KbKey::Port(kb::Port::Udp(port.to_string())))
            }
        }
    }

    pub async fn read_sockets(&self) -> tokio::sync::RwLockReadGuard<'_, NaslSockets> {
        self.sockets.read().await
    }

    pub async fn write_sockets(&self) -> tokio::sync::RwLockWriteGuard<'_, NaslSockets> {
        self.sockets.write().await
    }
}

impl Drop for ScanCtx<'_> {
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

/// Struct to hold joins to multicast groups.
#[derive(Default)]
pub struct JmpDesc {
    pub in_addr: Option<IpAddr>,
    pub count: usize,
    pub socket: Option<socket2::Socket>,
}

#[derive(Default)]
pub struct ScriptCtx {
    pub alive: bool,
    pub denial_port: Option<u16>,
    pub multicast_groups: Vec<JmpDesc>,
}

pub struct ScanCtxBuilder<'a, P: AsRef<Path>> {
    pub storage: &'a dyn ContextStorage,
    pub loader: &'a dyn Loader,
    pub executor: &'a Executor,
    pub scan_id: ScanID,
    pub target: Target,
    pub ports: Ports,
    pub filename: P,
    pub scan_preferences: ScanPrefs,
    pub alive_test_methods: Vec<AliveTestMethods>,
}

impl<'a, P: AsRef<Path>> ScanCtxBuilder<'a, P> {
    /// Builds the `Context`.
    pub fn build(self) -> ScanCtx<'a> {
        ScanCtx::new(
            self.scan_id,
            (self.target, self.ports).into(),
            self.filename.as_ref().to_owned(),
            self.storage,
            self.loader,
            self.executor,
            self.scan_preferences,
            self.alive_test_methods,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::utils::scan_ctx::TargetKind;

    use super::Target;

    #[test]
    fn target_kind() {
        assert_eq!(
            Target::do_not_resolve_hostname("1.2.3.4").kind(),
            &TargetKind::IpAddr
        );
        assert_eq!(
            Target::do_not_resolve_hostname("foo").kind(),
            &TargetKind::Hostname
        );
        // This should not do any actual resolution
        // but immediately parse the IP address instead.
        assert_eq!(
            Target::resolve_hostname("1.2.3.4").unwrap().kind(),
            &TargetKind::IpAddr
        );
    }
}

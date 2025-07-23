// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines the context used within the interpreter and utilized by the builtin functions

use tokio::sync::RwLock;

use crate::models::{AliveTestMethods, Port, Protocol, ScanPreference};
use crate::nasl::builtin::{KBError, NaslSockets};
use crate::nasl::syntax::Loader;
use crate::nasl::{FromNaslValue, WithErrorInfo};
use crate::scanner::preferences::preference::ScanPrefs;
use crate::storage::error::StorageError;
use crate::storage::infisto::json::JsonStorage;
use crate::storage::inmemory::InMemoryStorage;
use crate::storage::items::kb::{self, KbKey};
use crate::storage::items::kb::{GetKbContextKey, KbContextKey, KbItem};
use crate::storage::items::nvt::{Feed, FeedVersion, FileName, Nvt};
use crate::storage::items::nvt::{NvtField, Oid};
use crate::storage::items::result::{ResultContextKeyAll, ResultContextKeySingle, ResultItem};
use crate::storage::redis::{
    RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper,
};
use crate::storage::{self, ScanID};
use crate::storage::{Dispatcher, Remover, Retriever};
use rand::seq::SliceRandom;
use std::collections::BTreeSet;
use std::sync::MutexGuard;

use super::error::ReturnBehavior;
use super::executor::Executor;
use super::hosts::{LOCALHOST, resolve_hostname};
use super::{FnError, Register};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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

    #[cfg(test)]
    fn kind(&self) -> &TargetKind {
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
    fn add_hostname(&self, hostname: String, source: String) -> &CtxTarget {
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

    /// Get the Key
    pub fn scan(&self) -> &ScanID {
        &self.scan
    }

    fn filename(&self) -> &PathBuf {
        &self.filename
    }

    /// Get the `CtxTarget`
    pub fn target(&self) -> &CtxTarget {
        &self.target
    }

    pub fn add_hostname(&self, hostname: String, source: String) {
        self.target.add_hostname(hostname, source);
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

    fn dispatch_nvt(&self, nvt: Nvt) {
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

    pub fn scan_params(&self) -> impl Iterator<Item = &ScanPreference> {
        self.scan_preferences.iter()
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

    fn get_kb_items_with_keys(&self, key: &KbKey) -> Result<Vec<(String, Vec<KbItem>)>, FnError> {
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

    fn get_preference_bool(&self, key: &str) -> Option<bool> {
        self.scan_preferences.get_preference_bool(key)
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

    pub(crate) fn add_fn_global_vars(&self, register: &mut Register) {
        for (name, val) in self.executor.iter_fn_global_vars() {
            register.add_global_var(name, val);
        }
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

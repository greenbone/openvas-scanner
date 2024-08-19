use nasl_builtin_utils::{NaslFunctionExecuter, NaslFunctionRegister};
use nasl_syntax::{FSPluginLoader, Loader};
use storage::{DefaultDispatcher, Storage};

pub trait ScannerStack {
    type Storage: Storage + Sync + Send + 'static;
    type Loader: Loader + Send + 'static;
    type Executor: NaslFunctionExecuter + Send + 'static;
}

impl<S, L, F> ScannerStack for (S, L, F)
where
    S: Storage + Send + 'static,
    L: Loader + Send + 'static,
    F: NaslFunctionExecuter + Send + 'static,
{
    type Storage = S;
    type Loader = L;
    type Executor = F;
}

/// The default scanner stack, consisting of `DefaultDispatcher`,
/// `FSPluginLoader` and `NaslFunctionRegister`.
pub type DefaultScannerStack = (DefaultDispatcher, FSPluginLoader, NaslFunctionRegister);

/// The with storage scanner strack consisting of a statically living sendable Storage
/// implementation,`FSPPluginLoader` nasl `NaslFunctionRegister`.
pub type WithStorageScannerStack<S> = (S, FSPluginLoader, NaslFunctionRegister);

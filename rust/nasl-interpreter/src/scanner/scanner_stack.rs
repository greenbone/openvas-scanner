use nasl_builtin_utils::{NaslFunctionExecuter, NaslFunctionRegister};
use nasl_syntax::{FSPluginLoader, Loader};
use storage::{DefaultDispatcher, Storage};

use crate::scheduling::{ConcurrentVT, ConcurrentVTResult, VTError};

pub trait Schedule: Iterator<Item = ConcurrentVTResult> + Sized {
    fn cache(self) -> Result<Vec<ConcurrentVT>, VTError> {
        self.collect()
    }
}

impl<T> Schedule for T where T: Iterator<Item = ConcurrentVTResult> {}

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

/// Like `DefaultScannerStack` but with a specific storage type.
pub type ScannerStackWithStorage<S> = (S, FSPluginLoader, NaslFunctionRegister);

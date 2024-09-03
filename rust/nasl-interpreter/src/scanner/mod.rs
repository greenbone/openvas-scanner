//! Overview of the structure of this module: The `Scanner` is the
//! single instance managing all scans during a run with Openvasd
//! scanner type.  To do so, it starts a number of `RunningScan`s,
//! each of which is responsible for a single Scan.  The `RunningScan`
//! is responsible for computing the execution plan for this
//! particular Scan and running it to completion.  It also takes care
//! of controlling the status of the scan and stopping it if
//! necessary. Internally, it runs code via the `ScanRunner` which is
//! responsible for performing all VTs in all stages on each target
//! host.  It is also responsible for sticking to the scheduling
//! requirements. Finally, for a given VT and a given Host, the
//! VT is then run to completion using the `VTRunner`.

mod error;
mod running_scan;
mod scan_runner;
mod scanner;
mod scanner_stack;
mod vt_runner;

pub use error::ExecuteError;
pub use scan_runner::ScanRunner;
pub use scanner::Scanner;
pub use scanner_stack::DefaultScannerStack;
pub use scanner_stack::ScannerStack;
pub use scanner_stack::ScannerStackWithStorage;

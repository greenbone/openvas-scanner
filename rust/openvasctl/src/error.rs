use std::io;

pub enum OpenvasError {
    MissingID,
    DuplicateScanID,
    MissingExec,
    ScanNotFound,
    ScanAlreadyExists,
    CmdError(io::Error),
    BrokenChannel,
    MaxQueuedScans,
    UnableToRunExec,
}

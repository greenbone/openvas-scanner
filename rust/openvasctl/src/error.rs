use std::io;

pub enum OpenvasError {
    MissingID,
    MissingExec,
    UnableToRunExec,
    ScanNotFound,
    ScanAlreadyExists,
    CmdError(io::Error),
}

/// Modes that are used by the default logger
#[derive(PartialEq, PartialOrd, Default)]
pub enum Mode {
    /// Debug Mode, enables all logging
    Debug = 0,
    /// Info Mode, enables Info, Warning and Error Messages
    #[default]
    Info,
    /// Warning Mde, enables Warning and Error Messages
    Warning,
    /// Error Mode, enables only Error Messages
    Error,
    /// Disabled, no Messages are logged
    Nothing,
}
/// A interface for a logger for the NASL interpreter
pub trait NaslLogger {
    /// Print a Debug Message
    fn debug(&self, msg: String);
    /// Print a Info Message
    fn info(&self, msg: String);
    /// Print a Warning Message
    fn warning(&self, msg: String);
    /// Print a Error Message
    fn error(&self, msg: String);
    /// Print a normal Message
    fn print(&self, msg: String);
}

/// The default logger for NASL. It will just print to the terminal. It has a
/// basic mode system and color scheme for printing. The mode order is
/// debug > info > warning > error > nothing. Printing normal messages is meant
/// to be used by the display function therefore it cannot be disabled
#[derive(Default)]
pub struct DefaultLogger {
    mode: Mode,
}

impl DefaultLogger {
    /// Create a new DefaultLogger in the Info mode
    pub fn new() -> Self {
        Self { mode: Mode::Info }
    }

    /// Change the mode of the Logger
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }
}

impl NaslLogger for DefaultLogger {
    fn debug(&self, msg: String) {
        if self.mode > Mode::Debug {
            return;
        }
        println!("\x1b[38;5;8mDEBUG: \x1b[0m{}", msg);
    }

    fn info(&self, msg: String) {
        if self.mode > Mode::Info {
            return;
        }
        println!("\x1b[38;5;2mINFO : \x1b[0m{}", msg);
    }

    fn warning(&self, msg: String) {
        if self.mode > Mode::Warning {
            return;
        }
        println!("\x1b[38;5;3mWARN : \x1b[0m{}", msg);
    }

    fn error(&self, msg: String) {
        if self.mode > Mode::Error {
            return;
        }
        println!("\x1b[38;5;1mERROR: \x1b[0m{}", msg);
    }

    fn print(&self, msg: String) {
        println!("{}", msg);
    }
}

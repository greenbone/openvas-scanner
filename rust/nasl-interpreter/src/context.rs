use nasl_syntax::Statement;

use crate::interpreter::NaslValue;

/// Contexts are responbile to locate, add and delete everything that is declared within a NASL plugin

/// Represents a Value within the NaslContext
pub enum ContextType {
    /// Represents a Function definition
    Function(Statement),
    /// Represents a Variable or Parameter
    Value(NaslValue),
}

/// The context represents a temporary storage, which can contain local variables, global variables or defined functions
pub trait NaslContext {
    /// Adds a named value to the Context. This is used for local variables, function parameters and defined functions
    fn add_named(&mut self, name: &str, value: ContextType);
    /// Adds a global variable to the context
    fn add_global(&mut self, name: &str, value: ContextType);
    /// Adds a positional function parameter to the context
    fn add_postitional(&mut self, value: ContextType);
    /// Returns the value of a named parameter/variable or None if it does not exist
    fn get_named(&self, name: &str) -> Option<&ContextType>;
    /// Returns the value of a positional parameter or None if it does not exist
    fn get_positional(&self, pos: usize) -> Option<&ContextType>;
    /// Return a new Context, which contains the global variables of the current Context
    fn globals_copy(&self) -> Box<dyn NaslContext>;
}


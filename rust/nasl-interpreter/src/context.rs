use nasl_syntax::Statement;

use crate::{error::InterpretError, interpreter::NaslValue};

/// Contexts are responsible to locate, add and delete everything that is declared within a NASL plugin

/// Represents a Value within the NaslContext
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextType {
    /// Represents a Function definition
    Function(Vec<String>, Statement),
    /// Represents a Variable or Parameter
    Value(NaslValue),
}

/// Registers all NaslContext
///
/// When creating a new context call a corresponding create method.
/// Warning since those will be stored within a vector each context must be manually
/// deleted by calling drop_last when the context runs out of scope.
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
    pub fn root_initial(initial: Vec<(String, ContextType)>) -> Self {
        let root = NaslContext {
            defined: initial.into_iter().collect(),
            ..Default::default()
        };
        Self { blocks: vec![root] }
    }

    /// Returns the next index
    pub fn index(&self) -> usize {
        self.blocks.len()
    }

    /// Creates a child context
    pub fn create_child(&mut self, parent: &NaslContext, defined: Named) -> &NaslContext {
        let result = NaslContext {
            parent: Some(parent.id),
            id: self.index(),
            defined,
        };
        self.blocks.push(result);
        return self.blocks.last_mut().unwrap();
    }

    /// Creates a child context for the root context.
    ///
    /// This is used to function calls to prevent that the called function can access the
    /// context of the caller.
    pub fn create_root_child(&mut self, defined: Named) -> &NaslContext {
        let result = NaslContext {
            parent: Some(0),
            id: self.index(),
            defined,
        };
        self.blocks.push(result);
        return self.blocks.last_mut().unwrap();
    }

    /// Returns the last created context.
    ///
    /// The idea is that since NASL is an iterative language the last context is also the current
    /// one.
    fn last(&self) -> &NaslContext {
        let last = self.blocks.last();
        last.unwrap()
    }

    /// Finds a named ContextType
    pub fn named<'a>(&'a self, name: &'a str) -> Option<&ContextType> {
        self.last().named(self, name).map(|(_, val)| val)
    }

    /// Finds a named ContextType with index
    pub fn index_named<'a>(&'a self, name: &'a str) -> Option<(usize, &ContextType)> {
        self.last().named(self, name)
    }

    /// Returns a mutable reference of the current context
    pub fn last_mut(&mut self) -> &mut NaslContext {
        let last = self.blocks.last_mut();
        last.unwrap()
    }

    /// Adds a named parameter to the root context
    pub fn add_global(&mut self, name: &str, value: ContextType) {
        let global = &mut self.blocks[0];
        global.add_named(name, value);
    }

    /// Adds a named parameter to the root context
    pub fn add_to_index(
        &mut self,
        idx: usize,
        name: &str,
        value: ContextType,
    ) -> Result<(), InterpretError> {
        if idx >= self.blocks.len() {
            Err(InterpretError::new(format!(
                "{} is higher than available blocks ({})",
                idx,
                self.blocks.len()
            )))
        } else {
            let global = &mut self.blocks[idx];
            global.add_named(name, value);
            Ok(())
        }
    }
    /// Adds a named parameter to the last context
    pub fn add_local(&mut self, name: &str, value: ContextType) {
        let last = &mut self.last_mut();
        last.add_named(name, value);
    }

    /// Retrieves all positional definitions
    pub fn positional(&self) -> &[NaslValue] {
        match self.named("_FCT_ANON_ARGS") {
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
}

impl Default for Register {
    fn default() -> Self {
        Self::new()
    }
}
use std::collections::HashMap;
type Named = HashMap<String, ContextType>;

/// NaslContext is a struct to contain variables and if root declared functions
///
/// A context should never be created directly but via a Register.
/// The reason for that is that a Registrat contains all blocks and a block must be registered to ensure that each Block must be created via an Registrat.
#[derive(Default)]
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
    ) -> Option<(usize, &ContextType)> {
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

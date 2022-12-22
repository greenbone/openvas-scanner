use nasl_syntax::Statement;

use crate::interpreter::NaslValue;

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
        Self { blocks: vec![] }
    }

    /// Returns the next index
    pub fn index(&self) -> usize {
        self.blocks.len()
    }

    /// Creates a root context
    pub fn create_root(&mut self, initial: Vec<(String, ContextType)>) -> &NaslContext {
        let initial = initial.into_iter().collect();
        let result = NaslContext {
            parent: None,
            id: 0,
            class: NaslContextType::Execution(initial),
        };
        self.blocks.push(result);
        return self.blocks.last_mut().unwrap();
    }

    /// Creates a child context
    pub fn create_child(&mut self, parent: &NaslContext, class: NaslContextType) -> &NaslContext {
        let result = NaslContext {
            parent: Some(parent.id),
            id: self.index(),
            class,
        };
        self.blocks.push(result);
        return self.blocks.last_mut().unwrap();
    }

    /// Creates a child context for the root context.
    ///
    /// This is used to function calls to prevent that the called function can access the
    /// context of the caller.
    pub fn create_root_child(&mut self, class: NaslContextType) -> &NaslContext {
        let result = NaslContext {
            parent: Some(0),
            id: self.index(),
            class,
        };
        self.blocks.push(result);
        return self.blocks.last_mut().unwrap();
    }

    /// Returns the last created context.
    ///
    /// The idea is that since NASL is an iterative language the last context is also the current
    /// one.
    pub fn last(&self) -> &NaslContext {
        let last = self.blocks.last();
        last.unwrap()
    }


    /// Finds a named ContextType within last.
    pub fn named<'a>(&'a self, name: &'a str) -> Option<&ContextType> {
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
type Positional = ContextType;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NaslContextType {
    /// Root cannot contain position parameter since it is not a function call
    // TODO rename those are definitions
    Execution(Named),
    /// Used to prepare the functional context on call
    // TODO rename call context
    Function(Named, Vec<Positional>),


}

/// NaslContext is a struct to contain variables and if root declared functions
///
/// A context should never be created directly but via a Register.
/// The reason for that is that a Registrat contains all blocks and a block must be registered to ensure that each Block must be created via an Registrat.
pub struct NaslContext {
    /// Parent id within the register
    parent: Option<usize>,
    /// Own id within the register
    id: usize,
    /// The type of context.
    class: NaslContextType,
}

impl NaslContext {
    /// Finds the first context that is a function
    fn find_first_function(&self, registrat: &Register) -> Option<usize> {
        match self.class {
            NaslContextType::Execution(_) => match self.parent {
                Some(pid) => registrat.blocks[pid].find_first_function(registrat),
                None => None,
            },
            NaslContextType::Function(_, _) => Some(self.id),
        }
    }

    /// Adds a named parameter to the context
    // TODO remove from ContextType to NaslValue
    pub fn add_named(&mut self, name: &str, value: ContextType) {
        match &mut self.class {
            NaslContextType::Execution(named) => named.insert(name.to_owned(), value),
            NaslContextType::Function(named, _) => named.insert(name.to_owned(), value),
        };
    }

    /// Adds a named parameter to the root context
    pub fn add_global(&mut self, registrat: &mut Register, name: &str, value: ContextType) {
        let global = &mut registrat.blocks[0];
        global.add_named(name, value);
    }

    /// Adds a parameter as the last position
    pub fn add_positional(&mut self, value: ContextType) {
        match &mut self.class {
            NaslContextType::Function(_, position) => position.push(value),
            _ => todo!("Error handling"),
        }
    }

    /// Retrieves a named parameter
    pub fn named<'a>(&'a self, registrat: &'a Register, name: &'a str) -> Option<&ContextType> {
        let named = match &self.class {
            NaslContextType::Execution(named) => named,
            NaslContextType::Function(named, _) => named,
        };
        // first check local
        match named.get(name) {
            Some(ctx) => Some(ctx),
            None => match self.parent {
                Some(parent) => registrat.blocks[parent].named(registrat, name),
                None => None,
            },
        }

    }

    /// Retrieves positional parameter
    pub fn positional<'a>(&'a self, registrat: &'a Register) -> &[ContextType] {
        match self.find_first_function(registrat) {
            Some(id) => match &registrat.blocks[id].class {
                NaslContextType::Execution(_) => panic!("this should not happen"),
                NaslContextType::Function(_, positional) => positional,
            },
            None => &[],
        }
    }
}

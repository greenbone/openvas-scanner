use std::collections::HashMap;

use crate::nasl::{
    ArgumentError,
    utils::lookup_keys::{FC_ANON_ARGS, SCRIPT_PARAMS},
};

use super::{NaslValue, nasl_value::RuntimeValue};

/// Holds the defined variables and functions within a scope
/// (i.e. a block, such as loops or a function) during
/// execution of a NASL script.
#[derive(Default, Clone, Debug)]
struct Scope {
    /// Index of the parent scope (i.e. the surrounding scope) within the
    /// `Register`
    parent: Option<usize>,
    /// Own index within the register
    index: usize,
    /// The defined variables and functions.
    variables: HashMap<String, RuntimeValue>,
}

impl Scope {
    /// Adds a named variable to the scope.
    fn add_named(&mut self, name: &str, value: RuntimeValue) {
        self.variables.insert(name.to_owned(), value);
    }

    /// Retrieves a definition by name
    fn named<'a>(
        &'a self,
        register: &'a Register,
        name: &'a str,
    ) -> Option<(usize, &'a RuntimeValue)> {
        // first check local
        match self.variables.get(name) {
            Some(ctx) => Some((self.index, ctx)),
            None => match self.parent {
                Some(parent) => register.scopes[parent].named(register, name),
                None => None,
            },
        }
    }
}

/// Used to keep a temporary reference to a
/// specific variable within the interpreter.
#[derive(Copy, Clone)]
pub(super) struct Var<'a> {
    name: &'a str,
    scope_index: usize,
}

/// Holds all defined variables and functions during execution of NASL scripts.
#[derive(Clone, Debug)]
pub struct Register {
    /// A list of all the available scopes. Always non-empty, with the
    /// first entry corresponding to the global scope.
    scopes: Vec<Scope>,
}

impl Register {
    /// Creates a global scope based on the given initial values
    pub fn from_global_variables(initial: &[(String, NaslValue)]) -> Self {
        let defined = initial
            .iter()
            .cloned()
            .map(|(k, v)| (k, RuntimeValue::Value(v)))
            .collect();
        let global = Scope {
            variables: defined,
            ..Default::default()
        };
        Self {
            scopes: vec![global],
        }
    }

    fn next_index(&self) -> usize {
        self.scopes.len()
    }

    fn current_index(&self) -> usize {
        self.scopes.len() - 1
    }

    /// Creates a child scope using the last scope as a parent
    pub(super) fn create_child(&mut self) {
        let parent_index = self.scopes.last().map(|x| x.index).unwrap_or_default();
        let result = Scope {
            parent: Some(parent_index),
            index: self.next_index(),
            variables: HashMap::default(),
        };
        self.scopes.push(result);
    }

    /// Creates a child of the global scope scope.
    pub(super) fn create_global_child(&mut self, defined: HashMap<String, RuntimeValue>) {
        let result = Scope {
            parent: Some(0),
            index: self.next_index(),
            variables: defined,
        };
        self.scopes.push(result);
    }

    /// Adds a named variable to the global scope
    pub(crate) fn add_global_var(&mut self, name: &str, value: NaslValue) {
        let global = &mut self.scopes[0];
        global.add_named(name, RuntimeValue::Value(value));
    }

    /// Adds a named runtime value to the global scope
    pub(super) fn add_global(&mut self, name: &str, value: RuntimeValue) {
        let global = &mut self.scopes[0];
        global.add_named(name, value);
    }

    /// Adds a named variable to the innermost scope
    pub(super) fn add_local<'a>(&mut self, name: &'a str, value: RuntimeValue) -> Var<'a> {
        let scope = self.scopes.last_mut().unwrap();
        scope.add_named(name, value);
        let scope_index = self.current_index();
        Var { name, scope_index }
    }

    pub(super) fn get<'a>(&self, name: &'a str) -> Option<Var<'a>> {
        let scope_index = self.scopes.len() - 1;
        self.get_from_scope(name, scope_index)
    }

    fn get_from_scope<'a>(&self, name: &'a str, scope_index: usize) -> Option<Var<'a>> {
        let scope = &self.scopes[scope_index];
        if scope.variables.contains_key(name) {
            Some(Var { name, scope_index })
        } else if let Some(parent) = scope.parent {
            self.get_from_scope(name, parent)
        } else {
            None
        }
    }

    pub(super) fn get_val<'a>(&self, var: Var<'a>) -> &RuntimeValue {
        self.scopes[var.scope_index]
            .variables
            .get(var.name)
            .unwrap()
    }

    pub(super) fn get_val_mut<'a>(&mut self, var: Var<'a>) -> &mut RuntimeValue {
        self.scopes[var.scope_index]
            .variables
            .get_mut(var.name)
            .unwrap()
    }

    /// Remove the innermost scope. Called when execution of a block
    /// or function is finished.
    pub(super) fn drop_last(&mut self) {
        self.scopes.pop();
    }

    /// Gets a reference to a ContextType by name
    pub(super) fn named<'a>(&'a self, name: &'a str) -> Option<&'a RuntimeValue> {
        Some(self.get_val(self.get(name)?))
    }

    pub(crate) fn function_exists(&self, name: &str) -> bool {
        if let Some(val) = self.named(name) {
            matches!(val, RuntimeValue::Function(_, _))
        } else {
            false
        }
    }

    /// Return an iterator over the names of the named arguments.
    pub(crate) fn iter_named_args(&self) -> Option<impl Iterator<Item = &str>> {
        self.scopes
            .last()
            .map(|x| x.variables.keys().map(|x| x.as_str()))
    }

    /// Find a named argument and return its value as a variable
    /// or an error otherwise
    pub(crate) fn nasl_value<'a>(&'a self, arg: &'a str) -> Result<&'a NaslValue, ArgumentError> {
        match self.named(arg) {
            Some(RuntimeValue::Value(val)) => Ok(val),
            Some(_) => Err(ArgumentError::WrongArgument(format!(
                "Argument {arg} is a function but should be a value."
            ))),
            None => Err(ArgumentError::MissingNamed(vec![arg.to_string()])),
        }
    }

    /// Retrieves all positional definitions
    pub(crate) fn positional(&self) -> &[NaslValue] {
        match self.named(FC_ANON_ARGS) {
            Some(RuntimeValue::Value(NaslValue::Array(arr))) => arr,
            _ => &[],
        }
    }

    /// Retrieves a script parameter by id
    pub(crate) fn script_param(&self, id: usize) -> Option<NaslValue> {
        match self.named(format!("{SCRIPT_PARAMS}_{id}").as_str()) {
            Some(RuntimeValue::Value(v)) => Some(v.clone()),
            _ => None,
        }
    }

    pub(crate) fn dump(&self) {
        self.dump_scope(self.scopes.last().unwrap().index);
    }

    fn dump_scope(&self, index: usize) {
        match self.scopes.get(index) {
            Some(mut current) => {
                let mut vars = vec![];
                let mut funs = vec![];

                // Get number of positional arguments
                let num_pos = match current.named(self, FC_ANON_ARGS).map(|(_, val)| val) {
                    Some(RuntimeValue::Value(NaslValue::Array(arr))) => arr.len(),
                    _ => 0,
                };

                // collect all available functions and variables available in current and parent
                // context recursively
                loop {
                    for (name, ctype) in current.variables.clone() {
                        if vars.contains(&name) || funs.contains(&name) || name == FC_ANON_ARGS {
                            continue;
                        }

                        match ctype {
                            RuntimeValue::Function(_, _) => funs.push(name),
                            RuntimeValue::Value(_) => vars.push(name),
                        };
                    }
                    if let Some(parent) = current.parent {
                        current = &self.scopes[parent];
                    } else {
                        break;
                    }
                }

                // Print all available information
                println!("--------<CTXT>--------");
                println!("number of positional arguments: {num_pos}");
                println!();
                println!("available functions:");
                for function in funs {
                    print!("{function}\t");
                }
                println!();
                println!();
                println!("available variables:");
                for var in vars {
                    print!("{var}\t");
                }
                println!();
                println!("----------------------");
            }
            None => println!("No context available"),
        };
    }
}

impl Default for Register {
    fn default() -> Self {
        Self {
            scopes: vec![Scope::default()],
        }
    }
}

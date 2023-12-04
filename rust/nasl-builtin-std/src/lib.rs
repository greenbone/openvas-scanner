#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use nasl_builtin_utils::{Context, NaslFunctionRegister, NaslVarRegister, Register};
use nasl_syntax::{logger::NaslLogger, Loader};
use storage::{DefaultDispatcher, Storage};
mod array;

/// The description builtin function
///
/// Because it implements the NaslFunctionExecuter it can be added to the Context.
/// It contains all functions that are defined as a standard library function within NASL.
///
/// It does not contain user defined functions, as they created on runtime while executing a nasl
/// script. This is handled within the `nasl_interpreter::Interpreter`.
pub struct Std;

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for Std {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        array::lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        array::lookup::<K>(name).is_some()
    }
}

/// Creates a new NaslFunctionRegister and adds all the functions to it.
///
/// To add a new function to the register, add it to the builder by calling `push_register`.
/// This way the function will be added to the std and can be utilized by the nasl interpreter.
///
/// When you have a function that is considered experimental due to either dependencies on
/// c-library or other reasons, you have to add the library as optional and put it into the
/// `experimental` feature flag. Additionally you have to create two new functions one with the
/// library toggle enabled and one when it is disabled.
///
/// This way the user can decide on compile if the functionality is enabled or not.
///
/// # Example
///
/// ```
/// #[cfg(not(feature = "nasl-builtin-ssh"))]
/// fn add_ssh<K: AsRef<str>>(
///     builder: nasl_builtin_utils::NaslfunctionRegisterBuilder<K>,
/// ) -> nasl_builtin_utils::NaslfunctionRegisterBuilder<K> {
///     builder
/// }
///
/// #[cfg(feature = "nasl-builtin-ssh")]
/// fn add_ssh<K: AsRef<str>>(
///     builder: nasl_builtin_utils::NaslfunctionRegisterBuilder<K>,
/// ) -> nasl_builtin_utils::NaslfunctionRegisterBuilder<K> {
///     builder.push_register(nasl_builtin_ssh::Ssh::default())
/// }
///
/// ```
///
/// ```text
/// builder = add_ssh(builder);
/// ```
pub fn nasl_std_functions<K: AsRef<str>>() -> nasl_builtin_utils::NaslFunctionRegister<K> {
    let mut builder = nasl_builtin_utils::NaslfunctionRegisterBuilder::new()
        .push_register(Std)
        .push_register(nasl_builtin_knowledge_base::KnowledgeBase)
        .push_register(nasl_builtin_misc::Misc)
        .push_register(nasl_builtin_string::NaslString)
        .push_register(nasl_builtin_host::Host)
        .push_register(nasl_builtin_cryptographic::Cryptographic)
        .push_register(nasl_builtin_description::Description);
    builder = add_ssh(builder);
    builder = add_raw_ip(builder);
    builder.build()
}

/// Creates a new NaslVarRegister and adds all the predefined nasl variables.
///
/// To add new variables to the register, add it to the builder by calling `push_register`.
/// This way the predefined NASL variables will be added to the std and can be utilized by the nasl interpreter.
///
/// When you have a function that is considered experimental due to either dependencies on
/// c-library or other reasons, you have to add the library as optional and put it into the
/// `experimental` feature flag, so the variables can be added. Additionally you have to create two new functions:
/// one with the library toggle enabled and one when it is disabled.
///
/// This way the user can decide on compile if the functionality, and therefore the variables, are enabled or not.
///
/// # Example
///
/// ```
/// #[cfg(feature = "nasl-builtin-raw-ip")]
/// fn add_raw_ip_vars(
///     builder: nasl_builtin_utils::NaslVarRegisterBuilder,
/// ) -> nasl_builtin_utils::NaslVarRegisterBuilder {
///     builder.push_register(nasl_builtin_raw_ip::RawIpVars)
/// }
///
/// #[cfg(not(feature = "nasl-builtin-raw-ip"))]
/// fn add_raw_ip_vars(
///     builder: nasl_builtin_utils::NaslVarRegisterBuilder,
/// ) -> nasl_builtin_utils::NaslVarRegisterBuilder {
///     builder
/// }
/// ```
///
/// ```text
/// builder = add_raw_ip_vars(builder);
/// ```
pub fn nasl_std_variables() -> NaslVarRegister {
    let mut builder = nasl_builtin_utils::NaslVarRegisterBuilder::new();
    builder = add_raw_ip_vars(builder);
    builder.build()
}

#[cfg(not(feature = "nasl-builtin-ssh"))]
fn add_ssh<K: AsRef<str>>(
    builder: nasl_builtin_utils::NaslfunctionRegisterBuilder<K>,
) -> nasl_builtin_utils::NaslfunctionRegisterBuilder<K> {
    builder
}

#[cfg(feature = "nasl-builtin-raw-ip")]
fn add_raw_ip<K: AsRef<str>>(
    builder: nasl_builtin_utils::NaslfunctionRegisterBuilder<K>,
) -> nasl_builtin_utils::NaslfunctionRegisterBuilder<K> {
    builder.push_register(nasl_builtin_raw_ip::RawIp)
}

#[cfg(feature = "nasl-builtin-raw-ip")]
fn add_raw_ip_vars(
    builder: nasl_builtin_utils::NaslVarRegisterBuilder,
) -> nasl_builtin_utils::NaslVarRegisterBuilder {
    builder.push_register(nasl_builtin_raw_ip::RawIp)
}

#[cfg(feature = "nasl-builtin-ssh")]
fn add_ssh<K: AsRef<str>>(
    builder: nasl_builtin_utils::NaslfunctionRegisterBuilder<K>,
) -> nasl_builtin_utils::NaslfunctionRegisterBuilder<K> {
    builder.push_register(nasl_builtin_ssh::Ssh::default())
}

#[cfg(not(feature = "nasl-builtin-raw-ip"))]
fn add_raw_ip<K: AsRef<str>>(
    builder: nasl_builtin_utils::NaslfunctionRegisterBuilder<K>,
) -> nasl_builtin_utils::NaslfunctionRegisterBuilder<K> {
    builder
}

#[cfg(not(feature = "nasl-builtin-raw-ip"))]
fn add_raw_ip_vars(
    builder: nasl_builtin_utils::NaslVarRegisterBuilder,
) -> nasl_builtin_utils::NaslVarRegisterBuilder {
    builder
}

/// Contains the key as well as the dispatcher.
///
/// This is to ensure that the key and the dispatcher do have the same type.
/// It makes it also a bit easier to use as the key as well as the dispatcher are usually created
/// together.
pub struct KeyDispatcherSet<K: AsRef<str>> {
    key: K,
    storage: Box<dyn Storage<K>>,
}

/// The context builder.
///
/// This is the main entry point for the nasl interpreter and adds all the functions defined in
/// [nasl_std_functions] to functions register.
pub struct ContextBuilder<K: AsRef<str>, S> {
    /// The key and dispatcher set.
    pub key: S,
    /// The target to test.
    pub target: String,
    /// The loader to load the nasl files.
    pub loader: Box<dyn Loader>,
    /// The logger to log.
    pub logger: Box<dyn NaslLogger>,
    /// The functions available to the nasl script.
    pub functions: NaslFunctionRegister<K>,
}

impl Default for ContextBuilder<String, KeyDispatcherSet<String>> {
    fn default() -> Self {
        Self {
            key: KeyDispatcherSet {
                key: Default::default(),
                storage: Box::<DefaultDispatcher<String>>::default(),
            },
            target: Default::default(),
            loader: Default::default(),
            logger: Default::default(),
            functions: nasl_std_functions(),
        }
    }
}

impl<K: AsRef<str>, S> ContextBuilder<K, S> {
    /// Sets the target to test.
    pub fn target(mut self, target: String) -> Self {
        self.target = target;
        self
    }

    /// Sets the loader to load the nasl files.
    pub fn loader<L: Loader + 'static>(mut self, loader: L) -> Self {
        self.loader = Box::new(loader);
        self
    }

    /// Sets the logger to log.
    pub fn logger<L: NaslLogger + 'static>(mut self, logger: L) -> Self {
        self.logger = Box::new(logger);
        self
    }

    /// Sets the functions available to the nasl script.
    pub fn functions(mut self, functions: NaslFunctionRegister<K>) -> Self {
        self.functions = functions;
        self
    }
}

impl<K: AsRef<str>> ContextBuilder<K, KeyDispatcherSet<K>> {
    /// Creates a new context builder with the given key and storage.
    pub fn new(key: K, storage: Box<dyn Storage<K>>) -> Self {
        Self {
            key: KeyDispatcherSet { key, storage },
            target: Default::default(),
            loader: Default::default(),
            logger: Default::default(),
            functions: nasl_std_functions(),
        }
    }

    /// Createz the context.
    ///
    /// Be aware that unlike normal builder, because of the lifetime of the dispatcher, the ContextBuilder must exist as long as the context and cannot be dropped immediately.
    pub fn build(&self) -> Context<K> {
        Context::new(
            &self.key.key,
            &self.target,
            self.key.storage.as_dispatcher(),
            self.key.storage.as_retriever(),
            &*self.loader,
            self.logger.as_ref(),
            &self.functions,
        )
    }
}

/// The register builder for NASL Variables
///
/// This is the main entry point for the nasl interpreter and adds all the variables defined in
/// [nasl_std_variables] to variables register.
pub struct RegisterBuilder {
    /// Holds the access to the defined nasl variables
    pub variables: NaslVarRegister,
}

impl Default for RegisterBuilder {
    fn default() -> Self {
        Self {
            variables: nasl_std_variables(),
        }
    }
}

impl RegisterBuilder {
    /// Build a Register which includes all predefined globals variables.
    /// This is the register which is passed to the interpreter and nasl functions
    pub fn build() -> Register {
        let mut register = Register::new();
        let regbuilder = Self {
            variables: nasl_std_variables(),
        };
        for var_definer in regbuilder.variables.definers {
            for (var_name, nasl_val) in var_definer.nasl_var_define() {
                register.add_global(var_name, nasl_builtin_utils::ContextType::Value(nasl_val));
            }
        }
        register
    }
}

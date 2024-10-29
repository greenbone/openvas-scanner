mod builtin;
pub mod interpreter;
pub mod syntax;
pub mod utils;

#[cfg(test)]
pub mod test_utils;

pub mod prelude {
    pub use super::builtin::ContextFactory;
    pub use super::builtin::RegisterBuilder;
    pub use super::syntax::FSPluginLoader;
    pub use super::syntax::Loader;
    pub use super::syntax::NaslValue;
    pub use super::utils::function::CheckedPositionals;
    pub use super::utils::function::FromNaslValue;
    pub use super::utils::function::Positionals;
    pub use super::utils::function::ToNaslResult;
    pub use super::utils::Context;
    pub use super::utils::ContextType;
    pub use super::utils::FunctionErrorKind;
    pub use super::utils::NaslResult;
    pub use super::utils::Register;
    pub use crate::function_set;
    pub use nasl_function_proc_macro::nasl_function;
}

pub use prelude::*;

#[cfg(test)]
pub mod test_prelude {
    pub use super::prelude::*;
    pub use super::test_utils::check_code_result;
    pub use super::test_utils::DefaultTestBuilder;
    pub use super::test_utils::TestBuilder;
    pub use crate::check_code_result_matches;
    pub use crate::check_err_matches;
}

pub use builtin::nasl_std_functions;

pub use syntax::NoOpLoader;

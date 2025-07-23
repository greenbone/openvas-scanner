// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

mod array;
mod cert;
mod cryptographic;
mod description;
mod error;
mod host;
mod http;
mod isotime;
mod knowledge_base;
pub mod misc;
mod network;
mod preferences;
#[cfg(feature = "nasl-builtin-raw-ip")]
pub mod raw_ip;
mod regex;
mod report_functions;
mod ssh;
mod string;
mod sys;

#[cfg(test)]
mod tests;

pub use error::BuiltinError;
pub use host::HostError;
pub use knowledge_base::KBError;

use crate::nasl::utils::{NaslVarRegister, NaslVarRegisterBuilder, Register};

use super::utils::Executor;

pub use network::socket::NaslSockets;

/// Creates a new Executor and adds all the functions to it.
///
/// When you have a function that is considered experimental due to either dependencies on
/// c-library or other reasons, you have to add the library as optional and put it into the
/// `experimental` feature flag. Additionally you have to create two new functions one with the
/// library toggle enabled and one when it is disabled.
pub fn nasl_std_functions() -> Executor {
    let mut executor = Executor::default();
    executor
        .add_set(array::Array)
        .add_set(report_functions::Reporting::default())
        .add_set(knowledge_base::KnowledgeBase)
        .add_set(misc::Misc)
        .add_set(string::NaslString)
        .add_set(host::Host)
        .add_set(http::NaslHttp2::default())
        .add_set(http::NaslHttp)
        .add_set(network::socket::SocketFns)
        .add_set(network::network::Network)
        .add_set(regex::RegularExpressions)
        .add_set(cryptographic::Cryptographic)
        .add_set(description::Description)
        .add_set(isotime::NaslIsotime)
        .add_set(preferences::Preferences)
        .add_set(cryptographic::rc4::CipherHandlers::default())
        .add_set(sys::Sys)
        .add_set(ssh::Ssh::default())
        .add_set(cert::NaslCerts::default());

    #[cfg(feature = "nasl-builtin-raw-ip")]
    executor.add_set(raw_ip::RawIp);

    executor
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
pub fn nasl_std_variables() -> NaslVarRegister {
    let mut builder = NaslVarRegisterBuilder::new();
    builder = add_raw_ip_vars(builder);
    builder.build()
}

#[cfg(feature = "nasl-builtin-raw-ip")]
fn add_raw_ip_vars(builder: NaslVarRegisterBuilder) -> NaslVarRegisterBuilder {
    builder.push_register(raw_ip::RawIp)
}

#[cfg(not(feature = "nasl-builtin-raw-ip"))]
fn add_raw_ip_vars(builder: NaslVarRegisterBuilder) -> NaslVarRegisterBuilder {
    builder
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
                register.add_global(var_name, crate::nasl::utils::ContextType::Value(nasl_val));
            }
        }
        register
    }
}

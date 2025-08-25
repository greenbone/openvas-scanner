// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

mod array;
mod cert;
mod cryptographic;
mod description;
mod error;
mod find_service;
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

use super::utils::Executor;

pub use network::socket::NaslSockets;

/// Creates a new Executor and adds all the functions to it.
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
        .add_set(find_service::FindService)
        .add_set(cert::NaslCerts::default());

    #[cfg(feature = "nasl-builtin-raw-ip")]
    executor.add_set(raw_ip::RawIp);
    #[cfg(feature = "nasl-builtin-raw-ip")]
    executor.add_global_vars(raw_ip::RawIp);

    executor
}

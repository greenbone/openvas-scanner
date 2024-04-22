// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
/// Module with structures and methods to access redis.
mod connector;
pub use connector::{
    CacheDispatcher, RedisAddAdvisory, RedisAddNvt, RedisCtx, RedisGetNvt, RedisWrapper,
};
/// Module to handle custom errors
pub mod dberror;
pub use connector::NameSpaceSelector;
/// Default selector for feed update
pub use connector::FEEDUPDATE_SELECTOR;
pub use connector::NOTUSUPDATE_SELECTOR;

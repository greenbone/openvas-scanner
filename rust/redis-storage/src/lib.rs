// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#![doc = include_str!("../README.md")]
/// Module with structures and methods to access redis.
mod connector;
pub use connector::{CacheDispatcher, VtHelper, RedisCtx, RedisAddNvt, RedisAddAdvisory, RedisWrapper, RedisGetNvt };
/// Module to handle custom errors
pub mod dberror;
/// Default selector for feed update
pub use connector::FEEDUPDATE_SELECTOR;
pub use connector::{NOTUSUPDATE_SELECTOR, NOTUS_KEY};

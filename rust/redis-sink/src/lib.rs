// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

/// Module with structures and methods to access redis.
pub mod connector;
/// Module to handle custom errors
pub mod dberror;
/// Module to handle Nvt metadata. The Nvt structure is defined here as well
/// as the methods to set and get the struct members.
pub mod nvt;
/// Default selector for feed update
pub use connector::FEEDUPDATE_SELECTOR;

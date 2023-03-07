// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later
//! feed is a library specialized for feed handling and used by nasl-cli
//!
//! It handles update of a feed within update
#![warn(missing_docs)]
mod update;
mod verify;

pub use verify::Error as VerifyError;
pub use update::Error as UpdateError;
pub use update::Update;
pub use verify::FileNameLoader;
pub use verify::HashSumNameLoader;
pub use verify::Hasher;

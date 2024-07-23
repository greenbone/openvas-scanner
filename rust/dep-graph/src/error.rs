// SPDX-FileCopyrightText: 2023 Greenbone AG
// SPDX-FileCopyrightText: 2018 Nicolas Moutschen
//
// SPDX-License-Identifier: (GPL-2.0-or-later WITH x11vnc-openssl-exception) AND MIT

use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("Failed to resolve the graph: {reason}")]
    ResolveGraphError { reason: &'static str },
}

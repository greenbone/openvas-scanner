// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use thiserror::Error;

use crate::nasl::prelude::*;

#[derive(Debug, Error)]
pub enum FindServiceError {}

struct Service {
    name: String,
    generate_result: GenerateResult,
    save_banner: bool,
    special_behavior: Option<SpecialBehavior>,
}

enum GenerateResult {
    No,
    Yes { is_vulnerability: bool },
}

enum SpecialBehavior {
    // TODO fill this in for services
}

fn scan_port(port: u16) -> Option<Service> {
    None
}

#[nasl_function]
fn plugin_run_find_service(context: &Context) -> () {
    for port in context.port_range() {}
}

#[derive(Default)]
pub struct FindService {
    services: Vec<Service>,
}

function_set! {
    FindService,
    (
        plugin_run_find_service
    )
}

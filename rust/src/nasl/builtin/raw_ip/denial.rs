// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashSet;

use super::packet_forgery::nasl_tcp_ping_shared;
use crate::alive_test::Scanner;
use crate::function_set;
use crate::nasl::Register;
use crate::nasl::builtin::network::socket::make_tcp_socket;
use crate::nasl::prelude::*;
use crate::nasl::utils::ScanCtx;
use crate::nasl::utils::function::utils::DEFAULT_TIMEOUT;
use nasl_function_proc_macro::nasl_function;

fn get_timeout(context: &ScanCtx) -> u8 {
    if let Some(p) = context
        .scan_params()
        .find(|p| p.id == "checks_read_timeout")
    {
        p.value.parse::<u8>().unwrap_or(DEFAULT_TIMEOUT as u8)
    } else {
        DEFAULT_TIMEOUT as u8
    }
}
#[nasl_function]
fn start_denial(context: &ScanCtx, script_ctx: &mut ScriptCtx) -> Result<NaslValue, FnError> {
    let retry = get_timeout(context);

    let port = context.get_random_open_tcp_port().unwrap_or_default();
    if port > 0
        && let Ok(_soc) = make_tcp_socket(context.target().ip_addr(), port, retry)
    {
        script_ctx.denial_port = Some(port);

        return Ok(NaslValue::Null);
    }

    script_ctx.alive = nasl_tcp_ping_shared(context, None)? > NaslValue::Number(0);

    return Ok(NaslValue::Null);
}

#[nasl_function]
async fn end_denial(
    context: &ScanCtx<'_>,
    register: &Register,
    script_ctx: &ScriptCtx,
) -> Result<NaslValue, FnError> {
    let retry = get_timeout(context);

    match script_ctx.denial_port {
        Some(port) => {
            let vendor_version = match register.nasl_value("vendor_version")? {
                NaslValue::String(v) => v.clone(),
                _ => "".to_string(),
            };

            if let Ok(mut soc) = make_tcp_socket(context.target().ip_addr(), port, retry) {
                let bogus_data = format!("Network Security Scan by {vendor_version} in progress");
                if soc.write(bogus_data.as_bytes()).is_ok() {
                    return Ok(NaslValue::Number(1));
                }
            }
        }
        _ => {
            match script_ctx.alive {
                false => {
                    return Ok(NaslValue::Number(1));
                }
                true => {
                    return nasl_tcp_ping_shared(context, None);
                }
            };
        }
    };

    // Services seem to not respond.
    // Last test with boreas
    if let Ok(alive_test_result) = Scanner::new(
        HashSet::from([context.target().ip_addr().to_string()]),
        context.alive_test_methods(),
        Some(retry as u64),
    )
    .run_alive_test()
    .await
        && !alive_test_result.is_empty()
    {
        return Ok(NaslValue::Number(1));
    }

    Ok(NaslValue::Null)
}

pub struct Denial;

function_set! {
    Denial,
    (
        start_denial,
        end_denial,
    )
}

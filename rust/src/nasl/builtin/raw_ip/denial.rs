// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use super::packet_forgery::_internal_convert_nasl_tcp_ping;
use crate::alive_test::Scanner;
use crate::function_set;
use crate::nasl::Register;
use crate::nasl::builtin::network::socket::make_tcp_socket;
use crate::nasl::prelude::*;
use crate::nasl::utils::Context;
use nasl_function_proc_macro::nasl_function;

#[nasl_function]
fn start_denial(context: &Context, register: &Register) -> Result<NaslValue, FnError> {
    let retry = if let Some(p) = context
        .scan_params()
        .find(|p| p.id == "checks_read_timeout")
    {
        p.value.parse::<u8>().unwrap_or(5)
    } else {
        5
    };

    let port = context.get_host_open_port().unwrap_or_default();
    if port > 0 {
        if let Ok(_soc) = make_tcp_socket(context.target().ip_addr(), port, retry) {
            //todo!() register.add_global("denial_port", NaslValue::Number(port.into()).into());

            return Ok(NaslValue::Null);
        }
    };

    let _p = ContextType::Value(NaslValue::Boolean(
        _internal_convert_nasl_tcp_ping(register, context)? > NaslValue::Number(0),
    ));
    //todo!() register.add_global("alive", p);

    return Ok(NaslValue::Null);
}

#[nasl_function]
async fn stop_denial(context: &Context<'_>, register: &Register) -> Result<NaslValue, FnError> {
    let retry = if let Some(p) = context
        .scan_params()
        .find(|p| p.id == "checks_read_timeout")
    {
        p.value.parse::<u8>().unwrap_or(5)
    } else {
        5
    };

    match register.named(format!("denial_port").as_str()) {
        Some(ContextType::Value(NaslValue::Number(port))) => {
            let vendor_version = match register.named(format!("vendor_version").as_str()) {
                Some(ContextType::Value(NaslValue::String(v))) => v.clone(),
                _ => "".to_string(),
            };

            if let Ok(mut soc) = make_tcp_socket(context.target().ip_addr(), *port as u16, retry) {
                let bogus_data = format!("Network Security Scan by {} in progress", vendor_version);
                if let Ok(_) = &soc.write(bogus_data.as_bytes()) {
                    return Ok(NaslValue::Number(1));
                }
            }
        }
        _ => {
            match register.named(format!("alive").as_str()) {
                Some(ContextType::Value(NaslValue::Number(0))) => {
                    return Ok(NaslValue::Number(1));
                }
                _ => {
                    return _internal_convert_nasl_tcp_ping(register, context);
                }
            };
        }
    };

    // Services seem to not respond.
    // Last test with boreas
    if let Ok(alive_test_result) = Scanner::new(
        vec![context.target().ip_addr().to_string()],
        context.alive_test_methods(),
        Some(retry as u64),
    )
    .run_alive_test()
    .await
    {
        if !alive_test_result.is_empty() {
            return Ok(NaslValue::Number(1));
        }
    }

    Ok(NaslValue::Null)
}

pub struct Denial;

function_set! {
    Denial,
    (
        start_denial,
        stop_denial,
    )
}

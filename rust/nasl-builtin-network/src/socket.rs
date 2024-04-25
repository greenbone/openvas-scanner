// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::net::{TcpStream, UdpSocket};

use nasl_builtin_utils::{error::FunctionErrorKind, Context, Register};
use nasl_syntax::NaslValue;

pub struct NaslSocket;

impl NaslSocket {
    /// Open a KDC socket. This function takes no arguments, but it is mandatory that keys are set. The following keys are required:
    /// - Secret/kdc_hostname
    /// - Secret/kdc_port
    /// - Secret/kdc_use_tcp
    fn open_sock_kdc<K>(_: &Register, context: &Context<K>) -> Result<NaslValue, FunctionErrorKind>
    where
        K: AsRef<str>,
    {
        let hostname = match context.get_kb_item("Secret/kdc_hostname")? {
            NaslValue::String(x) => x,
            x => {
                return Err(FunctionErrorKind::Diagnostic(
                    "KB key 'Secret/kdc_hostname' is either missing or has wrong type".to_string(),
                    Some(x),
                ));
            }
        };

        let port = context.get_kb_item("Secret/kdc_hostname")?;

        let port = match port {
            NaslValue::Number(x) => {
                if x <= 0 || x > 65535 {
                    return Err(FunctionErrorKind::Diagnostic(
                        "KB key 'Secret/kdc_port' out of range".to_string(),
                        Some(port),
                    ));
                }
                x
            }
            x => {
                return Err(FunctionErrorKind::Diagnostic(
                    "KB key 'Secret/kdc_port' is either missing or has wrong type".to_string(),
                    Some(x),
                ));
            }
        };
        if port <= 0 || port > 65535 {
            return Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/kdc_port' out of range".to_string(),
                Some(NaslValue::Number(port)),
            ));
        }

        let use_tcp: bool = context.get_kb_item("Secret/kdc_hostname")?.into();

        if use_tcp {
            let stream = TcpStream::connect(format!("{hostname}:{port}")).unwrap();
        } else {
            let sock = UdpSocket::bind(format!("{hostname}:{port}")).unwrap();
        }

        todo!()
    }
}

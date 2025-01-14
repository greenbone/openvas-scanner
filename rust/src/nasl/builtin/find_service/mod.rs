// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::net::IpAddr;

use thiserror::Error;

use crate::nasl::prelude::*;

use super::network::socket::{make_tcp_socket, SocketError};

const TIMEOUT_MILLIS: u64 = 10000;

#[derive(Debug, Error)]
pub enum FindServiceError {
    #[error("{0}")]
    SocketError(#[from] SocketError),
}

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

async fn scan_port(target: IpAddr, port: u16) -> Result<Option<Service>, FindServiceError> {
    let socket = make_tcp_socket(target, port, 0)?;

    let mut buf: &mut [u8] = &mut [0; 10];
    todo!()
    // let result = timeout(Duration::from_millis(TIMEOUT_MILLIS), async move {
    //     let result = socket.read_line();
    //     Ok::<_, FindServiceError>(buf)
    // })
    // .await;
    // match result {
    //     Ok(Ok(buf)) => {
    //         println!("{}", String::from_utf8(buf.to_vec()).unwrap());
    //     }
    //     Ok(Err(_)) => {
    //         println!("err");
    //     }
    //     Err(_) => {
    //         println!("{}", port);
    //         println!("timeout");
    //     }
    // }
    // Ok(None)
}

#[nasl_function]
async fn plugin_run_find_service(context: &Context<'_>) -> () {
    for port in context.port_range() {
        match scan_port(context.target_ip(), port).await {
            Ok(_) => {}
            Err(e) => {}
        }
    }
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

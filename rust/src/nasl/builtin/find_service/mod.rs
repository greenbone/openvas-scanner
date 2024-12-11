// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{io, net::IpAddr, time::Duration};

use thiserror::Error;
use tokio::{io::AsyncReadExt, net::TcpStream, time::timeout};

use crate::nasl::prelude::*;

const TIMEOUT_MILLIS: u64 = 10000;

#[derive(Debug, Error)]
pub enum FindServiceError {
    #[error("Failed to connect to TCP: {0}")]
    TcpStreamConnect(io::Error),
    #[error("Failed to read from TCP: {0}")]
    TcpStreamRead(io::Error),
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
    let mut stream = TcpStream::connect((target, port))
        .await
        .map_err(|e| FindServiceError::TcpStreamConnect(e))?;

    let mut buf: &mut [u8] = &mut [0; 10];
    let result = timeout(Duration::from_millis(TIMEOUT_MILLIS), async move {
        // let mut buffer: Vec<u8> = vec![];
        let result = stream
            .read(&mut buf)
            .await
            .map_err(|e| FindServiceError::TcpStreamRead(e));
        dbg!(result?);
        Ok::<_, FindServiceError>(buf)
    })
    .await;
    match result {
        Ok(Ok(buf)) => {
            println!("{}", String::from_utf8(buf.to_vec()).unwrap());
        }
        Ok(Err(_)) => {
            println!("err");
        }
        Err(_) => {
            println!("{}", port);
            println!("timeout");
        }
    }
    Ok(None)

    // # open socket
    //             socket.connect(( str(sys.argv[1] + '.' + str(host)), int(port) ))
    //             print('Connecting to' + str(sys.argv[1]) + 'on the port' + str(port))
    //             # segs until timeout
    //             socket.settimeout(1)
    //             # getting the banner from the server
    //             banner = socket.recv(1024)
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

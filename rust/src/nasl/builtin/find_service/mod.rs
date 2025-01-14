// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{io, net::IpAddr, time::Duration};

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

enum ReadResult {
    Data(String),
    Timeout,
}

enum ScanPortResult {
    Service(Service),
    Timeout,
}

async fn read_from_tcp_at_port(target: IpAddr, port: u16) -> Result<ReadResult, FindServiceError> {
    let mut socket = make_tcp_socket(target, port, 0)?;
    let mut buf: &mut [u8] = &mut [0; 100];
    let result = socket.read_with_timeout(buf, Duration::from_millis(TIMEOUT_MILLIS));
    match result {
        Ok(pos) => Ok(ReadResult::Data(
            String::from_utf8(buf[0..pos].to_vec()).unwrap(),
        )),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(ReadResult::Timeout),
        Err(e) => Err(SocketError::IO(e).into()),
    }
}

async fn scan_port(target: IpAddr, port: u16) -> Result<ScanPortResult, FindServiceError> {
    let result = read_from_tcp_at_port(target, port).await?;
    match result {
        ReadResult::Data(data) => Ok(ScanPortResult::Service(find_service(data))),
        ReadResult::Timeout => Ok(ScanPortResult::Timeout),
    }
}

fn find_service(data: String) -> Service {
    todo!()
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

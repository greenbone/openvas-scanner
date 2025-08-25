// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//pub mod alivetest;

use std::collections::HashSet;

use clap::ArgAction;
// re-export to work around name conflict

use scannerlib::alive_test::Scanner;
use scannerlib::models::{AliveTestMethods, Host};

use crate::CliError;

#[derive(clap::Parser)]
/// Perform alive test using different strategies against the target.
pub struct AliveTestArgs {
    /// List of hosts to test against
    #[clap(short, long)]
    target: String,
    /// List of ports to test. Default port list is \"80,137,587,3128,8081\".
    #[clap(short, long)]
    ports: Option<String>,
    /// Wait time for replies.
    #[clap(long, value_name = "MILLISECONDS")]
    timeout: Option<u64>,
    /// ICMP ping. Default method when no method specified. Supports both IPv4 and IPv6.
    #[clap(long, action=ArgAction::SetTrue)]
    icmp: bool,
    /// TCP-SYN ping. Supports both IPv4 and IPv6.
    #[clap(long, action=ArgAction::SetTrue)]
    tcpsyn: bool,
    /// TCP-ACK ping. Supports both IPv4 and IPv6.
    #[clap(long, action=ArgAction::SetTrue)]
    tcpack: bool,
    /// ARP ping. Supports both IPv4 and IPv6.
    #[clap(long, action=ArgAction::SetTrue)]
    arp: bool,
}

pub async fn run(args: AliveTestArgs) -> Result<(), CliError> {
    // TODO: parse target and implement exclude
    let target = args
        .target
        .split(',')
        .map(|x| x.to_string())
        .collect::<HashSet<_>>();

    // TODO: implement parse port list.
    let _ports = args.ports.unwrap_or("80,137,587,3128,8081".to_string());

    let mut methods = vec![];
    if args.tcpsyn {
        methods.push(AliveTestMethods::TcpSyn);
    }
    if args.tcpack {
        methods.push(AliveTestMethods::TcpAck);
    }
    if args.arp {
        methods.push(AliveTestMethods::Arp);
    }

    if args.icmp || methods.is_empty() {
        methods.push(AliveTestMethods::Icmp);
    }

    execute(target, args.timeout, methods).await
}

async fn execute(
    target: HashSet<Host>,
    timeout: Option<u64>,
    methods: Vec<AliveTestMethods>,
) -> Result<(), CliError> {
    let s = Scanner::new(target, methods, timeout);
    if let Err(e) = s.run_alive_test().await {
        tracing::warn!("{e}");
    }
    Ok(())
}

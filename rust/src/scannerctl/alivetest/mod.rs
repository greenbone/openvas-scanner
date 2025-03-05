// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//pub mod alivetest;

use clap::{arg, Arg, ArgAction, Command};
// re-export to work around name conflict

use scannerlib::alive_test::Scanner;
use scannerlib::models::{AliveTestMethods, Host};

use crate::CliError;

pub fn extend_args(cmd: Command) -> Command {
    cmd.subcommand(
        crate::add_verbose(
            Command::new("alivetest")
                .about("Perform alive test using different strategies against the target")
                .arg(arg!(-t --target <TARGET> "List of hosts to test against").required(true))
                // TODO: implement exclude host list. 
                .arg(arg!(-p --ports <PORTS> "List of ports to test. Default port list is \"80,137,587,3128,8081\"").required(false))
                .arg(Arg::new("timeout")
                     .long("timeout")
                     .value_parser(clap::value_parser!(u64))
                     .value_name("MILLISECONDS")
                     .value_parser(clap::value_parser!(u64))
                     .help("Wait time for replies"))
                .arg(arg!(--icmp "ICMP ping. Default method when no method specified. Supports both IPv4 and IPv6.").required(false).action(ArgAction::SetTrue))
                .arg(arg!(--"tcpsyn" "TCP-SYN ping. Supports both IPv4 and IPv6.").required(false).action(ArgAction::SetTrue))
                .arg(arg!(--"tcpack" "TCP-ACK ping. Supports both IPv4 and IPv6.").required(false).action(ArgAction::SetTrue))
                .arg(arg!(--arp "ARP ping. Supports both IPv4 and IPv6.").required(false).action(ArgAction::SetTrue))
        )
    )
}

pub async fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _verbose) = crate::get_args_set_logging(root, "alivetest")?;
    // TODO: parse target and implement exclude
    let target = args.get_one::<String>("target").unwrap();
    let target = target.split(',').map(|x| x.to_string()).collect::<Vec<_>>();

    // TODO: implement parse port list.
    let _ports = args
        .get_one::<String>("ports")
        .cloned()
        .unwrap_or("80,137,587,3128,8081".to_string());

    let timeout = args.get_one::<u64>("timeout");
    let icmp = args.get_one::<bool>("icmp").cloned().unwrap_or_default();
    let tcp_syn = args.get_one::<bool>("tcpsyn").cloned().unwrap_or_default();
    let tcp_ack = args.get_one::<bool>("tcpack").cloned().unwrap_or_default();
    let arp = args.get_one::<bool>("arp").cloned().unwrap_or_default();

    let mut methods = vec![];
    if tcp_syn {
        methods.push(AliveTestMethods::TcpSyn);
    }
    if tcp_ack {
        methods.push(AliveTestMethods::TcpAck);
    }
    if arp {
        methods.push(AliveTestMethods::Arp);
    }

    if icmp || methods.is_empty() {
        methods.push(AliveTestMethods::Icmp);
    }

    Some(execute(target, timeout.copied(), methods).await)
}

async fn execute(
    target: Vec<Host>,
    timeout: Option<u64>,
    methods: Vec<AliveTestMethods>,
) -> Result<(), CliError> {
    let s = Scanner::new(target, methods, timeout);
    if let Err(e) = s.run_alive_test().await {
        tracing::warn!("{e}");
    }
    Ok(())
}

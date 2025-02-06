// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io::BufRead;
use std::{io::BufReader, path::PathBuf, sync::Arc};

use clap::{arg, value_parser, Arg, ArgAction, Command};
use scannerlib::models::{self, Parameter, Scan, VT};
use scannerlib::storage::{self, DefaultDispatcher, StorageError};
use start_scan::{StartScan, VtSelection};

use crate::{CliError, CliErrorKind};
use scannerlib::storage::item::{NVTField, NVTKey};
use scannerlib::storage::Field;
use scannerlib::storage::Retrieve;
mod start_scan;

pub fn extend_args(cmd: Command) -> Command {
    cmd.subcommand(crate::add_verbose(
        Command::new("osp")
            .about("Transforms a osp start-scan xml to a scan json for openvasd. ")
            .arg(
                arg!(-p --path <FILE> "Path to the feed.")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                Arg::new("ospd_xml")
                    .required(false),
            )
            .arg(
                arg!(-b --back "Serializes start scan command and pretty prints it back to stdout.")
                    .required(false)
                    .action(ArgAction::SetTrue),
            ),
    ))
}

pub async fn may_transform_start_scan<R, S>(
    print_back: bool,
    feed: Option<S>,
    reader: R,
) -> Option<Result<String, CliErrorKind>>
where
    R: BufRead,
    S: storage::Retriever,
{
    match quick_xml::de::from_reader(reader) {
        Ok(x) if print_back => Some(Ok(format!("{x}"))),
        Ok(x) if feed.is_some() => Some(transform_start_scan(feed.unwrap(), x).await),
        Ok(_) => Some(Err(CliErrorKind::MissingArguments(
            vec!["path".to_string()],
        ))),
        Err(_) => None,
    }
}

async fn transform_vts<S>(feed: S, vts: VtSelection) -> Result<Vec<models::VT>, CliErrorKind>
where
    S: storage::Retriever,
{
    let mut result: Vec<_> = vts
        .vt_single
        .into_iter()
        .flatten()
        .map(|x| VT {
            oid: x.id,
            parameters: x
                .vt_value
                .into_iter()
                .flatten()
                .filter_map(|x| x.id.parse().ok().map(|y| (y, x.text)))
                .filter_map(|(id, x)| x.map(|v| Parameter { id, value: v }))
                .collect(),
        })
        .collect();
    let gvts = vts.vt_group.into_iter().flatten().filter_map(|x| {
        match x.filter.split_once('=').map(|(k, v)| (k.trim(), v.trim())) {
            Some(("family", v)) => Some(v.to_string()),
            filter => {
                tracing::warn!(?filter, "only family is supported, ignoring entry");
                None
            }
        }
    });

    // we iterate here to return an error when storage is behaving in an unexpected fashion
    for family in gvts {
        let fvts: Vec<VT> = match feed.retry_retrieve_by_field(
            Field::NVT(NVTField::Family(family.to_string())),
            Retrieve::NVT(Some(NVTKey::Oid)),
            5,
        ) {
            Ok(x) => x
                .flat_map(|(_, f)| match &f {
                    Field::NVT(NVTField::Oid(oid)) => Some(VT {
                        oid: oid.clone(),
                        ..Default::default()
                    }),
                    _ => None,
                })
                .collect(),
            Err(StorageError::NotFound(_)) => {
                tracing::debug!(family, "not found");
                Vec::new()
            }
            Err(e) => return Err(e.into()),
        };
        result.extend(fvts);
    }
    result.sort();
    Ok(result)
}

async fn transform_start_scan<S>(feed: S, sc: StartScan) -> Result<String, CliErrorKind>
where
    S: storage::Retriever,
{
    // currently we ignore the previous order as the scanner will reorder
    // when scheduling internally anyway.
    let scan = Scan {
        scan_id: sc.id.unwrap_or_default(),
        scan_preferences: sc.scanner_params.values,
        target: sc.targets.target.into(),
        vts: transform_vts(feed, sc.vt_selection).await?,
    };
    let scan_json = match serde_json::to_string_pretty(&scan) {
        Ok(s) => s,
        Err(e) => return Err(e.into()),
    };
    Ok(scan_json)
}

pub async fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _) = crate::get_args_set_logging(root, "osp")?;

    let feed = match args.get_one::<PathBuf>("path") {
        Some(feed) => {
            tracing::info!("loading feed. This may take a while.");
            let storage = Arc::new(DefaultDispatcher::new());
            crate::feed::update::run(Arc::clone(&storage), feed.to_owned(), false)
                .await
                .unwrap();
            tracing::info!("feed loaded.");
            Some(storage)
        }
        None => None,
    };

    let config = args.get_one::<String>("ospd_xml");
    let mut bufreader: BufReader<Box<dyn std::io::Read>> = {
        if let Some(config) = config {
            let file = match std::fs::File::open(config) {
                Ok(x) => x,
                Err(e) => return Some(Err(e.into())),
            };
            BufReader::new(Box::new(file))
        } else {
            BufReader::new(Box::new(std::io::stdin()))
        }
    };
    let print_back = args.get_one::<bool>("back").cloned().unwrap_or_default();
    // currently we just support start scan if that changes chain the options.
    let output = may_transform_start_scan(print_back, feed, &mut bufreader).await;
    let result = match output {
        Some(Ok(x)) => {
            println!("{x}");
            Ok(())
        }
        Some(Err(e)) => Err(CliError {
            filename: config.cloned().unwrap_or_default(),
            kind: e,
        }),
        None => Err(CliError {
            filename: config.cloned().unwrap_or_default(),
            kind: CliErrorKind::Corrupt("Unknown ospd command.".to_string()),
        }),
    };

    Some(result)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use scannerlib::storage::{item::NVTField, ContextKey, DefaultDispatcher, Field};
    use storage::Dispatcher;

    use super::*;

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn print_scan_json() {
        let input = r#"
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<start_scan parallel="20" scan_id="36389b56-f5a0-11e9-bba4-482ae354ac4c">
    <targets>
        <target>
            <hosts>127.0.0.1</hosts>
            <ports>T:80-80,443-443</ports>
            <alive_test_ports>T:80-80,443-443</alive_test_ports>
            <alive_test>2</alive_test>
            <credentials>
                <credential type="up" service="ssh" port="22">
                  <password>PASSWORD</password>
                  <username>USER</username>
                </credential>
              </credentials>
            <exclude_hosts>localhost</exclude_hosts>
        </target>
    </targets>
    <vt_selection>
        <vt_group filter="family=A"/>        
        <vt_single id="1.3.6.1.4.1.25623.1.0.100151">
            <vt_value id="1">postgres</vt_value>
            <vt_value id="2"/>
        </vt_single>
    </vt_selection>
    <scanner_params>
        <use_mac_addr>0</use_mac_addr>
        <checks_read_timeout>5</checks_read_timeout>
        <cgi_path>/cgi-bin:/scripts</cgi_path>
        <time_between_request>0</time_between_request>
        <vhosts_ip/>
        <vhosts/>
    </scanner_params>
</start_scan>
    "#;
        let reader = BufReader::new(Cursor::new(input));
        let d = DefaultDispatcher::new();
        let dispatch = |k: &str, f: &str| {
            let key = ContextKey::FileName(format!("{k}.nasl"));
            d.dispatch(&key, Field::NVT(NVTField::Family(f.into())))
                .unwrap();

            d.dispatch(&key, Field::NVT(NVTField::Oid(k.into())))
                .unwrap();
        };
        dispatch("0", "A");
        dispatch("1", "A");
        dispatch("2", "A");
        dispatch("3", "A");

        let output = may_transform_start_scan(false, Some(d), reader)
            .await
            .unwrap()
            .unwrap();
        insta::assert_snapshot!(output);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn print_back() {
        let input = r#"
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<start_scan parallel="20" scan_id="36389b56-f5a0-11e9-bba4-482ae354ac4c">
    <targets>
        <target>
            <hosts>127.0.0.1</hosts>
            <ports>T:80-80,443-443</ports>
            <alive_test_ports>T:80-80,443-443</alive_test_ports>
            <alive_test>2</alive_test>
            <credentials>
                <credential type="up" service="ssh" port="22">
                  <password>PASSWORD</password>
                  <username>USER</username>
                </credential>
              </credentials>
            <exclude_hosts>localhost</exclude_hosts>
        </target>
    </targets>
    <vt_selection>
        <vt_group filter="family=AIX Local Security Checks"/>        
        <vt_single id="1.3.6.1.4.1.25623.1.0.100151">
            <vt_value id="1">postgres</vt_value>
            <vt_value id="2"/>
        </vt_single>
    </vt_selection>
    <scanner_params>
        <use_mac_addr>0</use_mac_addr>
        <checks_read_timeout>5</checks_read_timeout>
        <cgi_path>/cgi-bin:/scripts</cgi_path>
        <time_between_request>0</time_between_request>
        <vhosts_ip/>
        <vhosts/>
    </scanner_params>
</start_scan>
    "#;
        let reader = BufReader::new(Cursor::new(input));
        let output = may_transform_start_scan::<_, DefaultDispatcher>(true, None, reader)
            .await
            .unwrap()
            .unwrap();
        insta::assert_snapshot!(output);
    }
}

// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io::BufRead;
use std::path::Path;
use std::{io::BufReader, path::PathBuf, sync::Arc};

use scannerlib::models::{self, Parameter, Scan, VT};
use scannerlib::scanner::preferences::preference::ScanPrefs;
use scannerlib::storage::Retriever;
use scannerlib::storage::inmemory::InMemoryStorage;
use scannerlib::storage::items::nvt::{Feed, Nvt};
use start_scan::{StartScan, VtSelection};

use crate::{CliError, CliErrorKind};
mod start_scan;

#[derive(clap::Parser)]
/// Transforms a osp start-scan xml to a scan json for openvasd.
pub struct OspArgs {
    /// Path to the feed.
    feed_path: PathBuf,
    /// Path to the OSP XML file.
    ospd_xml: Option<PathBuf>,
    /// Serialize the start scan command and pretty print it
    /// back to stdout.
    #[clap(short, long)]
    print_back: bool,
}

async fn may_transform_start_scan<R, S>(
    print_back: bool,
    feed: Option<S>,
    reader: R,
) -> Result<String, CliErrorKind>
where
    R: BufRead,
    S: Retriever<Feed, Item = Vec<Nvt>>,
{
    let xml = quick_xml::de::from_reader(reader)?;
    if print_back {
        Ok(format!("{xml}"))
    } else {
        transform_start_scan(feed.unwrap(), xml).await
    }
}

async fn transform_vts<S>(feed: S, vts: VtSelection) -> Result<Vec<models::VT>, CliErrorKind>
where
    S: Retriever<Feed, Item = Vec<Nvt>>,
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
        // Retrieving the whole feed is always wrapped in a Some. In case there are no vts in the
        // feed, the result will be an empty vector.
        let vts = feed.retry_retrieve(&Feed, 5)?.unwrap();
        let fvts: Vec<VT> = vts
            .into_iter()
            .filter_map(|x| {
                if x.family == family {
                    Some(VT {
                        oid: x.oid.clone(),
                        ..Default::default()
                    })
                } else {
                    None
                }
            })
            .collect();

        result.extend(fvts);
    }
    result.sort();
    Ok(result)
}

async fn transform_start_scan<S>(feed: S, sc: StartScan) -> Result<String, CliErrorKind>
where
    S: Retriever<Feed, Item = Vec<Nvt>>,
{
    // currently we ignore the previous order as the scanner will reorder
    // when scheduling internally anyway.
    let scan = Scan {
        scan_id: sc.id.unwrap_or_default(),
        scan_preferences: ScanPrefs(sc.scanner_params.values),
        target: sc.targets.target.into(),
        vts: transform_vts(feed, sc.vt_selection).await?,
    };
    let scan_json = match serde_json::to_string_pretty(&scan) {
        Ok(s) => s,
        Err(e) => return Err(e.into()),
    };
    Ok(scan_json)
}

pub async fn run(args: OspArgs) -> Result<(), CliError> {
    let feed = load_feed(&args.feed_path).await;

    let mut bufreader: BufReader<Box<dyn std::io::Read>> = {
        if let Some(config) = args.ospd_xml {
            let file = std::fs::File::open(config)?;
            BufReader::new(Box::new(file))
        } else {
            BufReader::new(Box::new(std::io::stdin()))
        }
    };
    // currently we just support start scan if that changes chain the options.
    let output = may_transform_start_scan(args.print_back, feed, &mut bufreader).await?;
    println!("{output}");
    Ok(())
}

async fn load_feed(path: &Path) -> Option<Arc<InMemoryStorage>> {
    tracing::info!("loading feed. This may take a while.");
    let storage = Arc::new(InMemoryStorage::new());
    crate::feed::update::run(Arc::clone(&storage), path, false)
        .await
        .unwrap();
    tracing::info!("feed loaded.");
    Some(storage)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use scannerlib::storage::{Dispatcher, inmemory::InMemoryStorage, items::nvt::FileName};

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
        let d = InMemoryStorage::new();
        let dispatch = |k: &str, f: &str| {
            let key = FileName(format!("{k}.nasl"));
            let nvt = Nvt {
                oid: k.into(),
                family: f.into(),
                ..Default::default()
            };
            d.dispatch(key, nvt).unwrap();
        };
        dispatch("0", "A");
        dispatch("1", "A");
        dispatch("2", "A");
        dispatch("3", "A");

        let output = may_transform_start_scan(false, Some(d), reader)
            .await
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
        let output = may_transform_start_scan::<_, InMemoryStorage>(true, None, reader)
            .await
            .unwrap();
        insta::assert_snapshot!(output);
    }
}

// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt::{Display, Formatter};
use std::{io::BufReader, path::PathBuf, sync::Arc};

use clap::{arg, value_parser, Arg, ArgAction, Command};
use serde::Deserialize;

use crate::{get_path_from_openvas, read_openvas_config, CliError, CliErrorKind};
use std::collections::HashMap;
use std::io::BufRead;

pub fn extend_args(cmd: Command) -> Command {
    cmd.subcommand( crate::add_verbose(
            Command::new("scan-config")
                .about("Transforms a scan-config xml to a scan json for openvasd.
When piping a scan json it is enriched with the scan-config xml and may the portlist otherwise it will print a scan json without target or credentials.")
                .arg(arg!(-p --path <FILE> "Path to the feed.") .required(false)
                    .value_parser(value_parser!(PathBuf)))
                .arg(Arg::new("scan-config").required(true).action(ArgAction::Append))
                .arg(arg!(-i --input "Parses scan json from stdin.").required(false).action(ArgAction::SetTrue))
                .arg(arg!(-l --portlist <FILE> "Path to the port list xml") .required(false))
        )
    )
}

pub fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _) = crate::get_args_set_logging(root, "scan-config")?;

    let feed = args.get_one::<PathBuf>("path").cloned();
    let config: Vec<String> = args
        .get_many::<String>("scan-config")
        .expect("scan-config is required")
        .cloned()
        .collect();
    let port_list = args.get_one::<String>("portlist").cloned();
    tracing::debug!("port_list: {port_list:?}");
    let stdin = args.get_one::<bool>("input").cloned().unwrap_or_default();
    Some(execute(feed.as_ref(), &config, port_list.as_ref(), stdin))
}

fn execute(
    feed: Option<&PathBuf>,
    config: &[String],
    port_list: Option<&String>,
    stdin: bool,
) -> Result<(), CliError> {
    let map_error = |f: &str, e: Error| CliError {
        filename: f.to_string(),
        kind: CliErrorKind::Corrupt(format!("{e:?}")),
    };
    let as_bufreader = |f: &str| {
        let file = std::fs::File::open(f).map_err(|e| CliError {
            filename: f.to_string(),
            kind: CliErrorKind::Corrupt(format!("{e:?}")),
        })?;
        let reader = BufReader::new(file);
        Ok::<BufReader<std::fs::File>, CliError>(reader)
    };
    let storage = Arc::new(storage::DefaultDispatcher::new(true));
    let mut scan = {
        if stdin {
            tracing::debug!("reading scan config from stdin");
            serde_json::from_reader(std::io::stdin()).map_err(|e| CliError {
                filename: "".to_string(),
                kind: CliErrorKind::Corrupt(format!("{e:?}")),
            })?
        } else {
            models::Scan::default()
        }
    };
    let feed = match feed {
        Some(feed) => feed.to_owned(),
        None => read_openvas_config()
            .map(get_path_from_openvas)
            .map_err(|e| CliError {
                filename: "".to_string(),
                kind: CliErrorKind::Corrupt(format!("{e:?}")),
            })?,
    };

    tracing::info!("loading feed. This may take a while.");
    crate::feed::update::run(Arc::clone(&storage), feed.to_owned(), false)?;
    tracing::info!("feed loaded.");
    let ports = match port_list {
        Some(ports) => {
            tracing::debug!("reading port list from {ports}");
            let reader = as_bufreader(ports)?;
            parse_portlist(reader).map_err(|e| map_error(ports, e))?
        }
        None => vec![],
    };
    let mut vts = vec![];
    for a in config.iter().map(|f| {
        as_bufreader(f)
            .map_err(CliError::from)
            .and_then(|r| parse_vts(r, storage.as_ref(), &scan.vts).map_err(|e| map_error(f, e)))
    }) {
        vts.extend(a?);
    }
    scan.vts.extend(vts);
    scan.target.ports = ports;
    let out = serde_json::to_string_pretty(&scan).map_err(|e| CliError {
        filename: config.join(","),
        kind: CliErrorKind::Corrupt(format!("{e:?}")),
    })?;
    println!("{}", out);
    Ok(())
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct PortRange {
    #[serde(rename = "@id")]
    id: String,
    start: usize,
    end: usize,
    #[serde(rename(deserialize = "type"))]
    port_type: String,
    comment: Option<String>,
}

impl PortRange {
    fn as_port_range(&self) -> models::PortRange {
        let end = match self.end {
            0 => None,
            _ => Some(self.end),
        };
        models::PortRange {
            start: self.start,
            end,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct PortRangeList {
    port_range: Vec<PortRange>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct PortList {
    #[serde(rename = "@id")]
    id: String,
    name: Option<String>,
    comment: Option<String>,
    port_ranges: PortRangeList,
}

impl PortList {
    fn as_port_list(&self) -> Vec<models::Port> {
        let mut tcp = vec![];
        let mut udp = vec![];
        let mut none = vec![];
        for p in self.port_ranges.port_range.iter() {
            match p.port_type.as_str() {
                "tcp" => tcp.push(p.as_port_range()),
                "udp" => udp.push(p.as_port_range()),
                _ => none.push(p.as_port_range()),
            }
        }
        vec![
            models::Port {
                protocol: Some(models::Protocol::TCP),
                range: tcp,
            },
            models::Port {
                protocol: Some(models::Protocol::UDP),
                range: udp,
            },
            models::Port {
                protocol: None,
                range: none,
            },
        ]
    }
}

/// Error types
#[derive(Debug, Clone)]
pub enum Error {
    /// XML parse error
    ParseError(String),
    /// Storage error
    StorageError(storage::StorageError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ParseError(s) => write!(f, "Parse error: {}", s),
            Error::StorageError(s) => write!(f, "Storage error: {}", s),
        }
    }
}

impl From<storage::StorageError> for Error {
    fn from(e: storage::StorageError) -> Self {
        Error::StorageError(e)
    }
}

impl std::error::Error for Error {}

/// Parse a port list from a string.
pub fn parse_portlist<R>(pl: R) -> Result<Vec<models::Port>, Error>
where
    R: BufRead,
{
    let result = quick_xml::de::from_reader::<R, PortList>(pl)
        .map_err(|e| Error::ParseError(format!("Error parsing port list: {}", e)))?;
    tracing::trace!(
        "transforming portlist {} {} ({}) with {} entries.",
        &result.id,
        result.name.as_deref().unwrap_or(""),
        result.comment.as_deref().unwrap_or(""),
        &result.port_ranges.port_range.len()
    );
    Ok(result.as_port_list())
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct ScanConfig {
    #[serde(rename = "@id")]
    id: String,
    name: Option<String>,
    comment: Option<String>,
    #[serde(rename(deserialize = "type"))]
    scan_type: String,
    #[serde(rename(deserialize = "usage_type"))]
    usage_type: String,
    preferences: ScanConfigPreferences,
    nvt_selectors: ScanConfigNvtSelectors,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct ScanConfigNvtSelectors {
    nvt_selector: Vec<ScanConfigNvtSelector>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct ScanConfigNvtSelector {
    include: usize,
    #[serde(rename(deserialize = "type"))]
    nvt_type: usize,
    family_or_nvt: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct ScanConfigPreferences {
    preference: Vec<ScanConfigPreference>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct ScanConfigPreference {
    id: u16,
    name: String,
    value: String,
    #[serde(rename(deserialize = "type"))]
    preference_type: String,
    nvt: ScanConfigPreferenceNvt,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct ScanConfigPreferenceNvt {
    #[serde(rename = "@oid")]
    oid: String,
    name: String,
}

pub fn parse_vts<R, K>(
    sc: R,
    retriever: &dyn storage::Retriever<K>,
    vts: &[models::VT],
) -> Result<Vec<models::VT>, Error>
where
    R: BufRead,
{
    let result = quick_xml::de::from_reader::<R, ScanConfig>(sc)
        .map_err(|e| Error::ParseError(format!("Error parsing vts: {}", e)))?;
    tracing::debug!(
        "transforming vts {} {} ({}) with {} entries.",
        &result.id,
        result.name.as_deref().unwrap_or(""),
        result.comment.as_deref().unwrap_or(""),
        &result.preferences.preference.len()
    );
    let preference_lookup: HashMap<String, Vec<models::Parameter>> = result
        .preferences
        .preference
        .iter()
        .map(|p| {
            (
                p.nvt.oid.clone(),
                vec![models::Parameter {
                    id: p.id,
                    value: p.value.clone(),
                }],
            )
        })
        .collect();
    let oid_to_vt = |oid: &String| -> Result<models::VT, Error> {
        let parameters = preference_lookup.get(oid).unwrap_or(&vec![]).clone();
        Ok(models::VT {
            oid: oid.clone(),
            parameters,
        })
    };
    let is_not_already_present = |oid: &String| -> bool { !vts.iter().any(|vt| vt.oid == *oid) };
    result
        .nvt_selectors
        .nvt_selector
        .iter()
        .flat_map(|s| {
            if s.nvt_type == 2 {
                if is_not_already_present(&s.family_or_nvt) {
                    vec![oid_to_vt(&s.family_or_nvt)]
                } else {
                    vec![]
                }
            } else {
                // lookup oids via family
                use storage::item::NVTField;
                use storage::item::NVTKey;
                use storage::Field;
                use storage::Retrieve;
                match retriever.retrieve_by_field(
                    Field::NVT(NVTField::Family(s.family_or_nvt.clone())),
                    Retrieve::NVT(Some(NVTKey::Oid)),
                ) {
                    Ok(nvt) => {
                        let result: Vec<_> = nvt
                            .flat_map(|(_, f)| match &f {
                                Field::NVT(NVTField::Oid(oid)) if is_not_already_present(oid) => {
                                    Some(oid_to_vt(oid))
                                }
                                _ => None,
                            })
                            .collect();

                        tracing::debug!(
                            "found {} nvt entries for family {}",
                            result.len(),
                            s.family_or_nvt
                        );
                        result
                    }
                    Err(e) => vec![Err(e.into())],
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use storage::Storage;

    use super::*;

    #[test]
    fn parse_portlist() {
        let pl = r#"
<port_list id="c7e03b6c-3bbe-11e1-a057-406186ea4fc5">
  <name>OpenVAS Default</name>
  <comment>Version 20200827.</comment>
  <port_ranges>
    <port_range id="1626ec63-366a-4c1b-b779-da516edfcc33">
      <start>1</start>
      <end>5</end>
      <type>tcp</type>
      <comment/>
    </port_range>
    <port_range id="c492b604-8c97-464c-96d0-95ab54352a79">
      <start>7</start>
      <end>7</end>
      <type>tcp</type>
      <comment/>
    </port_range>
    <port_range id="c492b604-8c97-464c-96d0-95ab54352a79">
      <start>7</start>
      <end>7</end>
      <type>udp</type>
      <comment/>
    </port_range>
    <port_range id="c492b604-8c97-464c-96d0-95ab54352a79">
      <start>7</start>
      <end>7</end>
      <type></type>
      <comment/>
    </port_range>
    </port_ranges>
</port_list>"#;
        let presult = quick_xml::de::from_str::<PortList>(pl).unwrap();
        assert_eq!(presult.port_ranges.port_range.len(), 4);

        let result = super::parse_portlist(pl.as_bytes()).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].protocol, Some(models::Protocol::TCP));
        assert_eq!(result[0].range.len(), 2);
        assert_eq!(result[1].protocol, Some(models::Protocol::UDP));
        assert_eq!(result[1].range.len(), 1);
        assert_eq!(result[2].protocol, None);
        assert_eq!(result[2].range.len(), 1);
    }

    #[test]
    fn parse_scanconfig() {
        let sc = r#"
        <config id="8715c877-47a0-438d-98a3-27c7a6ab2196">
  <name>Discovery</name>
  <comment>Network Discovery scan configuration. Version 20201215.</comment>
  <type>0</type>
  <usage_type>scan</usage_type>
  <preferences>
    <preference>
      <nvt oid="1.3.6.1.4.1.25623.1.0.100315">
        <name>Ping Host</name>
      </nvt>
      <name>Report about unreachable Hosts</name>
      <type>checkbox</type>
      <value>no</value>
      <id>6</id>
    </preference>
    <preference>
      <nvt oid="1.3.6.1.4.1.25623.1.0.10330">
        <name>Services</name>
      </nvt>
      <name>Test SSL based services</name>
      <type>radio</type>
      <value>All;Known SSL ports;None</value>
      <default>All;None</default>
      <id>1</id>
    </preference>
    <preference>
      <nvt oid="1.3.6.1.4.1.25623.1.0.100315">
        <name>Ping Host</name>
      </nvt>
      <name>Mark unreachable Hosts as dead (not scanning)</name>
      <type>checkbox</type>
      <value>yes</value>
      <id>5</id>
    </preference>
  </preferences>
  <nvt_selectors>
    <nvt_selector>
      <include>1</include>
      <type>2</type>
      <family_or_nvt>1.3.6.1.4.1.25623.1.0.803575</family_or_nvt>
    </nvt_selector>
    <nvt_selector>
      <include>1</include>
      <type>1</type>
      <family_or_nvt>Product detection</family_or_nvt>
    </nvt_selector>
    </nvt_selectors>
    </config>"#;
        let result = quick_xml::de::from_str::<ScanConfig>(sc).unwrap();
        assert_eq!(result.nvt_selectors.nvt_selector.len(), 2);
        assert_eq!(result.preferences.preference.len(), 3);
        let shop: storage::DefaultDispatcher<String> = storage::DefaultDispatcher::default();
        let add_product_detection = |oid: &str| {
            shop.as_dispatcher()
                .dispatch(
                    &oid.to_string(),
                    storage::Field::NVT(storage::item::NVTField::Oid(oid.to_owned().to_string())),
                )
                .unwrap();
            shop.as_dispatcher()
                .dispatch(
                    &oid.to_string(),
                    storage::Field::NVT(storage::item::NVTField::Family(
                        "Product detection".to_string(),
                    )),
                )
                .unwrap();
        };
        add_product_detection("1");
        add_product_detection("2");
        add_product_detection("4");
        add_product_detection("5");
        let exists = vec![models::VT {
            oid: "1".to_string(),
            parameters: vec![],
        }];

        let result = super::parse_vts(sc.as_bytes(), &shop, &exists).unwrap();
        assert_eq!(result.len(), 4);
    }
}

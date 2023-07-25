use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    io::BufRead,
};

use serde::Deserialize;

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
                use storage::nvt::NVTField;
                use storage::nvt::NVTKey;
                use storage::Field;
                use storage::Retrieve;
                match retriever.retrieve_by_field(
                    &Field::NVT(NVTField::Family(s.family_or_nvt.clone())),
                    &Retrieve::NVT(Some(NVTKey::Oid)),
                ) {
                    Ok(nvt) => {
                        tracing::debug!(
                            "found {} nvt entries for family {}",
                            nvt.len(),
                            s.family_or_nvt
                        );
                        nvt.iter()
                            .flat_map(|(_, f)| {
                                f.iter().filter_map(|f| match f {
                                    Field::NVT(NVTField::Oid(oid))
                                        if is_not_already_present(oid) =>
                                    {
                                        Some(oid_to_vt(oid))
                                    }
                                    _ => None,
                                })
                            })
                            .collect()
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
                    storage::Field::NVT(storage::nvt::NVTField::Oid(oid.to_owned().to_string())),
                )
                .unwrap();
            shop.as_dispatcher()
                .dispatch(
                    &oid.to_string(),
                    storage::Field::NVT(storage::nvt::NVTField::Family(
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

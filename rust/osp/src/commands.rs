// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io::{self, Cursor};

use models::Scan;
use quick_xml::events::{attributes::Attribute, BytesEnd, BytesStart, BytesText, Event};

use crate::response::Status;

/// OSP Command
pub enum ScanCommand<'a> {
    /// Start a new scan.
    Start(&'a Scan),
    /// Delete a scan.
    Delete(&'a str),
    /// Stop a scan.
    Stop(&'a str),
    /// Get the status and results of a scan.
    Get(&'a str),
    /// Get the status and results of a scan and deletes results from OSPD.
    GetDelete(&'a str),
}

type Result<T> = std::result::Result<T, Error>;
type Writer = quick_xml::Writer<Cursor<Vec<u8>>>;

impl<'a> ScanCommand<'a> {
    fn as_byte_response(
        scan_id: &str,
        element_name: &str,
        additional: &[(&str, &str)],
        f: &mut dyn FnMut(&mut Writer) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut writer = Writer::new(Cursor::new(Vec::new()));
        writer.within_id_element(IDAttribute::ScanID(scan_id), additional, element_name, f)?;
        let result = writer.into_inner().into_inner();
        Ok(result)
    }

    /// Returns the XML representation of the command.
    pub fn try_to_xml(&self) -> Result<Vec<u8>> {
        match self {
            ScanCommand::Start(scan) => {
                ScanCommand::as_byte_response(&scan.scan_id, "start_scan", &[], &mut |writer| {
                    write_vts(scan, writer)?;
                    write_target(scan, writer)?;
                    write_scanner_prefs(scan, writer)?;
                    Ok(())
                })
            }
            ScanCommand::Delete(scan_id) => {
                ScanCommand::as_byte_response(scan_id, "delete_scan", &[], &mut |_| Ok(()))
            }
            ScanCommand::Stop(scan_id) => {
                ScanCommand::as_byte_response(scan_id, "stop_scan", &[], &mut |_| Ok(()))
            }
            ScanCommand::GetDelete(scan_id) => ScanCommand::as_byte_response(
                scan_id,
                "get_scans",
                // removes results from ospd-openvas
                &[("pop_results", "1"), ("progress", "1")],
                &mut |_| Ok(()),
            ),
            ScanCommand::Get(scan_id) => {
                ScanCommand::as_byte_response(scan_id, "get_scans", &[], &mut |_| Ok(()))
            }
        }
    }
}

enum IDAttribute<'a> {
    VTId(&'a str),
    ScanID(&'a str),
}

impl IDAttribute<'_> {
    fn key(&self) -> &str {
        match self {
            IDAttribute::VTId(_) => "id",
            IDAttribute::ScanID(_) => "scan_id",
        }
    }

    fn as_str(&self) -> &str {
        match self {
            IDAttribute::VTId(id) => id,
            IDAttribute::ScanID(id) => id,
        }
    }
}

trait WithinElement {
    /// Writes an element with the given name and attributes.
    fn within_element<F>(&mut self, name: &str, f: &mut F) -> Result<()>
    where
        F: FnMut(&mut Self) -> Result<()> + ?Sized,
    {
        self.within_parameter_element::<(&str, &str), F>(name, vec![], f)
    }
    /// Writes an element with an ID attribute and the given name and attributes.
    fn within_id_element<F>(
        &mut self,
        attr: IDAttribute,
        additional: &[(&str, &str)],
        name: &str,
        f: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&mut Self) -> Result<()> + ?Sized,
    {
        self.within_parameter_element(
            name,
            vec![(attr.key(), attr.as_str())]
                .into_iter()
                .chain(additional.iter().cloned())
                .collect(),
            f,
        )
    }

    /// Writes an element with the given parameters and attributes.
    fn within_parameter_element<'a, P, F>(
        &mut self,
        name: &str,
        params: Vec<P>,
        f: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&mut Self) -> Result<()> + ?Sized,
        P: Into<Attribute<'a>>;
}

impl WithinElement for Writer {
    fn within_parameter_element<'a, P, F>(
        &mut self,
        name: &str,
        params: Vec<P>,
        f: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&mut Self) -> Result<()> + ?Sized,
        P: Into<Attribute<'a>>,
    {
        let mut elem = BytesStart::new(name);
        for p in params {
            elem.push_attribute(p.into());
        }
        self.write_event(Event::Start(elem))?;
        f(self)?;
        self.write_event(Event::End(BytesEnd::new(name)))?;
        Ok(())
    }
}

fn write_vts(scan: &Scan, writer: &mut Writer) -> Result<()> {
    writer.within_element("vt_selection", &mut |writer| {
        for v in &scan.vts {
            writer.within_id_element(
                IDAttribute::VTId(&v.oid),
                &[],
                "vt_single",
                &mut |writer| {
                    for p in &v.parameters {
                        writer.within_id_element(
                            IDAttribute::VTId(&p.id.to_string()),
                            &[],
                            "vt_value",
                            &mut |writer| {
                                writer.write_event(Event::Text(BytesText::new(&p.value)))?;
                                Ok(())
                            },
                        )?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    })
}

// In the openvasd API it is called scanner preferences while in the OSP side
// it is called scanner parameters.
fn write_scanner_prefs(scan: &Scan, writer: &mut Writer) -> Result<()> {
    writer.write_event(Event::Start(BytesStart::new("scanner_params")))?;
    for p in &scan.scan_preferences {
        writer.write_event(Event::Start(BytesStart::new(&p.id)))?;
        writer.write_event(Event::Text(BytesText::new(&p.value)))?;
        writer.write_event(Event::End(BytesEnd::new(&p.id)))?;
    }

    writer.write_event(Event::End(BytesEnd::new("scanner_params")))?;
    Ok(())
}

fn write_str_element(writer: &mut Writer, name: &str, value: &str) -> Result<()> {
    write_event(name, writer, Event::Text(BytesText::new(value)))
}

fn write_int_element(writer: &mut Writer, name: &str, value: i64) -> Result<()> {
    write_event(
        name,
        writer,
        Event::Text(BytesText::new(&value.to_string())),
    )
}
fn write_event<'a, E: AsRef<Event<'a>>>(name: &str, writer: &mut Writer, event: E) -> Result<()> {
    writer.write_event(Event::Start(BytesStart::new(name)))?;
    writer.write_event(event)?;
    writer.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

fn write_target(scan: &Scan, writer: &mut Writer) -> Result<()> {
    let as_comma_list = |x: &[models::PortRange]| {
        x.iter()
            .map(|x| x.to_string())
            .reduce(|a, b| format!("{},{}", a, b))
            .unwrap_or_default()
    };
    writer.within_element("targets", &mut |writer| {
        writer.within_element("target", &mut |writer| {
            write_str_element(writer, "hosts", &scan.target.hosts.join(","))?;
            let mut tcp = String::new();
            let mut udp = String::new();
            let mut other = String::new();
            for p in &scan.target.ports {
                match &p.protocol {
                    None => {
                        other.push_str(&format!("{},", as_comma_list(&p.range)));
                    }
                    Some(models::Protocol::UDP) => {
                        udp.push_str(&format!("{},", as_comma_list(&p.range)));
                    }
                    Some(models::Protocol::TCP) => {
                        tcp.push_str(&format!("{},", as_comma_list(&p.range)));
                    }
                }
            }
            let ports = {
                if !tcp.is_empty() {
                    other.push_str(&format!("T:{}", tcp));
                }
                if !udp.is_empty() {
                    other.push_str(&format!("U:{}", udp));
                }
                other.trim_end_matches(',').to_string()
            };
            write_str_element(writer, "ports", &ports)?;
            write_int_element(
                writer,
                "reverse_lookup_only",
                scan.target.reverse_lookup_only.unwrap_or_default() as i64,
            )?;
            write_int_element(
                writer,
                "reverse_lookup_unify",
                scan.target.reverse_lookup_unify.unwrap_or_default() as i64,
            )?;
            write_credentials(scan, writer)?;
            Ok(())
        })
    })
}

fn write_credentials(scan: &Scan, writer: &mut Writer) -> Result<()> {
    writer.within_element("credentials", &mut |writer| {
        for c in &scan.target.credentials {
            let mut parameter = vec![
                ("type", c.credential_type.as_ref()),
                ("service", c.service.as_ref()),
            ];
            let sp = c.port.map(|p| p.to_string()).unwrap_or_default();
            if c.port.is_some() {
                parameter.push(("port", &sp));
            }
            use models::CredentialType;

            writer.within_parameter_element("credential", parameter, &mut |writer| {
                match &c.credential_type {
                    CredentialType::UP {
                        username,
                        password,
                        privilege,
                    } => {
                        write_str_element(writer, "username", username)?;
                        write_str_element(writer, "password", password)?;
                        if let Some(p) = privilege {
                            write_str_element(writer, "priv_username", &p.username)?;
                            write_str_element(writer, "priv_password", &p.password)?;
                        }
                    }
                    CredentialType::USK {
                        username,
                        password,
                        private_key,
                        privilege,
                    } => {
                        write_str_element(writer, "username", username)?;
                        write_str_element(writer, "password", password)?;
                        write_str_element(writer, "private", private_key)?;
                        if let Some(p) = privilege {
                            write_str_element(writer, "priv_username", &p.username)?;
                            write_str_element(writer, "priv_password", &p.password)?;
                        }
                    }
                    CredentialType::SNMP {
                        username,
                        password,
                        community,
                        auth_algorithm,
                        privacy_password,
                        privacy_algorithm,
                    } => {
                        write_str_element(writer, "username", username)?;
                        write_str_element(writer, "password", password)?;
                        write_str_element(writer, "community", community)?;
                        write_str_element(writer, "auth_algorithm", auth_algorithm)?;
                        write_str_element(writer, "privacy_password", privacy_password)?;
                        write_str_element(writer, "privacy_algorithm", privacy_algorithm)?;
                    }
                }

                Ok(())
            })?;
        }
        Ok(())
    })
}

#[derive(Debug)]
/// Errors that can occur when dealing with XML or sockets
pub enum Error {
    /// Error when writing XML
    WriteXML(String),
    /// Error when reading XML
    ReadXML(String),
    /// Error when opening a socket
    Socket(io::ErrorKind),
    /// Invalid response from OSPD
    InvalidResponse(Status),
}
impl From<Error> for models::scanner::Error {
    fn from(value: Error) -> Self {
        Self::Unexpected(format!("{value:?}"))
    }
}

impl From<quick_xml::de::DeError> for Error {
    fn from(value: quick_xml::de::DeError) -> Self {
        Error::ReadXML(value.to_string())
    }
}
impl From<quick_xml::Error> for Error {
    fn from(value: quick_xml::Error) -> Self {
        Error::WriteXML(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_start_scan() {
        let json_str = r#"
{
  "target": {
    "hosts": [
      "127.0.0.1"
    ],
    "ports": [
      {
        "protocol": "tcp",
        "range": [
          { "start": 42 },
          { "start": 33 }
        ]
      },
      {
        "range": [
          { "start": 22 }
        ]
      },
      {
        "protocol": "udp",
        "range": [
          { "start": 42 },
          { "start": 33 }
        ]
      }
    ]
  },
  "vts": [
    {
      "oid": "1.3.6.1.4.1.25623.1.0.10330"
    }
  ]
}
"#;
        // tests that it doesn't panic when parsing the json
        let scan: Scan = serde_json::from_str(json_str).unwrap();
        let result = ScanCommand::Start(&scan).try_to_xml().unwrap();
        let result = std::str::from_utf8(&result).unwrap();
        // ports must only have one T: and only one U: everything following is
        // of the same protocol.
        // ports that have no assigned protocol are in the front
        let expected = r#"
        <start_scan scan_id="replace_me">
            <vt_selection>
                <vt_single id="1.3.6.1.4.1.25623.1.0.10330"></vt_single>
            </vt_selection>
            <targets>
                <target>
                    <hosts>127.0.0.1</hosts>
                    <ports>22,T:42,33,U:42,33</ports>
                    <reverse_lookup_only>0</reverse_lookup_only>
                    <reverse_lookup_unify>0</reverse_lookup_unify>
                    <credentials></credentials>
                </target>
            </targets>
            <scanner_params>
            </scanner_params>
        </start_scan>
        "#;
        let expected = expected.replace("replace_me", &scan.scan_id);
        let expected = expected
            .trim()
            .lines()
            .map(|l| l.trim())
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(result, expected.trim().replace('\n', "").trim());
    }
}

// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! # Responses of OSPD commands
use std::{collections::HashMap, fmt};

use serde::{de::Visitor, Deserialize};

use crate::Error;

/// StringU32 is a wrapper around u32 to allow deserialization of strings
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StringU32(u32);

impl From<i64> for StringU32 {
    fn from(value: i64) -> Self {
        StringU32(value as u32)
    }
}

impl From<StringU32> for u32 {
    fn from(value: StringU32) -> Self {
        value.0
    }
}

impl From<StringU32> for i64 {
    fn from(value: StringU32) -> Self {
        value.0 as i64
    }
}

impl From<StringU32> for i32 {
    fn from(value: StringU32) -> Self {
        value.0 as i32
    }
}

/// Wrapper around f32 to allow deserialization of strings
#[derive(Clone, Debug, PartialEq)]
pub struct StringF32(f32);

impl From<f32> for StringF32 {
    fn from(value: f32) -> Self {
        StringF32(value)
    }
}

impl From<StringF32> for f32 {
    fn from(value: StringF32) -> Self {
        value.0
    }
}

impl From<StringF32> for f64 {
    fn from(value: StringF32) -> Self {
        value.0 as f64
    }
}

impl<'de> Deserialize<'de> for StringF32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MyVisitor;
        impl<'de> Visitor<'de> for MyVisitor {
            type Value = StringF32;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value.parse::<f32>() {
                    Ok(value) => Ok(StringF32(value)),
                    Err(_) => Err(E::custom("invalid number")),
                }
            }
        }
        deserializer.deserialize_any(MyVisitor)
    }
}

impl<'de> Deserialize<'de> for StringU32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MyVisitor;
        impl<'de> Visitor<'de> for MyVisitor {
            type Value = StringU32;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value.parse::<u32>() {
                    Ok(value) => Ok(StringU32(value)),
                    Err(_) => Err(E::custom("invalid number")),
                }
            }
        }
        deserializer.deserialize_any(MyVisitor)
    }
}

#[derive(Debug, Deserialize, PartialEq)]
/// Response from the OSP daemon
pub enum Response {
    /// Response on a unknown command
    ///
    /// Example:
    /// ```xml
    /// <osp_response status="400" status_text="Bogus command name" />
    /// ```
    #[serde(rename = "osp_response")]
    Failure {
        #[serde(flatten)]
        /// Status of the response
        status: Status,
    },
    /// Response from the start_scan command
    ///
    /// Example:
    /// ```xml
    /// <start_scan_response status_text="OK"
    ///                         status="200">
    ///    <id>2f616d53-595f-4785-9b97-4395116ca118</id>
    /// </start_scan_response>
    /// ```
    #[serde(rename = "start_scan_response")]
    StartScan {
        /// Scan ID
        id: Option<String>,
        #[serde(flatten)]
        /// Status of the response
        status: Status,
    },

    /// Response from the stop_scan command
    ///
    /// Example:
    /// ```xml
    /// <stop_scan_response status_text="OK" status="200"/>
    /// ```
    #[serde(rename = "stop_scan_response")]
    StopScan {
        #[serde(flatten)]
        /// Status of the response
        status: Status,
    },

    /// Response from the delete_scan command
    ///
    /// Example:
    /// ```xml
    /// <delete_scan_response status_text="OK" status="200"/>
    /// ```
    #[serde(rename = "delete_scan_response")]
    DeleteScan {
        #[serde(flatten)]
        /// Status of the response
        status: Status,
    },
    /// Response from the get_scans command
    ///
    /// Example:
    /// ```xml
    /// <get_scans_response status_text="OK" status="200">
    ///  <scan id="9750f1f8-07aa-49cc-9c31-2f9e469c8f65"
    ///      target="192.168.1.1"
    ///      end_time="0"
    ///      progress="78"
    ///      status="running"
    ///      start_time="1432000000">
    ///      <results>
    ///         <result host="192.168.1.1"
    ///                 hostname=""
    ///                 severity="2.5"
    ///                 port="22/tcp"
    ///                 test_id=""
    ///                 name="SSH Service Detection"
    ///                 type="Alarm">
    ///         An SSH service was detected on the remote host.
    ///         </result>
    ///     </results>
    ///     <progress>
    ///         <host name="127.0.0.1">45</host>
    ///         <host name="10.0.0.160">98</host>
    ///         <overall>78</overall>
    ///         <count_alive>2</count_alive>
    ///         <count_dead>10</count_dead>
    ///         <count_excluded>3</count_excluded>
    ///         <count_total>511</count_total>
    ///      </progress>
    ///  </scan>
    ///</get_scans_response>
    /// ```
    #[serde(rename = "get_scans_response")]
    GetScans {
        #[serde(flatten)]
        /// Status of the response
        status: Status,
        /// Scan
        scan: Option<Scan>,
    },
}

impl TryFrom<Response> for Scan {
    type Error = Error;
    fn try_from(response: Response) -> Result<Self, Self::Error> {
        match response {
            Response::GetScans { scan, status } => match scan {
                Some(scan) => Ok(scan),
                None => Err(Error::InvalidResponse(status)),
            },
            _ => Err(Error::InvalidResponse(response.status())),
        }
    }
}

impl From<Scan> for Vec<models::Result> {
    fn from(scan: Scan) -> Self {
        scan.results.into()
    }
}

impl TryFrom<Response> for Vec<models::Result> {
    type Error = Error;
    fn try_from(response: Response) -> Result<Self, Self::Error> {
        let scan = Scan::try_from(response)?;
        Ok(scan.into())
    }
}

impl From<Response> for Status {
    fn from(response: Response) -> Self {
        response.status()
    }
}

impl Response {
    /// Get the status of the response
    pub fn status(self) -> Status {
        match self {
            Response::Failure { status } => status,
            Response::StartScan { status, .. } => status,
            Response::StopScan { status } => status,
            Response::DeleteScan { status } => status,
            Response::GetScans { status, .. } => status,
        }
    }
}

/// Status response
#[derive(Debug, Deserialize, PartialEq)]
pub struct Status {
    #[serde(rename = "@status_text")]
    /// Status text
    pub text: String,
    #[serde(rename = "@status")]
    /// Status code
    pub code: StringU32,
}

impl Status {
    /// Check if the status is OK
    pub fn is_ok(&self) -> bool {
        self.code.0 == 200
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
/// OSPD does rename openvas messages
///
/// - ALARM -> Alarm
/// - LOG -> Log Message
/// - ERROR -> Error Message
/// - HOST_DETAIL -> Host Detail
///
/// See ospd/misc.py class ResultType for more information
pub enum ResultType {
    /// Alarm message
    #[serde(rename = "Alarm")]
    Alarm,
    /// Log message
    ///
    /// Additionally to logs produced by the NASL script, there is also logs
    /// with the name Host Details that has XML in them and is not marked as
    /// Host Detail type.
    #[serde(rename = "Log Message")]
    Log,
    /// Error message
    #[serde(rename = "Error Message")]
    Error,
    /// Host detail message
    ///
    /// Host details are not sent by the NASL script but by openvas.
    /// Making them a bit special
    #[serde(rename = "Host Detail")]
    HostDetail,
}

/// Scan result within the get_scans response
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ScanResult {
    #[serde(rename = "@host")]
    /// Host
    pub host: String,
    #[serde(rename = "@hostname")]
    /// Hostname
    pub hostname: String,
    #[serde(rename = "@severity")]
    /// Severity
    pub severity: StringF32,
    #[serde(rename = "@port")]
    /// Port
    pub port: String,
    #[serde(rename = "@test_id")]
    /// Test ID
    pub test_id: String,
    #[serde(rename = "@name")]
    /// Name
    pub name: String,
    #[serde(rename = "@type")]
    /// Type
    pub result_type: ResultType,
    /// Description
    #[serde(rename = "$text")]
    pub description: String,
}

impl From<&ScanResult> for models::ResultType {
    fn from(sr: &ScanResult) -> Self {
        match (sr.name.as_str(), &sr.result_type) {
            ("HOST_START", ResultType::Log) => models::ResultType::HostStart,
            ("HOST_END", ResultType::Log) => models::ResultType::HostEnd,
            ("DEADHOST", ResultType::Log) => models::ResultType::DeadHost,
            ("Host Details", ResultType::Log) => models::ResultType::HostDetail,
            (_, ResultType::Log) => models::ResultType::Log,
            (_, ResultType::Alarm) => models::ResultType::Alarm,
            (_, ResultType::Error) => models::ResultType::Error,
            // host details are sent via log messages
            (_, ResultType::HostDetail) => unreachable!(),
        }
    }
}

#[derive(Deserialize, Debug, Default)]
struct HostDetail {
    detail: Vec<models::Detail>,
}

impl HostDetail {
    pub fn extract(&self) -> Option<models::Detail> {
        self.detail.first().cloned()
    }
}

impl From<&ScanResult> for models::Result {
    fn from(result: &ScanResult) -> Self {
        // name == script_name can be found via oid and is ignored here
        let (port, protocol) = {
            let (m_port, m_protocol) = result
                .port
                .split_once('/')
                .unwrap_or((result.port.as_str(), ""));
            (
                m_port.parse().ok(),
                models::Protocol::try_from(m_protocol).ok(),
            )
        };
        let r_type = result.into();
        let message = match result.description.as_str() {
            "" => None,
            _ => Some(result.description.clone()),
        };
        let detail = match r_type {
            models::ResultType::HostDetail => match urlencoding::decode(&result.description) {
                Ok(decoded) => match quick_xml::de::from_str::<HostDetail>(&decoded) {
                    Ok(details) => details,
                    Err(_) => Default::default(),
                },
                Err(_) => Default::default(),
            },
            _ => Default::default(),
        };

        models::Result {
            id: 0,
            hostname: match result.hostname.as_str() {
                "" => None,
                _ => Some(result.hostname.clone()),
            },
            ip_address: match result.host.as_str() {
                "" => None,
                _ => Some(result.host.clone()),
            },
            port,
            protocol,
            oid: Some(result.test_id.clone()),
            r_type,
            message,
            detail: detail.extract(),
        }
    }
}

/// Scan within the get_scans response
#[derive(Clone, Default, Debug, Deserialize, PartialEq)]
pub struct Results {
    /// Results
    #[serde(default)]
    pub result: Vec<ScanResult>,
}

impl Results {
    /// Push a result to the results
    pub fn push(&mut self, result: ScanResult) {
        self.result.push(result);
    }

    /// Extend the results with another results
    pub fn extend(&mut self, results: Results) {
        self.result.extend(results.result);
    }
}

impl From<Results> for Vec<models::Result> {
    fn from(results: Results) -> Self {
        results
            .result
            .iter()
            .enumerate()
            .map(|r| r.into())
            .collect()
    }
}

/// Enum of the possible phases of a scan
#[derive(Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    #[default]
    /// A scan has been queued, but not started yet
    Queued,
    /// A scan has been requested, but not started yet
    Requested,
    /// A scan is currently running
    Running,
    /// A scan has been stopped by a client
    Stopped,
    /// A scan could not finish due to an error while scanning
    Failed,
    /// A scan has been finished
    Finished,
    /// A scan has been successfully finished
    Succeeded,
    /// A scan has been interrupted
    Interrupted,
}

impl From<&str> for ScanStatus {
    fn from(s: &str) -> Self {
        match s {
            "requested" => ScanStatus::Requested,
            "running" => ScanStatus::Running,
            "stopped" => ScanStatus::Stopped,
            "failed" => ScanStatus::Failed,
            "succeeded" => ScanStatus::Succeeded,
            "finished" => ScanStatus::Finished,
            "interrupted" => ScanStatus::Failed,
            _ => ScanStatus::default(),
        }
    }
}

/// Scan within the get_scans response
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Scan {
    #[serde(rename = "@id")]
    /// Scan ID
    pub id: String,
    #[serde(rename = "@target")]
    /// Target IP
    pub target: String,
    #[serde(rename = "@start_time")]
    /// Start time
    pub start_time: Option<StringU32>,
    #[serde(rename = "@end_time")]
    /// End time
    pub end_time: Option<StringU32>,
    #[serde(rename = "@progress")]
    /// Progress
    pub progress: StringU32,
    #[serde(rename = "@status")]
    /// Status
    pub status: ScanStatus,
    /// Results
    pub results: Results,
    #[serde(rename = "progress")]
    /// HostInfo
    pub host_info: Option<HostInfo>,
}

/// Information about the scan progress
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct HostInfo {
    #[serde(default)]
    /// Currently scanned hosts
    pub host: Vec<Host>,
    /// Overall progress
    pub overall: ElementU32,
    /// Number of alive hosts finished
    // TODO: Consider divide into alive and finished
    pub count_alive: ElementU32,
    /// Number of dead hosts
    pub count_dead: ElementU32,
    /// Number of excluded hosts
    pub count_excluded: ElementU32,
    /// Total number of hosts
    pub count_total: ElementU32,
}

/// An StringU32 element
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ElementU32 {
    #[serde(rename = "$text")]
    /// Content of the element
    pub content: StringU32,
}

/// Progress information for a single host
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Host {
    #[serde(rename = "@name")]
    /// IP of the host
    pub name: String,
    #[serde(rename = "$text")]
    /// Current progress for the host
    pub progress: StringU32,
}

impl Default for Scan {
    fn default() -> Self {
        Scan {
            id: "".to_string(),
            target: "".to_string(),
            start_time: None,
            end_time: None,
            progress: StringU32(0),
            status: ScanStatus::default(),
            results: Results { result: vec![] },
            host_info: None,
        }
    }
}
// TODO when traits moved to models create From for ScanResults
impl From<Scan> for models::Status {
    fn from(value: Scan) -> Self {
        let phase: models::Phase = match value.status {
            ScanStatus::Queued => models::Phase::Requested,
            ScanStatus::Requested => models::Phase::Requested,
            ScanStatus::Running => models::Phase::Running,
            ScanStatus::Stopped => models::Phase::Stopped,
            ScanStatus::Failed => models::Phase::Failed,
            ScanStatus::Finished => models::Phase::Succeeded,
            ScanStatus::Succeeded => models::Phase::Succeeded,
            ScanStatus::Interrupted => models::Phase::Failed,
        };

        let mut scanning: HashMap<String, i32> = HashMap::new();
        if let Some(i) = &value.host_info {
            for host in &i.host {
                scanning.insert(host.name.clone(), 0);
            }
        }

        models::Status {
            status: phase,
            start_time: value.start_time.map(|s| s.0),
            end_time: value.end_time.map(|s| s.0),
            host_info: value.host_info.map(|i| models::HostInfo {
                all: i.count_total.content.0,
                excluded: i.count_excluded.content.0,
                dead: i.count_dead.content.0,
                alive: i.count_alive.content.0,
                queued: i.count_total.content.0
                    - i.count_excluded.content.0
                    - i.count_alive.content.0
                    - i.host.len() as u32,
                finished: i.count_alive.content.0,
                scanning: Some(scanning),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::de::from_str;

    #[test]
    fn start_scan_response() {
        let xml = r#"<start_scan_response status_text="OK" status="200"><id>2f616d53-595f-4785-9b97-4395116ca118</id></start_scan_response>"#;
        let response: Response = from_str(xml).unwrap();
        assert_eq!(
            response,
            Response::StartScan {
                status: Status {
                    text: "OK".to_string(),
                    code: 200.into(),
                },
                id: Some("2f616d53-595f-4785-9b97-4395116ca118".to_string()),
            }
        );
    }
    #[test]
    fn stop_scan_response() {
        let xml = r#"<stop_scan_response status_text="OK" status="200"/>"#;
        let response: Response = from_str(xml).unwrap();
        assert_eq!(
            response,
            Response::StopScan {
                status: Status {
                    text: "OK".to_string(),
                    code: 200.into(),
                },
            }
        );
    }
    #[test]
    fn delete_scan_response() {
        let xml = r#"<delete_scan_response status_text="OK" status="200"/>"#;
        let response: Response = from_str(xml).unwrap();
        assert_eq!(
            response,
            Response::DeleteScan {
                status: Status {
                    text: "OK".to_string(),
                    code: 200.into(),
                },
            }
        );
    }

    #[test]
    fn get_scans_response() {
        // types Alarm, Log Message, nn
        // TODO write tests for Log Message, Error Message, Alarm
        let xml = r#"
     <get_scans_response status_text="OK"
                         status="200">
       <scan id="9750f1f8-07aa-49cc-9c31-2f9e469c8f65"
             target="192.168.1.252"
             end_time="0"
             progress="78"
             status="finished"
             start_time="1432824206">
         <results>
           <result host="192.168.1.252"
                   hostname=""
                   severity="2.5"
                   port="443/tcp"
                   test_id=""
                   name="Path disclosure vulnerability"
                   type="Log Message">
             bla
           </result>
         </results>
         <progress>
            <host name="127.0.0.1">45</host>
            <host name="10.0.0.160">98</host>
            <overall>78</overall>
            <count_alive>2</count_alive>
            <count_dead>10</count_dead>
            <count_excluded>3</count_excluded>
            <count_total>511</count_total>
        </progress>
       </scan>
     </get_scans_response>
            "#;
        let response: Response = from_str(xml).unwrap();
        match response {
            Response::GetScans { status, scan } => {
                assert_eq!(status.text, "OK");
                assert_eq!(status.code, 200.into());
                if let Some(scan) = scan {
                    let host_info = scan.host_info.unwrap();
                    assert_eq!(scan.id, "9750f1f8-07aa-49cc-9c31-2f9e469c8f65");
                    assert_eq!(scan.target, "192.168.1.252");
                    assert_eq!(scan.end_time, Some(0.into()));
                    assert_eq!(scan.progress, 78.into());
                    assert_eq!(scan.status, "finished".into());
                    assert_eq!(scan.start_time, Some(1432824206.into()));
                    assert_eq!(scan.results.result[0].host, "192.168.1.252");
                    assert_eq!(scan.results.result[0].hostname, "");
                    assert_eq!(scan.results.result[0].severity, 2.5.into());
                    assert_eq!(scan.results.result[0].port, "443/tcp");
                    assert_eq!(scan.results.result[0].test_id, "");
                    assert_eq!(scan.results.result[0].name, "Path disclosure vulnerability");
                    assert_eq!(scan.results.result[0].result_type, ResultType::Log);
                    assert_eq!(scan.results.result[0].description, "bla");
                    assert_eq!(host_info.count_alive.content.0, 2);
                    assert_eq!(host_info.count_dead.content.0, 10);
                    assert_eq!(host_info.count_excluded.content.0, 3);
                    assert_eq!(host_info.count_total.content.0, 511);
                } else {
                    panic!("no scan");
                }
            }
            _ => panic!("wrong type: {:?}", response),
        }
    }

    #[test]
    fn transform() {
        let xml = r#"
<?xml version="1.0"?>
<get_scans_response status_text="OK" status="200">
  <scan id="9750f1f8-07aa-49cc-9c31-2f9e469c8f65" target="192.168.1.252" end_time="1432824234" progress="100" status="finished" start_time="1432824206">
    <results>
      <result name="HOST_START" type="Log Message" severity="0.0" host="127.0.0.1" hostname="" test_id="" port="" qod="" uri="">Mon May  8 09:24:07 2023</result>
      <result name="Host Details" type="Log Message" severity="0.0" host="127.0.0.1" hostname="localhost" test_id="1.3.6.1.4.1.25623.1.0.103692" port="general/Host_Details" qod="80" uri="">&lt;host&gt;&lt;detail&gt;&lt;name&gt;test&lt;/name&gt;&lt;value&gt;bla&lt;/value&gt;&lt;source&gt;&lt;type&gt;nvt&lt;/type&gt;&lt;name&gt;1.3.6.1.4.1.25623.1.0.103692&lt;/name&gt;&lt;description&gt;SSL/TLS Certificate&lt;/description&gt;&lt;/source&gt;&lt;/detail&gt;&lt;/host&gt;
</result>
      <result name="HOST_END" type="Log Message" severity="0.0" host="127.0.0.1" hostname="" test_id="" port="" qod="" uri="">Mon May  8 09:31:41 2023</result>
    </results>
  </scan>
</get_scans_response>
            "#;
        let response: Response = from_str(xml).unwrap();
        let results: Vec<models::Result> = response.try_into().unwrap();
        use models::ResultType::*;
        let expected = [HostStart, HostDetail, HostEnd];
        assert_eq!(results.len(), expected.len());
        for (result, expected) in results.iter().zip(expected.iter()) {
            assert_eq!(result.r_type, *expected);
        }
    }
    #[test]
    fn host_detail() {
        let xml = r#"
<?xml version="1.0"?>
<get_scans_response status_text="OK" status="200">
  <scan id="9750f1f8-07aa-49cc-9c31-2f9e469c8f65" target="192.168.1.252" end_time="1432824234" progress="100" status="finished" start_time="1432824206">
    <results>
      <result name="Host Details" type="Log Message" severity="0.0" host="127.0.0.1" hostname="localhost" test_id="1.3.6.1.4.1.25623.1.0.103692" port="general/Host_Details" qod="80" uri="">&lt;host&gt;&lt;detail&gt;&lt;name&gt;test&lt;/name&gt;&lt;value&gt;bla&lt;/value&gt;&lt;source&gt;&lt;type&gt;nvt&lt;/type&gt;&lt;name&gt;1.3.6.1.4.1.25623.1.0.103692&lt;/name&gt;&lt;description&gt;SSL/TLS Certificate&lt;/description&gt;&lt;/source&gt;&lt;/detail&gt;&lt;/host&gt;
</result>
    </results>
  </scan>
</get_scans_response>
            "#;
        let response: Response = from_str(xml).unwrap();
        let results: Vec<models::Result> = response.try_into().unwrap();
        assert_eq!(results.len(), 1);
        let result = results.first().unwrap();
        let detail = result.detail.clone().unwrap();
        assert_eq!(detail.name, "test".to_string());
        assert_eq!(detail.value, "bla".to_string());
        assert_eq!(detail.source.s_type, "nvt".to_string());
        assert_eq!(
            detail.source.name,
            "1.3.6.1.4.1.25623.1.0.103692".to_string()
        );
        assert_eq!(detail.source.description, "SSL/TLS Certificate".to_string());
    }
}

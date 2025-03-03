use serde::ser::SerializeMap;
use std::collections::HashMap;
use std::fmt::{self, Display};

use itertools::Itertools;
use scannerlib::models::{self, CredentialType, Service};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Targets {
    pub target: Target,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub hosts: Vec<String>,
    pub ports: Option<Vec<models::Port>>,
    pub alive_test_ports: Option<Vec<models::Port>>,
    pub alive_test_methods: Option<Vec<models::AliveTestMethods>>,
    pub exclude_hosts: Option<Vec<String>>,
    pub finished_hosts: Option<Vec<String>>,
    pub reverse_lookup_unify: Option<bool>,
    pub reverse_lookup_only: Option<bool>,
    pub credentials: Option<Credentials>,
}

impl From<Credentials> for Vec<models::Credential> {
    fn from(other: Credentials) -> Self {
        other
            .credential
            .into_iter()
            .flatten()
            .map(|x| {
                fn find_key(key: &str, x: &[(String, String)]) -> Option<String> {
                    x.iter().find(|(k, _)| k == key).map(|(_, v)| v.to_string())
                }
                fn key(key: &str, x: &[(String, String)]) -> String {
                    find_key(key, x).unwrap_or_default()
                }
                let username = key("username", &x.credentials);
                let password = key("password", &x.credentials);

                let privilege = find_key("priv_username", &x.credentials).map(|y| {
                    models::PrivilegeInformation {
                        username: y,
                        password: key("priv_password", &x.credentials),
                    }
                });
                let kind = match &x.kind as &str {
                    "usk" => CredentialType::USK {
                        username,
                        password: Some(password),
                        private_key: key("private", &x.credentials),
                        privilege,
                    },
                    "snmp" => CredentialType::SNMP {
                        username,
                        password,
                        community: key("community", &x.credentials),
                        auth_algorithm: key("auth_algorithm", &x.credentials),
                        privacy_password: key("privacy_password", &x.credentials),
                        privacy_algorithm: key("privacy_algorithm", &x.credentials),
                    },
                    _ => CredentialType::UP {
                        username,
                        password,
                        privilege,
                    },
                };
                models::Credential {
                    service: (&x.service as &str).try_into().ok().unwrap_or(Service::SSH),
                    port: x.port.and_then(|x| x.parse().ok()),
                    credential_type: kind,
                }
            })
            .collect()
    }
}

impl From<Target> for models::Target {
    fn from(val: Target) -> Self {
        let credentials = val.credentials.map(|x| x.into()).unwrap_or_default();

        models::Target {
            hosts: val.hosts,
            ports: val.ports.unwrap_or_default(),
            excluded_hosts: val.exclude_hosts.unwrap_or_default(),
            credentials,
            alive_test_ports: val.alive_test_ports.unwrap_or_default(),
            alive_test_methods: val.alive_test_methods.unwrap_or_default(),
            reverse_lookup_unify: val.reverse_lookup_unify,
            reverse_lookup_only: val.reverse_lookup_only,
        }
    }
}

// Parses T:80-80,U:80-90 into a vector of ports
fn ports_from_ospd_string(ports: Option<&str>) -> Option<Vec<models::Port>> {
    let ports = ports?;
    let mut result = vec![];
    let mut start = 0;
    let mut end = None;
    let mut protocol = None;
    for port in ports.split(',') {
        for p in port.split(':') {
            match p {
                "T" => {
                    protocol = Some(models::Protocol::TCP);
                }
                "U" => {
                    protocol = Some(models::Protocol::UDP);
                }
                _ => {
                    for (i, r) in p.split('-').enumerate() {
                        if i == 0 {
                            start = r.parse().unwrap();
                        } else if i == 1 {
                            end = Some(r.parse().unwrap());
                        } else {
                            panic!("invalid port range");
                        }
                    }
                    let range = models::Port {
                        protocol,
                        range: vec![scannerlib::models::PortRange { start, end }],
                    };
                    start = 0;
                    end = None;
                    result.push(range);
                }
            };
        }
    }
    Some(result)
}

fn ports_to_ospd_string(ports: Option<&[models::Port]>) -> Option<String> {
    fn range_to_string(r: &[models::PortRange]) -> String {
        r.iter().map(|x| x.to_string()).join(",")
    }
    let ports = ports?;
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    for x in ports {
        let rs = range_to_string(&x.range);
        if rs.is_empty() {
            continue;
        }

        match x.protocol {
            Some(models::Protocol::TCP) => tcp.push(rs),
            Some(models::Protocol::UDP) => udp.push(rs),
            None => {
                tcp.push(rs.clone());
                udp.push(rs);
            }
        }
    }
    match (tcp.is_empty(), udp.is_empty()) {
        (true, true) => None,
        (false, false) => Some(format!("T:{},U:{}", tcp.join(","), udp.join(","))),
        (true, false) => Some(format!("U:{}", udp.join(","))),
        (false, true) => Some(format!("T:{}", tcp.join(","))),
    }
}

fn ospd_string_to_bool(v: &str) -> bool {
    matches!(&v.to_lowercase() as &str, "1" | "true" | "yes")
}

fn bool_to_ospd_string(v: bool) -> &'static str {
    match v {
        true => "1",
        false => "0",
    }
}

impl Serialize for Target {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        fn ospd_bool<S>(
            map: &mut <S as Serializer>::SerializeMap,
            key: &str,
            value: Option<bool>,
        ) -> Result<(), S::Error>
        where
            S: Serializer,
        {
            match value {
                Some(x) => map.serialize_entry(key, bool_to_ospd_string(x)),
                None => {
                    tracing::trace!(key, "ignoring empty");
                    Ok(())
                }
            }
        }
        let mut map = serializer.serialize_map(Some(5))?;
        let hosts = self.hosts.join(",");
        map.serialize_entry("hosts", &hosts)?;
        map.serialize_entry(
            "ports",
            &ports_to_ospd_string(self.ports.as_ref().map(|x| x as &[_])),
        )?;
        if let Some(alp) = &self.alive_test_ports {
            map.serialize_entry("alive_test_ports", &ports_to_ospd_string(Some(alp as &[_])))?;
        }
        if let Some(atm) = &self.alive_test_methods {
            let fields: HashMap<&'static str, &'static str> = atm
                .iter()
                .map(|x| match x {
                    models::AliveTestMethods::TcpAck => ("icmp_ack", "1"),
                    models::AliveTestMethods::Icmp => ("icmp", "1"),
                    models::AliveTestMethods::Arp => ("arp", "1"),
                    models::AliveTestMethods::ConsiderAlive => ("consider_alive", "1"),
                    models::AliveTestMethods::TcpSyn => ("tcp_sync", "1"),
                })
                .collect();
            if !fields.is_empty() {
                map.serialize_entry("alive_test_methods", &fields)?;
            }
        }

        if let Some(v) = &self.exclude_hosts {
            let exclude_hosts = v.join(",");
            map.serialize_entry("exclude_hosts", &exclude_hosts)?;
        }
        if let Some(v) = &self.finished_hosts {
            let finished_hosts = v.join(",");
            map.serialize_entry("finished_hosts", &finished_hosts)?;
        }

        map.serialize_entry("credentials", &self.credentials)?;
        ospd_bool::<S>(&mut map, "reverse_lookup_only", self.reverse_lookup_only)?;
        ospd_bool::<S>(&mut map, "reverse_lookup_unify", self.reverse_lookup_unify)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CredentialVisitor;

        impl<'de> Visitor<'de> for CredentialVisitor {
            type Value = Target;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a target XML element")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                fn comma_sep_to_vec<'de, A>(mut map: A) -> Result<Vec<String>, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let hosts: String = map.next_value()?;
                    Ok(hosts
                        .split(',')
                        .filter(|x| !x.is_empty())
                        .map(|x| x.to_string())
                        .collect_vec())
                }

                fn ospd_bool<'de, A>(mut map: A) -> Result<bool, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let value: String = map.next_value()?;
                    Ok(ospd_string_to_bool(&value))
                }
                let mut result = Target::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "hosts" => result.hosts = comma_sep_to_vec(&mut map)?,
                        "ports" => {
                            result.ports = {
                                let ports: Option<String> = map.next_value().ok();
                                ports_from_ospd_string(ports.as_ref().map(|x| x as &str))
                            }
                        }

                        "alive_test_ports" => {
                            result.alive_test_ports = {
                                let ports: Option<String> = map.next_value().ok();
                                ports_from_ospd_string(ports.as_ref().map(|x| x as &str))
                            }
                        }
                        "alive_test" => {
                            if let Ok(at) = map.next_value::<String>() {
                                if let Ok(at) = at.parse::<u8>() {
                                    if let Ok(at) = models::AliveTestMethods::try_from(at) {
                                        result.alive_test_methods = Some(vec![at]);
                                        continue;
                                    }
                                }
                                return Err(de::Error::custom(format!("{at} is not a valid number. It must be a number of 1, 2, 4, 8 or 16.")));
                            }
                        }
                        "alive_test_methods" => {
                            if let Ok(at) = map.next_value::<HashMap<String, String>>() {
                                let alive_test_methods = at
                                    .iter()
                                    .filter_map(|(k, v)| {
                                        if ospd_string_to_bool(v) {
                                            match &k.to_lowercase() as &str {
                                                "icmp" => Some(models::AliveTestMethods::Icmp),
                                                "tcp_syn" => Some(models::AliveTestMethods::TcpSyn),
                                                "tcp_ack" => Some(models::AliveTestMethods::TcpAck),
                                                "arp" => Some(models::AliveTestMethods::Arp),
                                                "consider_alive" => {
                                                    Some(models::AliveTestMethods::ConsiderAlive)
                                                }
                                                _ => None,
                                            }
                                        } else {
                                            None
                                        }
                                    })
                                    .collect::<Vec<_>>();
                                if !alive_test_methods.is_empty() {
                                    result.alive_test_methods = Some(alive_test_methods);
                                }
                            }
                        }
                        "exclude_hosts" => result.exclude_hosts = comma_sep_to_vec(&mut map).ok(),
                        "finished_hosts" => result.finished_hosts = comma_sep_to_vec(&mut map).ok(),
                        "credentials" => result.credentials = map.next_value().ok(),
                        "reverse_lookup_only" => {
                            result.reverse_lookup_only = ospd_bool(&mut map).ok()
                        }
                        "reverse_lookup_unify" => {
                            result.reverse_lookup_unify = ospd_bool(&mut map).ok()
                        }
                        _ => {
                            tracing::warn!(key, "skipping unknown field")
                        }
                    }
                }
                Ok(result)
            }
        }

        deserializer.deserialize_map(CredentialVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
// TODO: replace kind, username and password with enum
pub struct Credentials {
    pub credential: Option<Vec<Credential>>,
}
#[derive(Default, Debug, Clone, PartialEq, Eq)]
// TODO: replace kind, username and password with enum
pub struct Credential {
    pub kind: String,
    pub service: String,
    pub port: Option<String>,
    /// Contains all fields
    ///
    /// ```xml
    ///<credential type="up" service="ssh" port="22">
    ///  <password>PASSWORD</password>
    ///  <username>USER</username>
    ///</credential>
    /// ```
    ///
    /// credentials will hold the fields:
    /// - username
    /// - password
    ///
    /// This is done so that we don't have to explicitly create fields for all
    /// credential types as there is an explicit verification later on when we
    /// transform it to models::Credential
    pub credentials: Vec<(String, String)>,
}

impl Serialize for Credential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(3 + self.credentials.len()))?;
        map.serialize_entry("@type", &self.kind)?;
        map.serialize_entry("@service", &self.service)?;
        map.serialize_entry("@port", &self.port)?;
        for (key, value) in &self.credentials {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

// Custom Deserialize Implementation
impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CredentialVisitor;

        impl<'de> Visitor<'de> for CredentialVisitor {
            type Value = Credential;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a credential XML element")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut result = Credential::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "@type" => result.kind = map.next_value()?,
                        "@service" => result.service = map.next_value()?,
                        "@port" => result.port = map.next_value().ok(),
                        key => {
                            if let Some(value) = map.next_value()? {
                                result.credentials.push((key.to_string(), value));
                            }
                        }
                    }
                }
                Ok(result)
            }
        }
        deserializer.deserialize_map(CredentialVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VtSelection {
    pub vt_group: Option<Vec<VtGroup>>,
    pub vt_single: Option<Vec<VtSingle>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VtGroup {
    #[serde(rename = "@filter")]
    pub filter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VtSingle {
    #[serde(rename = "@id")]
    pub id: String,
    pub vt_value: Option<Vec<VtValue>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VtValue {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "$text")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerParameter {
    pub values: Vec<models::ScanPreference>,
}

impl Serialize for ScannerParameter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for x in &self.values {
            map.serialize_entry(&x.id, &x.value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ScannerParameter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct SPVisitor;

        impl<'de> Visitor<'de> for SPVisitor {
            type Value = ScannerParameter;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a credential XML element")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Vec::new();

                while let Some(key) = map.next_key::<String>()? {
                    let value: String = map.next_value()?;
                    values.push(models::ScanPreference {
                        id: key.to_string(),
                        value,
                    });
                }

                Ok(ScannerParameter { values })
            }
        }

        deserializer.deserialize_map(SPVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename = "start_scan")]
pub struct StartScan {
    #[serde(rename = "@parallel")]
    pub parallel: Option<String>,
    #[serde(rename = "@scan_id")]
    pub id: Option<String>,
    pub targets: Targets,
    pub vt_selection: VtSelection,
    pub scanner_params: ScannerParameter,
}
impl Display for StartScan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ser = quick_xml::se::Serializer::new(f);
        ser.indent(' ', 2);
        self.serialize(ser)
            .map_err(|x| {
                tracing::warn!(error=?x, "unable to serialize StartScan");
                fmt::Error
            })
            .map(|_| ())
    }
}

impl From<models::Credential> for Credential {
    fn from(value: models::Credential) -> Self {
        let service = value.service.as_ref().to_string();
        let port = value.port.map(|x| x.to_string());
        let kind = value.credential_type.as_ref().to_string();
        let mut credentials = Vec::new();
        match value.credential_type {
            models::CredentialType::KRB5 {
                username,
                password,
                realm,
                kdc,
            } => {
                credentials.push(("username".to_string(), username));
                credentials.push(("password".to_string(), password));
                credentials.push(("realm".to_string(), realm));
                credentials.push(("kdc".to_string(), kdc));
            }
            models::CredentialType::UP {
                username,
                password,
                privilege,
            } => {
                credentials.push(("username".to_string(), username));
                credentials.push(("password".to_string(), password));
                if let Some(p) = privilege {
                    credentials.push(("priv_username".to_string(), p.username));
                    credentials.push(("priv_password".to_string(), p.password));
                }
            }
            models::CredentialType::USK {
                username,
                password,
                private_key,
                privilege,
            } => {
                credentials.push(("username".to_string(), username));
                credentials.push(("password".to_string(), password.unwrap_or_default()));
                credentials.push(("private".to_string(), private_key));
                if let Some(p) = privilege {
                    credentials.push(("priv_username".to_string(), p.username));
                    credentials.push(("priv_password".to_string(), p.password));
                }
            }
            models::CredentialType::SNMP {
                username,
                password,
                community,
                auth_algorithm,
                privacy_password,
                privacy_algorithm,
            } => {
                credentials.push(("username".to_string(), username));
                credentials.push(("password".to_string(), password));
                credentials.push(("community".to_string(), community));
                credentials.push(("auth_algorithm".to_string(), auth_algorithm));
                credentials.push(("privacy_passwor".to_string(), privacy_password));
                credentials.push(("privacy_algorithm".to_string(), privacy_algorithm));
            }
        };
        Credential {
            kind,
            service,
            port,
            credentials,
        }
    }
}

impl From<Vec<models::Credential>> for Credentials {
    fn from(value: Vec<models::Credential>) -> Self {
        Credentials {
            credential: Some(value.into_iter().map(|x| x.into()).collect()),
        }
    }
}

impl From<models::Target> for Target {
    fn from(value: models::Target) -> Self {
        Target {
            hosts: value.hosts,
            ports: Some(value.ports),
            alive_test_ports: Some(value.alive_test_ports),
            alive_test_methods: Some(value.alive_test_methods),
            exclude_hosts: Some(value.excluded_hosts),
            finished_hosts: None,
            reverse_lookup_unify: value.reverse_lookup_unify,
            reverse_lookup_only: value.reverse_lookup_only,
            credentials: Some(value.credentials.into()),
        }
    }
}

impl From<models::Target> for Targets {
    fn from(value: models::Target) -> Self {
        Targets {
            target: value.into(),
        }
    }
}

impl From<Vec<models::VT>> for VtSelection {
    fn from(value: Vec<models::VT>) -> Self {
        let sv = value
            .into_iter()
            .map(|x| {
                let vt_value = {
                    let v = x
                        .parameters
                        .into_iter()
                        .map(|x| VtValue {
                            id: x.id.to_string(),
                            text: Some(x.value),
                        })
                        .collect::<Vec<_>>();
                    if v.is_empty() {
                        None
                    } else {
                        Some(v)
                    }
                };
                VtSingle {
                    id: x.oid,
                    vt_value,
                }
            })
            .collect();
        VtSelection {
            vt_group: None,
            vt_single: Some(sv),
        }
    }
}

impl From<Vec<models::ScanPreference>> for ScannerParameter {
    fn from(value: Vec<models::ScanPreference>) -> Self {
        ScannerParameter { values: value }
    }
}

impl From<models::Scan> for StartScan {
    fn from(value: models::Scan) -> Self {
        StartScan {
            parallel: None,
            id: Some(value.scan_id),
            targets: value.target.into(),
            vt_selection: value.vts.into(),
            scanner_params: value.scan_preferences.into(),
        }
    }
}

#[cfg(test)]
mod test {
    use quick_xml::de::from_str;

    use super::StartScan;

    #[test]
    fn pare_credential_without_port() {
        let input = r#"
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<start_scan scan_id="36389b56-f5a0-11e9-bba4-482ae354ac4c">
    <targets>
        <target>
            <hosts>127.0.0.1</hosts>
            <ports>T:80-80,443-443</ports>
            <alive_test>2</alive_test>
            <credentials>
                <credential type="up" service="ssh">
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
        let sc: StartScan = from_str(input).unwrap();
        insta::assert_snapshot!(sc);
    }

    #[test]
    fn parse_xml_with_empty_credentials() {
        let input = r#"
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<start_scan parallel="20" scan_id="36389b56-f5a0-11e9-bba4-482ae354ac4c">
    <targets>
        <target>
            <hosts>127.0.0.1</hosts>
            <ports>T:80-80,443-443</ports>
            <alive_test>2</alive_test>
            <credentials/>
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
        let sc: StartScan = from_str(input).unwrap();
        insta::assert_snapshot!(sc);
    }

    #[test]
    fn parse_without_credential() {
        let input = r#"
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<start_scan parallel="20" scan_id="36389b56-f5a0-11e9-bba4-482ae354ac4c">
    <targets>
        <target>
            <hosts>127.0.0.1</hosts>
            <ports>T:80-80,443-443</ports>
            <alive_test>2</alive_test>
            <exclude_hosts>localhost</exclude_hosts>
            <finished_hosts>localhost</finished_hosts>
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
        let sc: StartScan = from_str(input).unwrap();
        insta::assert_snapshot!(sc);
    }

    #[test]
    fn parse_xml() {
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
        let sc: StartScan = from_str(input).unwrap();
        insta::assert_snapshot!(sc);
    }
}

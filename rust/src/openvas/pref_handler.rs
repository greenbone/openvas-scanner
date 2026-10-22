// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use crate::models::{
    AliveTestMethods, CredentialType, Scan, Service, VT, ports_to_openvas_port_list,
};
use crate::scanner::preferences::preference::ScanPrefValue;
use crate::storage::redis::RedisStorageResult;

use super::cmd;
use super::openvas_redis::{KbAccess, VtHelper};

const OID_SSH_AUTH: &str = "1.3.6.1.4.1.25623.1.0.103591";
const OID_KRB5_AUTH: &str = "1.3.6.1.4.1.25623.1.0.102114";
const OID_SMB_AUTH: &str = "1.3.6.1.4.1.25623.1.0.90023";
const OID_ESXI_AUTH: &str = "1.3.6.1.4.1.25623.1.0.105058";
const OID_SNMP_AUTH: &str = "1.3.6.1.4.1.25623.1.0.105076";
const OID_PING_HOST: &str = "1.3.6.1.4.1.25623.1.0.100315";

const BOREAS_ALIVE_TEST: &str = "ALIVE_TEST";
const BOREAS_ALIVE_TEST_PORTS: &str = "ALIVE_TEST_PORTS";
const ALIVE_TEST_SCAN_CONFIG_DEFAULT: u8 = 0x00;

fn normalize_bool_str(value: &str) -> Option<String> {
    let value = value.to_lowercase();
    if value == "0" || value == "false" || value == "no" {
        return Some("no".to_string());
    }
    if value == "1" || value == "true" || value == "yes" {
        return Some("yes".to_string());
    }
    None
}

#[derive(Debug)]
pub struct PreferenceHandler<'a, H> {
    scan_config: Scan,
    redis_connector: &'a mut H,
    nvt_params: HashMap<String, String>,
    scan_params_defaults: HashMap<String, ScanPrefValue>,
}

impl<'a, H> PreferenceHandler<'a, H>
where
    H: VtHelper + KbAccess,
{
    pub fn new(
        scan_config: Scan,
        redis_connector: &'a mut H,
        scan_params_defaults: HashMap<String, ScanPrefValue>,
    ) -> Self {
        Self {
            scan_config,
            redis_connector,
            nvt_params: HashMap::new(),
            scan_params_defaults,
        }
    }

    pub async fn prepare_preferences_for_openvas(&mut self) -> RedisStorageResult<()> {
        self.prepare_scan_id_for_openvas()?;
        self.prepare_target_for_openvas()?;
        self.prepare_ports_for_openvas()?;
        self.prepare_credentials_for_openvas()?;
        self.prepare_plugins_for_openvas()?;
        self.prepare_main_kbindex_for_openvas()?;
        self.prepare_host_options_for_openvas()?;
        self.prepare_scan_params_for_openvas()?;
        self.prepare_reverse_lookup_opt_for_openvas()?;
        self.prepare_alive_test_option_for_openvas()?;

        // VT preferences are stored after all preferences have been processed,
        // since alive tests preferences have to be able to overwrite default
        // preferences of ping_host.nasl for the classic method.
        self.prepare_nvt_preferences()?;
        self.prepare_boreas_alive_test().await
    }

    fn prepare_main_kbindex_for_openvas(&mut self) -> RedisStorageResult<()> {
        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            format!("ov_maindbid|||{}", self.redis_connector.kb_id()?),
        )?;
        Ok(())
    }

    fn prepare_scan_id_for_openvas(&mut self) -> RedisStorageResult<()> {
        self.redis_connector.push_kb_item(
            format!("internal/{}", self.scan_config.scan_id.clone()).as_str(),
            "new",
        )?;
        self.redis_connector
            .push_kb_item("internal/scanid", self.scan_config.scan_id.clone())?;

        Ok(())
    }

    fn process_vts(&self, vts: &Vec<VT>) -> (Vec<String>, HashMap<String, String>) {
        let mut vts_list: Vec<String> = vec![];
        let mut pref_list: HashMap<String, String> = HashMap::new();

        for vt in vts {
            let nvt_opt = match self.redis_connector.get_nasl_vt(&vt.oid) {
                Ok(nvt) => nvt,
                Err(e) => {
                    tracing::warn!(
                        oid = %vt.oid,
                        error = %e,
                        "failed to load VT from redis; skipping (likely non-UTF8 byte in NVT cache)"
                    );
                    continue;
                }
            };
            if let Some(nvt) = nvt_opt {
                // add oid to the target list
                vts_list.push(vt.oid.clone());

                // prepare vt preferences
                for pref in &vt.parameters {
                    if let Some((prefid, class, name, _)) = nvt.preferences.iter().find_map(|p| {
                        if let Some(i) = p.id {
                            if i as u16 == pref.id {
                                Some(p.into())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }) {
                        let value_aux: String = if class == *"checkbox" {
                            match normalize_bool_str(&pref.value) {
                                Some(value) => value,
                                None => {
                                    tracing::warn!(
                                        oid = vt.oid,
                                        pref = pref.id,
                                        value = pref.value,
                                        "invalid boolean value for checkbox preference, skipping"
                                    );
                                    continue;
                                }
                            }
                        } else {
                            pref.value.to_string()
                        };

                        pref_list.insert(
                            format!("{}:{}:{}:{}", vt.oid, prefid, class, name),
                            value_aux,
                        );
                    } else {
                        tracing::debug!(oid = vt.oid, pref = pref.id, "set preference not found");
                    }
                }
            } else {
                tracing::debug!(oid = vt.oid, "not found or handled via notus");
                continue;
            }
        }
        (vts_list, pref_list)
    }

    fn prepare_plugins_for_openvas(&mut self) -> RedisStorageResult<()> {
        let nvts = &self.scan_config.vts;
        if nvts.is_empty() {
            return Ok(());
        }

        let (nvts, prefs) = self.process_vts(nvts);
        // update list of preferences
        self.nvt_params.extend(prefs);

        // prepare vts
        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            format!("plugin_set|||{}", nvts.join(";")),
        )
    }

    fn prepare_nvt_preferences(&mut self) -> RedisStorageResult<()> {
        let mut items: Vec<String> = vec![];
        for (k, v) in self.nvt_params.iter() {
            items.push(format!("{k}|||{v}"))
        }

        if items.is_empty() {
            return Ok(());
        }

        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            items,
        )
    }

    fn prepare_alive_test_option_for_openvas(&mut self) -> RedisStorageResult<()> {
        let mut prefs: HashMap<String, String> = HashMap::new();
        let mut alive_test = ALIVE_TEST_SCAN_CONFIG_DEFAULT;
        let mut value: &str = "no";

        let methods = self.scan_config.target.alive_test_methods.clone();
        for m in methods {
            alive_test |= m as u8;
        }

        //Preference 1
        if (alive_test & AliveTestMethods::TcpAck as u8) != 0
            || (alive_test & AliveTestMethods::TcpSyn as u8) != 0
        {
            value = "yes"
        }
        prefs.insert(
            format!("{OID_PING_HOST}:1:checkbox:Do a TCP ping"),
            value.to_string(),
        );

        //Preference 2
        value = "no";
        if (alive_test & AliveTestMethods::TcpAck as u8) != 0
            && (alive_test & AliveTestMethods::TcpSyn as u8) != 0
        {
            value = "yes"
        }
        prefs.insert(
            format!("{OID_PING_HOST}:2:checkbox:TCP ping tries also TCP-SYN ping"),
            value.to_string(),
        );

        //Preference 7
        value = "no";
        if (alive_test & AliveTestMethods::TcpSyn as u8) != 0
            && (alive_test & AliveTestMethods::TcpAck as u8) == 0
        {
            value = "yes"
        }
        prefs.insert(
            format!("{OID_PING_HOST}:7:checkbox:TCP ping tries only TCP-SYN ping"),
            value.to_string(),
        );

        //Preference 3
        value = "no";
        if (alive_test & AliveTestMethods::Icmp as u8) != 0 {
            value = "yes"
        }
        prefs.insert(
            format!("{OID_PING_HOST}:3:checkbox:Do an ICMP ping"),
            value.to_string(),
        );

        //Preference 4
        value = "no";
        if (alive_test & AliveTestMethods::Arp as u8) != 0 {
            value = "yes"
        }
        prefs.insert(
            format!("{OID_PING_HOST}:4:checkbox:Use ARP"),
            value.to_string(),
        );

        //Preference 5. This preference is confusing. Since the method name and the preference name have different logics
        value = "yes"; // consider hosts as dead
        if (alive_test & AliveTestMethods::ConsiderAlive as u8) != 0 {
            value = "no" // NO, means that hosts are not considered as dead.
        }

        prefs.insert(
            format!("{OID_PING_HOST}:5:checkbox:Mark unreachable Hosts as dead (not scanning)"),
            value.to_string(),
        );

        // It will replace the defaults with the values sent by the client
        self.nvt_params.extend(prefs);
        Ok(())
    }

    async fn prepare_boreas_alive_test(&mut self) -> RedisStorageResult<()> {
        // Check "test_alive_hosts_only" configuration from openvas.conf
        // If set no, boreas is disabled and alive_host.nasl is used instead.
        if let Ok(config) = cmd::read_openvas_config().await
            && let Some(setting) = config.get("default", "test_alive_hosts_only")
            && setting == "no"
        {
            return Ok(());
        }

        let methods = self.scan_config.target.alive_test_methods.clone();

        let mut alive_test = ALIVE_TEST_SCAN_CONFIG_DEFAULT;
        for m in methods {
            alive_test |= m as u8;
        }

        if (1..=32).contains(&alive_test) {
            self.redis_connector.push_kb_item(
                format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
                format!("{BOREAS_ALIVE_TEST}|||{alive_test}"),
            )?;
        };

        if alive_test == ALIVE_TEST_SCAN_CONFIG_DEFAULT {
            self.redis_connector.push_kb_item(
                format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
                format!("{BOREAS_ALIVE_TEST}|||{}", AliveTestMethods::Icmp as u8),
            )?;
        }

        let alive_test_ports = self.scan_config.target.alive_test_ports.clone();
        if let Some(ports) = ports_to_openvas_port_list(alive_test_ports) {
            self.redis_connector.push_kb_item(
                format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
                format!("{BOREAS_ALIVE_TEST_PORTS}|||{ports}"),
            )?;
        };

        Ok(())
    }

    fn prepare_reverse_lookup_opt_for_openvas(&mut self) -> RedisStorageResult<()> {
        let mut lookup_opts: Vec<String> = vec![];

        if self
            .scan_config
            .target
            .reverse_lookup_only
            .is_some_and(|x| x)
        {
            lookup_opts.push("reverse_lookup_only|||yes".to_string());
        } else {
            lookup_opts.push("reverse_lookup_only|||no".to_string());
        }

        if self
            .scan_config
            .target
            .reverse_lookup_unify
            .is_some_and(|x| x)
        {
            lookup_opts.push("reverse_lookup_unify|||yes".to_string());
        } else {
            lookup_opts.push("reverse_lookup_unify|||no".to_string());
        }
        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            lookup_opts,
        )
    }

    fn prepare_target_for_openvas(&mut self) -> RedisStorageResult<()> {
        let target = self.scan_config.target.hosts.join(",");
        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            format!("TARGET|||{target}"),
        )
    }

    fn prepare_ports_for_openvas(&mut self) -> RedisStorageResult<()> {
        let ports = self.scan_config.target.ports.clone();
        if let Some(ports) = ports_to_openvas_port_list(ports) {
            self.redis_connector.push_kb_item(
                format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
                format!("port_range|||{ports}"),
            )?;
        };

        Ok(())
    }

    fn prepare_host_options_for_openvas(&mut self) -> RedisStorageResult<()> {
        let excluded_hosts = self.scan_config.target.excluded_hosts.join(",");
        if excluded_hosts.is_empty() {
            return Ok(());
        }

        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            format!("exclude_hosts|||{excluded_hosts}"),
        )
    }

    fn prepare_scan_params_for_openvas(&mut self) -> RedisStorageResult<()> {
        let mut options = Vec::with_capacity(self.scan_params_defaults.len());
        for (id, default) in &self.scan_params_defaults {
            let set_by_client = self
                .scan_config
                .scan_preferences
                .iter()
                .find(|p| &p.id == id);

            let value = match set_by_client {
                // Booleans have to reach openvas as yes or no.
                Some(pref) if matches!(default, ScanPrefValue::Bool(_)) => {
                    normalize_bool_str(&pref.value).unwrap_or_else(|| {
                        tracing::warn!(
                            pref = id,
                            value = pref.value,
                            "invalid boolean value, falling back to the default"
                        );
                        default.to_string()
                    })
                }
                Some(pref) => pref.value.clone(),
                None => default.to_string(),
            };

            options.push(format!("{id}|||{value}"));
        }

        if options.is_empty() {
            return Ok(());
        }

        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            options,
        )
    }

    fn prepare_credentials_for_openvas(&mut self) -> RedisStorageResult<()> {
        let credentials = self.scan_config.target.credentials.clone();

        let mut credential_preferences: Vec<String> = vec![];
        for credential in credentials {
            // TODO: refactor that
            match credential.service {
                Service::KRB5 => {
                    if let Some(port) = credential.port {
                        credential_preferences.push(format!("auth_port_krb5|||{port}"));
                    } else {
                        credential_preferences.push("auth_port_krb5|||445".to_string());
                    };
                    if let CredentialType::KRB5 {
                        username,
                        password,
                        realm,
                        kdc,
                    } = credential.credential_type
                    {
                        credential_preferences
                            .push(format!("{OID_KRB5_AUTH}:1:entry::|||{username}"));
                        credential_preferences
                            .push(format!("{OID_KRB5_AUTH}:2:password::|||{password}"));
                        credential_preferences.push(format!("{OID_KRB5_AUTH}:3:entry::|||{realm}"));
                        credential_preferences.push(format!("{OID_KRB5_AUTH}:4:entry::|||{kdc}"));
                    }
                }
                Service::SSH => {
                    if let Some(port) = credential.port {
                        credential_preferences.push(format!("auth_port_ssh|||{port}"));
                    } else {
                        credential_preferences.push("auth_port_ssh|||22".to_string());
                    };

                    if let CredentialType::UP {
                        username,
                        password,
                        privilege,
                    } = credential.credential_type.clone()
                    {
                        credential_preferences.push(format!(
                            "{OID_SSH_AUTH}:3:password:SSH password (unsafe!):|||{password}"
                        ));
                        credential_preferences.push(format!(
                            "{OID_SSH_AUTH}:1:entry:SSH login name:|||{username}"
                        ));
                        if let Some(p) = privilege {
                            credential_preferences.push(format!(
                                "{OID_SSH_AUTH}:7:entry:SSH privilege login name:|||{}",
                                p.username
                            ));
                            credential_preferences.push(format!(
                                "{OID_SSH_AUTH}:8:password:SSH privilege password:|||{}",
                                p.password
                            ));
                        }
                    };
                    if let CredentialType::USK {
                        username,
                        password,
                        private_key,
                        privilege,
                    } = credential.credential_type
                    {
                        credential_preferences.push(format!(
                            "{OID_SSH_AUTH}:1:entry:SSH login name:|||{username}"
                        ));
                        credential_preferences.push(format!(
                            "{OID_SSH_AUTH}:2:password:SSH key passphrase:|||{}",
                            password.unwrap_or_default()
                        ));
                        credential_preferences.push(format!(
                            "{OID_SSH_AUTH}:4:file:SSH private key:|||{private_key}"
                        ));
                        if let Some(p) = privilege {
                            credential_preferences.push(format!(
                                "{OID_SSH_AUTH}:7:entry:SSH privilege login name:|||{}",
                                p.username
                            ));
                            credential_preferences.push(format!(
                                "{OID_SSH_AUTH}:8:password:SSH privilege password:|||{}",
                                p.password
                            ));
                        }
                    };
                }
                Service::SMB => {
                    if let CredentialType::UP {
                        username, password, ..
                    } = credential.credential_type.clone()
                    {
                        credential_preferences
                            .push(format!("{OID_SMB_AUTH}:1:entry:SMB login:|||{username}"));
                        credential_preferences.push(format!(
                            "{OID_SMB_AUTH}:2:password:SMB password:|||{password}"
                        ));
                    };
                }
                Service::ESXi => {
                    if let CredentialType::UP {
                        username, password, ..
                    } = credential.credential_type.clone()
                    {
                        credential_preferences.push(format!(
                            "{OID_ESXI_AUTH}:1:entry:ESXi login name:|||{username}"
                        ));
                        credential_preferences.push(format!(
                            "{OID_ESXI_AUTH}:2:password:ESXi login password:|||{password}"
                        ));
                    };
                }
                Service::SNMP => {
                    if let CredentialType::SNMP {
                        username,
                        password,
                        community,
                        auth_algorithm,
                        privacy_password,
                        privacy_algorithm,
                    } = credential.credential_type
                    {
                        // if there is a privacy password, a valid privacy algorithm must be provided.
                        if privacy_algorithm.is_empty()
                            && (!privacy_password.is_empty()
                                || (privacy_algorithm != "aes" && privacy_algorithm != "des"))
                        {
                            continue;
                        };

                        if auth_algorithm.is_empty()
                            || (auth_algorithm != "md5" && auth_algorithm != "sha1")
                        {
                            continue;
                        };

                        credential_preferences.push(format!(
                            "{OID_SNMP_AUTH}:1:password:SNMP Community:|||{community}"
                        ));
                        credential_preferences.push(format!(
                            "{OID_SNMP_AUTH}:2:entry:SNMPv3 Username:|||{username}"
                        ));
                        credential_preferences.push(format!(
                            "{OID_SNMP_AUTH}:3:password:SNMPv3 Password:|||{password}"
                        ));
                        credential_preferences.push(format!(
                                        "{OID_SNMP_AUTH}:4:radio:SNMPv3 Authentication Algorithm:|||{auth_algorithm}"
                                    ));
                        credential_preferences.push(format!(
                                        "{OID_SNMP_AUTH}:5:password:SNMPv3 Privacy Password:|||{privacy_password}"
                                    ));
                        credential_preferences.push(format!(
                                        "{OID_SNMP_AUTH}:6:radio:SNMPv3 Privacy Algorithm:|||{privacy_algorithm}"
                                    ));
                    }
                }

                // TODO: maybe treat as ssh?
                Service::Generic => unreachable!(
                    "OpenVAS is not aware about service::generic it was introduced for image-scanner"
                ),
            }
        }

        if !credential_preferences.is_empty() {
            self.redis_connector.push_kb_item(
                format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
                credential_preferences,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        models::{
            self, AliveTestMethods, Credential, CredentialType, Port, PortRange, Protocol, Scan,
            Service,
        },
        scanner::preferences::preference::PREFERENCES,
    };

    use super::{PreferenceHandler, ScanPrefValue, normalize_bool_str};
    use crate::openvas::openvas_redis::{KbAccess, test::FakeRedis};

    fn scan_config() -> Scan {
        Scan {
            scan_id: "123-456".to_string(),
            ..Default::default()
        }
    }

    fn fake_redis() -> FakeRedis {
        FakeRedis {
            data: HashMap::new(),
        }
    }

    fn handler(scan: Scan, redis: &mut FakeRedis) -> PreferenceHandler<'_, FakeRedis> {
        let defaults = PREFERENCES
            .iter()
            .map(|p| (p.id.to_string(), p.default.clone().into()))
            .collect();
        PreferenceHandler::new(scan, redis, defaults)
    }

    #[test]
    fn test_bool_to_str() {
        for value in ["1", "true", "True", "TRUE", "yes", "Yes", "YES"] {
            assert_eq!(normalize_bool_str(value).as_deref(), Some("yes"), "{value}");
        }
        for value in ["0", "false", "False", "FALSE", "no", "No", "NO"] {
            assert_eq!(normalize_bool_str(value).as_deref(), Some("no"), "{value}");
        }
        for value in ["", " ", " yes ", "2", "-1", "on", "off", "nein", "truthy"] {
            assert_eq!(normalize_bool_str(value), None, "{value}");
        }
    }

    #[test]
    fn test_scan_params_bool_values() {
        let mut scan = scan_config();
        scan.scan_preferences = vec![
            models::ScanPreference {
                id: "optimize_test".to_string(),
                value: "False".to_string(),
            },
            models::ScanPreference {
                id: "test_empty_vhost".to_string(),
                value: "1".to_string(),
            },
            models::ScanPreference {
                id: "safe_checks".to_string(),
                value: "maybe".to_string(),
            },
        ];

        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);
        assert!(prefh.prepare_scan_params_for_openvas().is_ok());

        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "optimize_test|||no")
        );
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "test_empty_vhost|||yes")
        );
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "safe_checks|||yes")
        );
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "dry_run|||no")
        );
    }

    fn prepare_vt_params(checkbox_value: &str) -> FakeRedis {
        let mut scan = scan_config();
        scan.vts = vec![models::VT {
            oid: "123".to_string(),
            parameters: vec![
                models::Parameter {
                    id: 1,
                    value: checkbox_value.to_string(),
                },
                models::Parameter {
                    id: 2,
                    value: "abc".to_string(),
                },
            ],
        }];

        let mut rc = fake_redis();
        {
            let mut prefh = handler(scan, &mut rc);
            assert!(prefh.prepare_plugins_for_openvas().is_ok());
            assert!(prefh.prepare_nvt_preferences().is_ok());
        }
        rc
    }

    #[test]
    fn test_vt_checkbox_bool_values() {
        for (value, expected) in [("TRUE", "yes"), ("0", "no")] {
            let rc = prepare_vt_params(value);
            assert!(
                rc.item_exists(
                    "internal/123-456/scanprefs",
                    &format!("123:1:checkbox:test1|||{expected}")
                ),
                "{value}"
            );
            assert!(rc.item_exists("internal/123-456/scanprefs", "123:2:entry:test2|||abc"));
        }

        // An unparsable checkbox value is dropped instead of being coerced
        let rc = prepare_vt_params("nope");
        assert!(!rc.item_exists("internal/123-456/scanprefs", "123:1:checkbox:test1|||yes"));
        assert!(!rc.item_exists("internal/123-456/scanprefs", "123:1:checkbox:test1|||no"));
        // Non-checkbox parameters are unaffected
        assert!(rc.item_exists("internal/123-456/scanprefs", "123:2:entry:test2|||abc"));
    }

    #[test]
    fn test_scan_id() {
        let mut rc = fake_redis();
        let mut prefh = handler(scan_config(), &mut rc);

        assert!(prefh.prepare_scan_id_for_openvas().is_ok());
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/scanid", "123-456")
        );
        assert!(prefh.redis_connector.item_exists("internal/123-456", "new"));
    }
    #[test]
    fn test_target() {
        let mut scan = scan_config();
        scan.target.hosts = vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()];
        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);

        assert!(prefh.prepare_target_for_openvas().is_ok());
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "TARGET|||127.0.0.1,10.0.0.1")
        );
    }

    #[test]
    fn test_ports() {
        let mut scan = scan_config();
        scan.target.ports = vec![Port {
            protocol: Some(Protocol::TCP),
            range: vec![
                PortRange {
                    start: 22,
                    end: Some(25),
                },
                PortRange {
                    start: 80,
                    end: None,
                },
            ],
        }];
        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);

        assert!(prefh.prepare_ports_for_openvas().is_ok());
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "port_range|||T:22-25,80")
        );
    }

    #[test]
    fn test_credentials() {
        let mut scan = scan_config();
        scan.target.credentials = vec![
            Credential {
                service: Service::SSH,
                port: Some(22),
                credential_type: CredentialType::UP {
                    username: "user".to_string(),
                    password: "pass".to_string(),
                    privilege: None,
                },
            },
            Credential {
                service: Service::KRB5,
                port: None,
                credential_type: CredentialType::KRB5 {
                    username: "user".to_string(),
                    password: "pass".to_string(),
                    realm: "realm".to_string(),
                    kdc: "kdc".to_string(),
                },
            },
        ];
        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);

        assert!(prefh.prepare_credentials_for_openvas().is_ok());
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login name:|||user"
        ));

        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.102114:1:entry::|||user"
        ));
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.102114:2:password::|||pass"
        ));
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.102114:3:entry::|||realm"
        ));
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.102114:4:entry::|||kdc"
        ));
    }

    #[test]
    fn test_plugins() {
        let mut scan = scan_config();
        scan.vts = vec![models::VT {
            oid: "123".to_string(),
            parameters: vec![],
        }];
        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);

        assert!(prefh.prepare_plugins_for_openvas().is_ok());
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "plugin_set|||123")
        );
    }

    #[test]
    fn test_main_kbindex() {
        let mut rc = fake_redis();
        let mut prefh = handler(scan_config(), &mut rc);
        assert_eq!(prefh.redis_connector.kb_id().unwrap(), 3);

        assert!(prefh.prepare_main_kbindex_for_openvas().is_ok());
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "ov_maindbid|||3")
        );
    }

    #[test]
    fn test_host_options() {
        let mut scan = scan_config();
        scan.target.excluded_hosts = vec!["127.0.0.1".to_string()];
        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);

        assert!(prefh.prepare_host_options_for_openvas().is_ok());
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "exclude_hosts|||127.0.0.1")
        );
    }

    #[test]
    fn test_scan_params() {
        let mut scan = scan_config();
        scan.scan_preferences = vec![
            models::ScanPreference {
                id: "auto_enable_dependencies".to_string(),
                value: "0".to_string(),
            },
            models::ScanPreference {
                id: "cgi_path".to_string(),
                value: "abc".to_string(),
            },
            models::ScanPreference {
                id: "checks_read_timeout".to_string(),
                value: "10".to_string(),
            },
        ];
        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);

        assert!(prefh.prepare_scan_params_for_openvas().is_ok());
        // Check overwrite bool
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "auto_enable_dependencies|||no"
        ));
        // Check overwrite string
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "cgi_path|||abc")
        );
        // Check overwrite int
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "checks_read_timeout|||10")
        );
        // Check default bool
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "unscanned_closed|||yes")
        );
        // Check default string
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "non_simult_ports|||139, 445, 3389, Services/irc"
        ));
        // Check default int
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "scanner_plugins_timeout|||36000"
        ));
    }

    #[test]
    fn test_configured_defaults() {
        let defaults = HashMap::from([
            ("safe_checks".to_string(), ScanPrefValue::Bool(false)),
            (
                "cgi_path".to_string(),
                ScanPrefValue::String("/custom".to_string()),
            ),
            ("plugins_timeout".to_string(), ScanPrefValue::Int(42)),
        ]);
        let mut rc = fake_redis();
        let mut prefh = PreferenceHandler::new(scan_config(), &mut rc, defaults);

        assert!(prefh.prepare_scan_params_for_openvas().is_ok());
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "safe_checks|||no")
        );
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "cgi_path|||/custom")
        );
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "plugins_timeout|||42")
        );
    }

    #[test]
    fn test_reverse_lookup_options() {
        let mut rc = fake_redis();
        let mut prefh = handler(scan_config(), &mut rc);

        assert!(prefh.prepare_reverse_lookup_opt_for_openvas().is_ok());
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "reverse_lookup_only|||no")
        );
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "reverse_lookup_unify|||no")
        );
    }

    #[test]
    fn test_alive_test_options() {
        let mut scan = scan_config();
        scan.target.alive_test_methods = vec![AliveTestMethods::Icmp, AliveTestMethods::TcpSyn];
        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);

        // The options only end up in the KB once the VT preferences are stored
        assert!(prefh.prepare_alive_test_option_for_openvas().is_ok());
        assert!(prefh.prepare_nvt_preferences().is_ok());
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.100315:1:checkbox:Do a TCP ping|||yes"
        ));
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.100315:2:checkbox:TCP ping tries also TCP-SYN ping|||no"
        ));
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.100315:7:checkbox:TCP ping tries only TCP-SYN ping|||yes"
        ));
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.100315:3:checkbox:Do an ICMP ping|||yes"
        ));
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.100315:4:checkbox:Use ARP|||no"
        ));
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.100315:5:checkbox:Mark unreachable Hosts as dead (not scanning)|||yes"
        ));
    }

    #[test]
    fn test_alive_test_options_tcp_syn_and_ack() {
        let mut scan = scan_config();
        scan.target.alive_test_methods = vec![AliveTestMethods::TcpSyn, AliveTestMethods::TcpAck];
        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);

        assert!(prefh.prepare_alive_test_option_for_openvas().is_ok());
        assert!(prefh.prepare_nvt_preferences().is_ok());

        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.100315:2:checkbox:TCP ping tries also TCP-SYN ping|||yes"
        ));
        // Requesting TCP-ACK as well means the test is not TCP-SYN only
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.100315:7:checkbox:TCP ping tries only TCP-SYN ping|||no"
        ));
    }

    #[tokio::test]
    async fn test_boreas_alive_test() {
        let mut scan = scan_config();
        scan.target.alive_test_methods = vec![AliveTestMethods::Icmp, AliveTestMethods::TcpSyn];
        let mut rc = fake_redis();
        let mut prefh = handler(scan, &mut rc);

        assert!(prefh.prepare_boreas_alive_test().await.is_ok());
        assert!(
            prefh
                .redis_connector
                .item_exists("internal/123-456/scanprefs", "ALIVE_TEST|||18")
        );
    }
}

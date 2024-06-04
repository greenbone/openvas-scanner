// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use models::{ports_to_openvas_port_list, AliveTestMethods, CredentialType, Scan, Service, VT};
use redis_storage::dberror::RedisStorageResult;

use super::cmd;
use super::openvas_redis::{KbAccess, VtHelper};

const OID_SSH_AUTH: &str = "1.3.6.1.4.1.25623.1.0.103591";
const OID_SMB_AUTH: &str = "1.3.6.1.4.1.25623.1.0.90023";
const OID_ESXI_AUTH: &str = "1.3.6.1.4.1.25623.1.0.105058";
const OID_SNMP_AUTH: &str = "1.3.6.1.4.1.25623.1.0.105076";
const OID_PING_HOST: &str = "1.3.6.1.4.1.25623.1.0.100315";

const BOREAS_ALIVE_TEST: &str = "ALIVE_TEST";
const BOREAS_ALIVE_TEST_PORTS: &str = "ALIVE_TEST_PORTS";
const ALIVE_TEST_SCAN_CONFIG_DEFAULT: u8 = 0x00;

fn bool_to_str(value: &str) -> String {
    if value == "0" {
        return "no".to_string();
    }
    "yes".to_string()
}

#[derive(Debug)]
pub struct PreferenceHandler<'a, H> {
    scan_config: Scan,
    redis_connector: &'a mut H,
    nvt_params: HashMap<String, String>,
}

impl<'a, H> PreferenceHandler<'a, H>
where
    H: VtHelper + KbAccess,
{
    pub fn new(scan_config: Scan, redis_connector: &'a mut H) -> Self {
        Self {
            scan_config,
            redis_connector,
            nvt_params: HashMap::new(),
        }
    }

    pub async fn prepare_preferences_for_openvas(&mut self) -> RedisStorageResult<()> {
        self.prepare_scan_id_for_openvas().await?;
        self.prepare_target_for_openvas().await?;
        self.prepare_ports_for_openvas().await?;
        self.prepare_credentials_for_openvas().await?;
        self.prepare_plugins_for_openvas().await?;
        self.prepare_main_kbindex_for_openvas().await?;
        self.prepare_host_options_for_openvas().await?;
        self.prepare_scan_params_for_openvas().await?;
        self.prepare_reverse_lookup_opt_for_openvas().await?;
        self.prepare_alive_test_option_for_openvas().await?;

        // VT preferences are stored after all preferences have been processed,
        // since alive tests preferences have to be able to overwrite default
        // preferences of ping_host.nasl for the classic method.
        self.prepare_nvt_preferences().await?;
        self.prepare_boreas_alive_test().await
    }

    async fn prepare_main_kbindex_for_openvas(&mut self) -> RedisStorageResult<()> {
        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", &self.scan_config.scan_id.clone()).as_str(),
            format!("ov_maindbid|||{}", &self.redis_connector.kb_id()?),
        )?;
        Ok(())
    }

    async fn prepare_scan_id_for_openvas(&mut self) -> RedisStorageResult<()> {
        self.redis_connector.push_kb_item(
            format!("internal/{}", &self.scan_config.scan_id.clone()).as_str(),
            "new",
        )?;
        self.redis_connector
            .push_kb_item("internal/scanid", self.scan_config.scan_id.clone())?;

        Ok(())
    }

    async fn process_vts(&self, vts: &Vec<VT>) -> (Vec<String>, HashMap<String, String>) {
        let mut vts_list: Vec<String> = vec![];
        let mut pref_list: HashMap<String, String> = HashMap::new();

        for vt in vts {
            if let Some(nvt) = self.redis_connector.get_vt(&vt.oid).unwrap() {
                // add oid to the target list
                vts_list.push(vt.oid.clone());

                // prepare vt preferences
                for pref in &vt.parameters {
                    if let Some((prefid, class, name, value)) =
                        nvt.preferences.iter().find_map(|p| {
                            if let Some(i) = p.id {
                                if i as u16 == pref.id {
                                    Some(p.into())
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                    {
                        let value_aux: String = if class == *"checkbox" {
                            bool_to_str(&pref.value)
                        } else {
                            value
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

    async fn prepare_plugins_for_openvas(&mut self) -> RedisStorageResult<()> {
        let nvts = &self.scan_config.vts;

        if nvts.is_empty() {
            return Ok(());
        }

        let (nvts, prefs) = self.process_vts(nvts).await;
        // update list of preferences
        self.nvt_params.extend(prefs);

        // prepare vts
        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            format!("plugin_set|||{}", nvts.join(";")),
        )
    }

    async fn prepare_nvt_preferences(&mut self) -> RedisStorageResult<()> {
        let mut items: Vec<String> = vec![];
        for (k, v) in self.nvt_params.iter() {
            items.push(format!("{}|||{}", k, v))
        }

        if items.is_empty() {
            return Ok(());
        }

        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            items,
        )
    }

    async fn prepare_alive_test_option_for_openvas(&mut self) -> RedisStorageResult<()> {
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
            && !(alive_test & AliveTestMethods::TcpAck as u8) != 0
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
        if let Ok(config) = cmd::read_openvas_config() {
            if let Some(setting) = config.get("default", "test_alive_hosts_only") {
                if setting == "no" {
                    return Ok(());
                }
            }
        }

        let methods = self.scan_config.target.alive_test_methods.clone();

        let mut alive_test = ALIVE_TEST_SCAN_CONFIG_DEFAULT;
        for m in methods {
            alive_test |= m as u8;
        }

        if (1..=31).contains(&alive_test) {
            self.redis_connector.push_kb_item(
                format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
                format!("{BOREAS_ALIVE_TEST}|||{}", alive_test),
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
                format!("{BOREAS_ALIVE_TEST_PORTS}|||{}", ports),
            )?;
        };

        Ok(())
    }

    async fn prepare_reverse_lookup_opt_for_openvas(&mut self) -> RedisStorageResult<()> {
        let mut lookup_opts: Vec<String> = vec![];

        if let Some(reverse_lookup_only) = self.scan_config.target.reverse_lookup_only {
            if reverse_lookup_only {
                lookup_opts.push(format!("reverse_lookup_only|||{}", "yes"));
            }
        } else {
            lookup_opts.push(format!("reverse_lookup_only|||{}", "no"));
        }

        if let Some(reverse_lookup_unify) = self.scan_config.target.reverse_lookup_unify {
            if reverse_lookup_unify {
                lookup_opts.push(format!("reverse_lookup_unify|||{}", "yes"));
            }
        } else {
            lookup_opts.push(format!("reverse_lookup_unify|||{}", "no"));
        }

        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            lookup_opts,
        )
    }

    async fn prepare_target_for_openvas(&mut self) -> RedisStorageResult<()> {
        let target = self.scan_config.target.hosts.join(",");
        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            format!("TARGET|||{}", target),
        )
    }

    async fn prepare_ports_for_openvas(&mut self) -> RedisStorageResult<()> {
        let ports = self.scan_config.target.ports.clone();
        if let Some(ports) = ports_to_openvas_port_list(ports) {
            self.redis_connector.push_kb_item(
                format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
                format!("port_range|||{}", ports),
            )?;
        };

        Ok(())
    }

    async fn prepare_host_options_for_openvas(&mut self) -> RedisStorageResult<()> {
        let excluded_hosts = self.scan_config.target.excluded_hosts.join(",");
        if excluded_hosts.is_empty() {
            return Ok(());
        }

        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            format!("exclude_hosts|||{}", excluded_hosts),
        )
    }

    async fn prepare_scan_params_for_openvas(&mut self) -> RedisStorageResult<()> {
        let options = self
            .scan_config
            .scan_preferences
            .clone()
            .iter()
            .map(|x| format!("{}|||{}", x.id, x.value))
            .collect::<Vec<String>>();

        if options.is_empty() {
            return Ok(());
        }

        self.redis_connector.push_kb_item(
            format!("internal/{}/scanprefs", self.scan_config.scan_id.clone()).as_str(),
            options,
        )
    }
    async fn prepare_credentials_for_openvas(&mut self) -> RedisStorageResult<()> {
        let credentials = self.scan_config.target.credentials.clone();

        let mut credential_preferences: Vec<String> = vec![];
        for credential in credentials {
            match credential.service {
                Service::SSH => {
                    if let Some(port) = credential.port {
                        credential_preferences.push(format!("auth_port_ssh|||{}", port));
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
                            "{OID_SSH_AUTH}:3:password:SSH password (unsafe!):|||{}",
                            password
                        ));
                        credential_preferences.push(format!(
                            "{OID_SSH_AUTH}:1:entry:SSH login name:|||{}",
                            username
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
                            "{OID_SSH_AUTH}:1:entry:SSH login name:|||{}",
                            username
                        ));
                        credential_preferences.push(format!(
                            "{OID_SSH_AUTH}:2:password:SSH key passphrase:|||{}",
                            password
                        ));
                        credential_preferences.push(format!(
                            "{OID_SSH_AUTH}:4:file:SSH private key:|||{}",
                            private_key
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
                            .push(format!("{OID_SMB_AUTH}:1:entry:SMB login:|||{}", username));
                        credential_preferences.push(format!(
                            "{OID_SMB_AUTH}:2:password:SMB password:|||{}",
                            password
                        ));
                    };
                }

                Service::ESXi => {
                    if let CredentialType::UP {
                        username, password, ..
                    } = credential.credential_type.clone()
                    {
                        credential_preferences.push(format!(
                            "{OID_ESXI_AUTH}:1:entry:ESXi login name:|||{}",
                            username
                        ));
                        credential_preferences.push(format!(
                            "{OID_ESXI_AUTH}:2:password:ESXi login password:|||{}",
                            password
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
                            "{OID_SNMP_AUTH}:1:password:SNMP Community:|||{}",
                            community
                        ));
                        credential_preferences.push(format!(
                            "{OID_SNMP_AUTH}:2:entry:SNMPv3 Username:|||{}",
                            username
                        ));
                        credential_preferences.push(format!(
                            "{OID_SNMP_AUTH}:3:password:SNMPv3 Password:|||{}",
                            password
                        ));
                        credential_preferences.push(format!(
                            "{OID_SNMP_AUTH}:4:radio:SNMPv3 Authentication Algorithm:|||{}",
                            auth_algorithm
                        ));
                        credential_preferences.push(format!(
                            "{OID_SNMP_AUTH}:5:password:SNMPv3 Privacy Password:|||{}",
                            privacy_password
                        ));
                        credential_preferences.push(format!(
                            "{OID_SNMP_AUTH}:6:radio:SNMPv3 Privacy Algorithm:|||{}",
                            privacy_algorithm
                        ));
                    }
                }
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

    use models::{AliveTestMethods, Credential, Port, PortRange, Scan};

    use super::PreferenceHandler;
    use crate::openvas_redis::{FakeRedis, KbAccess};

    #[tokio::test]
    async fn test_prefs() {
        let mut scan = Scan {
            scan_id: "123-456".to_string(),
            ..Default::default()
        };
        scan.target.alive_test_methods = vec![AliveTestMethods::Icmp, AliveTestMethods::TcpSyn];
        scan.target.credentials = vec![Credential {
            service: models::Service::SSH,
            port: Some(22),
            credential_type: models::CredentialType::UP {
                username: "user".to_string(),
                password: "pass".to_string(),
                privilege: None,
            },
        }];
        scan.target.excluded_hosts = vec!["127.0.0.1".to_string()];
        scan.target.ports = vec![Port {
            protocol: Some(models::Protocol::TCP),
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

        let mut rc = FakeRedis {
            data: HashMap::new(),
        };

        let mut prefh = PreferenceHandler::new(scan, &mut rc);
        assert_eq!(prefh.redis_connector.kb_id().unwrap(), 3);
        assert!(prefh.prepare_scan_id_for_openvas().await.is_ok());
        assert!(prefh
            .redis_connector
            .item_exists("internal/scanid", "123-456"));
        assert!(prefh.redis_connector.item_exists("internal/123-456", "new"));

        assert!(prefh.prepare_main_kbindex_for_openvas().await.is_ok());
        assert!(prefh
            .redis_connector
            .item_exists("internal/123-456/scanprefs", "ov_maindbid|||3"));

        assert!(prefh.prepare_boreas_alive_test().await.is_ok());
        assert!(prefh
            .redis_connector
            .item_exists("internal/123-456/scanprefs", "ALIVE_TEST|||18"));

        assert!(prefh.prepare_host_options_for_openvas().await.is_ok());
        assert!(prefh
            .redis_connector
            .item_exists("internal/123-456/scanprefs", "exclude_hosts|||127.0.0.1"));

        assert!(prefh.prepare_credentials_for_openvas().await.is_ok());
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.103591:3:password:SSH password (unsafe!):|||pass"
        ));
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login name:|||user"
        ));

        assert!(prefh.prepare_ports_for_openvas().await.is_ok());
        assert!(prefh.redis_connector.item_exists(
            "internal/123-456/scanprefs",
            "port_range|||T:22,23,24,25,80,"
        ));
    }
}

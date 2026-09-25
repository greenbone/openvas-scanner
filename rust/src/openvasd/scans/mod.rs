use std::sync::Arc;

use crate::api::states::ScannerBridge;
use crate::database::sqlite::DataBase;

use crate::{config::Config, crypt::ChaCha20Crypt, vts::orchestrator};
pub(crate) mod scheduling;

pub(crate) fn config_to_crypt(config: &Config) -> ChaCha20Crypt {
    // unwrap_or_else is a safe guard in the case the db is stored on disk but no key is provided.
    // Otherwise the credentials can never be decrypted.
    config
        .storage
        .credential_key()
        .map(ChaCha20Crypt::new)
        .unwrap_or_else(|| ChaCha20Crypt::new("insecure"))
}

pub async fn init(
    pool: DataBase,
    config: &Config,
    feed_status: orchestrator::Communicator,
) -> anyhow::Result<ScannerBridge> {
    let crypter = Arc::new(config_to_crypt(config));
    let scheduler = scheduling::init(pool.clone(), crypter.clone(), config, feed_status).await?;
    Ok(ScannerBridge::new(pool, Some(crypter), Some(scheduler)))
}

#[cfg(test)]
pub mod tests {
    use std::time::Duration;

    use super::*;

    use axum::body::{Body, to_bytes};
    use axum::extract::Request;
    use futures::StreamExt;
    use scannerlib::models::{
        self, AliveTestMethods, Credential, CredentialType, Phase, PrivilegeInformation,
        ScanPreference, Service,
    };
    use scannerlib::{scanner, utils::scanner_types::ScannerType};
    use sqlx::{SqlitePool, query_scalar};
    use tower::ServiceExt;

    use crate::api::{error::ApiError, routes};
    use crate::database::{dao::Execute, sqlite::scans::ScanDB};
    use crate::{config::Config, scans::config_to_crypt};

    async fn init(pool: SqlitePool, config: &Config) -> anyhow::Result<ScannerBridge> {
        let ignored = Default::default();

        super::init(pool, config, ignored).await
    }

    fn generate_hosts() -> Vec<Vec<String>> {
        vec![vec![], vec!["0".into()]]
    }
    fn generate_excluded_hosts() -> Vec<Vec<String>> {
        vec![vec![], vec!["1".into()]]
    }

    fn generate_ports() -> Vec<Vec<models::Port>> {
        vec![
            vec![],
            vec![
                models::Port {
                    protocol: None,
                    range: vec![],
                },
                models::Port {
                    protocol: None,
                    range: vec![
                        models::PortRange {
                            start: 22,
                            end: None,
                        },
                        models::PortRange {
                            start: 22,
                            end: Some(23),
                        },
                    ],
                },
                models::Port {
                    protocol: Some(models::Protocol::TCP),
                    range: vec![models::PortRange {
                        start: 42,
                        end: None,
                    }],
                },
                models::Port {
                    protocol: Some(models::Protocol::UDP),
                    range: vec![models::PortRange {
                        start: 69,
                        end: None,
                    }],
                },
            ],
        ]
    }

    fn all_services() -> Vec<Service> {
        vec![
            Service::SSH,
            Service::SMB,
            Service::ESXi,
            Service::SNMP,
            Service::KRB5,
        ]
    }

    fn all_ports() -> Vec<Option<u16>> {
        vec![None, Some(22)]
    }

    fn sample_privileges() -> Vec<Option<PrivilegeInformation>> {
        vec![
            None,
            Some(PrivilegeInformation {
                username: "priv_user".to_string(),
                password: "priv_pass".to_string(),
            }),
        ]
    }

    fn all_credential_types_for_service(service: &Service) -> Vec<CredentialType> {
        match service {
            Service::SSH => {
                let mut creds = Vec::new();
                for privilege in sample_privileges() {
                    creds.push(CredentialType::UP {
                        username: "root".to_string(),
                        password: "password".to_string(),
                        privilege: privilege.clone(),
                    });
                    creds.push(CredentialType::USK {
                        username: "root".to_string(),
                        password: Some("keypass".to_string()),
                        private_key: "private_key_data".to_string(),
                        privilege: privilege.clone(),
                    });
                    creds.push(CredentialType::USK {
                        username: "root".to_string(),
                        password: None,
                        private_key: "private_key_data".to_string(),
                        privilege: privilege.clone(),
                    });
                }
                creds
            }
            Service::SMB | Service::ESXi => {
                vec![CredentialType::UP {
                    username: "admin".to_string(),
                    password: "adminpass".to_string(),
                    privilege: None,
                }]
            }
            Service::SNMP => vec![CredentialType::SNMP {
                username: "snmpuser".to_string(),
                password: "snmppass".to_string(),
                community: "public".to_string(),
                auth_algorithm: "SHA".to_string(),
                privacy_password: "privpass".to_string(),
                privacy_algorithm: "AES".to_string(),
            }],
            Service::KRB5 => vec![CredentialType::KRB5 {
                username: "krbuser".to_string(),
                password: "krbpass".to_string(),
                realm: "EXAMPLE.COM".to_string(),
                kdc: "kdc.example.com".to_string(),
            }],
            Service::Generic => vec![CredentialType::UP {
                username: "moep".into(),
                password: "moep".into(),
                privilege: None,
            }],
        }
    }

    fn generate_credentials() -> Vec<Credential> {
        itertools::iproduct!(all_services().into_iter(), all_ports().into_iter())
            .flat_map(|(s, p)| {
                all_credential_types_for_service(&s)
                    .into_iter()
                    .map(move |c| (s.clone(), p, c))
            })
            .map(|(service, port, credential_type)| Credential {
                service,
                port,
                credential_type,
            })
            .collect()
    }

    fn generate_alive_test_methods() -> Vec<AliveTestMethods> {
        use AliveTestMethods::*;
        vec![TcpAck, Icmp, Arp, ConsiderAlive, TcpSyn]
    }

    fn generate_targets() -> Vec<models::Target> {
        itertools::iproduct!(
            generate_hosts(),
            generate_ports(),
            generate_excluded_hosts(),
            generate_ports()
        )
        .map(
            |(hosts, ports, excluded_hosts, alive_test_ports)| models::Target {
                hosts,
                ports,
                excluded_hosts,
                credentials: generate_credentials(),
                alive_test_ports,
                alive_test_methods: generate_alive_test_methods(),
                reverse_lookup_unify: None,
                reverse_lookup_only: Some(true),
            },
        )
        .collect()
    }

    fn generate_scan_prefs() -> Vec<ScanPreference> {
        vec![ScanPreference {
            id: "moep".into(),
            value: "narf".into(),
        }]
    }

    fn generate_vts() -> Vec<models::VT> {
        vec![
            models::VT {
                oid: "0".into(),
                parameters: vec![],
            },
            models::VT {
                oid: "1".into(),
                parameters: vec![models::Parameter {
                    id: 0,
                    value: "aha".to_string(),
                }],
            },
        ]
    }

    pub fn generate_scan() -> Vec<models::Scan> {
        let discovery = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/discovery.json"
        ));
        let mut discovery: models::Scan = serde_json::from_slice(discovery).unwrap();
        discovery.scan_id = "discovery".to_string();
        let simple_auth_ssh_scan = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/openvasd/simple_auth_ssh_scan.json"
        ));
        let mut simple_auth_ssh_scan: models::Scan =
            serde_json::from_slice(simple_auth_ssh_scan).unwrap();
        simple_auth_ssh_scan.scan_id = "simple_auth_ssh_scan".to_string();

        let mut results = vec![simple_auth_ssh_scan, discovery];
        results.extend(generate_targets().into_iter().map(|target| models::Scan {
            scan_id: uuid::Uuid::new_v4().to_string(),
            target,
            scan_preferences: generate_scan_prefs(),
            vts: generate_vts(),
        }));
        results
    }

    pub async fn create_pool() -> anyhow::Result<(Config, SqlitePool)> {
        let nasl = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/nasl").into();
        let advisories_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/feed/notus/advisories"
        )
        .into();
        let products_path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/notus/products").into();

        let feed = crate::config::Feed {
            path: nasl,
            ..Default::default()
        };
        let notus = crate::config::Notus {
            advisories_path,
            products_path,
            url: None,
        };
        let scanner = crate::config::Scanner {
            scanner_type: ScannerType::Openvasd,
            ..Default::default()
        };
        let scheduler = crate::config::Scheduler {
            check_interval: Duration::from_micros(10),
            ..Default::default()
        };

        let config = Config {
            feed,
            notus,
            scanner,
            scheduler,
            ..Default::default()
        };

        let pool = crate::setup_sqlite(&config).await?;

        Ok((config, pool))
    }

    pub async fn prepare_scans(pool: SqlitePool, config: &Config) -> Vec<i64> {
        let client_id = "moep".to_string();
        let scans = generate_scan();
        let crypter = config_to_crypt(config);
        for scan in scans {
            ScanDB::new(&pool, (&crypter, &client_id as &str, &scan))
                .exec()
                .await
                .unwrap();
        }
        query_scalar("SELECT id FROM scans")
            .fetch_all(&pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn post_scan() -> anyhow::Result<()> {
        let (config, pool) = create_pool().await?;

        let undertest = init(pool, &config).await?;
        let client_id = "moep".to_string();
        for scan in generate_scan() {
            undertest.post_scan(&client_id, &scan).await?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn post_scan_duplicate_id() -> anyhow::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await?;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            let result = undertest.post_scan(&client_id, &scan).await;
            assert!(result.is_ok(), "scan must be successfully added");
        }
        for scan in scans {
            let result = undertest.post_scan(&client_id, &scan).await;
            assert!(
                matches!(result, Err(crate::database::dao::DAOError::DBViolation(_))),
                "scan must be declined"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn map_id() -> anyhow::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await?;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            undertest.post_scan(&client_id, &scan).await?;
        }
        for scan in scans {
            let result = undertest.get_scan_id(&client_id, &scan.scan_id).await;
            assert!(result.is_ok(), "scan must be found");
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_scan_id() -> anyhow::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await?;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            undertest.post_scan(&client_id, &scan).await?;
        }
        for scan in scans {
            let result = undertest.get_scan(&client_id, &scan.scan_id).await?;
            assert_eq!(scan.scan_id, result.scan_id);
            assert_eq!(
                scan.target.credentials.len(),
                result.target.credentials.len()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_scans_preferences() -> anyhow::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await?;

        let router = routes::scans::router(
            undertest,
            crate::api::Authentication::Disabled,
            Arc::new(Vec::new()),
            false,
        );

        let response = router
            .oneshot(Request::get("/preferences").body(Body::empty())?)
            .await?;
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let preferences = String::from_utf8(bytes.to_vec())?;

        assert_eq!(
            preferences,
            *scanner::preferences::preference::PREFERENCES_JSON
        );

        Ok(())
    }

    #[tokio::test]
    async fn get_scan_id_status() -> anyhow::Result<()> {
        let (config, pool) = create_pool().await?;

        let crypter = Arc::new(config_to_crypt(&config));
        let (_, _, communicator) = orchestrator::Communicator::init();
        let scheduler = scheduling::init_with_scanner(
            pool.clone(),
            crypter.clone(),
            &config,
            scheduling::tests::scanner_succeeded().build(),
            communicator,
        )
        .await?;

        let undertest = super::ScannerBridge {
            pool,
            crypter: Some(crypter),
            scheduler: Some(scheduler),
        };

        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            undertest.post_scan(&client_id, &scan).await?;
        }
        for scan in scans.iter() {
            let result = undertest.get_scan_status(&client_id, &scan.scan_id).await?;
            assert_eq!(result.status, Phase::Stored);
        }

        for scan in scans.iter() {
            undertest
                .schedule_scan(&client_id, &scan.scan_id, models::Action::Start)
                .await?;
            let mut status;
            loop {
                status = undertest.get_scan_status(&client_id, &scan.scan_id).await?;
                if status.is_running() {
                    break;
                }
            }
            assert!(matches!(status.status, Phase::Requested | Phase::Running));
        }

        for scan in scans.iter() {
            // Why start them again ?
            undertest
                .schedule_scan(&client_id, &scan.scan_id, models::Action::Start)
                .await?;
            let mut status;
            loop {
                status = undertest.get_scan_status(&client_id, &scan.scan_id).await?;
                if status.is_done() {
                    break;
                }
            }

            assert!(matches!(status.status, Phase::Succeeded));

            let result = undertest
                .get_scan_results(&client_id, &scan.scan_id, None, None)
                .await?
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 2);
            let result = undertest
                .get_scan_results(&client_id, &scan.scan_id, Some(1), None)
                .await?
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 1);
            let result = undertest
                .get_scan_results(&client_id, &scan.scan_id, None, Some(0))
                .await?
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 1);
            let result = undertest
                .get_scan_results(&client_id, &scan.scan_id, Some(0), Some(0))
                .await?
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 1);
            let result = undertest
                .get_scan_results(&client_id, &scan.scan_id, Some(23), None)
                .await?
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.len(), 0);
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_scans() -> anyhow::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await?;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        for scan in generate_scan() {
            undertest.post_scan(&client_id, &scan).await?;
        }
        let client_ids = undertest
            .get_scans(client_id)
            .await
            .collect::<Vec<Result<String, ApiError>>>()
            .await;
        assert_eq!(client_ids.iter().filter(|x| x.is_err()).count(), 0);
        assert_eq!(client_ids.iter().filter(|x| x.is_ok()).count(), scans.len());
        let client_ids = undertest
            .get_scans("notme".to_string())
            .await
            .collect::<Vec<_>>()
            .await;
        assert!(client_ids.is_empty());

        Ok(())
    }
}

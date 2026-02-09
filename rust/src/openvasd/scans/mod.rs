use std::{pin::Pin, sync::Arc};

use crate::database::{
    dao::{DAOError, DBViolation, Execute, Fetch, StreamFetch},
    sqlite::{DataBase, results::DBResults, scans::ScanDB},
};
use futures::TryStreamExt;
use greenbone_scanner_framework::InternalIdentifier;
use greenbone_scanner_framework::prelude::*;
use scannerlib::scanner;
use tokio::sync::mpsc::Sender;

use crate::{
    config::Config,
    crypt::{ChaCha20Crypt, Crypt},
    vts::orchestrator,
};
mod scheduling;
pub struct Endpoints<E> {
    pool: DataBase,
    crypter: Arc<E>,
    scheduling: Sender<scheduling::Message>,
}

impl<T> Prefixed for Endpoints<T> {
    fn prefix(&self) -> &'static str {
        ""
    }
}

impl<E> PostScans for Endpoints<E>
where
    E: crate::crypt::Crypt + Sync + Send,
{
    fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> Pin<Box<dyn Future<Output = Result<String, PostScansError>> + Send + '_>> {
        Box::pin(async move {
            match ScanDB::new(
                &self.pool,
                (self.crypter.as_ref(), &client_id as &str, &scan),
            )
            .exec()
            .await
            {
                Ok(result) => Ok(result),
                Err(DAOError::DBViolation(DBViolation::UniqueViolation)) => {
                    Err(PostScansError::DuplicateId(scan.scan_id))
                }
                Err(x) => Err(PostScansError::External(Box::new(x))),
            }
        })
    }
}

impl<E> MapScanID for Endpoints<E>
where
    E: Send + Sync,
{
    fn contains_scan_id<'a>(
        &'a self,
        client_id: &'a str,
        scan_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<InternalIdentifier>> + Send + 'a>> {
        Box::pin(async move {
            match ScanDB::new(&self.pool, (client_id, scan_id)).fetch().await {
                Ok(x) => x,
                Err(error) => {
                    tracing::warn!(%error, "Unable to fetch id from client_scan_map. Returning no id found.");
                    None
                }
            }
        })
    }
}

fn into_external_error<T>(value: T) -> GetScansError
where
    T: std::error::Error + Send + Sync + 'static,
{
    GetScansError::External(Box::new(value))
}

impl<E> GetScans for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans(&self, client_id: String) -> StreamResult<String, GetScansError> {
        Box::pin(
            ScanDB::new(&self.pool, client_id)
                .stream_fetch()
                .map_err(into_external_error),
        )
    }
}

impl<E> GetScansPreferences for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_preferences(
        &self,
    ) -> Pin<Box<dyn Future<Output = Vec<models::ScanPreferenceInformation>> + Send>> {
        Box::pin(async move { scanner::preferences::preference::PREFERENCES.to_vec() })
    }
}

impl<E> GetScansId for Endpoints<E>
where
    E: Send + Sync + Crypt,
{
    fn get_scans_id(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<models::Scan, GetScansIDError>> + Send + '_>> {
        Box::pin(async move {
            let id = id.parse().map_err(into_external_error)?;
            ScanDB::new(&self.pool, (self.crypter.as_ref(), id))
                .fetch()
                .await
                .map_err(into_external_error)
        })
    }
}

impl<E> GetScansIdResults for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id_results(
        &self,
        id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> StreamResult<models::Result, GetScansIDResultsError> {
        let result = DBResults::new(&self.pool, (id, from, to))
            .stream_fetch()
            .map_err(GetScansError::from_external);

        Box::pin(result)
    }
}

impl<E> GetScansIdResultsId for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id_results_id(
        &self,
        id: String,
        result_id: usize,
    ) -> Pin<Box<dyn Future<Output = Result<models::Result, GetScansIDResultsIDError>> + Send + '_>>
    {
        Box::pin(async move {
            DBResults::new(&self.pool, (id, result_id))
                .fetch()
                .await
                .map_err(|e| match e {
                    DAOError::NotFound => GetScansIDResultsIDError::InvalidID,
                    e => e.into(),
                })
        })
    }
}

impl<E> GetScansIdStatus for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id_status(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send + '_>>
    {
        Box::pin(async move {
            let id: i64 = id
                .parse()
                .map_err(|e| GetScansIDStatusError::External(Box::new(e)))?;
            ScanDB::new(&self.pool, id)
                .fetch()
                .await
                .map_err(|e| GetScansIDStatusError::External(Box::new(e)))
        })
    }
}
impl<E> PostScansId for Endpoints<E>
where
    E: Send + Sync,
{
    fn post_scans_id(
        &self,
        id: String,
        action: models::Action,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostScansIDError>> + Send + '_>> {
        Box::pin(async move {
            self.scheduling
                .send(match action {
                    models::Action::Start => scheduling::Message::Start(id),
                    models::Action::Stop => scheduling::Message::Stop(id),
                })
                .await
                .map_err(|e| PostScansIDError::External(Box::new(e)))
        })
    }
}
impl<E> DeleteScansId for Endpoints<E>
where
    E: Send + Sync,
{
    fn delete_scans_id(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), DeleteScansIDError>> + Send + '_>> {
        Box::pin(async move {
            // everything else should have ON DELETE CASCADE
            ScanDB::new(&self.pool, id)
                .exec()
                .await
                .map_err(|e| DeleteScansIDError::External(Box::new(e)))
                .map(|_| ())
        })
    }
}

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
) -> Result<Endpoints<ChaCha20Crypt>, Box<dyn std::error::Error + Send + Sync>> {
    let crypter = Arc::new(config_to_crypt(config));
    let scheduler_sender =
        scheduling::init(pool.clone(), crypter.clone(), config, feed_status).await?;
    Ok(Endpoints {
        pool,
        crypter,
        scheduling: scheduler_sender,
    })
}

#[cfg(test)]
pub mod tests {
    use std::time::Duration;

    use super::*;

    use futures::StreamExt;
    use greenbone_scanner_framework::{
        GetScans, GetScansId, GetScansIdResults, GetScansIdStatus, GetScansPreferences, MapScanID,
        PostScans, PostScansError,
        models::{
            self, AliveTestMethods, Credential, CredentialType, PrivilegeInformation,
            ScanPreference, Service,
        },
        prelude::PostScansId,
    };
    use scannerlib::{models::Phase, scanner};
    use sqlx::{SqlitePool, query_scalar};

    use crate::{
        config::Config,
        crypt::ChaCha20Crypt,
        scans::{config_to_crypt, scheduling},
    };

    async fn init(pool: SqlitePool, config: &Config) -> super::Endpoints<ChaCha20Crypt> {
        let ignored = Default::default();

        super::init(pool, config, ignored).await.unwrap()
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
            "/examples/openvasd/discovery.json"
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

    pub async fn create_pool() -> crate::Result<(Config, SqlitePool)> {
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
            address: None,
        };
        let scanner = crate::config::Scanner {
            scanner_type: crate::config::ScannerType::Openvasd,
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
    async fn post_scan() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;

        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        for scan in generate_scan() {
            let id = scan.scan_id.clone();
            let result = undertest.post_scans(client_id.clone(), scan).await.unwrap();
            assert_eq!(id, result);
        }

        Ok(())
    }

    #[tokio::test]
    async fn post_scan_duplicate_id() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            let id = scan.scan_id.clone();
            let result = undertest.post_scans(client_id.clone(), scan).await;
            assert!(result.is_ok(), "scan must be successfully added");
            assert_eq!(id, result.unwrap());
        }
        for scan in scans {
            let result = undertest.post_scans(client_id.clone(), scan).await;
            assert!(
                matches!(result, Err(PostScansError::DuplicateId(_))),
                "scan must be declined"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn map_id() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            undertest.post_scans(client_id.clone(), scan).await?;
        }
        for scan in scans {
            let result = undertest.contains_scan_id(&client_id, &scan.scan_id).await;
            assert!(result.is_some(), "scan must be found");
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_scan_id() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            undertest.post_scans(client_id.clone(), scan).await?;
        }
        for scan in scans {
            let result = undertest
                .contains_scan_id(&client_id, &scan.scan_id)
                .await
                .unwrap();
            let result = undertest.get_scans_id(result).await?;
            assert_eq!(scan.scan_id, result.scan_id);
            assert_eq!(
                scan.target.credentials.len(),
                result.target.credentials.len()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_scans_preferences() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let result = undertest.get_scans_preferences().await;
        assert_eq!(
            result,
            scanner::preferences::preference::PREFERENCES.to_vec()
        );

        Ok(())
    }

    #[tokio::test]
    async fn get_scan_id_status() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;

        let crypter = Arc::new(config_to_crypt(&config));
        let (_, _, communicator) = orchestrator::Communicator::init();
        let scheduler_sender = scheduling::init_with_scanner(
            pool.clone(),
            crypter.clone(),
            &config,
            scheduling::tests::scanner_succeeded().build(),
            communicator,
        )
        .await?;
        let undertest = super::Endpoints {
            pool,
            crypter,
            scheduling: scheduler_sender,
        };

        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            undertest.post_scans(client_id.clone(), scan).await?;
        }
        for scan in scans.iter() {
            let result = undertest
                .contains_scan_id(&client_id, &scan.scan_id)
                .await
                .unwrap();
            let result = undertest.get_scans_id_status(result).await?;
            assert_eq!(result.status, Phase::Stored);
        }

        for scan in scans.iter() {
            let id = undertest
                .contains_scan_id(&client_id, &scan.scan_id)
                .await
                .unwrap();

            undertest
                .post_scans_id(id.clone(), models::Action::Start)
                .await?;
            let mut status;
            loop {
                status = undertest.get_scans_id_status(id.clone()).await?;
                if status.is_running() {
                    break;
                }
            }
            assert!(matches!(status.status, Phase::Requested | Phase::Running));
        }
        for scan in scans.iter() {
            let id = undertest
                .contains_scan_id(&client_id, &scan.scan_id)
                .await
                .unwrap();

            undertest
                .post_scans_id(id.clone(), models::Action::Start)
                .await?;
            let mut status;
            loop {
                status = undertest.get_scans_id_status(id.clone()).await?;
                if status.is_done() {
                    break;
                }
            }
            assert!(matches!(status.status, Phase::Succeeded));
            let result = undertest
                .get_scans_id_results(id.clone(), None, None)
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 2);
            let result = undertest
                .get_scans_id_results(id.clone(), Some(1), None)
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 1);
            let result = undertest
                .get_scans_id_results(id.clone(), None, Some(0))
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 1);
            let result = undertest
                .get_scans_id_results(id.clone(), Some(0), Some(0))
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 1);
            let result = undertest
                .get_scans_id_results(id, Some(23), None)
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.len(), 0);
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_scans() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        for scan in generate_scan() {
            undertest.post_scans(client_id.clone(), scan).await?;
        }
        let client_ids = undertest.get_scans(client_id).collect::<Vec<_>>().await;
        assert_eq!(client_ids.iter().filter(|x| x.is_err()).count(), 0);
        assert_eq!(client_ids.iter().filter(|x| x.is_ok()).count(), scans.len());
        let client_ids = undertest
            .get_scans("notme".to_string())
            .collect::<Vec<_>>()
            .await;
        assert!(client_ids.is_empty());

        Ok(())
    }
}

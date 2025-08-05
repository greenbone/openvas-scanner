use std::sync::Arc;

use futures::StreamExt;
use greenbone_scanner_framework::prelude::*;
use sqlx::Row;
use sqlx::{Acquire, QueryBuilder, SqlitePool, query};

use crate::{config::Config, crypt::ChaCha20Crypt};
pub struct Endpoints<E> {
    pool: SqlitePool,
    crypter: Arc<E>,
}

enum Error {
    Serialization(serde_json::Error),
    Sqlx(sqlx::Error),
}

impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        Self::Sqlx(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Error::Serialization(value)
    }
}

impl<E> Endpoints<E>
where
    E: crate::crypt::Crypt + Sync + Send,
{
    async fn insert_scan(&self, client: String, scan: models::Scan) -> Result<String, Error> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;

        let row = query("INSERT INTO client_scan_map(client_id, scan_id) VALUES (?, ?)")
            .bind(client.to_string())
            .bind(&scan.scan_id)
            .execute(&mut *tx)
            .await?;

        let mapped_id = row.last_insert_rowid().to_string();
        let auth_data = {
            if !scan.target.credentials.is_empty() {
                let bytes = serde_json::to_vec(&scan.target.credentials)?;
                let bytes = self.crypter.encrypt(bytes).await;
                Some(bytes.to_string())
            } else {
                None
            }
        };
        query("INSERT INTO scans (id, auth_data) VALUES (?, ?)")
            .bind(&mapped_id)
            .bind(auth_data)
            .execute(&mut *tx)
            .await?;
        if !scan.vts.is_empty() {
            let mut builder = QueryBuilder::new("INSERT INTO vts (id, vt)");
            builder.push_values(&scan.vts, |mut b, vt| {
                b.push_bind(&mapped_id).push_bind(&vt.oid);
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
            let mut builder =
                QueryBuilder::new("INSERT INTO vt_parameters (id, vt, param_id, param_value)");
            builder.push_values(
                scan.vts
                    .iter()
                    .flat_map(|x| x.parameters.iter().map(move |p| (&x.oid, p.id, &p.value))),
                |mut b, (oid, param_id, param_value)| {
                    b.push_bind(&mapped_id)
                        .push_bind(oid)
                        .push_bind(param_id as i64)
                        .push_bind(param_value);
                },
            );
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }

        if !scan.target.hosts.is_empty() {
            let mut builder = QueryBuilder::new("INSERT INTO hosts (id, host)");
            builder.push_values(scan.target.hosts, |mut b, host| {
                b.push_bind(&mapped_id).push_bind(host);
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }

        if !scan.target.excluded_hosts.is_empty() {
            let mut builder = QueryBuilder::new(
                "INSERT INTO resolved_hosts (id, original_host, resolved_host, kind, scan_status)",
            );
            builder.push_values(scan.target.excluded_hosts, |mut b, host| {
                //TODO: check host if ip v4, v6, dns or oci ... for now it doesn't matter.
                b.push_bind(&mapped_id)
                    .push_bind(host.clone())
                    .push_bind(host)
                    .push_bind("dns")
                    .push_bind("excluded");
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }

        if !scan.target.ports.is_empty() {
            let mut builder = QueryBuilder::new("INSERT INTO ports (id, protocol, start, end) ");
            builder.push_values(
                scan.target
                    .ports
                    .into_iter()
                    .flat_map(|port| port.range.into_iter().map(move |r| (port.protocol, r))),
                |mut b, (protocol, range)| {
                    b.push_bind(&mapped_id)
                        .push_bind(match protocol {
                            None => "udp_tcp",
                            Some(models::Protocol::TCP) => "tcp",
                            Some(models::Protocol::UDP) => "udp",
                        })
                        .push_bind(range.start as i64)
                        .push_bind(range.end.map(|x| x as i64));
                },
            );
            let query = builder.build();

            query.execute(&mut *tx).await?;
        }
        let mut scan_preferences = scan.scan_preferences;
        if scan.target.reverse_lookup_unify.unwrap_or_default() {
            scan_preferences.push(models::ScanPreference {
                id: "target_reverse_lookup_unify".to_string(),
                value: "true".to_string(),
            });
        }
        if scan.target.reverse_lookup_only.unwrap_or_default() {
            scan_preferences.push(models::ScanPreference {
                id: "target_reverse_lookup_only".to_string(),
                value: "true".to_string(),
            });
        }

        if !scan_preferences.is_empty() {
            let mut builder = QueryBuilder::new("INSERT INTO preferences (id, key, value)");
            builder.push_values(scan_preferences, |mut b, pref| {
                b.push_bind(&mapped_id)
                    .push_bind(pref.id)
                    .push_bind(pref.value);
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }

        tx.commit().await?;
        Ok(scan.scan_id)
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
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<String, PostScansError>> + Send + '_>> {
        let annoying = scan.scan_id.clone();
        Box::pin(async move {
            self.insert_scan(client_id, scan)
                .await
                .map_err(|x| match x {
                    Error::Sqlx(sqlx::Error::Database(db))
                        if matches!(db.kind(), sqlx::error::ErrorKind::UniqueViolation) =>
                    {
                        PostScansError::DuplicateId(annoying)
                    }
                    Error::Sqlx(error) => PostScansError::External(Box::new(error)),
                    Error::Serialization(error) => PostScansError::External(Box::new(error)),
                })
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
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move {
            match query("SELECT id FROM client_scan_map WHERE client_id = ? AND scan_id = ?")
                .bind(client_id)
                .bind(scan_id)
                .fetch_optional(&self.pool)
                .await
            {
                Ok(x) => x.map(|r| r.get::<i64, _>("id")).map(|x| x.to_string()),
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
    fn get_scans(&self, client_id: String) -> StreamResult<'static, String, GetScansError> {
        Box::new(
            query("SELECT scan_id FROM client_scan_map WHERE client_id = ?")
                .bind(client_id)
                .fetch(&self.pool)
                .map(|r| r.map(|r| r.get("scan_id")).map_err(into_external_error)),
        )
    }
}

impl<E> GetScansID for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id(
        &self,
        id: String,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<models::Scan, GetScansIDError>> + Send>> {
        todo!()
    }
}
impl<E> GetScansIDResults for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id_results(
        &self,
        id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> StreamResult<'static, models::Result, GetScansIDResultsError> {
        todo!()
    }
}
impl<E> GetScansIDResultsID for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id_results_id(
        &self,
        id: String,
        result_id: usize,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<models::Result, GetScansIDResultsIDError>> + Send + '_>,
    > {
        todo!()
    }
}
impl<E> GetScansIDStatus for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id_status(
        &self,
        id: String,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send + '_>,
    > {
        todo!()
    }
}
impl<E> PostScansID for Endpoints<E>
where
    E: Send + Sync,
{
    fn post_scans_id(
        &self,
        id: String,
        action: models::Action,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), PostScansIDError>> + Send + '_>> {
        todo!()
    }
}
impl<E> DeleteScansID for Endpoints<E>
where
    E: Send + Sync,
{
    fn delete_scans_id(
        &self,
        id: String,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), DeleteScansIDError>> + Send + '_>> {
        todo!()
    }
}

pub fn init(pool: SqlitePool, config: &Config) -> Endpoints<ChaCha20Crypt> {
    // unwrap_or_else is a safe guard in the case the db is stored on disk but no key is provided.
    // Otherweise the credentials can never be decrypted.
    let crypter = Arc::new(
        config
            .storage
            .fs
            .key
            .clone()
            .map(ChaCha20Crypt::new)
            .unwrap_or_else(|| ChaCha20Crypt::new("insecure")),
    );
    Endpoints { pool, crypter }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use greenbone_scanner_framework::{
        GetScans, MapScanID, PostScans, PostScansError,
        models::{
            self, AliveTestMethods, Credential, CredentialType, PrivilegeInformation,
            ScanPreference, Service,
        },
    };
    use sqlx::SqlitePool;

    use crate::config::Config;

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

    fn generate_scan() -> Vec<models::Scan> {
        generate_targets()
            .into_iter()
            .map(|target| models::Scan {
                scan_id: uuid::Uuid::new_v4().to_string(),
                target,
                scan_preferences: generate_scan_prefs(),
                vts: generate_vts(),
            })
            .collect()
    }

    async fn create_pool() -> crate::Result<(Config, SqlitePool)> {
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
        };

        let config = Config {
            feed,
            notus,
            ..Default::default()
        };

        let pool = crate::setup_sqlite(&config).await?;

        Ok((config, pool))
    }

    #[tokio::test]
    async fn post_scan() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = super::init(pool, &config);
        let client_id = "moep".to_string();
        for scan in generate_scan() {
            let id = scan.scan_id.clone();
            let result = undertest.post_scans(client_id.clone(), scan).await;
            assert!(result.is_ok(), "scan must be successfully added");
            assert_eq!(id, result.unwrap());
        }

        Ok(())
    }

    #[tokio::test]
    async fn post_scan_duplicate_id() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = super::init(pool, &config);
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
        let undertest = super::init(pool, &config);
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
    async fn get_scans() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = super::init(pool, &config);
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

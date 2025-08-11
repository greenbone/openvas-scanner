use std::sync::Arc;

use futures::StreamExt;
use greenbone_scanner_framework::models::{self, Scan};
use scannerlib::{
    openvas::{self, cmd},
    osp,
    scanner::{
        self, ScanDeleter, ScanResultFetcher, ScanResultKind, ScanStarter, ScanStopper, preferences,
    },
};
use sqlx::{QueryBuilder, Row, SqlitePool, query, query_scalar, sqlite::SqliteArguments};
use tokio::sync::mpsc::Sender;

use crate::{config::Config, crypt::Crypt};
mod nasl;

pub struct ScanScheduler<Scanner, Cryptor> {
    pool: SqlitePool,
    cryptor: Arc<Cryptor>,
    scanner: Arc<Scanner>,
    max_concurrent_scan: usize,
}

#[derive(Debug)]
pub enum Message {
    Start(String),
    // On Stop we also delete
    Stop(String),
}

type R<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl<T, C> ScanScheduler<T, C> {
    /// Should be called on restart if the application crashed while there were running scans.
    ///
    /// This is to safe guard against ghost scans that will never finish.
    async fn running_to_failed(&self) -> R<()> {
        let rows = query("UPDATE scans SET status = 'failed' WHERE status = 'running'")
            .execute(&self.pool)
            .await?;

        tracing::warn!(
            scans_failed = rows.rows_affected(),
            "Set scans to failed from previous runs."
        );
        Ok(())
    }

    //TODO: too wet
    async fn scan_stored_to_requested(&self, id: i64) -> R<()> {
        let row = query("UPDATE scans SET status = 'requested' WHERE id = ? AND status = 'stored'")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if row.rows_affected() > 0 {
            tracing::debug!(id, "Changed scan from stored to requested");
        } else {
            tracing::info!(
                id,
                "Unable to change scan from stored to requested because the status is not in stored."
            );
        }
        Ok(())
    }

    async fn scan_running_to_stopped(&self, id: i64) -> R<()> {
        let row = query("UPDATE scans SET status = 'stopped' WHERE id = ? AND status = 'running'")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if row.rows_affected() > 0 {
            tracing::debug!(id, "Changed scan from running to stopped");
        } else {
            tracing::info!(
                id,
                "Unable to change scan from stored to stopped because the status is not in 'running'."
            );
        }
        Ok(())
    }

    async fn scan_running_to_failed(&self, id: i64, reason: &str) -> R<()> {
        query("UPDATE scans SET status = 'failed' WHERE id = ? AND status = 'running'")
            .bind(id)
            .execute(&self.pool)
            .await?;
        tracing::warn!(id, reason, "Set scan from running to failed.");
        Ok(())
    }

    async fn scan_get_status(&self, id: i64) -> R<models::Status> {
        let scan_row = query(r#"
        SELECT created_at, start_time, end_time, host_dead, host_alive, host_queued, host_excluded, host_all, status
        FROM scans
        WHERE id = ?
        "#).bind(id).fetch_one(&self.pool).await?;
        let excluded = scan_row.get("host_excluded");
        let dead = scan_row.get("host_dead");
        let alive = scan_row.get("host_alive");
        let finished = excluded + dead + alive;
        let host_info = models::HostInfo {
            all: scan_row.get("host_all"),
            excluded,
            dead,
            alive,
            queued: scan_row.get("host_queued"),
            finished,
            scanning: None,
            remaining_vts_per_host: Default::default(),
        };
        let status = models::Status {
            start_time: scan_row.get("start_time"),
            end_time: scan_row.get("end_time"),
            status: scan_row.get::<String, _>("status").parse()?,
            host_info: Some(host_info),
        };

        Ok(status)
    }

    async fn scan_update_status(&self, id: i64, status: models::Status) -> R<()> {
        tracing::debug!(id, status = %status.status, "Set status.");
        let host_info = status.host_info.unwrap_or_default();

        let row = query(
            r#"
    UPDATE scans SET
        start_time    = COALESCE(?, start_time),
        end_time      = COALESCE(?, end_time),
        host_dead     = COALESCE(NULLIF(?, 0), host_dead),
        host_alive    = COALESCE(NULLIF(?, 0), host_alive),
        host_queued   = COALESCE(NULLIF(?, 0), host_queued),
        host_excluded = COALESCE(NULLIF(?, 0), host_excluded),
        host_all      = COALESCE(NULLIF(?, 0), host_all),
        status        = COALESCE(NULLIF(?, 'stored'), status)
    WHERE id = ?
    "#,
        )
        .bind(status.start_time.map(|x| x as i64))
        .bind(status.end_time.map(|x| x as i64))
        .bind(host_info.dead as i64)
        .bind(host_info.alive as i64)
        .bind(host_info.queued as i64)
        .bind(host_info.excluded as i64)
        .bind(host_info.all as i64)
        .bind(status.status.as_ref())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn scan_insert_results(&self, id: i64, results: Vec<models::Result>) -> R<()> {
        if !results.is_empty() {
            QueryBuilder::new(
                r#"INSERT INTO results (
                    id, result_id, type, ip_address, hostname, oid, port, protocol, message, 
                    detail_name, detail_value, 
                    source_type, source_name, source_description
                )"#,
            )
            .push_values(results, |mut b, result| {
                b.push_bind(id)
                    .push_bind(result.id as i64)
                    .push_bind(result.r_type.to_string())
                    .push_bind(result.ip_address)
                    .push_bind(result.hostname)
                    .push_bind(result.oid)
                    .push_bind(result.port)
                    .push_bind(result.protocol.map(|p| p.to_string()))
                    .push_bind(result.message)
                    .push_bind(result.detail.as_ref().map(|d| d.name.clone()))
                    .push_bind(result.detail.as_ref().map(|d| d.value.clone()))
                    .push_bind(result.detail.as_ref().map(|d| d.source.s_type.clone()))
                    .push_bind(result.detail.as_ref().map(|d| d.source.name.clone()))
                    .push_bind(result.detail.as_ref().map(|d| d.source.description.clone()));
            })
            .build()
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }
}

async fn scan_start<S>(pool: SqlitePool, scanner: Arc<S>, internal_id: i64, scan: Scan)
where
    S: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Send + Sync + 'static,
{
    match scanner.start_scan(scan).await {
        Ok(()) => {}
        Err(error) => {
            tracing::warn!(internal_id, %error, "Unable to start scan");
            if let Err(error) = query("UPDATE scans SET status = 'failed' WHERE id = ?")
                .bind(internal_id)
                .execute(&pool)
                .await
            {
                tracing::warn!(
                    internal_id,
                    %error,
                    "Unable to set scan to failed. This scan will be kept in running until restart"
                );
            }
        }
    }
}

impl<Scanner, C> ScanScheduler<Scanner, C>
where
    Scanner: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Send + Sync + 'static,
    C: Crypt + Send + Sync + 'static,
{
    /// Checks for scans that are requested and may start them
    ///
    /// After verifying concurrently running scans it starts a scan when the scan waas started
    /// succesfully than it sets it to 'running', if the start fails then it sets it to failed.
    ///
    /// In the case that the ScanStarter implementation blocks start_scan is spawned as a
    /// background task.
    async fn requested_to_running(&self) -> R<()> {
        let mut tx = self.pool.begin().await?;

        let ids: Vec<i64> = match self.max_concurrent_scan {
            0 => query_scalar(
                "SELECT id FROM scans WHERE status = 'requested' ORDER BY created_at ASC ",
            ),
            m => query_scalar(
                r#"
        WITH running_count AS (
            SELECT COUNT(*) AS running_total
            FROM scans
            WHERE status = 'running'
        )
        SELECT id
        FROM scans
        WHERE status = 'requested'
        ORDER BY created_at ASC
        LIMIT (
            SELECT MAX($1 - running_total, 0)
            FROM running_count
        )
        "#,
            )
            .bind(m as i64),
        }
        .fetch_all(&mut *tx)
        .await?;
        for id in ids {
            if !self.scanner.can_start_scan().await {
                break;
            }

            let scan = super::get_scan(&mut tx, self.cryptor.as_ref(), id).await?;
            let row = query("UPDATE scans SET status = 'running' WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tracing::info!(id, running = row.rows_affected(), "Started scan");
            tokio::task::spawn(scan_start(
                self.pool.clone(),
                self.scanner.clone(),
                id,
                scan,
            ));
        }

        tx.commit().await?;

        Ok(())
    }

    async fn scan_import_results(&self, internal_id: i64, scan_id: String) -> R<()> {
        let mut results = match self.scanner.fetch_results(scan_id).await {
            Ok(x) => x,
            Err(scannerlib::scanner::Error::ScanNotFound(scan_id)) => {
                let reason = format!("Tried to get results of an unknown scan ({scan_id})");
                return self.scan_running_to_failed(internal_id, &reason).await;
            }
            e => e?,
        };

        self.scan_insert_results(internal_id, results.results)
            .await?;
        let kind = self.scanner.scan_result_status_kind();
        let previous_status = self.scan_get_status(internal_id).await?;
        let status = match &kind {
            ScanResultKind::StatusOverride => results.status,
            // TODO: refactor on StatusAddition to do that within SQL directly instead of get mut
            ScanResultKind::StatusAddition => {
                results.status.update_with(&previous_status);
                results.status
            }
        };

        self.scan_update_status(internal_id, status).await
    }

    async fn import_results(&self) -> R<()> {
        let scan_ids: Vec<(i64, String)> =
            query("SELECT c.id, c.scan_id FROM client_scan_map AS c JOIN scans AS s ON c.id = s.id WHERE s.status = 'running'")
                .fetch(&self.pool)
                .filter_map(|x| async move { x.ok() })
                .map(|x| (x.get::<i64, _>("id"), x.get::<String, _>("scan_id")))
                .collect::<Vec<(i64, String)>>()
                .await;

        for (id, scan_id) in scan_ids {
            if let Err(error) = self.scan_import_results(id, scan_id).await {
                // we don't return error here as other imports may succeed
                tracing::warn!(id, %error, "Unable to import results of scan. This error may repeat itself until underlying scanner recovers or application is restarted.");
            }
        }

        Ok(())
    }

    async fn scan_stop(&self, id: i64) -> R<()> {
        let scan_id: String = query_scalar("SELECT scan_id FROM client_scan_map WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        self.scanner.stop_scan(scan_id.clone()).await?;
        self.scan_import_results(id, scan_id.clone()).await?;
        self.scanner.delete_scan(scan_id.clone()).await?;
        self.scan_running_to_stopped(id).await?;

        Ok(())
    }

    async fn on_message(&self, message: Message) -> R<()> {
        match message {
            Message::Start(id) => self.scan_stored_to_requested(id.parse()?).await?,
            Message::Stop(id) => self.scan_stop(id.parse()?).await?,
        };
        Ok(())
    }

    async fn on_schedule(&self) -> R<()> {
        self.requested_to_running().await?;
        self.import_results().await?;

        Ok(())
    }
}
trait ScannerTypus:
    ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Send + Sync + 'static
{
}

impl<T> ScannerTypus for T where
    T: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Send + Sync + 'static
{
}

async fn run_scheduler<S, E>(
    check_interval: std::time::Duration,
    scheduler: ScanScheduler<S, E>,
) -> R<Sender<Message>>
where
    S: ScannerTypus,
    E: Crypt + Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(check_interval);
    let (sender, mut recv) = tokio::sync::mpsc::channel(10);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(msg) = recv.recv() => {
                    if let Err(error) = scheduler.on_message(msg).await {
                        tracing::warn!(%error, "Unable to react on message");
                    }

                }

                _ = interval.tick() => {
                    if let Err(error) = scheduler.on_schedule().await {
                        tracing::warn!(%error, "Unable to schedule");
                    }
                }


                else => {
                    tracing::debug!("Channel closed, good bye");
                    break;
                }
            }
        }
    });

    Ok(sender)
}
fn check_redis_url(config: &Config) -> String {
    let redis_url = cmd::get_redis_socket();
    if redis_url != config.storage.redis.url {
        tracing::warn!(
            openvas_redis = &redis_url,
            openvasd_redis = &config.storage.redis.url,
            "openvas and openvasd use different redis connection. Using the openvas URL."
        );
    }
    redis_url
}

pub async fn init<E>(pool: SqlitePool, crypter: Arc<E>, config: &Config) -> R<Sender<Message>>
where
    E: Crypt + Send + Sync + 'static,
{
    let check_interval = config.scheduler.check_interval;
    match config.scanner.scanner_type {
        crate::config::ScannerType::OSPD => {
            //TODO: when in notus don't start scheduler at all
            if !config.scanner.ospd.socket.exists()
                && config.mode != crate::config::Mode::ServiceNotus
            {
                tracing::warn!(
                    "OSPD socket {} does not exist. Some commands will not work until the socket is created!",
                    config.scanner.ospd.socket.display()
                );
            }
            let scheduler = ScanScheduler {
                pool,
                cryptor: crypter,
                max_concurrent_scan: config.scheduler.max_queued_scans.unwrap_or(0),
                scanner: Arc::new(osp::Scanner::new(
                    config.scanner.ospd.socket.clone(),
                    config.scanner.ospd.read_timeout,
                )),
            };
            run_scheduler(check_interval, scheduler).await
        }
        crate::config::ScannerType::Openvas => {
            let scheduler = ScanScheduler {
                pool,
                cryptor: crypter,
                max_concurrent_scan: config.scheduler.max_queued_scans.unwrap_or(0),
                scanner: Arc::new(openvas::Scanner::new(
                    config.scheduler.min_free_mem,
                    None, // cpu_option are not available currently
                    cmd::check_sudo(),
                    check_redis_url(config),
                    preferences::preference::PREFERENCES.to_vec(),
                )),
            };
            run_scheduler(check_interval, scheduler).await
        }
        crate::config::ScannerType::Openvasd => {
            use scanner::LambdaBuilder;
            let scheduler = ScanScheduler {
                pool,
                cryptor: crypter,
                max_concurrent_scan: config.scheduler.max_queued_scans.unwrap_or(0),
                scanner: Arc::new(LambdaBuilder::new().build()),
            };
            run_scheduler(check_interval, scheduler).await
        }
    }
}

#[cfg(test)]
mod tests {
    use greenbone_scanner_framework::PostScans;
    use scannerlib::{
        models::Status,
        scanner::{LambdaBuilder, ScanResults},
    };

    use crate::{
        config::Config,
        crypt::ChaCha20Crypt,
        scans::{self, tests::create_pool},
    };

    use super::*;
    type TR = R<()>;

    async fn prepare_scans(pool: SqlitePool, config: &Config) -> Vec<i64> {
        let scans_endpoint = scans::init(pool.clone(), config).await.unwrap();
        let client_id = "moep".to_string();
        let scans = scans::tests::generate_scan();
        for scan in scans {
            scans_endpoint
                .post_scans(client_id.clone(), scan)
                .await
                .unwrap();
        }
        query_scalar("SELECT id FROM scans")
            .fetch_all(&pool)
            .await
            .unwrap()
    }

    async fn setup_test_env() -> R<(ScanScheduler<scanner::Lambda, ChaCha20Crypt>, Vec<i64>)> {
        setup_test_env_with_scanner(LambdaBuilder::default()).await
    }

    async fn setup_test_env_with_scanner(
        builder: LambdaBuilder,
    ) -> R<(ScanScheduler<scanner::Lambda, ChaCha20Crypt>, Vec<i64>)> {
        let (config, pool) = create_pool().await?;
        let scanner = Arc::new(builder.build());
        let cryptor = Arc::new(scans::config_to_crypt(&config));

        let under_test = ScanScheduler {
            pool: pool.clone(),
            scanner,
            cryptor,
            max_concurrent_scan: 4,
        };
        let known_scans = prepare_scans(pool.clone(), &config).await;
        Ok((under_test, known_scans))
    }

    #[tokio::test]
    async fn start_scan() -> TR {
        let (under_test, known_scans) = setup_test_env().await?;

        for id in known_scans.iter() {
            under_test
                .on_message(Message::Start(id.to_string()))
                .await?;
        }
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "requested").count(),
            status.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn run_scans() -> TR {
        let (under_test, known_scans) = setup_test_env().await?;
        for id in known_scans.iter() {
            under_test
                .on_message(Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "running").count(),
            under_test.max_concurrent_scan
        );
        let start_times: Vec<i64> =
            query_scalar("SELECT start_time FROM scans WHERE status = 'running'")
                .fetch_all(&under_test.pool)
                .await?;
        assert_eq!(
            start_times.iter().filter(|x| x > &&0).count(),
            start_times.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn reflect_status_phase_of_scan() -> TR {
        let (under_test, known_scans) =
            setup_test_env_with_scanner(LambdaBuilder::new().with_fetch(|id| {
                let results = vec![
                    models::Result {
                        id: 0,
                        r_type: models::ResultType::Alarm,
                        ip_address: None,
                        hostname: None,
                        oid: None,
                        port: None,
                        protocol: None,
                        message: None,
                        detail: None,
                    },
                    models::Result {
                        id: 1,
                        r_type: models::ResultType::Log,
                        ip_address: Some("127.0.0.1".to_string()),
                        hostname: Some("localhost".to_string()),
                        oid: Some("1".to_string()),
                        port: Some(22),
                        protocol: Some(models::Protocol::UDP),
                        message: Some("hooary".to_string()),
                        detail: Some(models::Detail {
                            name: "detail_name".to_string(),
                            value: "detail_value".to_string(),
                            source: models::Source {
                                s_type: "dunno".to_string(),
                                name: "something".to_string(),
                                description: "found something in don't know".to_string(),
                            },
                        }),
                    },
                ];

                Ok(ScanResults {
                    id: id.to_string(),
                    status: Status {
                        status: models::Phase::Succeeded,
                        ..Default::default()
                    },
                    results,
                })
            }))
            .await?;
        for id in known_scans.iter() {
            under_test
                .on_message(Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "succeeded").count(),
            under_test.max_concurrent_scan
        );

        let end_times: Vec<i64> =
            query_scalar("SELECT end_time FROM scans WHERE status = 'succeeded'")
                .fetch_all(&under_test.pool)
                .await?;
        assert_eq!(
            end_times.iter().filter(|x| x > &&0).count(),
            end_times.len()
        );
        let result_count: i64 = query_scalar("SELECT count(*) FROM results")
            .fetch_one(&under_test.pool)
            .await?;
        assert_eq!(result_count, (under_test.max_concurrent_scan * 2) as i64);

        Ok(())
    }

    #[tokio::test]
    async fn run_scans_failure() -> TR {
        let (under_test, known_scans) = setup_test_env_with_scanner(
            LambdaBuilder::new()
                .with_start(|_| Err(scanner::Error::Connection("nada".to_string()))),
        )
        .await?;
        for id in known_scans.iter() {
            under_test
                .on_message(Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "failed").count(),
            under_test.max_concurrent_scan
        );

        let end_times: Vec<i64> =
            query_scalar("SELECT end_time FROM scans WHERE status = 'failed'")
                .fetch_all(&under_test.pool)
                .await?;
        assert_eq!(
            end_times.iter().filter(|x| x > &&0).count(),
            end_times.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn dont_run_scans() -> TR {
        let (under_test, known_scans) =
            setup_test_env_with_scanner(LambdaBuilder::new().with_can_start(|| false)).await?;

        for id in known_scans.iter() {
            under_test
                .on_message(Message::Start(id.to_string()))
                .await?;
        }
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "requested").count(),
            status.len()
        );

        Ok(())
    }
}

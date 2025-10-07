use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

use futures::StreamExt;
use greenbone_scanner_framework::models::{self, Scan};
use scannerlib::{
    models::FeedState,
    openvas::{self, cmd},
    osp,
    scanner::{
        Lambda, ScanDeleter, ScanResultFetcher, ScanResultKind, ScanStarter, ScanStopper,
        preferences,
    },
    storage::redis::{RedisAddAdvisory, RedisAddNvt, RedisCtx, RedisWrapper},
};
use sqlx::{QueryBuilder, Row, SqlitePool, query, query_scalar};
use tokio::{sync::mpsc::Sender, time::MissedTickBehavior};

use crate::{config::Config, crypt::Crypt};
mod nasl;

struct ScanScheduler<Scanner, Cryptor> {
    pool: SqlitePool,
    cryptor: Arc<Cryptor>,
    scanner: Arc<Scanner>,
    max_concurrent_scan: usize,
    // Exists to prevent a bug in which scans were accidentally started twice due to deferred writes in sqlite.
    // To address this bug, this field keeps track of all requested scans manually, instead of relying on
    // sqlite for this information.
    //
    // This is a hack, if there are any better solutions that work as reliably this can be removed
    // without functional harm.
    requested_guard: Arc<RwLock<Vec<i64>>>,
}

#[derive(Debug)]
pub enum Message {
    Start(String),
    // On Stop we also delete
    Stop(String),
}

// maybe we should just use AnyHow
type R<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl<T, C> ScanScheduler<T, C> {
    /// Should be called on restart if the application crashed while there were running scans.
    ///
    /// This is to safe guard against ghost scans that will never finish.
    async fn running_to_failed(&self) -> R<()> {
        let rows = query("UPDATE scans SET status = 'failed' WHERE status = 'running'")
            .execute(&self.pool)
            .await?;
        if rows.rows_affected() > 0 {
            tracing::warn!(
                scans_failed = rows.rows_affected(),
                "Set scans to failed from previous runs."
            );
        }
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

    async fn scan_insert_results(&self, id: i64, results: Vec<models::Result>) -> R<()> {
        if !results.is_empty() {
            let offset: i64 =
                query_scalar("SELECT count(result_id) AS count FROM results WHERE id = ?")
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await?;
            tracing::trace!(offset, id, ?results);
            QueryBuilder::new(
                r#"INSERT INTO results (
                    id, result_id, type, ip_address, hostname, oid, port, protocol, message, 
                    detail_name, detail_value, 
                    source_type, source_name, source_description
                )"#,
            )
            .push_values(results.into_iter().enumerate(), |mut b, (idx, result)| {
                b.push_bind(id)
                    .push_bind(offset + idx as i64)
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
    async fn fetch_requested(&self) -> R<Vec<i64>> {
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
        .fetch_all(&self.pool)
        .await?;

        Ok(ids)
    }

    async fn is_already_started(&self, id: i64) -> bool {
        let guard = self.requested_guard.clone();
        tokio::task::spawn_blocking(move || {
            let cached = guard.read().unwrap();
            cached.contains(&id)
        })
        .await
        .unwrap()
    }

    async fn set_to_running(&self, id: i64) -> R<()> {
        let row = query("UPDATE scans SET status = 'running' WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        let mut tx = self.pool.begin().await?;
        let scan = super::get_scan(&mut tx, self.cryptor.as_ref(), id).await?;
        tx.commit().await?;
        if self.is_already_started(id).await {
            tracing::trace!(id, "Has been already started, skipping");
            return Ok(());
        }

        tracing::info!(id, running = row.rows_affected(), "Started scan");

        let guard = self.requested_guard.clone();
        tokio::task::spawn_blocking(move || {
            let mut x = guard.write().unwrap();
            x.push(id);
        })
        .await
        .unwrap();

        scan_start(self.pool.clone(), self.scanner.clone(), id, scan).await;
        Ok(())
    }
    /// Checks for scans that are requested and may start them
    ///
    /// After verifying concurrently running scans it starts a scan when the scan was started
    /// successfully than it sets it to 'running', if the start fails then it sets it to failed.
    async fn requested_to_running(&self) -> R<()> {
        let ids = self.fetch_requested().await?;

        for id in ids {
            // To prevent accidental state change from running -> requested based on an old
            // snapshot we only do a resource when a scan has not already been started.
            if !self.is_already_started(id).await && !self.scanner.can_start_scan().await {
                break;
            }

            self.set_to_running(id).await?;
        }

        Ok(())
    }

    async fn remove_id_from_guard(&self, id: i64) {
        let cache = self.requested_guard.clone();
        tokio::task::spawn_blocking(move || {
            let mut cache = cache.write().unwrap();
            if let Some(index) = cache.iter().position(|x| x == &id) {
                cache.swap_remove(index);
            }
        });
    }

    async fn scan_import_results(&self, internal_id: i64, scan_id: String) -> R<()> {
        let mut results = match self.scanner.fetch_results(scan_id.clone()).await {
            Ok(x) => x,
            Err(scannerlib::scanner::Error::ScanNotFound(scan_id)) => {
                let reason = format!("Tried to get results of an unknown scan ({scan_id})");
                return self.scan_running_to_failed(internal_id, &reason).await;
            }
            e => e?,
        };

        let kind = self.scanner.scan_result_status_kind();

        self.scan_insert_results(internal_id, results.results)
            .await?;
        let previous_status = super::scan_get_status(&self.pool, internal_id).await?;
        let status = match &kind {
            ScanResultKind::StatusOverride => results.status,
            // TODO: refactor on StatusAddition to do that within SQL directly instead of get mut
            ScanResultKind::StatusAddition => {
                results.status.update_with(&previous_status);
                results.status
            }
        };

        self.scan_update_status(internal_id, &status).await?;
        if status.is_done() {
            self.scanner_delete_scan(internal_id, scan_id).await?;
        }
        Ok(())
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

    async fn scan_update_status(&self, id: i64, status: &models::Status) -> R<()> {
        let host_info = status.host_info.clone().unwrap_or_default();

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
        tracing::debug!(id, rows_affected=row.rows_affected(), status = %status.status, "Set status.");
        Ok(())
    }

    async fn scanner_delete_scan(&self, internal_id: i64, scan_id: String) -> R<()> {
        self.remove_id_from_guard(internal_id).await;
        self.scanner.delete_scan(scan_id).await?;
        Ok(())
    }

    async fn scan_stop(&self, id: i64) -> R<()> {
        let scan_id: String = query_scalar("SELECT scan_id FROM client_scan_map WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        self.scanner.stop_scan(scan_id.clone()).await?;
        self.scan_import_results(id, scan_id.clone()).await?;

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

async fn run_scheduler<S, E>(
    check_interval: std::time::Duration,
    scheduler: ScanScheduler<S, E>,
) -> R<Sender<Message>>
where
    S: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Send + Sync + 'static,
    E: Crypt + Send + Sync + 'static,
{
    // happens when openvasd was killed when scans did still run
    if let Err(error) = scheduler.running_to_failed().await {
        tracing::warn!(%error, "Unable to set not stopped runs from a previous session to failed.")
    }
    let mut interval = tokio::time::interval(check_interval);
    // The default on missed ticks is bursted. Which means when a tick was missed instead of
    // ticking in the interval after the new time it is immediately triggering missed ticks
    // resulting in immediately calling scheduler.on_schedule. What we would rather do on a missed
    // tick is waiting for that interval until we check again.
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
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

pub(super) async fn init_with_scanner<E, S>(
    pool: SqlitePool,
    crypter: Arc<E>,
    config: &Config,
    scanner: S,
) -> R<Sender<Message>>
where
    S: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Send + Sync + 'static,
    E: Crypt + Send + Sync + 'static,
{
    let scheduler = ScanScheduler {
        pool,
        cryptor: crypter,
        max_concurrent_scan: config.scheduler.max_queued_scans.unwrap_or(0),
        scanner: Arc::new(scanner),
        requested_guard: Arc::new(RwLock::new(vec![])),
    };

    run_scheduler(config.scheduler.check_interval, scheduler).await
}

async fn init_redis_storage(redis_url: &str) -> R<(RedisCtx, RedisCtx)> {
    use scannerlib::storage::redis::*;
    let notus = RedisCtx::open(redis_url, NOTUSUPDATE_SELECTOR)?;
    let nvt = RedisCtx::open(redis_url, FEEDUPDATE_SELECTOR)?;
    Ok((nvt, notus))
}

async fn synchronize_redis_feed(pool: SqlitePool, redis_url: &str, feed_version: String) -> () {
    tracing::debug!("synchronizing redis with vt feed");
    let (vtc, nc) = match init_redis_storage(redis_url).await {
        Ok(x) => x,
        Err(error) => {
            tracing::warn!(%error, "Unable to create redis cache connections");
            return;
        }
    };
    tracing::info!("synchronized redis with vt feed");
    let nc = Arc::new(RwLock::new(nc));
    let vtc = Arc::new(RwLock::new(vtc));
    let rows = query("SELECT feed_type, json_blob FROM plugins").fetch(&pool);

    const CONCURRENCY_LIMIT: usize = 1024;
    rows.for_each_concurrent(CONCURRENCY_LIMIT, |x| {
        let nc = nc.clone();
        let vtc = vtc.clone();
        async move {
            match x {
                Ok(row) => {
                    tokio::task::spawn_blocking(move || {
                        match row.get("feed_type") {
                            "advisories" => {
                                tracing::trace!(feed_type = "advisories", "Mirroring");
                                let mut nc = nc.write().unwrap();
                                match serde_json::from_slice(row.get("json_blob")) {
                                    Ok(x) => {
                                        if let Err(error) = nc.redis_add_advisory(Some(x)) {
                                            tracing::warn!(%error,  "unable to mirror advisory")
                                        }
                                    }
                                    Err(error) => {
                                        tracing::warn!(%error, "Unable to parse advisory")
                                    }
                                };
                            }
                            feed_type => {
                                tracing::trace!(feed_type, "Mirroring");
                                let mut vtc = vtc.write().unwrap();
                                match serde_json::from_slice(row.get("json_blob")) {
                                    Ok(x) => {
                                        if let Err(error) = vtc.redis_add_nvt(x) {
                                            tracing::warn!(%error,  "unable to mirror NASL plugin")
                                        }
                                    }
                                    Err(error) => {
                                        tracing::warn!(%error, "Unable to parse NASL plugin")
                                    }
                                };
                            }
                        };
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "Unable to fetch plugins");
                }
            }
        }
    })
    .await;

    let nc = nc.clone();
    tokio::task::spawn_blocking(move || {
        let mut nv = nc.write().unwrap();
        if let Err(error) = nv.redis_add_advisory(None) {
            tracing::warn!(%error, "Unable set notus feed to be available");
        }
    });

    let vtc = vtc.clone();

    tokio::task::spawn_blocking(move || {
        // TODO: block scans until nvticache is available otherwise we cannot start scans anyway
        let mut vtc = vtc.write().unwrap();
        if let Err(error) = vtc
            .del("nvticache")
            .and_then(move |_| vtc.rpush("nvticache", &[&feed_version]))
        {
            tracing::warn!(%error, "Unable set nvticache for openvas. Scans might be unavailable");
        }
    });
}

pub async fn init<E, FS>(
    pool: SqlitePool,
    crypter: Arc<E>,
    feed_state: FS,
    config: &Config,
) -> R<Sender<Message>>
where
    E: Crypt + Send + Sync + 'static,
    FS: Fn() -> Pin<Box<dyn Future<Output = FeedState> + Send + 'static>> + Send + 'static,
{
    match config.scanner.scanner_type {
        crate::config::ScannerType::Ospd => {
            //TODO: when in notus don't start scheduler at all
            if !config.scanner.ospd.socket.exists()
                && config.mode != crate::config::Mode::ServiceNotus
            {
                tracing::warn!(
                    "OSPD socket {} does not exist. Some commands will not work until the socket is created!",
                    config.scanner.ospd.socket.display()
                );
            }
            let scanner = osp::Scanner::new(
                config.scanner.ospd.socket.clone(),
                config.scanner.ospd.read_timeout,
            );
            init_with_scanner(pool, crypter, config, scanner).await
        }
        crate::config::ScannerType::Openvas => {
            let redis_url = cmd::get_redis_socket();

            let scanner = openvas::Scanner::new(
                config.scheduler.min_free_mem,
                None, // cpu_option are not available currently
                cmd::check_sudo(),
                redis_url.clone(),
                preferences::preference::PREFERENCES.to_vec(),
            );
            let initial_check_interval = config.scheduler.check_interval;
            let slow_check_interval = config.feed.check_interval + Duration::from_secs(60);

            let fpool = pool.clone();
            tokio::task::spawn(async move {
                let mut previous_feed_state = FeedState::Unknown;
                loop {
                    let new_feed_state = feed_state().await;
                    if new_feed_state != previous_feed_state
                        && let FeedState::Synced(feed_version, _) = &new_feed_state
                    {
                        tracing::info!(from=?previous_feed_state, to=?new_feed_state, "feed changed");
                        let feed_version = feed_version.clone();
                        previous_feed_state = new_feed_state;
                        synchronize_redis_feed(fpool.clone(), &redis_url, feed_version).await;
                    }
                    // check often in an initial state
                    if !matches!(previous_feed_state, FeedState::Synced(_, _)) {
                        tokio::time::sleep(initial_check_interval).await
                    } else {
                        tokio::time::sleep(slow_check_interval).await
                    }
                }
            });

            init_with_scanner(pool, crypter, config, scanner).await
        }
        crate::config::ScannerType::Openvasd => {
            let scanner: Lambda = Lambda::default();
            init_with_scanner(pool, crypter, config, scanner).await
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use scannerlib::{
        models::Status,
        scanner::{self, LambdaBuilder, ScanResults},
    };

    use super::*;
    use crate::{
        config::Config,
        crypt::ChaCha20Crypt,
        scans::{self, tests::create_pool},
    };
    type TR = R<()>;

    async fn prepare_scans(pool: SqlitePool, config: &Config) -> Vec<i64> {
        let client_id = "moep".to_string();
        let scans = scans::tests::generate_scan();
        let crypter = scans::config_to_crypt(config);
        for scan in scans {
            scans::scan_insert(&pool, &crypter, &client_id, scan)
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
            requested_guard: Arc::new(RwLock::new(vec![])),
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

    pub(crate) fn scanner_succeeded() -> LambdaBuilder {
        LambdaBuilder::new().with_fetch(|id| {
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
        })
    }

    #[tokio::test]
    // maybe create a function of that so that it can be used within scans testing
    async fn reflect_status_phase_of_scan() -> TR {
        let (under_test, known_scans) = setup_test_env_with_scanner(scanner_succeeded()).await?;
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

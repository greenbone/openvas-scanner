use std::sync::Arc;
use tokio::sync::RwLock;

use greenbone_scanner_framework::models::{self, Scan};
use scannerlib::{
    models::FeedType,
    openvas::{self, cmd},
    osp,
    scanner::{
        Lambda, ScanDeleter, ScanResultFetcher, ScanResultKind, ScanStarter, ScanStopper,
        preferences,
    },
};
use sqlx::{QueryBuilder, SqlitePool, query_scalar};
use tokio::{
    sync::mpsc::{self, Sender},
    time::MissedTickBehavior,
};

use crate::{
    config::Config,
    crypt::Crypt,
    scans::state_change::ScanStateController,
    vts::orchestrator::{self, FeedStatusChange},
};

#[derive(Default, Debug)]
struct IsInProgress {
    need_approval_nasl: bool,
    need_approval_advisories: bool,
    approved_nasl: bool,
    approved_advisories: bool,
}

impl IsInProgress {
    fn set_based_on_message(&mut self, msg: &orchestrator::FeedStatusChange) {
        match msg {
            FeedStatusChange::Need(FeedType::Advisories) => {
                self.need_approval_advisories = true;
            }
            FeedStatusChange::Need(FeedType::NASL) => {
                self.need_approval_nasl = true;
            }
            FeedStatusChange::Synced(FeedType::Advisories) => {
                self.need_approval_advisories = false;
                self.approved_advisories = false;
            }
            FeedStatusChange::Synced(FeedType::NASL) => {
                self.need_approval_nasl = false;
                self.approved_nasl = false;
            }
            _ => {
                // ignore products
            }
        }
    }

    fn approve(&mut self) -> Vec<FeedType> {
        let mut result = Vec::with_capacity(2);
        if self.need_approve(&FeedType::NASL) {
            self.approved_nasl = true;
            result.push(FeedType::NASL);
        }
        if self.need_approve(&FeedType::Advisories) {
            self.approved_advisories = true;
            result.push(FeedType::Advisories);
        };
        result
    }

    fn scans_allowed(&self) -> bool {
        !self.need_approval_nasl
            && !self.approved_nasl
            && !self.need_approval_advisories
            && !self.approved_advisories
    }

    fn is_feed_sync_in_progress(&self) -> bool {
        !self.scans_allowed()
    }

    fn need_approve(&self, ft: &FeedType) -> bool {
        match ft {
            FeedType::Products => false,
            FeedType::Advisories => self.need_approval_advisories && !self.approved_advisories,
            FeedType::NASL => self.need_approval_nasl && !self.approved_nasl,
        }
    }

    fn contains_need(&self) -> bool {
        (self.need_approval_nasl && !self.approved_nasl)
            || (self.need_approval_advisories && !self.approved_advisories)
    }
}

struct ScanScheduler<Scanner, Cryptor> {
    pool: SqlitePool,
    cryptor: Arc<Cryptor>,
    scanner: Arc<Scanner>,
    max_concurrent_scan: usize,
    // we store the need and allow requests in the case of a feed sync
    //
    // On need we know that we actually need to send the allows because we waited for the scans to
    // finish. One allow we just wait for synced.
    // We use the fact that we don't handle products as a differentiation between need and allow
    // otherwise we would need to store two separate lists.
    feed_sync_in_progress: Arc<RwLock<IsInProgress>>,
    scan_state: ScanStateController,
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
        let affected = self
            .scan_state
            .change_state_all("running", "failed")
            .await?;

        if affected > 0 {
            tracing::warn!(
                scans_failed = affected,
                "Set scans to failed from previous runs."
            );
        }
        Ok(())
    }

    async fn scan_stored_to_requested(&self, id: i64) -> R<()> {
        self.scan_state
            .change_state(id, "stored", "requested")
            .await?;
        Ok(())
    }

    async fn scan_running_to_failed(&self, id: i64, reason: &str) -> R<()> {
        let changed = self
            .scan_state
            .change_state(id, "running", "failed")
            .await?;

        if changed {
            tracing::warn!(id, reason, "Set scan from running to failed.");
        }
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

impl<Scanner, C> ScanScheduler<Scanner, C>
where
    Scanner: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Send + Sync + 'static,
    C: Crypt + Send + Sync + 'static,
{
    async fn scan_start(&self, id: i64, scan: Scan) {
        match self.scanner.start_scan(scan).await {
            Ok(()) => {}
            Err(error) => {
                tracing::warn!(id, %error, "Unable to start scan");
                if let Err(error) = self.scan_state.change_state(id, "running", "failed").await {
                    tracing::warn!(
                        id,
                        %error,
                        "Unable to set scan to failed. This scan will be kept in running until restart"
                    );
                }
            }
        }
    }

    async fn fetch_requested(&self) -> R<Vec<i64>> {
        let limit: Option<i64> = if self.max_concurrent_scan > 0 {
            let running = self.scan_state.count_scans_in_state("running").await?;
            Some(if running > self.max_concurrent_scan {
                0
            } else {
                (self.max_concurrent_scan - running) as i64
            })
        } else {
            None
        };
        let ids = self
            .scan_state
            .fetch_scans_in_state("requested", limit)
            .await?;

        Ok(ids)
    }

    async fn is_feed_sync_in_progress(&self) -> bool {
        self.feed_sync_in_progress
            .read()
            .await
            .is_feed_sync_in_progress()
    }

    async fn set_to_running(&self, id: i64) -> R<()> {
        let running = self
            .scan_state
            .change_state(id, "requested", "running")
            .await?;

        let mut tx = self.pool.begin().await?;
        let scan = super::get_scan(&mut tx, self.cryptor.as_ref(), id).await?;
        tx.commit().await?;

        tracing::info!(id, running, "Started scan");

        self.scan_start(id, scan).await;
        Ok(())
    }

    /// Checks for scans that are requested and may start them
    ///
    /// After verifying concurrently running scans it starts a scan when the scan was started
    /// successfully than it sets it to 'running', if the start fails then it sets it to failed.
    ///
    /// In the case that the ScanStarter implementation blocks start_scan is spawned as a
    /// background task.
    async fn requested_to_running(&self) -> R<()> {
        if self.is_feed_sync_in_progress().await {
            tracing::trace!("Skipping to set new scans to running because of feed sync.");
            return Ok(());
        }

        let ids = self.fetch_requested().await?;
        for id in ids {
            // To prevent accidental state change from running -> requested based on an old
            // snapshot we only do a resource when a scan has not already been started.
            if !self.scanner.can_start_scan().await {
                break;
            }

            self.set_to_running(id).await?;
        }

        Ok(())
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
        let previous_status = self.scan_state.scan_get_status(internal_id).await?;
        let status = match &kind {
            ScanResultKind::StatusOverride => results.status,
            // TODO: refactor on StatusAddition to do that within SQL directly instead of get mut
            ScanResultKind::StatusAddition => {
                results.status.update_with(&previous_status);
                results.status
            }
        };

        self.scan_state
            .scan_update_status(internal_id, &status)
            .await?;
        if status.is_done() {
            tracing::info!(internal_id, scan_id, status=%status.status, "Scan is finished.");
            if let Err(error) = self.scanner_delete_scan(internal_id, scan_id).await {
                tracing::debug!(internal_id, %error, "It may be that the scanner self deleted the scan on finish.");
            }
        }
        Ok(())
    }

    async fn import_results(&self) -> R<()> {
        let scans = self
            .scan_state
            .fetch_scans_in_state("running", None)
            .await?;

        for id in scans {
            let scan_id = query_scalar("SELECT scan_id FROM client_scan_map WHERE id = ?")
                .bind(id)
                .fetch_one(&self.pool)
                .await?;
            if let Err(error) = self.scan_import_results(id, scan_id).await {
                // we don't return error here as other imports may succeed
                tracing::warn!(id, %error, "Unable to import results of scan.");
            }
        }

        Ok(())
    }

    async fn scanner_delete_scan(&self, internal_id: i64, scan_id: String) -> R<()> {
        tracing::debug!(internal_id, scan_id, "deleting scan from scanner");
        self.scanner.delete_scan(scan_id).await?;
        Ok(())
    }

    async fn scan_stop(&self, id: i64) -> R<()> {
        let scan_id: String = query_scalar("SELECT scan_id FROM client_scan_map WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        self.scan_import_results(id, scan_id.clone()).await?;
        self.scanner.stop_scan(scan_id.clone()).await?;

        let changed = self
            .scan_state
            .change_state(id, "running", "stopped")
            .await?;
        tracing::debug!(changed, id, "Changed scan from running to stopped");

        Ok(())
    }

    async fn on_user_action(&self, message: &Message) -> R<()> {
        match message {
            Message::Start(id) => self.scan_stored_to_requested(id.parse()?).await?,
            Message::Stop(id) => self.scan_stop(id.parse()?).await?,
        };
        Ok(())
    }

    async fn on_feed_action(
        &self,
        message: &orchestrator::FeedStatusChange,
    ) -> R<Option<Vec<orchestrator::Allow>>> {
        let msg = message.clone();
        self.feed_sync_in_progress
            .write()
            .await
            .set_based_on_message(&msg);
        let result = match message {
            FeedStatusChange::Need(_) => {
                let count_running: i64 = self.get_running_count().await;
                if count_running == 0 {
                    Some(self.feed_sync_in_progress.write().await.approve())
                } else {
                    None
                }
            }
            FeedStatusChange::Synced(ft) => {
                let scans_allowed = self.feed_sync_in_progress.read().await.scans_allowed();
                tracing::info!(allowing_new_scans=scans_allowed, feed=?ft, "Synchronized");
                None
            }
        };

        Ok(result)
    }

    async fn get_running_count(&self) -> i64 {
        match query_scalar("SELECT count(id) FROM scans WHERE status = 'running'")
            .fetch_one(&self.pool)
            .await
        {
            Ok(x) => x,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Unable to count running scans, still preventing start of new scans"
                );
                1
            }
        }
    }

    async fn contains_need(&self) -> bool {
        self.feed_sync_in_progress.read().await.contains_need()
    }

    async fn need_to_allow(&self) -> Vec<orchestrator::Allow> {
        self.feed_sync_in_progress.write().await.approve()
    }

    async fn on_schedule(&self) -> R<Vec<orchestrator::Allow>> {
        if self.contains_need().await {
            let count_running: i64 =
                query_scalar("SELECT count(id) FROM scans WHERE status = 'running'")
                    .fetch_one(&self.pool)
                    .await?;
            if count_running == 0 {
                return Ok(self.need_to_allow().await);
            }
        }
        self.requested_to_running().await?;
        self.import_results().await?;

        Ok(vec![])
    }
}

async fn run_scheduler<S, E>(
    check_interval: std::time::Duration,
    scheduler: ScanScheduler<S, E>,
    feed: orchestrator::Communicator,
) -> R<mpsc::Sender<Message>>
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
    let (sender, mut recv) = mpsc::channel(10);
    tokio::spawn(async move {
        let send_allow = async |msgs: Vec<orchestrator::Allow>| {
            for msg in msgs {
                tracing::info!(feed_type=?msg, "Sending feed sync allow.");
                if let Err(error) = feed.approve(msg).await {
                    tracing::warn!(%error, "Unable to send allow message to orchestrator");
                }
            }
        };
        loop {
            tokio::select! {
                Some(msg) = feed.receive_state_changes() => {
                    match scheduler.on_feed_action(&msg).await {
                       Ok(Some(msg)) => {
                            send_allow(msg).await;
                        }
                        Ok(None) => {},
                        Err(error) =>  tracing::warn!(?msg, %error, "Unable to react on feed message"),

                    }


                }
                Some(msg) = recv.recv() => {
                    if let Err(error) = scheduler.on_user_action(&msg).await {
                        tracing::warn!(?msg, %error, "Unable to react on message");
                    }

                }

                _ = interval.tick() => {
                    match scheduler.on_schedule().await {
                        Err(error) => tracing::warn!(%error, "Unable to schedule"),
                        Ok(msgs) => {
                                send_allow(msgs).await;
                        }

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
    feed: orchestrator::Communicator,
) -> R<Sender<Message>>
where
    S: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Send + Sync + 'static,
    E: Crypt + Send + Sync + 'static,
{
    let change_scan_status = ScanStateController::init(pool.clone()).await?;
    let scheduler = ScanScheduler {
        pool,
        cryptor: crypter,
        max_concurrent_scan: config.scheduler.max_queued_scans.unwrap_or(0),
        scanner: Arc::new(scanner),
        feed_sync_in_progress: Arc::new(RwLock::new(IsInProgress::default())),
        scan_state: change_scan_status,
    };

    run_scheduler(config.scheduler.check_interval, scheduler, feed).await
}

pub async fn init<E>(
    pool: SqlitePool,
    crypter: Arc<E>,
    config: &Config,
    feed_status: orchestrator::Communicator,
) -> R<Sender<Message>>
where
    E: Crypt + Send + Sync + 'static,
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
            init_with_scanner(pool, crypter, config, scanner, feed_status).await
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

            init_with_scanner(pool, crypter, config, scanner, feed_status).await
        }
        crate::config::ScannerType::Openvasd => {
            let scanner: Lambda = Lambda::default();
            init_with_scanner(pool, crypter, config, scanner, feed_status).await
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
        crypt::ChaCha20Crypt,
        scans::{
            self,
            tests::{create_pool, prepare_scans},
        },
    };
    type TR = R<()>;

    async fn setup_test_env() -> R<(ScanScheduler<scanner::Lambda, ChaCha20Crypt>, Vec<i64>)> {
        setup_test_env_with_scanner(LambdaBuilder::default()).await
    }

    async fn setup_test_env_with_scanner(
        builder: LambdaBuilder,
    ) -> R<(ScanScheduler<scanner::Lambda, ChaCha20Crypt>, Vec<i64>)> {
        setup_test_env_with_scanner_and_feed_messages(builder, Default::default()).await
    }

    async fn setup_test_env_with_scanner_and_feed_messages(
        builder: LambdaBuilder,
        feed_changes: IsInProgress,
    ) -> R<(ScanScheduler<scanner::Lambda, ChaCha20Crypt>, Vec<i64>)> {
        let (config, pool) = create_pool().await?;
        let scanner = Arc::new(builder.build());
        let cryptor = Arc::new(scans::config_to_crypt(&config));

        let change_scan_status = ScanStateController::init(pool.clone()).await?;
        let under_test = ScanScheduler {
            pool: pool.clone(),
            scanner,
            cryptor,
            max_concurrent_scan: 4,
            feed_sync_in_progress: Arc::new(RwLock::new(feed_changes)),
            scan_state: change_scan_status,
        };
        let known_scans = prepare_scans(pool.clone(), &config).await;
        Ok((under_test, known_scans))
    }

    #[tokio::test]
    async fn start_scan() -> TR {
        let (under_test, known_scans) = setup_test_env().await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
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
                .on_user_action(&Message::Start(id.to_string()))
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
                .on_user_action(&Message::Start(id.to_string()))
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
                .on_user_action(&Message::Start(id.to_string()))
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
    async fn do_not_start_when_scanner_cannot_start_scan() -> TR {
        let (under_test, known_scans) =
            setup_test_env_with_scanner(LambdaBuilder::new().with_can_start(|| false)).await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
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
    async fn do_not_start_on_feed_sync() -> TR {
        let iip = IsInProgress {
            need_approval_nasl: true,
            ..Default::default()
        };
        let (under_test, known_scans) =
            setup_test_env_with_scanner_and_feed_messages(LambdaBuilder::new(), iip).await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
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

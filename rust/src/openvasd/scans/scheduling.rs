// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use fslock::LockFile;
use sqlx::{Connection, SqliteConnection};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use scannerlib::{
    models::FeedType,
    nasl::{builtin::nasl_std_executor, syntax::Loader},
    openvas::{self, cmd},
    osp,
    scanner::{OpenvasdScanner, ScanResultKind, Scanner},
    utils::scanner_types::{self, ScannerType},
};

use crate::database::sqlite::{SqliteDatabase, scan_storage::ScanStorage};
use tokio::{
    sync::mpsc::{self, Sender},
    time::MissedTickBehavior,
};

use crate::{
    config::Config,
    database::sqlite::DataBase,
    vts::orchestrator::{self, FeedStatusChange},
};

const LOCK_FILE: &str = "feed-update.lock";

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
            // A new request always needs a new approval. Without resetting `approved_*` a
            // previous sync that failed (and therefore never sent `Synced`) would leave the
            // approval set forever, so the request would never be approved again and no scan
            // could be started anymore.
            FeedStatusChange::Need(FeedType::Advisories) => {
                self.need_approval_advisories = true;
                self.approved_advisories = false;
            }
            FeedStatusChange::Need(FeedType::NASL) => {
                self.need_approval_nasl = true;
                self.approved_nasl = false;
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

struct ScanScheduler<Scanner> {
    db: Arc<SqliteDatabase>,
    scanner: Arc<Scanner>,
    max_concurrent_scan: usize,
    // we store the need and allow requests in the case of a feed sync
    //
    // On need we know that we actually need to send the allows because we waited for the scans to
    // finish. One allow we just wait for synced.
    // We use the fact that we don't handle products as a differentiation between need and allow
    // otherwise we would need to store two separate lists.
    feed_sync_in_progress: Arc<RwLock<IsInProgress>>,
    lock_file_dir: String,
}

#[derive(Debug)]
pub enum Message {
    Start(String),
    // On Stop we also delete
    Stop(String),
}

#[derive(Debug, thiserror::Error)]
enum LockFileError {
    #[error("Unable to open feed update lock file {path}: {source}")]
    Open {
        path: String,
        source: std::io::Error,
    },
    #[error("Unable to check feed update lock file {path}: {source}")]
    TryLock {
        path: String,
        source: std::io::Error,
    },
    #[error("Unable to unlock feed update lock file {path}: {source}")]
    Unlock {
        path: String,
        source: std::io::Error,
    },
}

impl<T> ScanScheduler<T> {
    /// Should be called on restart if the application crashed while there were running scans.
    ///
    /// This is to safe guard against ghost scans that will never finish.
    async fn running_to_failed(&self) -> anyhow::Result<()> {
        let affected = self
            .db
            .change_scan_state_all(&mut *self.db.conn().await?, "running", "failed")
            .await?;

        if affected > 0 {
            tracing::warn!(
                scans_failed = affected,
                "Set scans to failed from previous runs."
            );
        }
        Ok(())
    }

    async fn scan_to_requested(&self, id: i64) -> anyhow::Result<()> {
        let mut tx = self.db.tx().await?;

        self.db
            .change_scan_state(&mut tx, id, "stored", "requested")
            .await?;
        self.db
            .change_scan_state(&mut tx, id, "stopped", "requested")
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn scan_running_to_failed(
        &self,
        tx: &mut SqliteConnection,
        id: i64,
        reason: &str,
    ) -> anyhow::Result<()> {
        let changed = self
            .db
            .change_scan_state(tx, id, "running", "failed")
            .await?;

        if changed {
            tracing::warn!(id, reason, "Set scan from running to failed.");
        }
        Ok(())
    }
}

fn is_file_locked(path: String) -> anyhow::Result<bool> {
    let mut file = LockFile::open(&path).map_err(|source| LockFileError::Open {
        path: path.clone(),
        source,
    })?;

    if file.try_lock().map_err(|source| LockFileError::TryLock {
        path: path.clone(),
        source,
    })? {
        file.unlock()
            .map_err(|source| LockFileError::Unlock { path, source })?;
        Ok(false)
    } else {
        // locked by another process
        Ok(true)
    }
}

impl<SC> ScanScheduler<SC>
where
    SC: Scanner + Send + Sync + 'static,
{
    async fn start_requested(&self) -> anyhow::Result<()> {
        if self.is_feed_sync_in_progress().await {
            tracing::trace!("Feed sync is in progress. Skipping starting new scans");
            return Ok(());
        }

        if !self.scanner.can_start_scan().await {
            tracing::debug!("Scanner has no resources available to start new scans");
            return Ok(());
        }

        let mut conn = self.db.conn().await?;

        let scans = {
            let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;

            let ids = self.fetch_requested(&mut tx).await?;
            let mut scans = Vec::with_capacity(ids.len());

            for id in ids {
                match self.db.get_scan(&mut tx, id.into()).await {
                    Ok(scan) => {
                        self.db
                            .change_scan_state(&mut tx, id, "requested", "running")
                            .await?;
                        scans.push((id, scan));
                    }
                    Err(e) => {
                        tracing::warn!(id, "Unable to load scan, setting it to failed: {e:#}");
                        self.db
                            .change_scan_state(&mut tx, id, "requested", "failed")
                            .await?;
                    }
                }
            }

            // commit the transaction, requested scans are now either running or failed
            tx.commit().await?;
            scans
        };

        let mut failed = vec![];
        let mut postponed = vec![];
        for (id, scan) in scans {
            if !self.scanner.can_start_scan().await {
                postponed.push(id);
                continue;
            }

            match self.scanner.start_scan(scan).await {
                Ok(()) => tracing::info!(id, "Started scan"),
                Err(e) => {
                    tracing::warn!(id, %e, "Unable to start scan");
                    failed.push(id);
                }
            }
        }

        for id in failed {
            if let Err(e) = self
                .db
                .change_scan_state(&mut conn, id, "running", "failed")
                .await
            {
                tracing::warn!(id, %e,
                    "Unable to set scan to failed, it will be marked as failed on the next result import"
                );
            }
        }

        for id in postponed {
            // Set the scan to requested again and reset its start_time that was set by an SQL TRIGGER
            if let Err(e) = self.db.postpone_scan(&mut conn, id).await {
                tracing::warn!(id, %e,
                    "Unable to postpone scan, it will be marked as failed on the next result import"
                );
            }
        }

        Ok(())
    }

    async fn fetch_requested(&self, tx: &mut SqliteConnection) -> anyhow::Result<Vec<i64>> {
        let limit: Option<i64> = if self.max_concurrent_scan > 0 {
            let running = self.db.count_scans_in_state(tx, "running").await?;
            Some(if running > self.max_concurrent_scan {
                0
            } else {
                (self.max_concurrent_scan - running) as i64
            })
        } else {
            None
        };
        let ids = self.db.get_scans_in_state(tx, "requested", limit).await?;

        Ok(ids)
    }

    async fn is_feed_sync_in_progress(&self) -> bool {
        self.feed_sync_in_progress
            .read()
            .await
            .is_feed_sync_in_progress()
    }

    async fn scan_import_results(
        &self,
        tx: &mut SqliteConnection,
        internal_id: i64,
        scan_id: String,
    ) -> anyhow::Result<()> {
        let mut results = match self.scanner.fetch_results(scan_id.clone()).await {
            Ok(x) => x,
            Err(scannerlib::scanner::Error::ScanNotFound(scan_id)) => {
                let reason = format!("Tried to get results of an unknown scan ({scan_id})");
                return self.scan_running_to_failed(tx, internal_id, &reason).await;
            }
            e => e?,
        };

        let kind = self.scanner.scan_result_status_kind();

        self.db
            .insert_results(&mut *tx, internal_id, results.results)
            .await?;

        let previous_status = self.db.scan_get_status(&mut *tx, internal_id).await?;
        let status = match &kind {
            ScanResultKind::StatusOverride => results.status,
            // TODO: refactor on StatusAddition to do that within SQL directly instead of get mut
            ScanResultKind::StatusAddition => {
                results.status.update_with(&previous_status);
                results.status
            }
        };

        self.db
            .scan_update_status(&mut *tx, internal_id, &status)
            .await?;
        if status.is_done() {
            tracing::info!(internal_id, scan_id, status=%status.status, "Scan is finished.");
            if let Err(error) = self.scanner_delete_scan(internal_id, scan_id).await {
                tracing::debug!(internal_id, %error, "It may be that the scanner self deleted the scan on finish.");
            }
        }

        Ok(())
    }

    async fn import_results(&self) -> anyhow::Result<()> {
        let mut tx = self.db.tx().await?;
        let scans = self.db.get_scans_in_state(&mut tx, "running", None).await?;

        for id in scans {
            let scan_id = self.db.oid_to_id(&mut tx, id).await?;
            if let Err(error) = self.scan_import_results(&mut tx, id, scan_id).await {
                // we don't return error here as other imports may succeed
                tracing::warn!(id, %error, "Unable to import results of scan.");
            }
        }

        tx.commit().await?;

        Ok(())
    }

    async fn scanner_delete_scan(&self, internal_id: i64, scan_id: String) -> anyhow::Result<()> {
        tracing::debug!(internal_id, scan_id, "deleting scan from scanner");
        self.scanner.delete_scan(scan_id).await?;
        Ok(())
    }

    async fn scan_stop(&self, id: i64) -> anyhow::Result<()> {
        let mut tx = self.db.tx().await?;

        let scan_id = self.db.oid_to_id(&mut tx, id).await?;

        let current_status = self.db.scan_get_status(&mut tx, id).await?;
        if current_status.is_stopped() {
            tracing::debug!(id, "Scan already stopped");
            return Ok(());
        }

        self.scan_import_results(&mut tx, id, scan_id.clone())
            .await?;
        self.scanner.stop_scan(scan_id.clone()).await?;

        let changed = self
            .db
            .change_scan_state(&mut tx, id, "running", "stopped")
            .await?;
        tracing::debug!(changed, id, "Changed scan from running to stopped");

        tx.commit().await?;

        Ok(())
    }

    async fn on_user_action(&self, message: &Message) -> anyhow::Result<()> {
        match message {
            Message::Start(id) => self.scan_to_requested(id.parse()?).await?,
            Message::Stop(id) => self.scan_stop(id.parse()?).await?,
        };
        Ok(())
    }

    async fn on_feed_action(
        &self,
        message: &orchestrator::FeedStatusChange,
    ) -> anyhow::Result<Option<Vec<orchestrator::Allow>>> {
        let msg = message.clone();
        self.feed_sync_in_progress
            .write()
            .await
            .set_based_on_message(&msg);
        let result = match message {
            FeedStatusChange::Need(_) => {
                let mut conn = self.db.conn().await?;
                let count_running =
                    self.db.count_scans_in_state(&mut conn, "running").await? as i64;
                let is_file_locked = {
                    let mut lockfile = PathBuf::from(self.lock_file_dir.clone());
                    lockfile.push(LOCK_FILE);
                    is_file_locked(lockfile.to_string_lossy().to_string())?
                };
                if self.scan_type() == ScannerType::Openvas && !is_file_locked {
                    Some(self.feed_sync_in_progress.write().await.approve())
                } else if (self.scan_type() == ScannerType::Openvas && is_file_locked)
                    || count_running > 0
                {
                    None
                } else {
                    Some(self.feed_sync_in_progress.write().await.approve())
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

    async fn contains_need(&self) -> bool {
        self.feed_sync_in_progress.read().await.contains_need()
    }

    async fn need_to_allow(&self) -> Vec<orchestrator::Allow> {
        self.feed_sync_in_progress.write().await.approve()
    }

    async fn on_schedule(&self) -> anyhow::Result<Vec<orchestrator::Allow>> {
        if self.contains_need().await {
            let count_running = self
                .db
                .count_scans_in_state(&mut *self.db.conn().await?, "running")
                .await?;

            let filelocked = {
                let mut lockfile = PathBuf::from(self.lock_file_dir.clone());
                lockfile.push(LOCK_FILE);
                is_file_locked(lockfile.to_string_lossy().to_string())?
            };

            if count_running == 0 || (self.scan_type() == ScannerType::Openvas && !filelocked) {
                return Ok(self.need_to_allow().await);
            }
        }

        if let Err(e) = self.start_requested().await {
            tracing::warn!("failed to start requested scans: {e:#}");
        }

        self.import_results().await?;

        Ok(vec![])
    }

    fn scan_type(&self) -> ScannerType {
        self.scanner.scanner_type()
    }
}

async fn run_scheduler<S>(
    check_interval: std::time::Duration,
    scheduler: ScanScheduler<S>,
    feed: orchestrator::Communicator,
) -> anyhow::Result<mpsc::Sender<Message>>
where
    S: Scanner + Send + Sync + 'static,
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
                tracing::debug!(feed_type=?msg, "Sending feed sync allow.");
                feed.approve(msg).await?;
            }
            Ok::<(), orchestrator::CommunicationIssues>(())
        };
        loop {
            tokio::select! {
                Some(msg) = feed.receive_state_changes() => {
                    match scheduler.on_feed_action(&msg).await {
                        Ok(Some(msg)) => {
                            if let Err(error) = send_allow(msg).await {
                                tracing::warn!(%error, "Unable to send allow message to orchestrator");
                                break;
                            }
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
                            if let Err(error) = send_allow(msgs).await {
                                tracing::warn!(%error, "Unable to send allow message to orchestrator");
                                break;
                            }
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

pub(super) async fn init_with_scanner<S>(
    config: &Config,
    scanner: S,
    feed: orchestrator::Communicator,
) -> anyhow::Result<Sender<Message>>
where
    S: Scanner + Send + Sync + 'static,
{
    let scheduler = ScanScheduler {
        db: SqliteDatabase::init(&config.storage.to_sqlite_cfg(), "openvasd").await?,
        max_concurrent_scan: config.scheduler.max_queued_scans.unwrap_or(0),
        scanner: Arc::new(scanner),
        feed_sync_in_progress: Arc::new(RwLock::new(IsInProgress::default())),
        lock_file_dir: config.feed.lock_file_dir().to_string_lossy().to_string(),
    };

    run_scheduler(config.scheduler.check_interval, scheduler, feed).await
}

fn openvas_scanner(config: &Config, sudo: bool, redis_url: String) -> openvas::OpenvasScanner {
    openvas::OpenvasScanner::new(
        config.scheduler.min_free_mem,
        None, // cpu_option are not available currently
        sudo,
        redis_url,
        config.scanner.preferences.clone(),
    )
}

pub async fn init(
    pool: DataBase,
    config: &Config,
    feed_status: orchestrator::Communicator,
) -> anyhow::Result<Sender<Message>> {
    match config.scanner.scanner_type {
        scanner_types::ScannerType::Ospd => {
            //TODO: when in notus don't start scheduler at all
            if !config.scanner.ospd.socket.exists()
                && config.mode != crate::config::Mode::ServiceNotus
            {
                tracing::warn!(
                    "OSPD socket {} does not exist. Some commands will not work until the socket is created!",
                    config.scanner.ospd.socket.display()
                );
            }
            let scanner = osp::OspScanner::new(
                config.scanner.ospd.socket.clone(),
                config.scanner.ospd.read_timeout,
            );
            init_with_scanner(config, scanner, feed_status).await
        }
        scanner_types::ScannerType::Openvas => {
            let redis_url = cmd::get_redis_socket().await;
            let scanner = openvas_scanner(config, cmd::check_sudo(), redis_url);

            init_with_scanner(config, scanner, feed_status).await
        }
        scanner_types::ScannerType::Openvasd => {
            let loader = Loader::from_feed_path(&config.feed.path);
            let executor = nasl_std_executor();
            let notus = config
                .notus
                .url
                .clone()
                .map(scannerlib::nasl::utils::ctx::NotusCtx::Address);
            let storage = ScanStorage::new(
                pool.clone(),
                config.feed.path.clone(),
                config.feed.signature_check,
            );
            let scanner = OpenvasdScanner::new(storage, loader, executor, notus);
            init_with_scanner(config, scanner, feed_status).await
        }
        _ => panic!("Invalid Scanner type"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;

    use scannerlib::{
        models::{self, Status},
        scanner::{self, ScanResults, TestScannerBuilder, preferences::preference::ScanPrefValue},
    };
    use sqlx::query_scalar;

    use super::*;
    use crate::{
        database::sqlite::DbGuard,
        scans::tests::{create_test_env, prepare_scans},
    };

    async fn setup_test_env()
    -> anyhow::Result<(ScanScheduler<scanner::TestScanner>, Vec<i64>, DbGuard)> {
        setup_test_env_with_scanner(TestScannerBuilder::default()).await
    }

    async fn setup_test_env_with_scanner(
        builder: TestScannerBuilder,
    ) -> anyhow::Result<(ScanScheduler<scanner::TestScanner>, Vec<i64>, DbGuard)> {
        setup_test_env_with_scanner_and_feed_messages(builder, Default::default()).await
    }

    async fn setup_test_env_with_scanner_and_feed_messages(
        builder: TestScannerBuilder,
        feed_changes: IsInProgress,
    ) -> anyhow::Result<(ScanScheduler<scanner::TestScanner>, Vec<i64>, DbGuard)> {
        let (config, pool, guard) = create_test_env().await?;
        let scanner = Arc::new(builder.build());

        let under_test = ScanScheduler {
            db: SqliteDatabase::init(&config.storage.to_sqlite_cfg(), "openvasd").await?,
            scanner,
            max_concurrent_scan: 4,
            feed_sync_in_progress: Arc::new(RwLock::new(feed_changes)),
            lock_file_dir: String::new(),
        };
        let known_scans = prepare_scans(pool.clone(), &config).await;
        Ok((under_test, known_scans, guard))
    }

    #[test]
    fn openvas_scanner_uses_configured_preferences() {
        let mut config = Config::default();
        config.scanner.preferences = HashMap::from([
            ("safe_checks".to_string(), ScanPrefValue::Bool(false.into())),
            ("plugins_timeout".to_string(), ScanPrefValue::Int(11)),
        ]);

        let scanner = openvas_scanner(&config, false, "redis://localhost".to_string());

        assert_eq!(scanner.scan_preferences(), &config.scanner.preferences);
    }

    #[tokio::test]
    async fn start_scan() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) = setup_test_env().await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(under_test.db.pool())
            .await?;
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "requested").count(),
            status.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn run_scans() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) = setup_test_env().await?;
        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(under_test.db.pool())
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "running").count(),
            under_test.max_concurrent_scan
        );
        let start_times: Vec<i64> =
            query_scalar("SELECT start_time FROM scans WHERE status = 'running'")
                .fetch_all(under_test.db.pool())
                .await?;
        assert_eq!(
            start_times.iter().filter(|x| x > &&0).count(),
            start_times.len()
        );

        Ok(())
    }

    pub(crate) fn scanner_succeeded() -> TestScannerBuilder {
        TestScannerBuilder::new().with_fetch(|id| {
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
    async fn reflect_status_phase_of_scan() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) =
            setup_test_env_with_scanner(scanner_succeeded()).await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(under_test.db.pool())
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "succeeded").count(),
            under_test.max_concurrent_scan
        );

        let end_times: Vec<i64> =
            query_scalar("SELECT end_time FROM scans WHERE status = 'succeeded'")
                .fetch_all(under_test.db.pool())
                .await?;
        assert_eq!(
            end_times.iter().filter(|x| x > &&0).count(),
            end_times.len()
        );
        let result_count: i64 = query_scalar("SELECT count(*) FROM results")
            .fetch_one(under_test.db.pool())
            .await?;
        assert_eq!(result_count, (under_test.max_concurrent_scan * 2) as i64);

        Ok(())
    }

    #[tokio::test]
    async fn run_scans_failure() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) = setup_test_env_with_scanner(
            TestScannerBuilder::new()
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
            .fetch_all(under_test.db.pool())
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());

        assert_eq!(
            status.iter().filter(|s| s as &str == "failed").count(),
            under_test.max_concurrent_scan
        );

        let end_times: Vec<i64> =
            query_scalar("SELECT end_time FROM scans WHERE status = 'failed'")
                .fetch_all(under_test.db.pool())
                .await?;
        assert_eq!(
            end_times.iter().filter(|x| x > &&0).count(),
            end_times.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn do_not_start_when_scanner_cannot_start_scan() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) =
            setup_test_env_with_scanner(TestScannerBuilder::new().with_can_start(|| false)).await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(under_test.db.pool())
            .await?;
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "requested").count(),
            status.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn do_not_start_on_feed_sync() -> anyhow::Result<()> {
        let iip = IsInProgress {
            need_approval_nasl: true,
            ..Default::default()
        };
        let (under_test, known_scans, _guard) =
            setup_test_env_with_scanner_and_feed_messages(TestScannerBuilder::new(), iip).await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(under_test.db.pool())
            .await?;
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "requested").count(),
            status.len()
        );

        Ok(())
    }

    #[test]
    fn need_after_failed_sync_is_approved_again() {
        let mut iip = IsInProgress::default();
        iip.set_based_on_message(&FeedStatusChange::Need(FeedType::NASL));
        assert_eq!(iip.approve(), vec![FeedType::NASL]);
        assert!(!iip.scans_allowed());

        // The feed update failed, therefore no `Synced` message was sent. The next feed check
        // requests approval again.
        iip.set_based_on_message(&FeedStatusChange::Need(FeedType::NASL));
        assert!(iip.contains_need());
        assert_eq!(iip.approve(), vec![FeedType::NASL]);

        iip.set_based_on_message(&FeedStatusChange::Synced(FeedType::NASL));
        assert!(iip.scans_allowed());
    }

    #[tokio::test]
    async fn feed_sync_imports_results_but_does_not_start_scans() -> anyhow::Result<()> {
        // need approved -> sync is running, contains_need() is false
        let iip = IsInProgress {
            need_approval_nasl: true,
            approved_nasl: true,
            ..Default::default()
        };
        let (under_test, known_scans, _guard) =
            setup_test_env_with_scanner_and_feed_messages(scanner_succeeded(), iip).await?;

        let (running, requested) = known_scans.split_first().unwrap();
        sqlx::query("UPDATE scans SET status = 'running' WHERE id = ?")
            .bind(running)
            .execute(under_test.db.pool())
            .await?;
        for id in requested {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;

        let mut conn = under_test.db.conn().await?;
        assert_eq!(
            under_test
                .db
                .count_scans_in_state(&mut conn, "succeeded")
                .await?,
            1
        );

        assert_eq!(
            under_test
                .db
                .count_scans_in_state(&mut conn, "requested")
                .await?,
            requested.len()
        );

        assert_eq!(
            under_test
                .db
                .count_scans_in_state(&mut conn, "running")
                .await?,
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn need_is_approved_after_running_scans_finish() -> anyhow::Result<()> {
        let iip = IsInProgress {
            need_approval_nasl: true,
            ..Default::default()
        };
        let (mut under_test, known_scans, _guard) =
            setup_test_env_with_scanner_and_feed_messages(scanner_succeeded(), iip).await?;
        // on_schedule checks the feed lock file, keep it out of the working directory
        let lock_dir = tempfile::tempdir()?;
        under_test.lock_file_dir = lock_dir.path().to_string_lossy().to_string();

        sqlx::query("UPDATE scans SET status = 'running' WHERE id = ?")
            .bind(known_scans[0])
            .execute(under_test.db.pool())
            .await?;

        // a scan is running -> need is not approved, but its results must be imported
        assert!(under_test.on_schedule().await?.is_empty());
        assert_eq!(
            under_test
                .db
                .count_scans_in_state(&mut *under_test.db.conn().await?, "running")
                .await?,
            0
        );

        // nothing is running anymore -> need gets approved
        assert_eq!(under_test.on_schedule().await?, vec![FeedType::NASL]);
        Ok(())
    }

    #[tokio::test]
    async fn postpone_scans_when_resources_run_out() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 1st call: check before picking, 2nd: first scan, after that: no resources
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let (under_test, known_scans, _guard) = setup_test_env_with_scanner(
            TestScannerBuilder::new().with_can_start(move || c.fetch_add(1, Ordering::SeqCst) < 2),
        )
        .await?;
        for id in &known_scans {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }

        under_test.on_schedule().await?;
        let mut conn = under_test.db.conn().await?;
        assert_eq!(
            under_test
                .db
                .count_scans_in_state(&mut conn, "running")
                .await?,
            1
        );
        assert_eq!(
            under_test
                .db
                .count_scans_in_state(&mut conn, "failed")
                .await?,
            0
        );
        assert_eq!(
            under_test
                .db
                .count_scans_in_state(&mut conn, "requested")
                .await?,
            known_scans.len() - 1
        );

        let stale_start_times: i64 = query_scalar(
            "SELECT count(*) FROM scans WHERE status = 'requested' AND start_time IS NOT NULL",
        )
        .fetch_one(&mut *conn)
        .await?;
        assert_eq!(stale_start_times, 0);
        Ok(())
    }

    #[tokio::test]
    async fn unloadable_scan_fails_without_blocking_others() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) = setup_test_env().await?;
        for id in &known_scans {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }

        // corrupt credentials -> get_scan fails on decrypt
        let broken = *known_scans.iter().min().unwrap();
        sqlx::query("UPDATE scans SET auth_data = 'garbage' WHERE id = ?")
            .bind(broken)
            .execute(under_test.db.pool())
            .await?;

        under_test.on_schedule().await?;
        let status: String = query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(broken)
            .fetch_one(under_test.db.pool())
            .await?;
        assert_eq!(status, "failed");

        let mut conn = under_test.db.conn().await?;
        assert_eq!(
            under_test
                .db
                .count_scans_in_state(&mut conn, "running")
                .await?,
            under_test.max_concurrent_scan - 1
        );

        // next tick fills the freed slot
        under_test.on_schedule().await?;

        assert_eq!(
            under_test
                .db
                .count_scans_in_state(&mut conn, "running")
                .await?,
            under_test.max_concurrent_scan
        );
        Ok(())
    }
}

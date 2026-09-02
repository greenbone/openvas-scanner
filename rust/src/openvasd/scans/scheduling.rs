// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use fslock::LockFile;
use sqlx::{Sqlite, Transaction};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use scannerlib::{
    models::{self, FeedType},
    nasl::{builtin::nasl_std_executor, syntax::Loader},
    openvas::{self, cmd},
    osp,
    scanner::{OpenvasdScanner, Scanner, preferences},
    utils::scanner_types::{self, ScannerType},
};

use crate::database::sqlite::{SqliteDatabase, scan_storage::ScanStorage};
use tokio::{
    sync::mpsc::{self, Sender},
    time::MissedTickBehavior,
};

use crate::{
    config::Config,
    database::{dao::RetryExec, sqlite::results::DBResults},
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

struct ScanScheduler<Scanner> {
    db: SqliteDatabase,
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
        let affected = sqlx::query("UPDATE scans SET status = 'failed' WHERE status = 'running'")
            .execute(self.db.pool())
            .await?
            .rows_affected();

        if affected > 0 {
            tracing::warn!(
                scans_failed = affected,
                "Set scans to failed from previous runs."
            );
        }
        Ok(())
    }

    async fn scan_to_requested(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE scans SET status = 'requested' WHERE id = ? AND (status = 'stored' OR status = 'stopped')",
        )
        .bind(id)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    async fn scan_running_to_failed(&self, id: i64, reason: &str) -> anyhow::Result<()> {
        let changed =
            sqlx::query("UPDATE scans SET status = 'failed' WHERE id = ? AND status = 'running'")
                .bind(id)
                .execute(self.db.pool())
                .await?
                .rows_affected()
                != 0;

        if changed {
            tracing::warn!(id, reason, "Set scan from running to failed.");
        }
        Ok(())
    }

    async fn scan_insert_results(
        &self,
        id: i64,
        results: Vec<models::Result>,
    ) -> anyhow::Result<()> {
        // TODO: maybe better to use i64 in the impl?
        let id: &str = &id.to_string();
        // TODO: replace
        DBResults::new(&self.db.pool(), (id, &results as &[_]))
            .retry_exec()
            .await?;
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

impl<S> ScanScheduler<S>
where
    S: Scanner + Send + Sync + 'static,
{
    async fn is_feed_sync_in_progress(&self) -> bool {
        self.feed_sync_in_progress
            .read()
            .await
            .is_feed_sync_in_progress()
    }

    /// Checks for scans that are requested and may start them
    ///
    /// After verifying concurrently running scans it starts a scan when the scan was started
    /// successfully than it sets it to 'running', if the start fails then it sets it to failed.
    ///
    /// In the case that the ScanStarter implementation blocks start_scan is spawned as a
    /// background task.
    async fn requested_to_running(&self) -> anyhow::Result<()> {
        if self.is_feed_sync_in_progress().await {
            tracing::trace!("Skipping to set new scans to running because of feed sync.");
            return Ok(());
        }

        let mut tx = self.db.begin().await?;
        let scan_ids: Vec<i64> = sqlx::query_scalar(
            r#"
            SELECT id
            FROM scans
            WHERE status = 'requested'
            LIMIT MAX(
                0,
                ? - (
                    SELECT COUNT(*)
                    FROM scans
                    WHERE status = 'running'
                )
            )"#,
        )
        .bind(self.max_concurrent_scan as i64)
        .fetch_all(&mut *tx)
        .await?;

        for id in scan_ids {
            // To prevent accidental state change from running -> requested based on an old
            // snapshot we only do a resource when a scan has not already been started.
            if !self.scanner.can_start_scan().await {
                break;
            }

            sqlx::query("UPDATE scans SET status = 'running' WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;

            let scan = self.db.get_scan_tx(&mut tx, id).await?;
            match self.scanner.start_scan(scan).await {
                Ok(()) => tracing::info!(id, "Started scan"),
                Err(error) => {
                    tracing::warn!(id, %error, "Unable to start scan");
                    if let Err(error) =
                        sqlx::query("UPDATE scans SET status = 'failed' WHERE id = ?")
                            .bind(id)
                            .execute(&mut *tx)
                            .await
                    {
                        tracing::warn!(
                            id,
                            %error,
                            "Unable to set scan to failed. This scan will be kept in running until restart"
                        );
                    }
                }
            }
        }

        tx.commit().await?;
        Ok(())
    }

    async fn scan_import_results(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        internal_id: i64,
        scan_id: String,
    ) -> anyhow::Result<()> {
        let results = match self.scanner.fetch_results(scan_id.clone()).await {
            Ok(x) => x,
            Err(scannerlib::scanner::Error::ScanNotFound(scan_id)) => {
                let reason = format!("Tried to get results of an unknown scan ({scan_id})");
                return self.scan_running_to_failed(internal_id, &reason).await;
            }
            e => e?,
        };

        let kind = self.scanner.scan_result_status_kind();
        let status = self
            .db
            .update_scan_results(tx, internal_id, kind, results)
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
        // TODO: the transaction might not be required here
        let mut tx = self.db.begin().await?;

        let scans: Vec<(i64, String)> =
            sqlx::query_as("SELECT id, scan_id FROM scans WHERE status = 'running'")
                .fetch_all(&mut *tx)
                .await?;

        for (id, scan_id) in scans {
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

    // TODO: stop the conversation between scan_id and scan_oid
    async fn scan_stop(&self, id: i64) -> anyhow::Result<()> {
        let mut tx = self.db.begin().await?;

        let scan_id: Option<String> =
            sqlx::query_scalar("SELECT scan_id FROM scans WHERE id = ? AND status != 'stopped'")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;

        if scan_id.is_some() {
            tracing::debug!(id, "Scan already stopped");
            return Ok(());
        }

        let scan_id = scan_id.unwrap();
        // TODO: why do we have to do this here? aren't all results being imported on the schedule tick anyway?
        self.scan_import_results(&mut tx, id, scan_id.clone())
            .await?;
        self.scanner.stop_scan(scan_id.clone()).await?;
        let changed = sqlx::query("UPDATE scans SET status = 'stopped' WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            != 0;

        tx.commit().await?;
        tracing::debug!(changed, id, "Changed scan from running to stopped");

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
                let count_running: i64 = self.get_running_count().await;
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

    async fn get_running_count(&self) -> i64 {
        match sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM scans
            WHERE status = 'running'"#,
        )
        .fetch_one(self.db.pool())
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

    async fn on_schedule(&self) -> anyhow::Result<Vec<orchestrator::Allow>> {
        if self.contains_need().await {
            let count_running = self.get_running_count().await;
            let filelocked = {
                let mut lockfile = PathBuf::from(self.lock_file_dir.clone());
                lockfile.push(LOCK_FILE);
                is_file_locked(lockfile.to_string_lossy().to_string())?
            };
            if count_running == 0 || (self.scan_type() == ScannerType::Openvas && !filelocked) {
                return Ok(self.need_to_allow().await);
            }
        }

        // requesting the scans and importing results are each run in individual transactions
        self.requested_to_running().await?;
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
    db: SqliteDatabase,
    config: &Config,
    scanner: S,
    feed: orchestrator::Communicator,
) -> anyhow::Result<Sender<Message>>
where
    S: Scanner + Send + Sync + 'static,
{
    let scheduler = ScanScheduler {
        db,
        max_concurrent_scan: config.scheduler.max_queued_scans.unwrap_or(0),
        scanner: Arc::new(scanner),
        feed_sync_in_progress: Arc::new(RwLock::new(IsInProgress::default())),
        lock_file_dir: config.feed.lock_file_dir().to_string_lossy().to_string(),
    };

    run_scheduler(config.scheduler.check_interval, scheduler, feed).await
}

pub async fn init(
    db: SqliteDatabase,
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
            init_with_scanner(db, config, scanner, feed_status).await
        }
        scanner_types::ScannerType::Openvas => {
            let redis_url = cmd::get_redis_socket().await;

            let scanner = openvas::OpenvasScanner::new(
                config.scheduler.min_free_mem,
                None, // cpu_option are not available currently
                cmd::check_sudo(),
                redis_url.clone(),
                preferences::preference::PREFERENCES.to_vec(),
            );

            init_with_scanner(db, config, scanner, feed_status).await
        }
        scanner_types::ScannerType::Openvasd => {
            let loader = Loader::from_feed_path(&config.feed.path);
            let executor = nasl_std_executor();
            let notus = config
                .notus
                .url
                .clone()
                .map(scannerlib::nasl::utils::ctx::NotusCtx::Address);
            let storage = ScanStorage::new(db.pool().clone());
            let scanner = OpenvasdScanner::new(storage, loader, executor, notus);
            init_with_scanner(db, config, scanner, feed_status).await
        }
        _ => panic!("Invalid Scanner type"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use scannerlib::{
        models::{self, Status},
        scanner::{self, ScanResults, TestScannerBuilder},
    };
    use sqlx::query_scalar;

    use super::*;
    use crate::scans::tests::{create_pool, prepare_scans};

    async fn setup_test_env() -> anyhow::Result<(ScanScheduler<scanner::TestScanner>, Vec<i64>)> {
        setup_test_env_with_scanner(TestScannerBuilder::default()).await
    }

    async fn setup_test_env_with_scanner(
        builder: TestScannerBuilder,
    ) -> anyhow::Result<(ScanScheduler<scanner::TestScanner>, Vec<i64>)> {
        setup_test_env_with_scanner_and_feed_messages(builder, Default::default()).await
    }

    async fn setup_test_env_with_scanner_and_feed_messages(
        builder: TestScannerBuilder,
        feed_changes: IsInProgress,
    ) -> anyhow::Result<(ScanScheduler<scanner::TestScanner>, Vec<i64>)> {
        let (config, _) = create_pool().await?;
        let db = SqliteDatabase::init(&config).await?;
        let scanner = Arc::new(builder.build());

        let under_test = ScanScheduler {
            db: db.clone(),
            scanner,
            max_concurrent_scan: 4,
            feed_sync_in_progress: Arc::new(RwLock::new(feed_changes)),
            lock_file_dir: String::new(),
        };
        let known_scans = prepare_scans(db).await;
        Ok((under_test, known_scans))
    }

    #[tokio::test]
    async fn start_scan() -> anyhow::Result<()> {
        let (under_test, known_scans) = setup_test_env().await?;

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
        let (under_test, known_scans) = setup_test_env().await?;
        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;

        let mut conn = under_test.db.pool().acquire().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&mut *conn)
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "running").count(),
            under_test.max_concurrent_scan
        );
        let start_times: Vec<i64> =
            query_scalar("SELECT start_time FROM scans WHERE status = 'running'")
                .fetch_all(&mut *conn)
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
        let (under_test, known_scans) = setup_test_env_with_scanner(scanner_succeeded()).await?;
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
        let (under_test, known_scans) = setup_test_env_with_scanner(
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

        let mut conn = under_test.db.pool().acquire().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&mut *conn)
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "failed").count(),
            under_test.max_concurrent_scan
        );

        let end_times: Vec<i64> =
            query_scalar("SELECT end_time FROM scans WHERE status = 'failed'")
                .fetch_all(&mut *conn)
                .await?;
        assert_eq!(
            end_times.iter().filter(|x| x > &&0).count(),
            end_times.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn do_not_start_when_scanner_cannot_start_scan() -> anyhow::Result<()> {
        let (under_test, known_scans) =
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
        let (under_test, known_scans) =
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
}

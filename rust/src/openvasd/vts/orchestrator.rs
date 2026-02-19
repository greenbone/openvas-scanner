use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use greenbone_scanner_framework::GetVTsError;
use greenbone_scanner_framework::models::FeedType;
use scannerlib::models::FeedState;
use scannerlib::{Promise, feed};
use tokio::sync::mpsc;

use crate::vts::FeedHashes;

pub type Allow = FeedType;

#[derive(Debug)]
pub struct Communicator {
    from_orchestrator: Arc<RwLock<mpsc::Receiver<FeedStatusChange>>>,
    to_orchestrator: mpsc::Sender<Allow>,
    needs_approval_advisories: Arc<RwLock<bool>>,
    needs_approval_nasl: Arc<RwLock<bool>>,
}

impl Communicator {
    #[cfg(test)]
    pub fn init() -> (mpsc::Sender<FeedStatusChange>, mpsc::Receiver<Allow>, Self) {
        let (txsc, rx) = mpsc::channel(1);
        let (tx, rxallow) = mpsc::channel(2);
        let me = Self {
            from_orchestrator: Arc::new(tokio::sync::RwLock::new(rx)),
            to_orchestrator: tx,
            needs_approval_advisories: Default::default(),
            needs_approval_nasl: Default::default(),
        };
        (txsc, rxallow, me)
    }
}

#[cfg(test)]
// This is just for test cases don't need an Orchestrator
impl Default for Communicator {
    fn default() -> Self {
        let (_, _, me) = Self::init();
        me
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CommunicationIssues {
    #[error("Trying to approve without request.")]
    NeedsRequest,
    #[error("Receiver is not available.")]
    ReceiverUnavailable,
}

impl Communicator {
    fn new(
        from_orchestrator: mpsc::Receiver<FeedStatusChange>,
        to_orchestrator: mpsc::Sender<Allow>,
    ) -> Self {
        Self {
            from_orchestrator: Arc::new(tokio::sync::RwLock::new(from_orchestrator)),
            to_orchestrator,
            needs_approval_advisories: Default::default(),
            needs_approval_nasl: Default::default(),
        }
    }

    async fn set_false_when_true(b: Arc<RwLock<bool>>) -> bool {
        let mut adv = b.write().await;
        if *adv {
            *adv = false;
            true
        } else {
            false
        }
    }

    async fn toggle_advisories(&self) -> bool {
        Self::set_false_when_true(self.needs_approval_advisories.clone()).await
    }

    async fn toggle_nasl(&self) -> bool {
        Self::set_false_when_true(self.needs_approval_nasl.clone()).await
    }

    pub async fn approve(&self, feed: Allow) -> Result<(), CommunicationIssues> {
        match &feed {
            FeedType::Products => Ok(()),
            FeedType::Advisories if self.toggle_advisories().await => self
                .to_orchestrator
                .send(feed)
                .await
                .map_err(|_| CommunicationIssues::ReceiverUnavailable),
            FeedType::NASL if self.toggle_nasl().await => self
                .to_orchestrator
                .send(feed)
                .await
                .map_err(|_| CommunicationIssues::ReceiverUnavailable),
            _ => Err(CommunicationIssues::NeedsRequest),
        }
    }
    pub async fn receive_state_changes(&self) -> Option<FeedStatusChange> {
        let mut from_orchestrator = self.from_orchestrator.write().await;
        let result = from_orchestrator.recv().await;
        if let Some(fsc) = result.as_ref() {
            match fsc {
                FeedStatusChange::Need(FeedType::Advisories) => {
                    let mut adv = self.needs_approval_advisories.write().await;
                    *adv = true;
                }
                FeedStatusChange::Need(FeedType::NASL) => {
                    let mut nasl = self.needs_approval_nasl.write().await;
                    *nasl = true;
                }
                _ => {}
            }
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedStatusChange {
    // Synced. When all the running scans are finished, it MUST send `Allow` back.
    Need(FeedType),
    // Communicate downstream that the feed is synchronized.
    Synced(FeedType),
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("Unable to fetch cached hash: {0}")]
    Cache(#[from] sqlx::error::Error),
    #[error("Unable to calculate hash: {0}")]
    Calculation(#[from] feed::VerifyError),
    #[error("Unable to synchronize: {0}")]
    Sync(#[from] GetVTsError),
    #[error("Unable to serialize: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Unable to send message. Receiver dropped.")]
    Send,
}

pub trait Worker {
    fn cached_hashes(&self) -> Promise<Result<Option<FeedHashes>, WorkerError>>;

    fn signature_check(&self) -> bool;
    fn plugin_feed(&self) -> PathBuf;
    fn advisory_feed(&self) -> PathBuf;

    fn calculated_hashes(&self) -> Promise<Result<FeedHashes, WorkerError>> {
        let signature_check = self.signature_check();
        let plugin_feed = self.plugin_feed();
        let advisory_feed = self.advisory_feed();
        Box::pin(async move {
            let nasl_hash = Self::calculate_hash(signature_check, plugin_feed).await?;
            let advisories_hash = Self::calculate_hash(signature_check, advisory_feed).await?;
            Ok((nasl_hash, advisories_hash))
        })
    }
    fn update_feed(&self, kind: FeedType, new_hash: String) -> Promise<Result<(), WorkerError>>;

    fn calculate_hash(
        signature_check: bool,
        path: PathBuf,
    ) -> Promise<Result<String, feed::VerifyError>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                if signature_check {
                    scannerlib::feed::check_signature(&path)?;
                }
                super::sumfile_hash(&path)
            })
            .await
            .unwrap()
        })
    }
}

pub struct Orchestrator<W> {
    /// Feed state for the HTTP header
    outer_state: Arc<std::sync::RwLock<FeedState>>,
    receiver: mpsc::Receiver<Allow>,
    sender: mpsc::Sender<FeedStatusChange>,
    worker: Arc<W>,
}

impl<W> Orchestrator<W>
where
    W: Worker + Send + Sync + 'static,
{
    pub(crate) fn new(
        outer_state: Arc<std::sync::RwLock<FeedState>>,
        worker: W,
    ) -> (Communicator, Orchestrator<W>) {
        let (tx, rx) = mpsc::channel(1);
        let (tx2, rx2) = mpsc::channel(1);
        let communicator = Communicator::new(rx, tx2);
        let orc = Orchestrator {
            outer_state,
            worker: Arc::new(worker),
            receiver: rx2,
            sender: tx,
        };
        (communicator, orc)
    }
    pub async fn init(
        interval: Duration,
        outer_state: Arc<std::sync::RwLock<FeedState>>,
        worker: W,
    ) -> Communicator
    where
        W: Worker,
    {
        let (com, orc) = Self::new(outer_state, worker);
        tokio::spawn(async move {
            let mut orc = orc;
            loop {
                match orc.verify().await {
                    Ok(()) => tracing::debug!("Feed checked"),
                    Err(error) => tracing::warn!(%error, "Unable to check feed"),
                }
                tokio::time::sleep(interval).await;
            }
        });
        com
    }
    async fn change_outer_state(&self, state: FeedState) {
        let narf = self.outer_state.clone();
        tokio::task::spawn_blocking(move || {
            let mut out = narf.write().unwrap();
            *out = state;
        })
        .await
        .unwrap();
    }
    pub async fn verify(&mut self) -> Result<(), WorkerError> {
        let cached_hashes = self.worker.cached_hashes().await?;
        let (calc_nasl, calc_advisories) = self.worker.calculated_hashes().await?;
        let send_need = async |kind| {
            tracing::info!(?kind, "Sending feed sync request.");
            self.sender
                .send(FeedStatusChange::Need(kind))
                .await
                .map_err(|_| WorkerError::Send)
        };
        let send_synced = async |kind| {
            tracing::info!(?kind, "Finished feed synchronization.");
            self.sender
                .send(FeedStatusChange::Synced(kind))
                .await
                .map_err(|_| WorkerError::Send)
        };

        let (sync_nasl, sync_advisories) = match cached_hashes {
            None => (true, true),
            Some((cached_nasl, cached_advisories)) => (
                cached_nasl != calc_nasl,
                cached_advisories != calc_advisories,
            ),
        };

        if !sync_nasl && !sync_advisories {
            // This is necessary for bootstrap when we have vts cached in the DB and restarted
            // openvasd.
            self.change_outer_state(FeedState::Synced(calc_nasl, calc_advisories))
                .await;
            return Ok(());
        }
        if sync_nasl {
            send_need(FeedType::NASL).await?;
        }
        if sync_advisories {
            send_need(FeedType::Advisories).await?;
        }

        let mut nasl_handle = None;
        let mut advisory_handle = None;

        loop {
            // we wait for messages from the scheduler to continue.
            // This can potentially endup in a endless loop/await when there is no scheduler
            // reacting to those messages. But since we don't know how long the already started
            // scans will be running we cannot simply put a timeout onto recv and call it a day.
            // As the consequences of a task that is stuck and never finishing the feed
            // synchronization is rather limited compared to not having a scheduler and thus not
            // being able to scan anything I think it is fine as is.
            match self.receiver.recv().await {
                Some(x) => match x {
                    FeedType::NASL if sync_nasl => {
                        if advisory_handle.is_none() {
                            self.change_outer_state(FeedState::Syncing).await;
                        }
                        let worker = self.worker.clone();
                        let calc_nasl = calc_nasl.clone();
                        nasl_handle = Some(tokio::task::spawn(async move {
                            worker.update_feed(FeedType::NASL, calc_nasl).await
                        }));
                    }
                    FeedType::Advisories if sync_advisories => {
                        if nasl_handle.is_none() {
                            self.change_outer_state(FeedState::Syncing).await;
                        }
                        let worker = self.worker.clone();
                        let calc_advisories = calc_advisories.clone();
                        advisory_handle = Some(tokio::task::spawn(async move {
                            worker
                                .update_feed(FeedType::Advisories, calc_advisories)
                                .await
                        }))
                    }
                    msg => {
                        tracing::warn!(
                            ?msg,
                            sync_nasl,
                            sync_advisories,
                            "Received approval without request."
                        )
                    }
                },
                None => tracing::warn!("Sender dropped."),
            }

            match (
                sync_nasl,
                nasl_handle.is_some(),
                sync_advisories,
                advisory_handle.is_some(),
            ) {
                (true, true, true, true)
                | (false, false, true, true)
                | (true, true, false, false) => break,
                (sync_nasl, nasl_handle, sync_advisories, advisories_handle) => tracing::debug!(
                    sync_nasl,
                    nasl_handle,
                    sync_advisories,
                    advisories_handle,
                    "Continue wairing for Allow message"
                ),
            }
        }

        if let Some(handle) = nasl_handle {
            handle.await.unwrap()?;
            send_synced(FeedType::NASL).await?;
        }
        if let Some(handle) = advisory_handle {
            handle.await.unwrap()?;
            send_synced(FeedType::Advisories).await?;
        }
        self.change_outer_state(FeedState::Synced(calc_nasl, calc_advisories))
            .await;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {

    use super::*;
    struct Yesman {
        cached: Option<FeedHashes>,
        calculated: FeedHashes,
    }

    impl Worker for Yesman {
        fn cached_hashes(&self) -> Promise<Result<Option<FeedHashes>, WorkerError>> {
            let cached = self.cached.clone();
            Box::pin(async move { Ok(cached) })
        }

        fn calculated_hashes(&self) -> Promise<Result<FeedHashes, WorkerError>> {
            let calculated = self.calculated.clone();
            Box::pin(async move { Ok(calculated) })
        }

        fn update_feed(&self, _: FeedType, _: String) -> Promise<Result<(), WorkerError>> {
            Box::pin(async move { Ok(()) })
        }

        fn signature_check(&self) -> bool {
            false
        }

        fn plugin_feed(&self) -> PathBuf {
            PathBuf::default()
        }

        fn advisory_feed(&self) -> PathBuf {
            PathBuf::default()
        }
    }

    pub async fn verify_allowed_for<Worker>(
        worker: Worker,
        snapshot: Arc<std::sync::RwLock<FeedState>>,
        fts: &[FeedType],
    ) -> anyhow::Result<()>
    where
        Worker: super::Worker + Send + Sync + 'static,
    {
        let (communicator, mut orc) = Orchestrator::new(snapshot, worker);
        let expected_wait = fts.len();
        let mut count = 0;

        let ov = tokio::spawn(async move { orc.verify().await });
        while let Some(msg) = communicator.receive_state_changes().await {
            if let FeedStatusChange::Need(ft) = msg {
                communicator.approve(ft).await?;
            }
            if matches!(msg, FeedStatusChange::Synced(_)) {
                count += 1;
            }

            if count == expected_wait {
                break;
            }
        }

        ov.await??;
        Ok(())
    }

    #[tokio::test]
    async fn cached_hash_start() {
        let expected = ("one".to_string(), "two".to_string());
        let outer_state = Arc::new(std::sync::RwLock::new(FeedState::Unknown));
        let worker = Yesman {
            cached: Some(expected.clone()),
            calculated: expected.clone(),
        };
        let (_, mut orc) = Orchestrator::new(outer_state.clone(), worker);
        orc.verify().await.unwrap();
        let outer_state = outer_state.read().unwrap();
        assert!(matches!(&*outer_state, FeedState::Synced(_, _)));
    }

    async fn change_synced_feed_from_to_verify_expectation(
        old: (String, String),
        new: (String, String),
        expected: (Option<&str>, Option<&str>),
    ) {
        let fs = FeedState::Synced(old.0, old.1);
        change_feed_state_from_to_verify_expectation(fs, new, expected).await
    }

    async fn change_feed_state_from_to_verify_expectation(
        fs: FeedState,
        new: (String, String),
        expected: (Option<&str>, Option<&str>),
    ) {
        let outer_state = Arc::new(std::sync::RwLock::new(fs.clone()));
        let worker = Yesman {
            cached: match fs {
                FeedState::Unknown | FeedState::Syncing => None,
                FeedState::Synced(nasl, advisories) => Some((nasl, advisories)),
            },
            calculated: new,
        };
        verify_allowed_for(worker, outer_state.clone(), &[FeedType::NASL])
            .await
            .unwrap();

        let outer_state = outer_state.read().unwrap();
        assert_eq!(outer_state.nasl(), expected.0);
        assert_eq!(outer_state.advisories(), expected.1);
    }

    #[tokio::test]
    async fn new_sync_nasl() {
        let old = ("nasl".to_string(), "two".to_string());
        let new = ("one".to_string(), "two".to_string());
        let expected = (Some("one"), Some("two"));
        change_synced_feed_from_to_verify_expectation(old, new, expected).await;
    }

    #[tokio::test]
    async fn new_sync_advisories() {
        let old = ("one".to_string(), "advisories".to_string());
        let new = ("one".to_string(), "two".to_string());
        let expected = (Some("one"), Some("two"));
        change_synced_feed_from_to_verify_expectation(old, new, expected).await;
    }

    #[tokio::test]
    async fn new_sync() {
        let old = ("nasl".to_string(), "advisories".to_string());
        let new = ("one".to_string(), "two".to_string());
        let expected = (Some("one"), Some("two"));
        change_synced_feed_from_to_verify_expectation(old, new, expected).await;
    }

    #[tokio::test]
    async fn sync_no_old() {
        let new = ("one".to_string(), "two".to_string());
        let expected = (Some("one"), Some("two"));
        change_feed_state_from_to_verify_expectation(FeedState::Unknown, new, expected).await
    }
}

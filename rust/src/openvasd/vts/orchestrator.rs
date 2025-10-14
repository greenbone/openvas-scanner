use std::sync::{Arc, RwLock};
use std::time::Duration;

use greenbone_scanner_framework::GetVTsError;
use greenbone_scanner_framework::models::FeedType;
use scannerlib::models::FeedState;
use scannerlib::{PinBoxFut, feed};
use tokio::sync::broadcast::{self, Receiver, Sender};

use crate::vts::FeedHashes;

// Use message instead of directly FeedStatusChange if we want to add meta data later.
#[derive(Debug, Clone)]
pub struct Message {
    change: FeedStatusChange,
}

impl Message {
    pub fn change(&self) -> &FeedStatusChange {
        &self.change
    }

    pub fn is_need(&self) -> bool {
        matches!(&self.change, FeedStatusChange::Need(_))
    }

    pub fn is_allow(&self) -> bool {
        matches!(&self.change, FeedStatusChange::Allow(_))
    }

    pub fn to_allow(&self) -> Option<Message> {
        match &self.change {
            FeedStatusChange::Need(ft) => Some(Message {
                change: FeedStatusChange::Allow(*ft),
            }),
            _ => None,
        }
    }
}

impl From<FeedStatusChange> for Message {
    fn from(value: FeedStatusChange) -> Self {
        Message { change: value }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedStatusChange {
    // Synced. When all the running scans are finished, it MUST send `Allow` back.
    Need(FeedType),
    // Communicate upstream that we can synchronize a feed
    //
    // This means a scan scheduler should finish running scans while not allowing new scans until
    // Synced.
    Allow(FeedType),
    // Communicate downstream that the feed is synchronized.
    Synced(FeedType),
}

impl FeedStatusChange {
    pub fn feed_type(&self) -> &FeedType {
        match self {
            FeedStatusChange::Need(feed_type)
            | FeedStatusChange::Allow(feed_type)
            | FeedStatusChange::Synced(feed_type) => feed_type,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("Unable to fetch cached hash: {0}")]
    Cache(#[from] sqlx::error::Error),
    #[error("Unable to calculate hash: {0}")]
    Calculation(#[from] feed::VerifyError),
    #[error("Unable to synchronize: {0}")]
    Sync(#[from] GetVTsError),
    #[error("Unable to send message. Receiver dropped.")]
    Send,
}

pub trait Worker {
    fn cached_hashes(&self) -> PinBoxFut<Result<Option<FeedHashes>, WorkerError>>;
    fn calculated_hashes(&self) -> PinBoxFut<Result<FeedHashes, WorkerError>>;
    fn update_feed(&self, kind: FeedType, new_hash: String) -> PinBoxFut<Result<(), WorkerError>>;
}

pub struct Orchestrator<W> {
    /// Feed state for the HTTP header
    outer_state: Arc<RwLock<FeedState>>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    worker: Arc<W>,
}

impl<W> Orchestrator<W>
where
    W: Worker + Send + Sync + 'static,
{
    pub(crate) fn new(
        outer_state: Arc<RwLock<FeedState>>,
        worker: W,
    ) -> (Sender<Message>, Orchestrator<W>) {
        let (tx, rx) = broadcast::channel(2);
        let tx2 = tx.clone();
        let orc = Orchestrator {
            outer_state,
            worker: Arc::new(worker),
            receiver: rx,
            sender: tx2,
        };
        (tx, orc)
    }
    pub async fn init(
        interval: Duration,
        outer_state: Arc<RwLock<FeedState>>,
        worker: W,
    ) -> Sender<Message>
    where
        W: Worker,
    {
        let (tx, orc) = Self::new(outer_state, worker);
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
        tx
    }
    async fn change_outer_state(&self, state: FeedState) {
        let outer_state = self.outer_state.clone();

        tokio::task::spawn_blocking(move || {
            let mut out = outer_state.write().unwrap();
            *out = state;
        })
        .await
        .unwrap();
    }
    pub async fn verify(&mut self) -> Result<(), WorkerError> {
        let cached_hashes = self.worker.cached_hashes().await?;
        let (calc_nasl, calc_advisories) = self.worker.calculated_hashes().await?;
        let send_need = |kind| {
            tracing::info!(?kind, "Sending feed sync request.");
            self.sender
                .send(Message {
                    change: FeedStatusChange::Need(kind),
                })
                .map_err(|_| WorkerError::Send)
        };
        let send_synced = |kind| {
            tracing::info!(?kind, "Finished feed synchronization.");
            self.sender
                .send(Message {
                    change: FeedStatusChange::Synced(kind),
                })
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
            send_need(FeedType::NASL)?;
        }
        if sync_advisories {
            send_need(FeedType::Advisories)?;
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
                Ok(x) => match x.change {
                    FeedStatusChange::Allow(FeedType::NASL) if sync_nasl => {
                        if advisory_handle.is_none() {
                            self.change_outer_state(FeedState::Syncing).await;
                        }
                        let worker = self.worker.clone();
                        let calc_nasl = calc_nasl.clone();
                        nasl_handle = Some(tokio::task::spawn(async move {
                            worker.update_feed(FeedType::NASL, calc_nasl).await
                        }));
                    }
                    FeedStatusChange::Allow(FeedType::Advisories) if sync_advisories => {
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
                        tracing::trace!(
                            ?msg,
                            sync_nasl,
                            sync_advisories,
                            "Ignoring mismatching message."
                        )
                    }
                },
                Err(error) => tracing::trace!(%error, "ignoring missed messages"),
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
            send_synced(FeedType::NASL)?;
        }
        if let Some(handle) = advisory_handle {
            handle.await.unwrap()?;
            send_synced(FeedType::Advisories)?;
        }
        self.change_outer_state(FeedState::Synced(calc_nasl, calc_advisories))
            .await;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {

    use super::*;
    struct BWLer {
        cached: Option<FeedHashes>,
        calculated: FeedHashes,
    }

    impl Worker for BWLer {
        fn cached_hashes(&self) -> PinBoxFut<Result<Option<FeedHashes>, WorkerError>> {
            let cached = self.cached.clone();
            Box::pin(async move { Ok(cached) })
        }

        fn calculated_hashes(&self) -> PinBoxFut<Result<FeedHashes, WorkerError>> {
            let calculated = self.calculated.clone();
            Box::pin(async move { Ok(calculated) })
        }

        fn update_feed(&self, _: FeedType, _: String) -> PinBoxFut<Result<(), WorkerError>> {
            Box::pin(async move { Ok(()) })
        }
    }

    pub async fn verify_allowed_for<Worker>(
        worker: Worker,
        snapshot: Arc<RwLock<FeedState>>,
        fts: &[FeedType],
    ) -> anyhow::Result<()>
    where
        Worker: super::Worker + Send + Sync + 'static,
    {
        let (tx, mut orc) = Orchestrator::new(snapshot, worker);
        let mut recv = tx.subscribe();
        let expected_wait = fts.len();
        let mut count = 0;

        let ov = tokio::spawn(async move { orc.verify().await });
        while let Ok(msg) = recv.recv().await {
            if let Some(answer) = msg.to_allow() {
                count += 1;
                tx.send(answer)?;
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
        let outer_state = Arc::new(RwLock::new(FeedState::Unknown));
        let worker = BWLer {
            cached: Some(expected.clone()),
            calculated: expected.clone(),
        };
        let (_, mut orc) = Orchestrator::new(outer_state.clone(), worker);
        orc.verify().await.unwrap();
        let outer_state = outer_state.read().unwrap();
        assert!(matches!(&*outer_state, FeedState::Synced(_, _)));
    }

    #[tokio::test]
    async fn new_sync_nasl() {
        let old = ("nasl".to_string(), "two".to_string());
        let new = ("one".to_string(), "two".to_string());
        let expected_nasl = Some("one");
        let expected_advisories = Some("two");

        let outer_state = Arc::new(RwLock::new(FeedState::Synced(old.0.clone(), old.1.clone())));
        let worker = BWLer {
            cached: Some(old),
            calculated: new,
        };
        verify_allowed_for(worker, outer_state.clone(), &[FeedType::NASL])
            .await
            .unwrap();

        let outer_state = outer_state.read().unwrap();
        assert_eq!(outer_state.nasl(), expected_nasl);
        assert_eq!(outer_state.advisories(), expected_advisories);
    }

    #[tokio::test]
    async fn new_sync_advisories() {
        let old = ("one".to_string(), "advisories".to_string());
        let new = ("one".to_string(), "two".to_string());
        let expected_nasl = Some("one");
        let expected_advisories = Some("two");

        let outer_state = Arc::new(RwLock::new(FeedState::Synced(old.0.clone(), old.1.clone())));
        let worker = BWLer {
            cached: Some(old),
            calculated: new,
        };

        verify_allowed_for(worker, outer_state.clone(), &[FeedType::Advisories])
            .await
            .unwrap();

        let outer_state = outer_state.read().unwrap();
        assert_eq!(outer_state.nasl(), expected_nasl);
        assert_eq!(outer_state.advisories(), expected_advisories);
    }

    #[tokio::test]
    async fn new_sync() {
        let old = ("nasl".to_string(), "advisories".to_string());
        let new = ("one".to_string(), "two".to_string());
        let expected_nasl = Some("one");
        let expected_advisories = Some("two");

        let outer_state = Arc::new(RwLock::new(FeedState::Synced(old.0.clone(), old.1.clone())));
        let worker = BWLer {
            cached: Some(old),
            calculated: new,
        };

        verify_allowed_for(
            worker,
            outer_state.clone(),
            &[FeedType::Advisories, FeedType::NASL],
        )
        .await
        .unwrap();

        let outer_state = outer_state.read().unwrap();
        assert_eq!(outer_state.nasl(), expected_nasl);
        assert_eq!(outer_state.advisories(), expected_advisories);
    }

    #[tokio::test]
    async fn sync_no_old() {
        let new = ("one".to_string(), "two".to_string());
        let expected_nasl = Some("one");
        let expected_advisories = Some("two");

        let outer_state = Arc::new(RwLock::new(FeedState::Unknown));
        let worker = BWLer {
            cached: None,
            calculated: new,
        };

        verify_allowed_for(
            worker,
            outer_state.clone(),
            &[FeedType::Advisories, FeedType::NASL],
        )
        .await
        .unwrap();

        let outer_state = outer_state.read().unwrap();
        assert_eq!(outer_state.nasl(), expected_nasl);
        assert_eq!(outer_state.advisories(), expected_advisories);
    }
}

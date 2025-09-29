use std::sync::{Arc, RwLock};
use std::time::Duration;

use greenbone_scanner_framework::models::FeedType;
use scannerlib::models::FeedState;
use scannerlib::{ExternalError, PinBoxFut};
use tokio::sync::broadcast::{self, Receiver, Sender};

use crate::vts::{FeedHash, FeedHashes};

// Use message instead of directly FeedStatusChange if we want to add meta data later.
#[derive(Debug, Clone)]
pub struct Message {
    change: FeedStatusChange,
}

#[derive(Debug, Clone)]
enum FeedStatusChange {
    // Communicate downstream that we need to synchronize a feed
    //
    // This means a scan scheduler should finish running scans while not allowing new scans until
    // Synced. When all the o scans are finished then it MUST send Allow back.
    Need(FeedType),
    // Communicate upstream that we can synchronize a feed
    //
    // This means a scan scheduler should finish running scans while not allowing new scans until
    // Synced.
    Allow(FeedType),
    // Communicate downstream that the feed is synchronized.
    Synced(FeedType),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum WorkerError {
    #[error("Unable to fetch cached hash: {0}")]
    Cache(String),
    #[error("Unable to calculate hash: {0}")]
    Calculation(String),
}

pub trait Worker {
    fn cached_hashes(&self) -> PinBoxFut<Result<Option<FeedHashes>, WorkerError>>;
    fn calculated_hashes(&self) -> PinBoxFut<Result<FeedHashes, WorkerError>>;
    fn update_feed(&self, kind: FeedType) -> PinBoxFut<Result<(), WorkerError>>;
}

pub struct Orchestrator<W> {
    /// Feed state for the HTTP header
    outer_state: Arc<RwLock<FeedState>>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    // overhead is minimal and it is easier to change later on
    worker: W,
}

impl<W> Orchestrator<W>
where
    W: Worker + Send + Sync + 'static,
{
    fn _init(outer_state: Arc<RwLock<FeedState>>, worker: W) -> (Sender<Message>, Orchestrator<W>) {
        let (tx, rx) = broadcast::channel(2);
        let tx2 = tx.clone();
        let orc = Orchestrator {
            outer_state,
            worker,
            receiver: rx,
            sender: tx2,
        };
        (tx, orc)
    }
    pub async fn init(
        intervall: Duration,
        outer_state: Arc<RwLock<FeedState>>,
        worker: W,
    ) -> Sender<Message>
    where
        W: Worker,
    {
        let (tx, mut orc) = Self::_init(outer_state, worker);
        tokio::spawn(async move {
            loop {
                match orc.verify().await {
                    Ok(()) => tracing::debug!("Feed checked"),
                    Err(error) => tracing::warn!(%error, "Unable to check feed"),
                }
                tokio::time::sleep(intervall).await;
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
    async fn verify(&mut self) -> Result<(), WorkerError> {
        let cached_hashs = self.worker.cached_hashes().await?;
        let (calc_nasl, calc_advisories) = self.worker.calculated_hashes().await?;
        let send_need = |kind| {
            self.sender
                .send(Message {
                    change: FeedStatusChange::Need(kind),
                })
                .unwrap();
        };
        let send_synced = |kind| {
            self.sender
                .send(Message {
                    change: FeedStatusChange::Synced(kind),
                })
                .unwrap()
        };

        let (sync_nasl, sync_advisories) = match cached_hashs {
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
        dbg!(sync_nasl, sync_advisories);
        //TODO: error handling
        if sync_nasl {
            send_need(FeedType::NASL);
        }
        if sync_advisories {
            send_need(FeedType::Advisories);
        }

        let mut nasl_handle = None;
        let mut advisory_handle = None;
        loop {
            // we wait for messages from the scheduler to abort
            match self.receiver.recv().await {
                Ok(x) => match x.change {
                    FeedStatusChange::Allow(FeedType::NASL) if sync_nasl => {
                        if advisory_handle.is_none() {
                            self.change_outer_state(FeedState::Syncing).await;
                        }
                        nasl_handle = Some(self.worker.update_feed(FeedType::NASL));
                    }
                    FeedStatusChange::Allow(FeedType::Advisories) if sync_advisories => {
                        if nasl_handle.is_none() {
                            self.change_outer_state(FeedState::Syncing).await;
                        }
                        advisory_handle = Some(self.worker.update_feed(FeedType::NASL))
                    }
                    msg => {
                        tracing::trace!(
                            ?msg,
                            sync_nasl,
                            sync_advisories,
                            "Ignoring missmatching message."
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
            handle.await?;
            send_synced(FeedType::NASL);
        }
        if let Some(handle) = advisory_handle {
            handle.await?;
            send_synced(FeedType::Advisories);
        }
        self.change_outer_state(FeedState::Synced(calc_nasl, calc_advisories))
            .await;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use tokio::select;

    use super::*;
    struct BWLer {
        cached: Result<Option<FeedHashes>, WorkerError>,
        calculated: Result<FeedHashes, WorkerError>,
        updated: Result<(), WorkerError>,
    }

    impl Worker for BWLer {
        fn cached_hashes(&self) -> PinBoxFut<Result<Option<FeedHashes>, WorkerError>> {
            let cached = self.cached.clone();
            Box::pin(async move { cached })
        }

        fn calculated_hashes(&self) -> PinBoxFut<Result<FeedHashes, WorkerError>> {
            let calculated = self.calculated.clone();
            Box::pin(async move { calculated })
        }

        fn update_feed(&self, kind: FeedType) -> PinBoxFut<Result<(), WorkerError>> {
            let updated = self.updated.clone();
            Box::pin(async move { updated })
        }
    }

    #[tokio::test]
    async fn initialization() {
        let init_state = Arc::new(RwLock::new(FeedState::Unknown));
        let worker = BWLer {
            cached: Ok(Some(("one".to_string(), "two".to_string()))),
            calculated: Ok(("one".to_string(), "two".to_string())),
            updated: Ok(()),
        };
        let outer_state = Arc::new(RwLock::new(FeedState::Unknown));
        let (tx, mut orc) = Orchestrator::_init(outer_state, worker);
        tokio::spawn(async move {
            let mut rx = tx.subscribe();
            select! {
                messge = rx.recv() => {
                    let msg = messge.unwrap();
                    match msg.change {
                        FeedStatusChange::Need(feed_type) => {tx.send(Message {

                        change: FeedStatusChange::Allow(feed_type),
                        }).unwrap();}
                        FeedStatusChange::Allow(feed_type) => {

                        },
                        FeedStatusChange::Synced(feed_type) => {dbg!(&feed_type); },
                    };

                    dbg!(&msg);
                }

            }
        });
        orc.verify().await.unwrap();
        dbg!(&init_state.read().unwrap());
        todo!()
    }
}

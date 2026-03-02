use std::time::Duration;

use tokio::time::Instant;

use crate::{
    container_image_scanner::scheduling::db::{DataBase, timed_layer::DBTimedLayer},
    database::dao::{Fetch, RetryExec},
};

#[derive(Default, Debug, Copy, Clone)]
pub enum BenchType {
    #[default]
    Download,
    Extraction,
    Scan,
    All,
}

impl From<&str> for BenchType {
    fn from(value: &str) -> Self {
        match value {
            "download" => Self::Download,
            "extraction" => Self::Extraction,
            "all" => Self::All,
            _ => Self::Scan,
        }
    }
}

impl AsRef<str> for BenchType {
    fn as_ref(&self) -> &str {
        match self {
            BenchType::Download => "download",
            BenchType::Extraction => "extraction",
            BenchType::Scan => "scan",
            BenchType::All => "download + extraction + scan",
        }
    }
}

#[derive(Debug, Default)]
pub struct Benched {
    pub kind: BenchType,
    pub micro_seconds: u128,
    pub layer_index: Option<usize>,
}

impl Benched {
    pub fn new(layer_index: Option<usize>, kind: BenchType, micro_seconds: u128) -> Self {
        Self {
            kind,
            micro_seconds,
            layer_index,
        }
    }

    pub fn download(layer_index: usize, duration: &Duration) -> Self {
        Self::new(Some(layer_index), BenchType::Download, duration.as_micros())
    }

    pub fn scan(duration: &Duration) -> Self {
        Self::new(None, BenchType::Scan, duration.as_micros())
    }

    pub fn extraction(layer_index: usize, duration: &Duration) -> Self {
        Self::new(
            Some(layer_index),
            BenchType::Extraction,
            duration.as_micros(),
        )
    }

    pub fn kind(&self) -> BenchType {
        self.kind
    }

    pub fn micro_seconds(&self) -> u128 {
        self.micro_seconds
    }

    pub fn msg(&self) -> String {
        if let Some(layer_index) = self.layer_index {
            format!(
                "layer({}) {} took {}ms",
                layer_index,
                self.kind.as_ref(),
                self.micro_seconds / 1000,
            )
        } else {
            format!(
                "{} took {}ms",
                self.kind.as_ref(),
                self.micro_seconds / 1000,
            )
        }
    }

    pub async fn store(&self, pool: &DataBase, scan_id: &str, image: &str) {
        if let Err(error) = DBTimedLayer::new(pool, (scan_id, image, self))
            .retry_exec()
            .await
        {
            tracing::warn!(?self, %error, "Unable to store. Layer duration lost.")
        }
    }
    pub async fn retrieve(pool: &DataBase, scan_id: &str, image: &str) -> Vec<Benched> {
        let result = DBTimedLayer::new(pool, (scan_id, image)).fetch().await;

        if let Err(error) = &result {
            tracing::warn!(scan_id, image, %error, "Unable to retrieve. Layer duration lost.")
        }
        result.unwrap_or_default()
    }
}

pub struct Measured<T>(Duration, T);

impl<T> Measured<T> {
    pub fn unpack(self) -> (Duration, T) {
        (self.0, self.1)
    }
}

pub async fn measure<F, Out>(f: F) -> Measured<Out>
where
    F: Future<Output = Out>,
{
    let start = Instant::now();
    let result = f.await;
    let elapsed = start.elapsed();
    Measured(elapsed, result)
}

pub async fn measure_result<F, OK, ERR>(f: F) -> Result<Measured<OK>, ERR>
where
    F: Future<Output = Result<OK, ERR>>,
{
    let start = Instant::now();
    f.await.map(|x| Measured(start.elapsed(), x))
}

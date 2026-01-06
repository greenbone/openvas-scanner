use std::time::Duration;

use sqlx::{SqlitePool, query};
use tokio::time::Instant;

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
    kind: BenchType,
    micro_seconds: u128,
    layer_index: Option<usize>,
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
                "layer({}) {} took {}ms ({}μs)",
                layer_index,
                self.kind.as_ref(),
                self.micro_seconds / 1000,
                self.micro_seconds
            )
        } else {
            format!(
                "{} took {}ms ({}μs)",
                self.kind.as_ref(),
                self.micro_seconds / 1000,
                self.micro_seconds
            )
        }
    }

    pub async fn store(&self, pool: &SqlitePool, scan_id: &str, image: &str) {
        if let Err(error) = query(
            r#"INSERT INTO timed_layer (scan_id, image, layer_index, kind, micro_seconds)
            VALUES(?, ?, ?, ?, ?)"#,
        )
        .bind(scan_id)
        .bind(image)
        .bind(self.layer_index.map(|x| x as i64).unwrap_or_default())
        .bind(self.kind.as_ref())
        .bind(self.micro_seconds as i64)
        .execute(pool)
        .await
        {
            tracing::warn!(?self, %error, "Unable to store. Layer duration lost.")
        }
    }
    pub async fn retrieve(pool: &SqlitePool, scan_id: &str, image: &str) -> Vec<Benched> {
        use sqlx::Row;
        let result = query(
            r#"SELECT layer_index, kind, micro_seconds
               FROM timed_layer
               WHERE scan_id = ? AND image = ? "#,
        )
        .bind(scan_id)
        .bind(image)
        .fetch_all(pool)
        .await;

        if let Err(error) = &result {
            tracing::warn!(scan_id, image, %error, "Unable to retrieve. Layer duration lost.")
        }
        result
            .unwrap_or_default()
            .iter()
            .map(|row| Benched {
                kind: BenchType::from(row.get::<&str, _>("kind")),
                // it's very unlikely that we ever reach the duration limit of i64
                micro_seconds: row.get::<i64, _>("micro_seconds") as u128,
                layer_index: Some(row.get::<i64, _>("layer_index") as usize),
            })
            .collect()
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

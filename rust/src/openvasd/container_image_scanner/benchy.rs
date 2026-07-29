use std::time::Duration;

use tokio::time::Instant;

#[derive(Default, Debug, Copy, Clone)]
pub enum BenchType {
    #[default]
    Download,
    Extraction,
    Scan,
    All,
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

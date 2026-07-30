use std::time::Duration;

use tokio::time::Instant;

#[derive(Default, Debug, Copy, Clone)]
pub enum TimingType {
    #[default]
    Download,
    Extraction,
    Scan,
    All,
}

impl AsRef<str> for TimingType {
    fn as_ref(&self) -> &str {
        match self {
            TimingType::Download => "download",
            TimingType::Extraction => "extraction",
            TimingType::Scan => "scan",
            TimingType::All => "download + extraction + scan",
        }
    }
}

#[derive(Debug, Default)]
pub struct Timing {
    kind: TimingType,
    micro_seconds: u128,
    layer_index: Option<usize>,
}

impl Timing {
    pub fn new(layer_index: Option<usize>, kind: TimingType, micro_seconds: u128) -> Self {
        Self {
            kind,
            micro_seconds,
            layer_index,
        }
    }

    pub fn download(layer_index: usize, duration: &Duration) -> Self {
        Self::new(
            Some(layer_index),
            TimingType::Download,
            duration.as_micros(),
        )
    }

    pub fn scan(duration: &Duration) -> Self {
        Self::new(None, TimingType::Scan, duration.as_micros())
    }

    pub fn extraction(layer_index: usize, duration: &Duration) -> Self {
        Self::new(
            Some(layer_index),
            TimingType::Extraction,
            duration.as_micros(),
        )
    }

    pub fn kind(&self) -> TimingType {
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

pub struct Timed<T>(Duration, T);

impl<T> Timed<T> {
    pub fn unpack(self) -> (Duration, T) {
        (self.0, self.1)
    }

    pub async fn measure<F>(f: F) -> Timed<T>
    where
        F: Future<Output = T>,
    {
        let start = Instant::now();
        let result = f.await;
        let elapsed = start.elapsed();
        Timed(elapsed, result)
    }

    pub async fn measure_result<F, ERR>(f: F) -> Result<Timed<T>, ERR>
    where
        F: Future<Output = Result<T, ERR>>,
    {
        let start = Instant::now();
        f.await.map(|x| Timed(start.elapsed(), x))
    }
}

use std::{collections::HashMap, io::Write, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::{Level, metadata::ParseLevelError};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt};

struct EnsureCrlf<W: Write>(W);

impl<W: Write> Write for EnsureCrlf<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf);
        let fixed = s.replace("\n", "\r\n").replace("\r\r\n", "\r\n");
        self.0.write_all(fixed.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SerLevel(Level);

impl Default for SerLevel {
    fn default() -> Self {
        Self(Level::INFO)
    }
}

impl FromStr for SerLevel {
    type Err = ParseLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Level::from_str(s).map(SerLevel)
    }
}

impl From<Level> for SerLevel {
    fn from(level: Level) -> Self {
        SerLevel(level)
    }
}

impl From<SerLevel> for Level {
    fn from(ser_level: SerLevel) -> Self {
        ser_level.0
    }
}

impl Serialize for SerLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for SerLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Level::from_str(&s)
            .map(SerLevel)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct Logging {
    pub level: SerLevel,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub additional: HashMap<String, SerLevel>,
}

impl Logging {
    pub fn init(&self) -> WorkerGuard {
        let mut filter = filter::Targets::new().with_default(Level::from(self.level));
        for (name, level) in self.additional.iter() {
            filter = filter.with_target(name, Level::from(*level));
        }
        let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
        let layer = tracing_subscriber::fmt::layer()
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NONE)
            .with_writer(move || EnsureCrlf(non_blocking.clone()));
        tracing_subscriber::registry()
            .with(layer)
            .with(filter)
            .init();
        guard
    }
}

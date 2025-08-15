use serde::{Deserialize, Deserializer, Serializer};
use std::time::Duration;

/// Deserialize a duration from a string like "1s", "500ms", etc.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse(&s).map_err(serde::de::Error::custom)
}

/// Serialize a duration into a string like "1s", "500ms", etc.
pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = format_duration(duration);
    serializer.serialize_str(&s)
}

/// Parses duration from String
pub fn parse(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let value: String = s.chars().take_while(|c| c.is_numeric()).collect();
    let value: u64 = value
        .parse()
        .map_err(|_| format!("Invalid number in duration: {s}"))?;
    let unit_part: String = s.chars().skip_while(|c| c.is_numeric()).collect();

    #[allow(clippy::type_complexity)]
    let supported_units: &[(&'static str, Box<dyn Fn(u64) -> Duration>)] = &[
        ("ns", Box::new(Duration::from_nanos)),
        ("us", Box::new(Duration::from_micros)),
        ("µs", Box::new(Duration::from_micros)),
        ("ms", Box::new(Duration::from_millis)),
        ("s", Box::new(Duration::from_secs)),
    ];
    for (u, f) in supported_units {
        if u == &unit_part.as_str() {
            return Ok(f(value));
        }
    }
    let supported_units = supported_units
        .iter()
        .map(|(k, _)| k)
        .fold(String::default(), |a, b| format!("{a}, {b}"));
    Err(format!(
        "Unknown duration unit '{unit_part}' only '{supported_units}' are supported",
    ))
}

fn format_duration(duration: &Duration) -> String {
    if duration.as_nanos() % 1_000 == 0 {
        let ms = duration.as_millis();
        if ms % 1000 == 0 {
            format!("{}s", ms / 1000)
        } else {
            format!("{ms}ms")
        }
    } else {
        format!("{}ns", duration.as_nanos())
    }
}

// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::time::Duration;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

/// Deserialize a duration from either:
/// - A string like "1s", "500ms", etc.
/// - An object with secs and nanos fields (for backward compatibility)
pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    struct DurationVisitor;

    impl<'de> Visitor<'de> for DurationVisitor {
        type Value = Duration;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter
                .write_str("a duration string like '1s' or an object with secs and nanos fields")
        }

        fn visit_str<E>(self, value: &str) -> Result<Duration, E>
        where
            E: de::Error,
        {
            parse(value).map_err(de::Error::custom)
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let (a, b) = (map.next_entry()?, map.next_entry()?);
            match (a, b) {
                (Some(a), Some(b)) => {
                    let ((k1, v1), (k2, v2)): ((String, u64), (String, u64)) = (a, b);
                    match (&k1 as &str, &k2 as &str) {
                        ("secs", "nanos") => Ok(Duration::new(v1, v2 as u32)),
                        ("nanos", "secs") => Ok(Duration::new(v2, v1 as u32)),
                        (a, b) => Err(serde::de::Error::custom(format!(
                            "unexpected keys {a}, {b}"
                        ))),
                    }
                }
                _ => Err(serde::de::Error::custom("Insufficient data for a Duratio6")),
            }
        }
    }

    deserializer.deserialize_any(DurationVisitor)
}

pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = format_duration(duration);
    serializer.serialize_str(&s)
}

fn parse(s: &str) -> Result<Duration, String> {
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
    if duration.as_nanos().is_multiple_of(1_000) {
        let ms = duration.as_millis();
        if ms.is_multiple_of(1000) {
            format!("{}s", ms / 1000)
        } else {
            format!("{ms}ms")
        }
    } else {
        format!("{}ns", duration.as_nanos())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_string_format() {
        assert_eq!(parse("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn test_deserialize_map_format() {
        let json = r#"{"secs": 3600, "nanos": 500000000}"#;
        let duration: Duration = serde_json::from_str(json).unwrap();
        assert_eq!(duration, Duration::new(3600, 500_000_000));
    }
}

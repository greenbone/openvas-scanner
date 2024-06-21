// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines time implementation for storage usages

/// Is an extension to add as_timestamp method for various types
pub trait AsUnixTimeStamp {
    /// Returns a i64 unix time stamp when parseable otherwise None
    fn as_timestamp(&self) -> Option<i64>;
}

use time::{format_description, OffsetDateTime};

// the function panics because the support formats are hardcoded and therefore the user cannot change anything
fn parse_or_panic(input: &str) -> Vec<time::format_description::FormatItem> {
    match format_description::parse(input) {
        Ok(x) => x,
        Err(e) => panic!("expected {input} to be parsable: {e:?}"),
    }
}

// for more information see:
// https://time-rs.github.io/book/api/format-description.html
const SUPPORTED_FORMATS: &[&str] = &[
"[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour][offset_minute]",
"[weekday repr:short] [month repr:short] [day] [hour]:[minute]:[second] [year] [offset_hour][offset_minute]",
"[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] [offset_hour][offset_minute]",
];

impl AsUnixTimeStamp for String {
    fn as_timestamp(&self) -> Option<i64> {
        (self as &str).as_timestamp()
    }
}

impl AsUnixTimeStamp for &str {
    fn as_timestamp(&self) -> Option<i64> {
        let to_parse = {
            // transforms `wanted (....)` to wanted
            self.splitn(2, " (")
                .find(|x| !x.is_empty())
                .unwrap_or_default()
        };

        SUPPORTED_FORMATS
            .iter()
            .map(|x| parse_or_panic(x))
            .filter_map(|x| OffsetDateTime::parse(to_parse, &x).ok())
            .map(|x| x.unix_timestamp())
            .next()
    }
}

#[cfg(test)]
mod tests {
    use super::AsUnixTimeStamp;

    #[test]
    fn date_string() {
        let example = "2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018)";
        assert_eq!(example.as_timestamp(), Some(1536311311));
    }

    #[test]
    fn iso_orientated() {
        let example = "2012-09-23 02:15:34 -0400";
        assert_eq!(example.as_timestamp(), Some(1348380934));
        let example = "2012-09-23 02:15:34 +0400";
        assert_eq!(example.as_timestamp(), Some(1348352134));
    }

    #[test]
    fn something_else() {
        let example = "Fri Feb 10 16:09:30 2023 +0100";
        assert_eq!(example.as_timestamp(), Some(1676041770));
        let example = "Fri, 10 Feb 2023 16:09:30 +0100";
        assert_eq!(example.as_timestamp(), Some(1676041770));
    }
}

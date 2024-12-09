// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL functions regarding isotime.

#[cfg(test)]
mod tests;

use crate::nasl::prelude::*;
use chrono::{Datelike, Months, NaiveDate, NaiveDateTime, TimeDelta};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct IsotimeError(String);

const ISOFORMAT: &str = "yyyymmddThhmmss";
const READABLEFORMAT: &str = "yyyy-mm-dd hh:mm:ss";

fn parse_isotime(time: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(time, "%Y%m%dT%H%M%S").ok()
}

fn parse_readable_time(time: &str) -> Option<NaiveDateTime> {
    if let Ok(time) = NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S") {
        return Some(time);
    }
    if let Ok(time) = NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M") {
        return Some(time);
    }
    if let Some((date, hours)) = time.split_once(" ") {
        if let Ok(date) = NaiveDate::parse_from_str(date, "%Y-%m-%d") {
            if let Ok(hours) = hours.parse::<u32>() {
                if let Some(time) = date.and_hms_opt(hours, 0, 0) {
                    return Some(time);
                }
            }
        }
    }
    if let Ok(date) = NaiveDate::parse_from_str(time, "%Y-%m-%d") {
        // Cannot fail, since we add no time to the date
        return Some(date.and_hms_opt(0, 0, 0).unwrap());
    }

    None
}

fn parse_time(time: &str) -> Result<NaiveDateTime, IsotimeError> {
    if let Some(time) = parse_isotime(time) {
        return Ok(time);
    }
    if let Some(time) = parse_readable_time(time) {
        return Ok(time);
    }
    Err(IsotimeError(format!(
        "The given time is not in the correct isotime ({}) or readable time format ({}): {}",
        ISOFORMAT, READABLEFORMAT, time
    )))
}

#[nasl_function(named(years, days, seconds))]
fn isotime_add(
    time: &str,
    years: Option<i64>,
    days: Option<i64>,
    seconds: Option<i64>,
) -> Result<String, IsotimeError> {
    let mut time = parse_time(time)?;

    if let Some(years) = years {
        if years < 0 {
            time = time - Months::new((-years) as u32 * 12);
        } else {
            time = time + Months::new(years as u32 * 12);
        }
    }

    if let Some(days) = days {
        time += TimeDelta::days(days);
    }

    if let Some(seconds) = seconds {
        time += TimeDelta::seconds(seconds);
    }

    if time.year() < 0 || time.year() > 9999 {
        return Err(IsotimeError(format!(
            "The resulting year is out of range (0000-9999): {}.",
            time.year()
        )));
    }

    Ok(time.format("%Y%m%dT%H%M%S").to_string())
}

#[nasl_function]
fn isotime_is_valid(time: &str) -> bool {
    parse_time(time).is_ok()
}

#[nasl_function]
fn isotime_now() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%S").to_string()
}

#[nasl_function]
fn isotime_print(time: &str) -> Result<String, FnError> {
    Ok(parse_time(time)?.format("%Y-%m-%d %H:%M:%S").to_string())
}

#[nasl_function]
fn isotime_scan(time: &str) -> Result<String, FnError> {
    let time = parse_time(time)?;

    Ok(time.format("%Y%m%dT%H%M%S").to_string())
}

pub struct NaslIsotime;

function_set! {
    NaslIsotime,
    (
        isotime_add,
        isotime_is_valid,
        isotime_now,
        isotime_print,
        isotime_scan
    )
}

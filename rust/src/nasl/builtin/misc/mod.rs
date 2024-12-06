// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL miscellaneous functions

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    thread,
    time::{self, Duration, UNIX_EPOCH},
};

use chrono::{
    self, DateTime, Datelike, FixedOffset, Local, LocalResult, Offset, TimeZone, Timelike, Utc,
};
use nasl_function_proc_macro::nasl_function;
use thiserror::Error;

use crate::nasl::{prelude::*, utils::function::Maybe};
use flate2::{
    read::GzDecoder, read::ZlibDecoder, write::GzEncoder, write::ZlibEncoder, Compression,
};

#[derive(Debug, Error)]
pub enum MiscError {
    #[error("IO Error: {0}")]
    IO(#[from] io::Error),
    #[error("Encountered time before 1970. {0}")]
    TimeBefore1970(String),
}

#[inline]
#[cfg(unix)]
/// Reads 8 bytes from /dev/urandom and parses it to an i64
pub fn random_impl() -> Result<i64, MiscError> {
    let mut rng = File::open("/dev/urandom")?;
    let mut buffer = [0u8; 8];
    rng.read_exact(&mut buffer)
        .map(|_| i64::from_be_bytes(buffer))
        .map_err(|e| e.into())
}

/// NASL function to get random number
#[nasl_function]
fn rand() -> Result<i64, MiscError> {
    random_impl()
}

/// NASL function to get host byte order
#[nasl_function]
fn get_byte_order() -> bool {
    cfg!(target_endian = "little")
}

/// NASL function to convert given number to string
#[nasl_function(named(num))]
fn dec2str(num: i64) -> String {
    num.to_string()
}

/// takes an integer and sleeps the amount of seconds
#[nasl_function]
fn sleep(secs: u64) {
    thread::sleep(Duration::from_secs(secs))
}

/// takes an integer and sleeps the amount of microseconds
#[nasl_function]
fn usleep(micros: u64) {
    thread::sleep(Duration::from_micros(micros))
}

/// Returns the type of given unnamed argument.
// typeof is a reserved keyword, therefore it is prefixed with "nasl_"
#[nasl_function]
fn nasl_typeof(val: NaslValue) -> String {
    match val {
        NaslValue::Null => "undef",
        NaslValue::String(_) => "string",
        NaslValue::Array(_) => "array",
        NaslValue::Dict(_) => "array",
        NaslValue::Boolean(_) => "int",
        NaslValue::Number(_) => "int",
        NaslValue::Data(_) => "data",
        _ => "unknown",
    }
    .into()
}

/// Returns true when the given unnamed argument is null.
#[nasl_function]
fn isnull(val: NaslValue) -> bool {
    matches!(val, NaslValue::Null)
}

/// Returns the seconds counted from 1st January 1970 as an integer.
#[nasl_function]
fn unixtime() -> Result<u64, MiscError> {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|e| MiscError::TimeBefore1970(e.to_string()))
}

/// Compress given data with gzip, when headformat is set to 'gzip' it uses gzipheader.
#[nasl_function(named(data, headformat))]
fn gzip(data: NaslValue, headformat: Option<&str>) -> Option<Vec<u8>> {
    let data = Vec::<u8>::from(data);
    let headformat = headformat.unwrap_or("noheaderformat");
    if headformat.eq_ignore_ascii_case("gzip") {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&data).and_then(|_| e.finish()).ok()
    } else {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(&data).and_then(|_| e.finish()).ok()
    }
}

/// uncompress given data with gzip, when headformat is set to 'gzip' it uses gzipheader.
#[nasl_function(named(data))]
fn gunzip(data: NaslValue) -> Option<String> {
    let data = Vec::<u8>::from(data);
    let mut uncompress = ZlibDecoder::new(&data[..]);
    let mut uncompressed = String::new();
    match uncompress.read_to_string(&mut uncompressed) {
        Ok(_) => Some(uncompressed),
        Err(_) => {
            let mut uncompress = GzDecoder::new(&data[..]);
            let mut uncompressed = String::new();
            if uncompress.read_to_string(&mut uncompressed).is_ok() {
                Some(uncompressed)
            } else {
                None
            }
        }
    }
}

/// Takes seven named arguments sec, min, hour, mday, mon, year, isdst and returns the Unix time.
#[nasl_function(named(sec, min, hour, mday, mon, year, isdst))]
fn mktime(
    sec: u32,
    min: u32,
    hour: u32,
    mday: u32,
    mon: u32,
    year: i32,
    isdst: Option<i32>,
) -> Option<i64> {
    // TODO: fix isdst
    let _isdst = isdst.unwrap_or(-1);

    let offset = chrono::Local::now().offset().fix().local_minus_utc();
    let r_dt = Utc.with_ymd_and_hms(year, mon, mday, hour, min, sec);
    match r_dt {
        LocalResult::Single(x) => Some(x.naive_local().and_utc().timestamp() - offset as i64),
        _ => None,
    }
}

fn create_localtime_map<T>(date: chrono::DateTime<T>) -> HashMap<String, NaslValue>
where
    T: chrono::TimeZone,
{
    HashMap::from([
        ("sec".to_string(), NaslValue::from(date.second() as i64)),
        ("min".to_string(), NaslValue::from(date.minute() as i64)),
        ("hour".to_string(), NaslValue::from(date.hour() as i64)),
        ("mday".to_string(), NaslValue::from(date.day() as i64)),
        ("mon".to_string(), NaslValue::from(date.month() as i64)),
        ("year".to_string(), NaslValue::from(date.year() as i64)),
        (
            "wday".to_string(),
            NaslValue::from(date.weekday() as i64 + 1),
        ),
        ("yday".to_string(), NaslValue::from(date.ordinal() as i64)),
        // TODO: fix isdst
        ("isdst".to_string(), NaslValue::from(0)),
    ])
}

/// Returns an dict(mday, mon, min, wday, sec, yday, isdst, year, hour) based on optional given time in seconds and optional flag if utc or not.
#[nasl_function(named(utc))]
fn localtime(secs: Option<i64>, utc: Option<NaslValue>) -> HashMap<String, NaslValue> {
    let utc_flag = match utc {
        Some(NaslValue::Number(x)) => x != 0,
        Some(NaslValue::Boolean(x)) => x,
        _ => false,
    };

    match (utc_flag, secs) {
        (true, None) => create_localtime_map(Utc::now()),
        (false, None) => create_localtime_map(Local::now()),
        (true, Some(secs)) => match Utc.timestamp_opt(secs, 0) {
            LocalResult::Single(x) => create_localtime_map(x),
            _ => create_localtime_map(Utc::now()),
        },

        (false, Some(secs)) => match DateTime::from_timestamp(secs, 0) {
            Some(dt) => {
                let offset = chrono::Local::now().offset().fix();
                let dt: DateTime<FixedOffset> = (dt + offset).into();
                create_localtime_map(dt)
            }
            _ => create_localtime_map(Local::now()),
        },
    }
}

/// NASL function to determine if a function is defined.
///
/// Uses the first positional argument to verify if a function is defined.
/// This argument must be a string everything else will return False per default.
/// Returns NaslValue::Boolean(true) when defined NaslValue::Boolean(false) otherwise.
#[nasl_function]
fn defined_func(ctx: &Context, register: &Register, fn_name: Option<Maybe<&str>>) -> bool {
    fn_name
        .and_then(Maybe::as_option)
        .map(|fn_name| match register.named(fn_name) {
            Some(ContextType::Function(_, _)) => true,
            _ => ctx.nasl_fn_defined(fn_name),
        })
        .unwrap_or(false)
}

/// Returns the seconds and microseconds counted from 1st January 1970. It formats a string
/// containing the seconds separated by a `.` followed by the microseconds.
///
/// For example: “1067352015.030757” means 1067352015 seconds and 30757 microseconds.
#[nasl_function]
fn gettimeofday() -> Result<String, MiscError> {
    match time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH) {
        Ok(time) => {
            let time = time.as_micros();
            Ok(format!("{}.{:06}", time / 1000000, time % 1000000))
        }
        Err(e) => Err(MiscError::TimeBefore1970(e.to_string())),
    }
}

/// Is a debug function to print the keys available within the called context. It does not take any
/// nor returns any arguments.
#[nasl_function]
fn dump_ctxt(register: &Register) {
    register.dump(register.index() - 1);
}

pub struct Misc;

function_set! {
    Misc,
    (
        rand,
        get_byte_order,
        dec2str,
        (nasl_typeof, "typeof"),
        isnull,
        unixtime,
        localtime,
        mktime,
        usleep,
        sleep,
        gzip,
        gunzip,
        defined_func,
        gettimeofday,
        dump_ctxt,
    )
}

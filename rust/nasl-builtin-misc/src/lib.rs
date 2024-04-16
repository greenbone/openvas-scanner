// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL miscellaneous functions

use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    thread,
    time::{self, Duration, UNIX_EPOCH},
};

use chrono::{
    self, DateTime, Datelike, FixedOffset, Local, LocalResult, Offset, TimeZone, Timelike, Utc,
};
use nasl_syntax::NaslValue;

use flate2::{
    read::GzDecoder, read::ZlibDecoder, write::GzEncoder, write::ZlibEncoder, Compression,
};
use nasl_builtin_utils::{error::FunctionErrorKind, resolve_positional_arguments, NaslFunction};
use nasl_builtin_utils::{Context, ContextType, Register};

#[inline]
#[cfg(unix)]
/// Reads 8 bytes from /dev/urandom and parses it to an i64
pub fn random_impl() -> Result<i64, FunctionErrorKind> {
    let mut rng = File::open("/dev/urandom")?;
    let mut buffer = [0u8; 8];
    rng.read_exact(&mut buffer)
        .map(|_| i64::from_be_bytes(buffer))
        .map_err(|e| e.kind().into())
}

/// NASL function to get random number
fn rand<K>(_: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    random_impl().map(NaslValue::Number)
}

/// NASL function to get host byte order
fn get_byte_order<K>(_: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    Ok(NaslValue::Boolean(cfg!(target_endian = "little")))
}

/// NASL function to convert given number to string
fn dec2str<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    match register.named("num") {
        Some(ContextType::Value(NaslValue::Number(x))) => Ok(NaslValue::String(x.to_string())),
        x => Err(("0", "numeric", x).into()),
    }
}

/// takes an integer and sleeps the amount of seconds
fn sleep<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    match positional[0] {
        NaslValue::Number(x) => {
            thread::sleep(Duration::new(x as u64, 0));
            Ok(NaslValue::Null)
        }
        _ => Ok(NaslValue::Null),
    }
}

/// takes an integer and sleeps the amount of microseconds
fn usleep<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    match positional[0] {
        NaslValue::Number(x) => {
            thread::sleep(Duration::new(0, (1000 * x) as u32));
            Ok(NaslValue::Null)
        }
        _ => Ok(NaslValue::Null),
    }
}

/// Returns the type of given unnamed argument.
// typeof is a reserved keyword, therefore it is prefixed with "nasl_"
fn nasl_typeof<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.is_empty() {
        return Ok(NaslValue::Null);
    }
    match positional[0] {
        NaslValue::Null => Ok(NaslValue::String("undef".to_string())),
        NaslValue::String(_) => Ok(NaslValue::String("string".to_string())),
        NaslValue::Array(_) => Ok(NaslValue::String("array".to_string())),
        NaslValue::Dict(_) => Ok(NaslValue::String("array".to_string())),
        NaslValue::Boolean(_) => Ok(NaslValue::String("int".to_string())),
        NaslValue::Number(_) => Ok(NaslValue::String("int".to_string())),
        NaslValue::Data(_) => Ok(NaslValue::String("data".to_string())),
        _ => Ok(NaslValue::String("unknown".to_string())),
    }
}

/// Returns true when the given unnamed argument is null.
fn isnull<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.is_empty() {
        return Err(FunctionErrorKind::MissingPositionalArguments {
            expected: 1,
            got: positional.len(),
        });
    }
    match positional[0] {
        NaslValue::Null => Ok(NaslValue::Boolean(true)),
        _ => Ok(NaslValue::Boolean(false)),
    }
}

/// Returns the seconds counted from 1st January 1970 as an integer.
fn unixtime<K>(_: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    match std::time::SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(t) => Ok(NaslValue::Number(t.as_secs() as i64)),
        Err(_) => Err(("0", "numeric").into()),
    }
}

/// Compress given data with gzip, when headformat is set to 'gzip' it uses gzipheader.
fn gzip<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Null)) => return Ok(NaslValue::Null),
        Some(ContextType::Value(x)) => Vec::<u8>::from(x),
        _ => return Err(("data").into()),
    };
    let headformat = match register.named("headformat") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        _ => "noheaderformat",
    };

    match headformat.to_string().eq_ignore_ascii_case("gzip") {
        true => {
            let mut e = GzEncoder::new(Vec::new(), Compression::default());
            match e.write_all(&data) {
                Ok(_) => match e.finish() {
                    Ok(compress) => Ok(NaslValue::Data(compress)),
                    Err(_) => Ok(NaslValue::Null),
                },
                Err(_) => Ok(NaslValue::Null),
            }
        }
        false => {
            let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
            match e.write_all(&data) {
                Ok(_) => match e.finish() {
                    Ok(compress) => Ok(NaslValue::Data(compress)),
                    Err(_) => Ok(NaslValue::Null),
                },
                Err(_) => Ok(NaslValue::Null),
            }
        }
    }
}

/// uncompress given data with gzip, when headformat is set to 'gzip' it uses gzipheader.
fn gunzip<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Null)) => return Ok(NaslValue::Null),
        Some(ContextType::Value(x)) => Vec::<u8>::from(x),
        _ => return Err(("data").into()),
    };

    let mut uncompress = ZlibDecoder::new(&data[..]);
    let mut uncompressed = String::new();
    match uncompress.read_to_string(&mut uncompressed) {
        Ok(_) => Ok(NaslValue::String(uncompressed)),
        Err(_) => {
            let mut uncompress = GzDecoder::new(&data[..]);
            let mut uncompressed = String::new();
            if uncompress.read_to_string(&mut uncompressed).is_ok() {
                Ok(NaslValue::String(uncompressed))
            } else {
                Ok(NaslValue::Null)
            }
        }
    }
}
/// Takes seven named arguments sec, min, hour, mday, mon, year, isdst and returns the Unix time.
fn mktime<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let sec = match register.named("sec") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u32,
        _ => 0,
    };
    let min = match register.named("min") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u32,
        _ => 0,
    };
    let hour = match register.named("hour") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u32,
        _ => 0,
    };
    let mday = match register.named("mday") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u32,
        _ => 0,
    };
    let mon = match register.named("mon") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u32,
        _ => 1,
    };
    let year = match register.named("year") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
        _ => 0,
    };

    // TODO: fix isdst
    let _isdst = match register.named("isdst") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
        _ => -1,
    };

    let offset = chrono::Local::now().offset().fix().local_minus_utc();
    let r_dt = Utc.with_ymd_and_hms(year, mon, mday, hour, min, sec);
    match r_dt {
        LocalResult::Single(x) => Ok(NaslValue::Number(
            x.naive_local().and_utc().timestamp() - offset as i64,
        )),
        _ => Ok(NaslValue::Null),
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
fn localtime<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let utc_flag = match register.named("utc") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x != 0,
        Some(ContextType::Value(NaslValue::Boolean(x))) => *x,
        _ => false,
    };

    let secs = match register.positional() {
        [] => 0,
        [x0, ..] => i64::from(x0),
    };
    let date = match (utc_flag, secs) {
        (true, 0) => create_localtime_map(Utc::now()),
        (true, secs) => match Utc.timestamp_opt(secs, 0) {
            LocalResult::Single(x) => create_localtime_map(x),
            _ => create_localtime_map(Utc::now()),
        },
        (false, 0) => create_localtime_map(Local::now()),

        (false, secs) => match DateTime::from_timestamp(secs, 0) {
            Some(dt) => {
                let offset = chrono::Local::now().offset().fix();
                let dt: DateTime<FixedOffset> = (dt + offset).into();
                create_localtime_map(dt)
            }
            _ => create_localtime_map(Local::now()),
        },
    };

    Ok(NaslValue::Dict(date))
}

/// NASL function to determine if a function is defined.
///
/// Uses the first positional argument to verify if a function is defined.
/// This argument must be a string everything else will return False per default.
/// Returns NaslValue::Boolean(true) when defined NaslValue::Boolean(false) otherwise.
fn defined_func<K>(register: &Register, ctx: &Context<K>) -> Result<NaslValue, FunctionErrorKind>
where
    K: AsRef<str>,
{
    let positional = resolve_positional_arguments(register);

    Ok(match positional.first() {
        Some(NaslValue::String(x)) => match register.named(x) {
            Some(ContextType::Function(_, _)) => true.into(),
            _ => ctx.nasl_fn_defined(x).into(),
        },
        _ => false.into(),
    })
}

/// Returns the seconds and microseconds counted from 1st January 1970. It formats a string
/// containing the seconds separated by a `.` followed by the microseconds.
///
/// For example: “1067352015.030757” means 1067352015 seconds and 30757 microseconds.
fn gettimeofday<K>(_: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind>
where
    K: AsRef<str>,
{
    match time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH) {
        Ok(time) => {
            let time = time.as_micros();
            Ok(NaslValue::String(format!(
                "{}.{:06}",
                time / 1000000,
                time % 1000000
            )))
        }
        Err(e) => Err(FunctionErrorKind::Dirty(format!("{e}"))),
    }
}

/// Is a debug function to print the keys available within the called context. It does not take any
/// nor returns any arguments.
fn dump_ctxt<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind>
where
    K: AsRef<str>,
{
    register.dump(register.index() - 1);
    Ok(NaslValue::Null)
}

/// Returns found function for key or None when not found
fn lookup<K>(key: &str) -> Option<NaslFunction<K>>
where
    K: AsRef<str>,
{
    match key {
        "rand" => Some(rand),
        "get_byte_order" => Some(get_byte_order),
        "dec2str" => Some(dec2str),
        "typeof" => Some(nasl_typeof),
        "isnull" => Some(isnull),
        "unixtime" => Some(unixtime),
        "localtime" => Some(localtime),
        "mktime" => Some(mktime),
        "usleep" => Some(usleep),
        "sleep" => Some(sleep),
        "gzip" => Some(gzip),
        "gunzip" => Some(gunzip),
        "defined_func" => Some(defined_func),
        "gettimeofday" => Some(gettimeofday),
        "dump_ctxt" => Some(dump_ctxt),
        _ => None,
    }
}

/// The description builtin function
pub struct Misc;

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for Misc {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        lookup::<K>(name).is_some()
    }
}

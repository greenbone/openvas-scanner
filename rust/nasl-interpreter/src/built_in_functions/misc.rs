// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL miscellaneous functions

use std::{
    fs::File,
    io::{Read, Write},
    thread,
    time::{UNIX_EPOCH, Duration}, collections::HashMap,
};

use chrono::{self, TimeZone, Local, Utc, LocalResult, Offset};

use sink::Sink;

use crate::{
    error::{FunctionError, FunctionErrorKind},
    ContextType, NaslFunction, NaslValue, Register,
};
use flate2::{
    read::GzDecoder, read::ZlibDecoder, write::GzEncoder, write::ZlibEncoder, Compression,
};

#[inline]
#[cfg(unix)]
/// Reads 8 bytes from /dev/urandom and parses it to an i64
fn random_impl() -> Result<i64, FunctionError> {
    let mut rng =
        File::open("/dev/urandom").map_err(|e| FunctionError::new("randr", e.kind().into()))?;
    let mut buffer = [0u8; 8];
    rng.read_exact(&mut buffer)
        .map(|_| i64::from_be_bytes(buffer))
        .map_err(|e| FunctionError::new("randr", e.kind().into()))
}

/// NASL function to get random number
pub fn rand(_: &str, _: &dyn Sink, _: &Register) -> Result<NaslValue, FunctionError> {
    random_impl().map(NaslValue::Number)
}

/// NASL function to get host byte order
pub fn get_byte_order(_: &str, _: &dyn Sink, _: &Register) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Boolean(cfg!(target_endian = "little")))
}

/// NASL function to convert given number to string
pub fn dec2str(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    match register.named("num") {
        Some(ContextType::Value(NaslValue::Number(x))) => Ok(NaslValue::String(x.to_string())),
        x => Err(FunctionError::new("dec2str", ("0", "numeric", x).into())),
    }
}

/// takes an integer and sleeps the amount of seconds
pub fn sleep(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
    match positional[0] {
        NaslValue::Number(x) => {
            thread::sleep(Duration::new(x as u64, 0));
            Ok(NaslValue::Null)
        },
        _ => Ok(NaslValue::Null)
    }
}


/// takes an integer and sleeps the amount of microseconds
pub fn usleep(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
    match positional[0] {
        NaslValue::Number(x) => {
            thread::sleep(Duration::new(0, (1000 * x) as u32));
            Ok(NaslValue::Null)
        },
        _ => Ok(NaslValue::Null)
    }
}

/// Returns the type of given unnamed argument.
// typeof is a reserved keyword, therefore it is prefixed with "nasl_"
pub fn nasl_typeof(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
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
pub fn isnull(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
    if positional.is_empty() {
        return Err(FunctionError::new(
            "isnull",
            FunctionErrorKind::MissingPositionalArguments {
                expected: 1,
                got: positional.len(),
            },
        ));
    }
    match positional[0] {
        NaslValue::Null => Ok(NaslValue::Boolean(true)),
        _ => Ok(NaslValue::Boolean(false)),
    }
}

/// Returns the seconds counted from 1st January 1970 as an integer.
pub fn unixtime(_: &str, _: &dyn Sink, _: &Register) -> Result<NaslValue, FunctionError> {
    match std::time::SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(t) => Ok(NaslValue::Number(t.as_secs() as i64)),
        Err(_) => Err(FunctionError::new("unixtime", ("0", "numeric").into())),
    }
}

/// Compress given data with gzip, when headformat is set to 'gzip' it uses gzipheader.
pub fn gzip(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Null)) => return Ok(NaslValue::Null),
        Some(ContextType::Value(x)) => Vec::<u8>::from(x),
        _ => return Err(FunctionError::new("gzip", ("data").into())),
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
pub fn gunzip(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Null)) => return Ok(NaslValue::Null),
        Some(ContextType::Value(x)) => Vec::<u8>::from(x),
        _ => return Err(FunctionError::new("gzip", ("data").into())),
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
pub fn mktime(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {

    let sec;
    match register.named("sec") {
        Some(ContextType::Value(NaslValue::Number(x))) => {sec = *x as u32},
        _ => {sec = 0;},
    };
    let min;
    match register.named("min") {
        Some(ContextType::Value(NaslValue::Number(x))) => {min = *x as u32},
        _ => {min = 0;},
    };
    let hour;
    match register.named("hour") {
        Some(ContextType::Value(NaslValue::Number(x))) => {hour = *x as u32},
        _ => {hour = 0;},
    };
    let mday;
    match register.named("mday") {
        Some(ContextType::Value(NaslValue::Number(x))) => {mday = *x as u32},
        _ => {mday = 0;},
    };
    let mon;
    match register.named("mon") {
        Some(ContextType::Value(NaslValue::Number(x))) => {mon = *x as u32},
        _ => {mon = 1;},
    };
    let year;
    match register.named("year") {
        Some(ContextType::Value(NaslValue::Number(x))) => {year = *x as i32},
        _ => {year = 0;},
    };

    // TODO: fix isdst
    let isdst;
    match register.named("isdst") {
        Some(ContextType::Value(NaslValue::Number(x))) => {isdst = *x as i32},
        _ => {isdst = -1;},
    };

    let offset = chrono::Local::now().offset().fix().local_minus_utc();
    let r_dt = Utc.with_ymd_and_hms(year, mon, mday, hour, min, sec);
    match r_dt {
        LocalResult::Single(x) => Ok(NaslValue::Number(x.naive_local().timestamp() - offset as i64)),
        _ => Ok(NaslValue::Null),
    }
}



/// Returns an dict(mday, mon, min, wday, sec, yday, isdst, year, hour) based on optional given time in seconds and optinal flag if utc or not.
pub fn localtime(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let named = register.named("utc");
    let utc_flag;
    match named {
        Some(ContextType::Value(NaslValue::Number(x))) => {utc_flag = *x != 0i64;},
        Some(ContextType::Value(NaslValue::Boolean(x))) => {utc_flag = *x;},
        _ => {utc_flag = false;},
    };
        
    let mut tictac_local: chrono::DateTime<Local> = Local::now();
    let mut tictac_utc: chrono::DateTime<Utc> = Utc::now();
    let tictac: Vec<&str>;
    let mut secs: i64 = 0;
    let positional = register.positional();
    if !(positional.is_empty()) && positional[0] != NaslValue::Number(0)
    {
        match &positional[0] {
            NaslValue::Number(x) => {
                if *x > 0 {
                    secs = *x as i64;
                }
                else {
                    return Err(FunctionError::new("localtime", ("0", "numeric").into()));
                };
            },
            NaslValue::String(x) => {
                let secstr: Vec<&str> = x.split(".").collect();
                let r_secs = secstr[0].to_string().parse::<i64>();
                match r_secs {
                    Ok(x) => secs = x as i64,
                    Err(_) => return Err(FunctionError::new("localtime", ("0", "numeric").into())),
                }
            },
            _ => return Err(FunctionError::new("localtime", ("0", "numeric").into())),
        }
    }

    let strfmt;
    if utc_flag {
        if secs != 0 {
            match Utc.timestamp_opt(secs, 0) {
                LocalResult::Single(x) => {tictac_utc = x;},
                _ => (),
            };
        }
        strfmt = tictac_utc.format("%S %M %H %d %m %Y %w %j").to_string();
        tictac = strfmt.split(" ").collect();
        
    }
    else {
        if secs != 0 {
            match Local.timestamp_opt(secs, 0) {
                LocalResult::Single(x) => {tictac_local = x;},
                _ => (),
            };
        }
        strfmt = tictac_local.format("%S %M %H %d %m %Y %w %j").to_string();
        tictac = strfmt.split(" ").collect();

    }

    let mut date: HashMap::<String, NaslValue> = HashMap::new();
    date.insert("sec".to_string(), NaslValue::from(tictac[0].to_string().parse::<i64>().unwrap_or(0)));
    date.insert("min".to_string(), NaslValue::from(tictac[1].to_string().parse::<i64>().unwrap_or(0)));
    date.insert("hour".to_string(), NaslValue::from(tictac[2].to_string().parse::<i64>().unwrap_or(0)));
    date.insert("mday".to_string(), NaslValue::from(tictac[3].to_string().parse::<i64>().unwrap_or(0)));
    date.insert("mon".to_string(), NaslValue::from(tictac[4].to_string().parse::<i64>().unwrap_or(0)));
    date.insert("year".to_string(), NaslValue::from(tictac[5].to_string().parse::<i64>().unwrap_or(0)));
    date.insert("wday".to_string(), NaslValue::from(tictac[6].to_string().parse::<i64>().unwrap_or(0)));
    date.insert("yday".to_string(), NaslValue::from(tictac[7].to_string().parse::<i64>().unwrap_or(0)));
    // TODO: fix isdst
    date.insert("isdst".to_string(), NaslValue::from(0));
    
    Ok(NaslValue::Dict(date))

}
    

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use nasl_syntax::parse;
    use sink::DefaultSink;
    use chrono::{Offset, offset};
    use crate::{Interpreter, NaslValue, NoOpLoader, Register};

    #[test]
    fn rand() {
        let code = r###"
        rand();
        rand();
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        let first = parser.next();
        let second = parser.next();
        assert!(matches!(first, Some(Ok(NaslValue::Number(_)))));
        assert!(matches!(second, Some(Ok(NaslValue::Number(_)))));
        assert_ne!(first, second);
    }

    #[test]
    fn get_byte_order() {
        let code = r###"
        get_byte_order();
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Boolean(_)))));
    }

    #[test]
    fn dec2str() {
        let code = r###"
        dec2str(num: 23);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok("23".into())));
    }

    #[test]
    fn nasl_typeof() {
        let code = r###"
        typeof("AA");
        typeof(1);
        typeof('AA');
        typeof(make_array());
        d['test'] = 2;
        typeof(d);
        typeof(NULL);
        typeof(a);
        typeof(23,76);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("string".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("int".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("data".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("array".into()))));
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("array".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("undef".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("undef".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("int".into()))));
    }

    #[test]
    fn isnull() {
        let code = r###"
        isnull(42);
        isnull(Null);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(false))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(true))));
    }

    #[test]
    fn unixtime() {
        let code = r###"
        unixtime();
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Number(_)))));
    }

    #[test]
    fn gzip() {
        let code = r###"
        gzip(data: 'z', headformat: "gzip");
        gzip(data: 'z');
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 171, 2, 0, 175, 119, 210, 98, 1, 0, 0, 0]
                    .into()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [120, 156, 171, 2, 0, 0, 123, 0, 123].into()
            )))
        );
    }

    #[test]
    fn gunzip() {
        let code = r###"
        z = raw_string (0x78, 0x9c, 0xab, 0x02, 0x00, 0x00, 0x7b, 0x00, 0x7b);
        gunzip(data: z);
        # With Header Format and data is data
        gz = gzip(data: 'gz', headformat: "gzip");
        gunzip(data: gz);
        # Without Header format and data is a string
        ngz = gzip(data: "ngz");
        gunzip(data: ngz);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("z".into()))));
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("gz".into()))));
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("ngz".into()))));
    }

    #[test]
    fn localtime() {
        let code = r###"
        a = localtime(1676900372, utc: TRUE);
        b = localtime(1676900372, utc: FALSE);
        c = localtime(utc: TRUE);
        d = localtime(utc: FALSE);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));

        let offset = chrono::Local::now().offset().fix().local_minus_utc();
        let date_a = parser.next();
        assert!(matches!(date_a, Some(Ok(NaslValue::Dict(_)))));
        match date_a.unwrap().unwrap() {
            NaslValue::Dict(x) => {
                assert_eq!(x["sec"], NaslValue::Number(32));
                assert_eq!(x["min"], NaslValue::Number(39));
                assert_eq!(x["hour"], NaslValue::Number(13));
                assert_eq!(x["mday"], NaslValue::Number(20));
                assert_eq!(x["mon"], NaslValue::Number(2));
                assert_eq!(x["year"], NaslValue::Number(2023));
                assert_eq!(x["wday"], NaslValue::Number(1));
                assert_eq!(x["yday"], NaslValue::Number(51));
                assert_eq!(x["isdst"], NaslValue::Number(0));
                
            },
            _ => panic!("NO DICT"),
        }

        let date_b = parser.next();
        assert!(matches!(date_b, Some(Ok(NaslValue::Dict(_)))));
        match date_b.unwrap().unwrap() {
            NaslValue::Dict(x) => {
                assert_eq!(x["sec"], NaslValue::Number(32));
                assert_eq!(x["min"], NaslValue::Number(39));
                assert_eq!(x["hour"], NaslValue::Number(13 + (offset/3600) as i64));
                assert_eq!(x["mday"], NaslValue::Number(20));
                assert_eq!(x["mon"], NaslValue::Number(2));
                assert_eq!(x["year"], NaslValue::Number(2023));
                assert_eq!(x["wday"], NaslValue::Number(1));
                assert_eq!(x["yday"], NaslValue::Number(51));
                assert_eq!(x["isdst"], NaslValue::Number(0));
                
            },
            _ => panic!("NO DICT"),
        }

        let date_c = parser.next().unwrap().unwrap();
        let date_d = parser.next().unwrap().unwrap();
        let hour_c: i64;
        let hour_d: i64;
        let min_c: i64;
        let min_d: i64;
        match date_c {
            NaslValue::Dict(x) => {
                hour_c = i64::from(x["hour"].to_owned());
                min_c = i64::from(x["min"].to_owned());
            },
            _ => panic!("NO DICT"),
        }
        match date_d {
            NaslValue::Dict(x) => {
                hour_d = i64::from(x["hour"].to_owned());
                min_d = i64::from(x["min"].to_owned());
            },
            _ => panic!("NO DICT"),
        }
        assert_eq!(hour_c * 60 + min_c, hour_d * 60 + min_d - (offset/60) as i64);
    }

     #[test]
    fn mktime() {
        let code = r###"
        mktime(sec: 01, min: 02, hour: 03, mday: 01, mon: 01, year: 1970);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        let offset = chrono::Local::now().offset().fix().local_minus_utc();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(10921 - offset as i64))));

    }

    #[test]
    fn sleep() {
        let code = r###"
        sleep(1);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        let now = Instant::now();
        parser.next();
        assert!(now.elapsed().as_secs() >= 1);
    }

    #[test]
    fn usleep() {
        let code = r###"
        usleep(1000);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        let now = Instant::now();
        parser.next();
        assert!(now.elapsed().as_micros() >= 1000);
    }
}

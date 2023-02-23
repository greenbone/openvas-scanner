// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL miscellaneous functions

use std::{
    fs::File,
    io::{Read, Write},
    time::UNIX_EPOCH,
};

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

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "rand" => Some(rand),
        "get_byte_order" => Some(get_byte_order),
        "dec2str" => Some(dec2str),
        "typeof" => Some(nasl_typeof),
        "isnull" => Some(isnull),
        "unixtime" => Some(unixtime),
        "gzip" => Some(gzip),
        "gunzip" => Some(gunzip),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

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
}

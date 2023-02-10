// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL functions that deal with cryptography

use digest::{
    block_buffer::Eager,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    crypto_common::BlockSizeUser,
    typenum::{IsLess, Le, NonZero, U256},
    HashMarker, InvalidLength,
};
use hex::encode;
use hmac::{Hmac, Mac};
use md2::Md2;
use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use sink::Sink;

use crate::{error::FunctionError, ContextType, NaslFunction, NaslValue, Register};

fn hmac<D>(register: &Register, function: &str) -> Result<NaslValue, FunctionError>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let key = match register.named("key") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        Some(ContextType::Value(NaslValue::Null)) => return Ok(NaslValue::Null),
        x => return Err(FunctionError::new(function, ("key", "string", x).into())),
    };
    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        Some(ContextType::Value(NaslValue::Null)) => return Ok(NaslValue::Null),
        x => return Err(FunctionError::new(function, ("data", "string", x).into())),
    };
    let mut hmac = match Hmac::<D>::new_from_slice(key.as_bytes()) {
        Ok(x) => x,
        Err(InvalidLength) => {
            return Err(FunctionError::new(
                function,
                ("valid size key", "invalid size key").into(),
            ))
        }
    };
    hmac.update(data.as_bytes());
    Ok(NaslValue::String(encode(
        hmac.finalize().into_bytes().as_slice(),
    )))
}

/// NASL function to get HMAC MD2 string
pub fn hmac_md2(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    hmac::<Md2>(register, "HMAC_MD2")
}

/// NASL function to get HMAC MD5 string
pub fn hmac_md5(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    hmac::<Md5>(register, "HMAC_MD5")
}

/// NASL function to get HMAC RIPEMD160 string
pub fn hmac_ripemd160(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    hmac::<Ripemd160>(register, "HMAC_RIPEMD160")
}

/// NASL function to get HMAC SHA1 string
pub fn hmac_sha1(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    hmac::<Sha1>(register, "HMAC_SHA1")
}

/// NASL function to get HMAC SHA256 string
pub fn hmac_sha256(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    hmac::<Sha256>(register, "HMAC_SHA256")
}

/// NASL function to get HMAC SHA384 string
pub fn hmac_sha384(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    hmac::<Sha384>(register, "HMAC_SHA384")
}

/// NASL function to get HMAC SHA512 string
pub fn hmac_sha512(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    hmac::<Sha512>(register, "HMAC_SHA512")
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "HMAC_MD2" => Some(hmac_md2),
        "HMAC_MD5" => Some(hmac_md5),
        "HMAC_RIPEMD160" => Some(hmac_ripemd160),
        "HMAC_SHA1" => Some(hmac_sha1),
        "HMAC_SHA256" => Some(hmac_sha256),
        "HMAC_SHA384" => Some(hmac_sha384),
        "HMAC_SHA512" => Some(hmac_sha512),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{Interpreter, NoOpLoader, Register};

    #[test]
    fn hmac_md2() {
        let code = r###"
        HMAC_MD2(key: "my_shared?key", data: "so much wow");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok("9558b32badac84072d54422d05bd601a".into()))
        );
    }

    #[test]
    fn hmac_md5() {
        let code = r###"
        HMAC_MD5(key: "my_shared?key", data: "so much wow");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok("815292959633f0e63666d90d6f47cb79".into()))
        );
    }

    #[test]
    fn hmac_ripemd160() {
        let code = r###"
        HMAC_RIPEMD160(key: "my_shared?key", data: "so much wow");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok("e337eca2ca86bd2d4678462b491d72f03dbc70c8".into()))
        );
    }

    #[test]
    fn hmac_sha1() {
        let code = r###"
        HMAC_SHA1(key: "my_shared?key", data: "so much wow");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok("3815da2d914cdddd3fe2ca620dd1f1a2ba5f17bc".into()))
        );
    }

    #[test]
    fn hmac_sha256() {
        let code = r###"
        HMAC_SHA256(key: "my_shared?key", data: "so much wow");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok(
                "08e56e5751d78aaeb49f16142a8b5fb6636a88f7fbf6ee7a93bbfa9be18c4ea6".into()
            ))
        );
    }

    #[test]
    fn hmac_sha384() {
        let code = r###"
        HMAC_SHA384(key: "my_shared?key", data: "so much wow");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok("fce1f12094a52a4654c4a0f7086a470e74096fa200187a79f770384e33dd9f1a224b7bd86f6ced2dd1be6d922f8418b2".into()))
        );
    }

    #[test]
    fn hmac_sha512() {
        let code = r###"
        HMAC_SHA512(key: "my_shared?key", data: "so much wow");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok("7e251167d67f7f29fc978048d338f6ebe0d8bb5213f5ccacca50359b3435df19e60fa709241b98b0ed9e1aeb994df6f900c5fa87201c3fc971b0120968c96cb3".into()))
        );
    }
}

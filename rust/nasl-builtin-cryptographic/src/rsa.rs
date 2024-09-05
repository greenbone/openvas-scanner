// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later
//use md5::Digest;
use crate::get_required_named_data;
use core::str;
use nasl_builtin_utils::{Context, FunctionErrorKind, NaslFunction, Register};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::digest::Digest;
use rsa::{Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use std::fs::{self, File};
use std::io::Read;

fn rsa_public_encrypt(
    register: &Register,
    _: &Context,
) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let data = get_required_named_data(register, "data")?;
    let n = get_required_named_data(register, "n")?;
    let e = get_required_named_data(register, "e")?;
    let mut rng = rand::thread_rng();
    let pub_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
    )
    .unwrap();
    let enc_data = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data).unwrap();
    Ok(enc_data.to_vec().into())
}

fn rsa_private_decrypt(
    register: &Register,
    _: &Context,
) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let data = get_required_named_data(register, "data")?;
    let n = get_required_named_data(register, "n")?;
    let e = get_required_named_data(register, "e")?;
    let d = get_required_named_data(register, "d")?;
    let priv_key = match RsaPrivateKey::from_components(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
        rsa::BigUint::from_bytes_be(d),
        vec![],
    ) {
        Ok(val) => Ok(val),
        Err(code) => Err(nasl_builtin_utils::FunctionErrorKind::GeneralError(
            nasl_builtin_utils::error::GeneralErrorType::UnexpectedData(format!(
                "Error code {}",
                code
            )),
        )),
    };
    let dec_data = match priv_key.unwrap().decrypt(Pkcs1v15Encrypt, data) {
        Ok(val) => Ok(val),
        Err(code) => Err(nasl_builtin_utils::FunctionErrorKind::GeneralError(
            nasl_builtin_utils::error::GeneralErrorType::UnexpectedData(format!(
                "Error code {}",
                code
            )),
        )),
    };
    Ok(dec_data.unwrap().to_vec().into())
}

fn rsa_sign(register: &Register, _: &Context) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let data = get_required_named_data(register, "data")?;
    let pem = get_required_named_data(register, "priv")?;
    let passphrase = get_required_named_data(register, "passphrase")?;
    let mut f = File::open(&str::from_utf8(pem).expect("msg")).expect("Pem-file not found");
    let mut buffer = vec![
        0;
        fs::metadata(&str::from_utf8(pem).expect("Error while decoding filename"))
            .expect("Cannot read attribute length from file")
            .len() as usize
    ];
    f.read(&mut buffer).expect("Buffer overflow");
    let rsa = if passphrase.is_empty() {
        RsaPrivateKey::from_pkcs8_pem(
            str::from_utf8(buffer.as_ref()).expect("Error while decoding pem"),
        )
        .expect("Failed to get private key")
    } else {
        RsaPrivateKey::from_pkcs8_pem(
            str::from_utf8(buffer.as_ref()).expect("Error while decoding pem"),
        )
        .expect("Cant decrypt private key with passphrase, not supported yet")
    };
    let mut hasher = Sha1::new_with_prefix(data);
    hasher.update(data);
    let hashed_data = hasher.finalize();
    let signature = rsa
        .sign(Pkcs1v15Sign::new_unprefixed(), &hashed_data)
        .expect("Signing failed");
    Ok(signature.into())
}

fn rsa_public_decrypt(
    register: &Register,
    _: &Context,
) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let sign = get_required_named_data(register, "sign")?;
    let n = get_required_named_data(register, "n")?;
    let e = get_required_named_data(register, "e")?;
    let e_b = rsa::BigUint::from_bytes_be(e);
    let n_b = rsa::BigUint::from_bytes_be(n);
    let public_key = RsaPublicKey::new(n_b, e_b).expect("Failed to create Public key");
    let mut rng = rand::thread_rng();
    let enc_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, sign).unwrap();
    Ok(enc_data.to_vec().into())
}

pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "rsa_public_encrypt" => Some(rsa_public_encrypt),
        "rsa_private_decrypt" => Some(rsa_private_decrypt),
        "rsa_sign" => Some(rsa_sign),
        "rsa_public_decrypt" => Some(rsa_public_decrypt),
        _ => None,
    }
}

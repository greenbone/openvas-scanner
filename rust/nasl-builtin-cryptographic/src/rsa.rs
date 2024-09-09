// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later
//use md5::Digest;
use crate::get_required_named_bool;
use crate::get_required_named_data;
use ccm::aead::OsRng;
use core::str;
use nasl_builtin_utils::{Context, FunctionErrorKind, NaslFunction, Register};
use nasl_syntax::NaslValue;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::digest::Digest;
use rsa::{BigUint, Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;

fn rsa_public_encrypt(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    let data = get_required_named_data(register, "data")?;
    let n = get_required_named_data(register, "n")?;
    let e = get_required_named_data(register, "e")?;
    let pad = get_required_named_bool(register, "pad").unwrap_or_default();
    let mut rng = rand::thread_rng();
    let pub_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
    )
    .expect("Failed to get public key");
    let biguint_data = BigUint::from_bytes_be(data);
    let enc_data = if pad {
        pub_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .expect("Failed to encrypt data")
    } else {
        rsa::hazmat::rsa_encrypt(&pub_key, &biguint_data)
            .expect("Failed to encrypt data")
            .to_bytes_be()
    };
    Ok(enc_data.to_vec().into())
}

fn rsa_private_decrypt(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    let data = get_required_named_data(register, "data")?;
    let n = get_required_named_data(register, "n")?;
    let e = get_required_named_data(register, "e")?;
    let d = get_required_named_data(register, "d")?;
    let pad = get_required_named_bool(register, "pad")?;
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
    }
    .expect("Failed to get private key");
    let mut rng = OsRng;
    let biguint_data = BigUint::from_bytes_be(data);
    let dec_data = if pad {
        match priv_key.decrypt(Pkcs1v15Encrypt, data) {
            Ok(val) => Ok(val),
            Err(code) => Err(nasl_builtin_utils::FunctionErrorKind::GeneralError(
                nasl_builtin_utils::error::GeneralErrorType::UnexpectedData(format!(
                    "Error code {}",
                    code
                )),
            )),
        }
        .expect("Failed to decode")
    } else {
        rsa::hazmat::rsa_decrypt_and_check(&priv_key, Some(&mut rng), &biguint_data)
            .expect("Failed to decode")
            .to_bytes_be()
    };

    Ok(dec_data.to_vec().into())
}

fn rsa_sign(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    let data = get_required_named_data(register, "data")?;
    let pem = get_required_named_data(register, "priv")?;
    let passphrase = get_required_named_data(register, "passphrase")?;
    let rsa = if passphrase.is_empty() {
        RsaPrivateKey::from_pkcs8_pem(str::from_utf8(pem).expect("Error while decoding pem"))
            .expect("Failed to decode passphrase")
    } else {
        pkcs8::DecodePrivateKey::from_pkcs8_encrypted_pem(
            str::from_utf8(pem).expect("Error while decoding pem"),
            str::from_utf8(passphrase).expect("Error while decoding pem"),
        )
        .expect("Failed to decode passphrase, maybe wrong passphrase for pem?")
    };
    let mut hasher = Sha1::new_with_prefix(data);
    hasher.update(data);
    let hashed_data = hasher.finalize();
    let signature = rsa
        .sign(Pkcs1v15Sign::new_unprefixed(), &hashed_data)
        .expect("Signing failed");
    Ok(signature.into())
}

fn rsa_public_decrypt(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
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

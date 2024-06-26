// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later

use nasl_builtin_utils::{Context, FunctionErrorKind, NaslFunction, Register};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::str;

use crate::get_required_named_data;

fn rsa_public_encrypt<K>(
    register: &Register,
    _: &Context<K>,
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

fn rsa_private_decrypt<K>(
    register: &Register,
    _: &Context<K>,
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

fn rsa_sign<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let data = get_required_named_data(register, "data")?;
    let pem = get_required_named_data(register, "priv")?;
    let passphrase = get_required_named_data(register, "passphrase")?;
    let rsa;
    if passphrase.len() == 0 {
        rsa = Rsa::private_key_from_pem(pem).expect("Failed to get private key");
    } else {
        rsa = Rsa::private_key_from_pem_passphrase(pem, passphrase)
            .expect("Failed to get private key from passphrase");
    }
    let pkey = PKey::from_rsa(rsa).expect("Failed to get private key from rsa(pem)");
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey).expect("Failed to init signer");
    signer.update(data).expect("Failed to update signer");
    let signature = signer.sign_to_vec().expect("Failed to get vector");
    Ok(signature.into())
}

fn rsa_public_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let sign = get_required_named_data(register, "sign")?;
    let n = get_required_named_data(register, "n")?;
    let e = get_required_named_data(register, "e")?;
    let mut e_b = BigNum::new().unwrap();
    let mut n_b = BigNum::new().unwrap();
    BigNum::copy_from_slice(&mut n_b, n).expect("Failed to get n");
    BigNum::copy_from_slice(&mut e_b, e).expect("Failed to get e");
    let public_key = Rsa::from_public_components(n_b, e_b).expect("Failed to get public key");
    let pkey = PKey::from_rsa(public_key.clone()).expect("Failed to get public key from clone");
    let sign_bytes = sign;
    let mut decrypted = vec![0; pkey.size() as usize];
    let len = public_key
        .public_decrypt(&sign_bytes, &mut decrypted, Padding::PKCS1)
        .expect("Failed to public decrypt");
    decrypted.truncate(len);
    Ok(decrypted.to_vec().into())
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "rsa_public_encrypt" => Some(rsa_public_encrypt),
        "rsa_private_decrypt" => Some(rsa_private_decrypt),
        "rsa_sign" => Some(rsa_sign),
        "rsa_public_decrypt" => Some(rsa_public_decrypt),
        _ => None,
    }
}

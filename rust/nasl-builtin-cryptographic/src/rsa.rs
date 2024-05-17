// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later

use nasl_builtin_utils::{Context, FunctionErrorKind, NaslFunction, Register};
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::{self, SigningKey},
    sha2::{Digest, Sha256},
    Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
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
    let enc_data = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .expect("failed to encrypt");
    return Ok(enc_data.to_vec().into());
}

fn rsa_private_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let data = get_required_named_data(register, "data")?;
    let n = get_required_named_data(register, "n")?;
    let e = get_required_named_data(register, "e")?;
    let d = get_required_named_data(register, "d")?;
    let priv_key = RsaPrivateKey::from_components(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
        rsa::BigUint::from_bytes_be(d),
        vec![],
    )
    .unwrap();
    let dec_data = priv_key
        .decrypt(Pkcs1v15Encrypt, data)
        .expect("failed to decrypt");
    return Ok(dec_data.to_vec().into());
}

fn rsa_sign<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let data = get_required_named_data(register, "data")?;
    let pem = get_required_named_data(register, "priv")?;
    let passphrase = get_required_named_data(register, "passphrase")?;
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::from_pkcs1_pem(std::str::from_utf8(pem).unwrap())
        .expect("failed to generate a key");
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign_with_rng(&mut rng, data);
    verifying_key
        .verify(data, &signature)
        .expect("failed to verify");
    return Ok(verifying_key.to_vec().into());
}

fn rsa_public_decrypt<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let sig = get_required_named_data(register, "sig")?;
    let n = get_required_named_data(register, "n")?;
    let e = get_required_named_data(register, "e")?;
    let mut rng = rand::thread_rng();
    let pub_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
    )
    .unwrap();
    return Ok(sig.to_vec().into());
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

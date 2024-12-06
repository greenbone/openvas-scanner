// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later
use crate::function_set;
use crate::nasl::prelude::*;
use ccm::aead::OsRng;
use nasl_function_proc_macro::nasl_function;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::digest::Digest;
use rsa::{BigUint, Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;

use super::CryptographicError;

#[nasl_function(named(data, n, e, pad))]
fn rsa_public_encrypt(
    data: &[u8],
    n: &[u8],
    e: &[u8],
    pad: Option<bool>,
) -> Result<NaslValue, CryptographicError> {
    let pad = pad.unwrap_or_default();
    let mut rng = rand::thread_rng();
    let pub_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
    )
    .map_err(|e| CryptographicError::Rsa(e.to_string()))?;
    let biguint_data = BigUint::from_bytes_be(data);
    let enc_data = if pad {
        pub_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .map_err(|e| CryptographicError::Rsa(e.to_string()))?
    } else {
        rsa::hazmat::rsa_encrypt(&pub_key, &biguint_data)
            .map_err(|e| CryptographicError::Rsa(e.to_string()))?
            .to_bytes_be()
    };
    Ok(enc_data.to_vec().into())
}

#[nasl_function(named(data, n, e, d, pad))]
fn rsa_private_decrypt(
    data: &[u8],
    n: &[u8],
    e: &[u8],
    d: &[u8],
    pad: Option<bool>,
) -> Result<NaslValue, FnError> {
    let pad = pad.unwrap_or_default();
    let priv_key = match RsaPrivateKey::from_components(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
        rsa::BigUint::from_bytes_be(d),
        vec![],
    ) {
        Ok(val) => Ok(val),
        Err(code) => Err(
            FnError::from(CryptographicError::Rsa(format!("Error code {}", code))).with(
                ReturnValue(NaslValue::Array(vec![
                    NaslValue::Data(n.to_vec()),
                    NaslValue::Data(e.to_vec()),
                    NaslValue::Data(d.to_vec()),
                ])),
            ),
        ),
    }
    .map_err(|e| CryptographicError::Rsa(e.to_string()))?;
    let mut rng = OsRng;
    let biguint_data = BigUint::from_bytes_be(data);
    let dec_data = if pad {
        match priv_key.decrypt(Pkcs1v15Encrypt, data) {
            Ok(val) => Ok(val),
            Err(code) => Err(FnError::from(CryptographicError::Rsa(format!(
                "Error code {}",
                code
            )))
            .with(ReturnValue(NaslValue::Data(data.to_vec())))),
        }
        .map_err(|e| CryptographicError::Rsa(e.to_string()))?
    } else {
        rsa::hazmat::rsa_decrypt_and_check(&priv_key, Some(&mut rng), &biguint_data)
            .map_err(|e| CryptographicError::Rsa(e.to_string()))?
            .to_bytes_be()
    };

    Ok(dec_data.to_vec().into())
}

#[nasl_function(named(data, pem, passphrase))]
fn rsa_sign(data: &[u8], pem: &[u8], passphrase: Option<&str>) -> Result<NaslValue, FnError> {
    let pem_str = std::str::from_utf8(pem).map_err(|e| CryptographicError::Rsa(e.to_string()))?;
    let rsa: RsaPrivateKey = if passphrase.unwrap_or_default() != "" {
        pkcs8::DecodePrivateKey::from_pkcs8_encrypted_pem(pem_str, passphrase.unwrap_or_default())
            .map_err(|e| CryptographicError::Rsa(e.to_string()))?
    } else {
        RsaPrivateKey::from_pkcs8_pem(pem_str)
            .map_err(|e| CryptographicError::Rsa(e.to_string()))?
    };
    let mut hasher = Sha1::new_with_prefix(data);
    hasher.update(data);
    let hashed_data = hasher.finalize();
    let signature = rsa
        .sign(Pkcs1v15Sign::new_unprefixed(), &hashed_data)
        .map_err(|e| CryptographicError::Rsa(e.to_string()))?;
    Ok(signature.into())
}

#[nasl_function(named(sign, n, e))]
fn rsa_public_decrypt(sign: &[u8], n: &[u8], e: &[u8]) -> Result<NaslValue, FnError> {
    let e_b = rsa::BigUint::from_bytes_be(e);
    let n_b = rsa::BigUint::from_bytes_be(n);
    let public_key =
        RsaPublicKey::new(n_b, e_b).map_err(|e| CryptographicError::Rsa(e.to_string()))?;
    let mut rng = rand::thread_rng();
    let enc_data = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, sign)
        .map_err(|e| CryptographicError::Rsa(e.to_string()))?;
    Ok(enc_data.to_vec().into())
}

pub struct Rsa;
function_set! {
    Rsa,
    (
        (rsa_public_encrypt, "rsa_public_encrypt"),
        (rsa_private_decrypt, "rsa_private_decrypt"),
        (rsa_sign, "rsa_sign"),
        (rsa_public_decrypt, "rsa_public_decrypt"),
    )
}

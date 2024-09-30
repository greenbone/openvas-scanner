// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later
//use md5::Digest;
use ccm::aead::OsRng;
use core::str;
use nasl_builtin_utils::function_set;
use nasl_builtin_utils::FunctionErrorKind;
use nasl_function_proc_macro::nasl_function;
use nasl_syntax::NaslValue;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::digest::Digest;
use rsa::{BigUint, Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;

#[nasl_function(named(data, n, e, pad))]
fn rsa_public_encrypt(
    data: Option<&[u8]>,
    n: Option<&[u8]>,
    e: Option<&[u8]>,
    pad: Option<bool>,
) -> Result<NaslValue, FunctionErrorKind> {
    let data = data.unwrap();
    let n = n.unwrap();
    let e = e.unwrap();
    let pad = pad.unwrap_or_default();
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

#[nasl_function(named(data, n, e, d, pad))]
fn rsa_private_decrypt(
    data: Option<&[u8]>,
    n: Option<&[u8]>,
    e: Option<&[u8]>,
    d: Option<&[u8]>,
    pad: Option<bool>,
) -> Result<NaslValue, FunctionErrorKind> {
    let data = data.unwrap();
    let n = n.unwrap();
    let e = e.unwrap();
    let d = d.unwrap();
    let pad = pad.unwrap_or_default();
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

#[nasl_function(named(data, pem, passphrase))]
fn rsa_sign(
    data: Option<&[u8]>,
    pem: Option<&str>,
    passphrase: Option<&str>,
) -> Result<NaslValue, FunctionErrorKind> {
    let data = data.unwrap();
    //let pem_str = pem.unwrap().iter().map(|x| *x as char).collect::<String>();
    let pem_str = pem.unwrap();
    //let passphrase_str = str::from_utf8(passphrase.unwrap()).unwrap();
    let passphrase_str = passphrase.unwrap();
    dbg!(pem_str);
    dbg!(passphrase_str);
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let rsa: RsaPrivateKey = if passphrase_str == "" {
        //RsaPrivateKey::from_pkcs8_pem(pem_str).expect("Failed to decode passphrase")
        RsaPrivateKey::new(&mut rng, bits).unwrap()
    } else {
        pkcs8::DecodePrivateKey::from_pkcs8_encrypted_pem(pem_str, passphrase_str)
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

#[nasl_function(named(sign, n, e))]
fn rsa_public_decrypt(
    sign: Option<&[u8]>,
    n: Option<&[u8]>,
    e: Option<&[u8]>,
) -> Result<NaslValue, FunctionErrorKind> {
    let sign = sign.unwrap();
    let n = n.unwrap();
    let e = e.unwrap();
    let e_b = rsa::BigUint::from_bytes_be(e);
    let n_b = rsa::BigUint::from_bytes_be(n);
    let public_key = RsaPublicKey::new(n_b, e_b).expect("Failed to create Public key");
    let mut rng = rand::thread_rng();
    let enc_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, sign).unwrap();
    Ok(enc_data.to_vec().into())
}

pub struct Rsa;
function_set! {
    Rsa,
    sync_stateless,
    (
        (rsa_public_encrypt, "rsa_public_encrypt"),
        (rsa_private_decrypt, "rsa_private_decrypt"),
        (rsa_sign, "rsa_sign"),
        (rsa_public_decrypt, "rsa_public_decrypt"),
    )
}

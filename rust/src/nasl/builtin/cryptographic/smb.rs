// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later
use crate::function_set;
use crate::nasl::builtin::cryptographic::CryptographicError;
use crate::nasl::builtin::cryptographic::aes_cmac::aes_cmac;
use crate::nasl::builtin::cryptographic::hmac::hmac;
use crate::nasl::{FnError, NaslValue};
use nasl_function_proc_macro::nasl_function;
use sha2::Sha256;

#[nasl_function(named(key, buf))]
fn smb_cmac_aes_signature(key: &[u8], buf: &[u8]) -> Result<NaslValue, FnError> {
    aes_cmac(key, buf)
}

#[cfg(feature = "nasl-c-lib")]
#[nasl_function(named(key, buf, iv))]
fn smb_gmac_aes_signature(key: &[u8], buf: &[u8], iv: &[u8]) -> Result<NaslValue, FnError> {
    use crate::nasl::builtin::cryptographic::aes_gmac::aes_gmac;

    aes_gmac(buf, key, iv)
}

#[nasl_function(named(key, label, ctx, lvalue))]
fn smb3kdf(key: &str, label: &str, ctx: &str, lvalue: i32) -> Result<Vec<u8>, FnError> {
    if lvalue != 128 && lvalue != 256 {
        return Err(CryptographicError::Smb(format!(
            "invalid key length: expected 128 or 256, got {lvalue}",
        ))
        .into());
    }
    let key = key.as_bytes();
    let label = label.as_bytes();
    let ctx = ctx.as_bytes();
    let buflen = 4 + label.len() + 1 + ctx.len() + 4;
    let resultlen = lvalue / 8;
    let mut buf = Vec::with_capacity(buflen);

    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(label);
    buf.push(0u8);
    buf.extend_from_slice(ctx);
    buf.extend_from_slice(&lvalue.to_be_bytes());
    println!("buf: {:?}", buf);
    let result = hmac::<Sha256>(key, &buf)?;
    Ok(result[..resultlen as usize].to_vec())
}

pub struct Smb;
#[cfg(feature = "nasl-c-lib")]
function_set! {
    Smb,
    (
        (smb_gmac_aes_signature, "smb_gmac_aes_signature"),
        (smb_cmac_aes_signature, "smb_cmac_aes_signature"),
        (smb3kdf, "smb3kdf"),
    )
}

#[cfg(not(feature = "nasl-c-lib"))]
function_set! {
    Smb,
    (
        smb_cmac_aes_signature,
        smb3kdf,
    )
}

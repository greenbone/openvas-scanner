// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// Until the Crypto scene is moving away from GenericArray
#![allow(deprecated)]

use thiserror::Error;

// use crate::nasl::utils::combine_function_sets;

use crate::nasl::utils::{IntoFunctionSet, StoredFunctionSet};

mod aes_ccm;
mod aes_cmac;
mod aes_ctr;
mod aes_gcm;
mod aes_gmac;
mod cbc;
mod des;
mod dh;
mod hash;
mod hmac;
mod misc;
mod ntlm;
mod pem_to;
mod prf;
pub mod rc4;
mod rsa;
mod smb;

#[cfg(test)]
mod tests;

#[derive(Debug, Error)]
pub enum CryptographicError {
    #[error("Error in AesGcm: insufficient buffer size.")]
    InsufficientBufferSize,
    #[error("Error in AesCcm: unable to encrypt.")]
    AesCcmUnableToEncrypt,
    #[error("Error in AesGmac: {0}.")]
    AesGmacError(String),
    #[error("Invalid length of key in AesCmac {0}.")]
    AesCmacInvalidLength(digest::InvalidLength),
    #[error("Error in RSA: {0}.")]
    Rsa(String),
    #[error("Error in RC4: {0}.")]
    Rc4(String),
    #[error("Error in SMB: {0}.")]
    Smb(String),
}

enum Crypt {
    Encrypt,
    Decrypt,
}

pub struct Cryptographic;

impl IntoFunctionSet for Cryptographic {
    type State = Cryptographic;

    fn into_function_set(self) -> StoredFunctionSet<Cryptographic> {
        let mut set = StoredFunctionSet::new(self);
        set.add_set(aes_ccm::AesCcm);
        set.add_set(hmac::HmacFns);
        set.add_set(cbc::Cbc);
        set.add_set(aes_ctr::AesCtr);
        set.add_set(aes_gcm::AesGcmFns);
        set.add_set(aes_cmac::AesCmac);
        set.add_set(aes_gmac::AesGmac);
        set.add_set(hash::Hash);
        set.add_set(des::Des);
        set.add_set(rsa::Rsa);
        set.add_set(pem_to::PemTo);
        set.add_set(smb::Smb);
        set.add_set(misc::Misc);
        set.add_set(ntlm::Ntlm);
        set.add_set(dh::Dh);
        set.add_set(prf::Prf);
        set
    }
}

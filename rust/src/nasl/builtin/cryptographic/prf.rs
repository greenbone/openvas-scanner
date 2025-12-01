// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::cipher::BlockSizeUser;
use ccm::consts::U256;
use digest::HashMarker;
use digest::block_buffer::Eager;
use digest::core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore};
use digest::typenum::{IsLess, Le, NonZero};
use sha2::{Sha256, Sha384};

use crate::nasl::builtin::cryptographic::hmac::hmac;
use crate::nasl::prelude::*;
use crate::nasl::utils::function::StringOrData;

fn prf<D>(
    secret: StringOrData,
    seed: StringOrData,
    label: StringOrData,
    outlen: usize,
) -> Result<Vec<u8>, FnError>
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
    let secret = secret.data();
    let label_seed = [label.data(), seed.data()].concat();

    let mut ai = hmac::<D>(secret, &label_seed)?;

    let mut result = vec![];
    while result.len() < outlen {
        let mut tmp = ai.clone();
        tmp.extend_from_slice(&label_seed);
        let tmp2 = hmac::<D>(secret, &tmp)?;
        result.extend_from_slice(&tmp2);
        ai = hmac::<D>(secret, &ai)?;
    }
    result.truncate(outlen);
    Ok(result)
}

#[nasl_function(named(secret, seed, label, outlen))]
fn prf_sha256(
    secret: StringOrData,
    seed: StringOrData,
    label: StringOrData,
    outlen: usize,
) -> Result<Vec<u8>, FnError> {
    prf::<Sha256>(secret, seed, label, outlen)
}

#[nasl_function(named(secret, seed, label, outlen))]
fn prf_sha384(
    secret: StringOrData,
    seed: StringOrData,
    label: StringOrData,
    outlen: usize,
) -> Result<Vec<u8>, FnError> {
    prf::<Sha384>(secret, seed, label, outlen)
}

pub struct Prf;

function_set! {
    Prf,
    (
        prf_sha256,
        prf_sha384,
    )
}

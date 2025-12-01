// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use dsa::BigUint;

use crate::nasl::{
    prelude::*,
    utils::function::{StringOrData, utils::get_named_arg},
};

/// Computes the Diffie-Hellman shared secret key from the shared
/// parameters p and g, the server's public key dh_server_pub and the
/// client's public and private keys pub_key an priv_key.  The return
/// value is the shared secret key as an MPI (Multi Precision Integer).
#[nasl_function(named(p, g, dh_server_pub, pub_key, priv_key))]
fn dh_compute_key(
    p: StringOrData,
    #[allow(unused_variables)] g: StringOrData,
    dh_server_pub: StringOrData,
    #[allow(unused_variables)] pub_key: StringOrData,
    priv_key: StringOrData,
) -> Vec<u8> {
    let p = BigUint::from_bytes_be(p.data());
    let dh_server_pub = BigUint::from_bytes_be(dh_server_pub.data());
    let priv_key = BigUint::from_bytes_be(priv_key.data());

    dh_server_pub.modpow(&priv_key, &p).to_bytes_be().to_vec()
}

/// Generates a Diffie-Hellman public key from the shared parameters p
/// and g and the private parameter priv. The return value is the public
/// key as an MPI (Multi Precision Integer).
#[nasl_function]
fn dh_generate_key(reg: &Register) -> Result<Vec<u8>, FnError> {
    // Get named arguments from Register, as `priv` is a reserved keyword in Rust
    // Therefore we cannot use priv within the `nasl_function` macro
    let (p, g, priv_key): (StringOrData, StringOrData, StringOrData) = (
        get_named_arg(reg, "p")?,
        get_named_arg(reg, "g")?,
        get_named_arg(reg, "priv")?,
    );
    let p = BigUint::from_bytes_be(p.data());
    let g = BigUint::from_bytes_be(g.data());
    let priv_key = BigUint::from_bytes_be(priv_key.data());

    Ok(g.modpow(&priv_key, &p).to_bytes_be().to_vec())
}

pub struct Dh;

function_set! {
    Dh,
    (
        dh_compute_key,
        dh_generate_key,
    )
}

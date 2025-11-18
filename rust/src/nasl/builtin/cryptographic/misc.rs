// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::nasl::{prelude::*, utils::function::StringOrData};

use num_bigint::BigUint;
use rand::{Rng, rng};

#[nasl_function]
fn insert_hexzeros(register: &Register) -> Result<Vec<u8>, FnError> {
    // As in is a keyword in rust, we cannot use the nasl_function annotation for named arguments.
    let data = register
        .local_nasl_value("in")
        .map_err(|_| ArgumentError::MissingNamed(vec!["in".into()]))?;
    let data = match data {
        NaslValue::Data(x) => x,
        NaslValue::String(x) => x.as_bytes(),
        _ => return Err(ArgumentError::WrongArgument("expected Data.".to_string()).into()),
    };

    let mut result = vec![];
    for byte in data {
        if *byte == 0 {
            break;
        }
        result.push(*byte);
        result.push(0);
    }
    Ok(result)
}

/// Given two big numbers key1 and key2 as bytes, this compares them and returns -1 if key1 < key2,
/// 0 if key1 == key2, or 1 if key1 > key2.
#[nasl_function(named(key1, key2))]
fn bn_cmp(key1: StringOrData, key2: StringOrData) -> i64 {
    let a = BigUint::from_bytes_be(key1.data());
    let b = BigUint::from_bytes_be(key2.data());
    match a.cmp(&b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// This function generates a big number (bn) with the given amount of bits.
/// As this function generates the number as bytes, it actually takes the number of bits, divides them by 8
/// and rounds them up. It does not only generate the desired number of bits for the last byte, but a whole
/// random byte.
///
/// A big number is an integer, that is probably to big for any primitive data type. In case of the
/// c implementation the mpi (multi-precision integer) type of libgcrypt was used.
#[nasl_function(named(need))]
fn bn_random(need: u64) -> Vec<u8> {
    let digits = need / 8;
    let rem = need % 8;

    let digits = if rem > 0 { digits + 1 } else { digits };

    let mut rng = rng();
    (0..digits).map(|_| rng.random()).collect()
}

pub struct Misc;

function_set! {
    Misc,
    (
        (insert_hexzeros, "insert_hexzeros"),
        bn_cmp,
        bn_random,
    )
}

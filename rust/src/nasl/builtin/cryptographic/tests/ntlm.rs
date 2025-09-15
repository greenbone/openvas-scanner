// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use super::helper::decode_hex;
use crate::nasl::test_prelude::*;

#[test]
fn des_encrypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("0101010101010101");"#);
    t.run(r#"data = hexstr_to_data("95f8a5e5dd31d900");"#);
    t.ok(r#"DES(data,key);"#, decode_hex("8000000000000000").unwrap());
}

#[test]
fn ntlmv1_hash() {
    let mut t = TestBuilder::default();
    t.run(r#"passhash = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07);"#);
    t.run(r#"cryptkey = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16);"#);
    t.ok(
        r#"NTLMv1_HASH(cryptkey: cryptkey, passhash: passhash);"#,
        decode_hex("466bfb51076c1c41cead373db80eabf8cead373db80eabf8").unwrap(),
    );
}

#[test]
fn ntlm_response() {
    let mut t = TestBuilder::default();
    t.run(r#"passhash = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10);"#);
    t.run(r#"cryptkey = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16);"#);
    t.run(r#"nt_hash = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16);"#);
    t.ok(
        r#"ntlm_response(cryptkey: cryptkey, password: passhash, nt_hash: nt_hash, neg_flags: 0);"#,
        decode_hex("f61e5ef412e3b2424ba184a50249c2ee95890979bcd198b4466bfb51076c1c41765c7570ae31953f17dc217996caa63cce6c0da423ce8b177b87fb24640578d8").unwrap(),
    );
}

#[test]
fn lm_owf_gen() {
    let mut t = TestBuilder::default();
    t.run(r#"pass = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10);"#);
    t.ok(
        r#"result = lm_owf_gen(pass);"#,
        decode_hex("f857d5f92342ba67d110ce58bfa155d7").unwrap(),
    );
}

#[test]
fn nt_owf_gen() {
    let mut t = TestBuilder::default();
    t.run(r#"pass = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10);"#);
    t.ok(
        r#"result = nt_owf_gen(pass);"#,
        decode_hex("e65796bd1b533adde5b71063447b0610").unwrap(),
    );
}

#[test]
fn ntv2_owf_gen() {
    let mut t = TestBuilder::default();
    t.run(r#"owf = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10);"#);
    t.run(r#"login = "user";"#);
    t.run(r#"domain = "domain";"#);
    t.ok(
        r#"result = ntv2_owf_gen(owf: owf, login: login, domain: domain);"#,
        decode_hex("7b313f129d35d795f4505df372cab865").unwrap(),
    );
}

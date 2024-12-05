// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// FnError::GeneralError
use super::helper::decode_hex;
use crate::nasl::test_prelude::*;

#[test]
fn aes128_gcm_crypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("7fddb57453c241d03efbed3ac44e371c");"#);
    t.run(r#"data = hexstr_to_data("d5de42b461646c255c87bd2962d3b9a2");"#);
    t.run(r#"iv = hexstr_to_data("ee283a3fc75575e33efd4887");"#);
    t.ok(
        r#"crypt = aes128_gcm_encrypt(key: key, data: data, iv: iv);"#,
        decode_hex("2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3").unwrap(),
    );
    t.ok(
        r#"aes128_gcm_decrypt(key: key, data: crypt, iv: iv);"#,
        decode_hex("d5de42b461646c255c87bd2962d3b9a2").unwrap(),
    );
}

#[test]
fn aes128_gcm_crypt_auth() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("c939cc13397c1d37de6ae0e1cb7c423c");"#);
    t.run(r#"data = hexstr_to_data("c3b3c41f113a31b73d9a5cd432103069");"#);
    t.run(r#"iv = hexstr_to_data("b3d8cc017cbb89b39e0f67e2");"#);
    t.run(r#"aad = hexstr_to_data("24825602bd12a984e0092d3e448eda5f");"#);
    t.ok(
        r#"crypt = aes128_gcm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);"#,
        decode_hex("93fe7d9e9bfd10348a5606e5cafa73540032a1dc85f1c9786925a2e71d8272dd").unwrap(),
    );
    t.ok(
        r#"aes128_gcm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);"#,
        decode_hex("c3b3c41f113a31b73d9a5cd432103069").unwrap(),
    );
}

#[test]
fn aes192_gcm_crypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("fbc0b4c56a714c83217b2d1bcadd2ed2e9efb0dcac6cc19f");"#);
    t.run(r#"data = hexstr_to_data("d2ae38c4375954835d75b8e4c2f9bbb4");"#);
    t.run(r#"iv = hexstr_to_data("5f4b43e811da9c470d6a9b01");"#);
    t.ok(
        r#"crypt = aes192_gcm_encrypt(key: key, data: data, iv: iv);"#,
        decode_hex("69482957e6be5c54882d00314e0259cf191e9f29bef63a26860c1e020a21137e").unwrap(),
    );
    t.ok(
        r#"aes192_gcm_decrypt(key: key, data: crypt, iv: iv);"#,
        decode_hex("d2ae38c4375954835d75b8e4c2f9bbb4").unwrap(),
    );
}

#[test]
fn aes192_gcm_crypt_auth() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("6f44f52c2f62dae4e8684bd2bc7d16ee7c557330305a790d");"#);
    t.run(r#"data = hexstr_to_data("37222d30895eb95884bbbbaee4d9cae1");"#);
    t.run(r#"iv = hexstr_to_data("9ae35825d7c7edc9a39a0732");"#);
    t.run(r#"aad = hexstr_to_data("1b4236b846fc2a0f782881ba48a067e9");"#);
    t.ok(
        r#"crypt = aes192_gcm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);"#,
        decode_hex("a54b5da33fc1196a8ef31a5321bfcaeb1c198086450ae1834dd6c2636796bce2").unwrap(),
    );
    t.ok(
        r#"aes192_gcm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);"#,
        decode_hex("37222d30895eb95884bbbbaee4d9cae1").unwrap(),
    );
}

#[test]
fn aes256_gcm_crypt() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22");"#);
    t.run(r#"data = hexstr_to_data("2db5168e932556f8089a0622981d017d");"#);
    t.run(r#"iv = hexstr_to_data("0d18e06c7c725ac9e362e1ce");"#);
    t.ok(
        r#"crypt = aes256_gcm_encrypt(key: key, data: data, iv: iv);"#,
        decode_hex("fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489").unwrap(),
    );
    t.ok(
        r#"aes256_gcm_decrypt(key: key, data: crypt, iv: iv);"#,
        decode_hex("2db5168e932556f8089a0622981d017d").unwrap(),
    );
}

#[test]
fn aes256_gcm_crypt_auth() {
    let mut t = TestBuilder::default();
    t.run(r#"key = hexstr_to_data("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b");"#);
    t.run(r#"data = hexstr_to_data("2d71bcfa914e4ac045b2aa60955fad24");"#);
    t.run(r#"iv = hexstr_to_data("ac93a1a6145299bde902f21a");"#);
    t.run(r#"aad = hexstr_to_data("1e0889016f67601c8ebea4943bc23ad6");"#);
    t.ok(
        r#"crypt = aes256_gcm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);"#,
        decode_hex("8995ae2e6df3dbf96fac7b7137bae67feca5aa77d51d4a0a14d9c51e1da474ab").unwrap(),
    );
    t.ok(
        r#"aes256_gcm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);"#,
        decode_hex("2d71bcfa914e4ac045b2aa60955fad24").unwrap(),
    );
}

#[test]
fn padding() {
    let mut t = TestBuilder::default();
    t.run_all(
        r#"
            key = hexstr_to_data("7fddb57453c241d03efbed3ac44e371c");
            data1 = hexstr_to_data("d5de42b461646c255c87bd29");
            data2 = hexstr_to_data("d5de42b461646c255c87bd2900000000");
            iv = hexstr_to_data("ee283a3fc75575e33efd4887");
            aes128_gcm_encrypt(key: key, data: data1, iv: iv);
            aes128_gcm_encrypt(key: key, data: data2, iv: iv);
        "#,
    );
    let results = t.results();
    assert_eq!(
        results[results.len() - 2].as_ref().unwrap(),
        results[results.len() - 1].as_ref().unwrap()
    );
}

// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod tests {

    use crate::nasl::builtin::cryptographic::tests::helper::decode_hex;
    use crate::nasl::test_prelude::*;
    use crate::nasl::test_utils::TestBuilder;

    #[test]
    fn prf_sha256() {
        let mut t = TestBuilder::default();
        t.run(r#"secret = "mysecret";"#);
        t.run(r#"seed = "myseed";"#);
        t.run(r#"label = "mylabel";"#);
        t.run(r#"outlen = 33;"#);
        t.ok(
            r#"prf_sha256(secret:secret,seed:seed,label:label,outlen:outlen);"#,
            NaslValue::Data(
                decode_hex("16b8ad158f73cb9c96c7c83e81fe9f9dcb740fe35d27343e0f239a8146b93dad66")
                    .unwrap(),
            ),
        );
    }

    #[test]
    fn prf_sha384() {
        let mut t = TestBuilder::default();
        t.run(r#"secret = "mysecret";"#);
        t.run(r#"seed = "myseed";"#);
        t.run(r#"label = "mylabel";"#);
        t.run(r#"outlen = 33;"#);
        t.ok(
            r#"prf_sha384(secret:secret,seed:seed,label:label,outlen:outlen);"#,
            NaslValue::Data(
                decode_hex("c54442096f12f7d75a71b9582f0c4cf61953663f616eb0006c7aa6e42aa8f9d5dd")
                    .unwrap(),
            ),
        );
    }
}

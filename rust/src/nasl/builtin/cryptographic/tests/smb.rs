// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod tests {

    use crate::nasl::builtin::cryptographic::tests::helper::decode_hex;
    use crate::nasl::test_prelude::*;
    use crate::nasl::test_utils::TestBuilder;

    #[test]
    fn smb3kdf() {
        let mut t = TestBuilder::default();
        t.run(r#"key = "mykey";"#);
        t.run(r#"label = "mylabel";"#);
        t.run(r#"ctx = "mycontext";"#);
        t.run(r#"lvalue = 128;"#);
        t.ok(
            r#"smb3kdf(key:key,label:label,ctx:ctx,lvalue:lvalue);"#,
            NaslValue::Data(decode_hex("a5948d63659bd73a5a642b1a81d172c6").unwrap()),
        );
    }

    #[test]
    fn get_smb2_signature() {
        let mut t = TestBuilder::default();
        t.run(r#"key = "key must be at least 16 bytes!";"#);
        t.run(r#"buf = "so much wow this string has to be long enough to cover the minimum required length of 64 bytes!";"#);
        t.ok(
            r#"get_smb2_signature(key:key,buf:buf);"#,
            NaslValue::Data(decode_hex("736f206d75636820776f77207468697320737472696e672068617320746f206265206c6f6e6720656e6f75676820746fc26033a736a1808de5dfc646f814b26e756d207265717569726564206c656e677468206f6620363420627974657321").unwrap()),
        );
    }
}

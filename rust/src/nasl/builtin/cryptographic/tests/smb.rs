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
        t.run(r#"display(smb3kdf(key:key,label:label,ctx:ctx,lvalue:lvalue));"#);
        t.ok(
            r#"smb3kdf(key:key,label:label,ctx:ctx,lvalue:lvalue);"#,
            NaslValue::Data(decode_hex("a5948d63659bd73a5a642b1a81d172c6").unwrap()),
        );
    }
}

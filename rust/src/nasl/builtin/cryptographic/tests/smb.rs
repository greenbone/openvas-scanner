// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod tests {

    use crate::nasl::builtin::cryptographic::tests::helper::decode_hex;
    use crate::nasl::test_prelude::*;
    use crate::nasl::test_utils::TestBuilder;

    #[test]
    fn smb_cmac_aes_signature() {
        let mut t = TestBuilder::default();
        t.run(r#"key = "1274637383948293";"#);
        t.run(r#"buf = "1274637383948293";"#);
        t.ok(
            r#"smb_cmac_aes_signature(key:key,buf:buf);"#,
            NaslValue::Data(decode_hex("73C1B26E84FFC51037E057734B8AC8E2").unwrap()),
        );
    }
    #[test]
    fn smb_gmac_aes_signature() {
        let mut t = TestBuilder::default();
        t.run(r#"key = "1274637383948293";"#);
        t.run(r#"buf = "1274637383948293";"#);
        t.run(r#"iv = "127463738394";"#);
        t.ok(
            r#"smb_gmac_aes_signature(key:key,buf:buf,iv:iv);"#,
            NaslValue::Data(decode_hex("73C1B26E84FFC51037E057734B8AC8E2").unwrap()),
        );
    }
    #[test]
    fn smb3kdf() {
        let mut t = TestBuilder::default();
        t.run(r#"key = "1274637383948293";"#);
        t.run(r#"label = "1274637383948293";"#);
        t.run(r#"ctx = "28374928";"#);
        t.run(r#"lvalue = 128;"#);
        t.run(r#"display(smb3kdf(key:key,label:label,ctx:ctx,lvalue:lvalue));"#);
        t.ok(
            r#"smb3kdf(key:key,label:label,ctx:ctx,lvalue:lvalue);"#,
            NaslValue::Data(decode_hex("73C1B26E84FFC51037E057734B8AC8E2").unwrap()),
        );
    }
}

// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod helper;
#[cfg(test)]
mod tests {

    use super::helper::decode_hex;
    use nasl_interpreter::*;

    #[test]
    fn aes128_ccm_crypt() {
        let code = r#"
        key = hexstr_to_data("d24a3d3dde8c84830280cb87abad0bb3");
        data = hexstr_to_data("7c86135ed9c2a515aaae0e9a208133897269220f30870006");
        iv = hexstr_to_data("f1100035bb24a8d26004e0e24b");
        crypt = aes128_ccm_encrypt(key: key, data: data, iv: iv);
        aes128_ccm_decrypt(key: key, data: crypt, iv: iv);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("1faeb0ee2ca2cd52f0aa3966578344f24e69b742c4ab37ab1123301219c70599b7c373ad4b3ad67b").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("7c86135ed9c2a515aaae0e9a208133897269220f30870006").unwrap()
            )))
        );
    }

    #[test]
    fn aes128_ccm_crypt_auth() {
        let code = r#"
        key = hexstr_to_data("5a33980e71e7d67fd6cf171454dc96e5");
        data = hexstr_to_data("a34dfa24847c365291ce1b54bcf8d9a75d861e5133cc3a74");
        iv = hexstr_to_data("33ae68ebb8010c6b3da6b9cb29");
        aad = hexstr_to_data("eca622a37570df619e10ebb18bebadb2f2b49c4d2b2ff715873bb672e30fc0ff");
        crypt = aes128_ccm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);
        aes128_ccm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("7a60fa7ee8859e283cce378fb6b95522ab8b70efcdb0265f7c4b4fa597666b86dd1353e400f28864").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("a34dfa24847c365291ce1b54bcf8d9a75d861e5133cc3a74").unwrap()
            )))
        );
    }

    #[test]
    fn aes192_ccm_crypt() {
        let code = r#"
        key = hexstr_to_data("26511fb51fcfa75cb4b44da75a6e5a0eb8d9c8f3b906f886");
        data = hexstr_to_data("39f08a2af1d8da6212550639b91fb2573e39a8eb5d801de8");
        iv = hexstr_to_data("15b369889699b6de1fa3ee73e5");
        crypt = aes192_ccm_encrypt(key: key, data: data, iv: iv);
        aes192_ccm_decrypt(key: key, data: crypt, iv: iv);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("6342b8700edec97a960eb16e7cb1eb4412fb4e263ddd2206b090155d34a76c8324e5550c3ef426ed").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("39f08a2af1d8da6212550639b91fb2573e39a8eb5d801de8").unwrap()
            )))
        );
    }

    #[test]
    fn aes192_ccm_crypt_auth() {
        let code = r#"
        key = hexstr_to_data("50925853a84a33ff392154e4e737efc18dcfc98f4d5235a9");
        data = hexstr_to_data("718f061e8b972a3adcf465d66c5b28e8661f080127f6722f");
        iv = hexstr_to_data("809343e986f6ff47f54d4cac22");
        aad = hexstr_to_data("d70aef3532bdc5293a3ebb11589ac1f801c9f93ea0d656e1d04068facf9f768b");
        crypt = aes192_ccm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);
        aes192_ccm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("bad3b0e6772e9c4c9c631c095e259d99692292932efb72b8966e91a19617bb748f3495aa433585bb").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("718f061e8b972a3adcf465d66c5b28e8661f080127f6722f").unwrap()
            )))
        );
    }

    #[test]
    fn aes256_ccm_crypt() {
        let code = r#"
        key = hexstr_to_data("26511fb51fcfa75cb4b44da75a6e5a0eb8d9c8f3b906f886df3ba3e6da3a1389");
        data = hexstr_to_data("30d56ff2a25b83fee791110fcaea48e41db7c7f098a81000");
        iv = hexstr_to_data("72a60f345a1978fb40f28a2fa4");
        crypt = aes256_ccm_encrypt(key: key, data: data, iv: iv);
        aes256_ccm_decrypt(key: key, data: crypt, iv: iv);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("55f068c0bbba8b598013dd1841fd740fda2902322148ab5e935753e601b79db4ae730b6ae3500731").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("30d56ff2a25b83fee791110fcaea48e41db7c7f098a81000").unwrap()
            )))
        );
    }

    #[test]
    fn aes256_ccm_crypt_auth() {
        let code = r#"
        key = hexstr_to_data("2e6e34070caf1b8820ed39edfa83459abe1c15a1827f1c39f7ac316c4c27910f");
        data = hexstr_to_data("771a7baa9cf83aa253349f6475d5e74dba4525307b022ba7");
        iv = hexstr_to_data("c49ccef869bb86d21932cb443b");
        aad = hexstr_to_data("d37e35d7cdccd9824a1ae4c787819735e4af798a3beb49d4705336d6496853ad");
        crypt = aes256_ccm_encrypt_auth(key: key, data: data, iv: iv, aad: aad);
        aes256_ccm_decrypt_auth(key: key, data: crypt, iv: iv, aad: aad);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("eebac2475004970071dfa2cfb855c4e78b1add8dcbccfc0bd6b14027324b657a56263df148665393").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("771a7baa9cf83aa253349f6475d5e74dba4525307b022ba7").unwrap()
            )))
        );
    }
}

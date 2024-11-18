// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod tests {

    use crate::nasl::builtin::cryptographic::tests::helper::decode_hex;
    use crate::nasl::test_prelude::*;
    use crate::nasl::test_utils::TestBuilder;

    #[test]
    fn rsa_public_encrypt() {
        let mut t = TestBuilder::default();
        t.run(r#"data = raw_string("Message for test case!");"#);
        t.run(r#"priv_pem = '-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA0iwwjNj9ol+FbDDN\n9A/43IkHT1IixxqoeaGOecrGbqGa3NU9rCVIPzX8d9Nox+gLmG7QM1fUIs/lgoCR\nq55EOwIDAQABAkBuNZnn4cluoeRXDWiSOOXozzo0EAAIpCQAVAVgPEK9s7EyFz9/\nbSA+MIQ+Rz3eyMrsIk0+Q2RvTMu484jSq7ZRAiEA68ymGnja/ogJs9WWmAza7Mkd\n1C+5IV/FCNqMowkKwHUCIQDkLYQPzCxjpNec1XZWT1hvJnaQHYnZpESZx2EUch9b\n7wIhAJQimSeATXQiWpYT1OvpB5BCOO8YnCGPXOVXB4tVHuARAiAw9KcJ8KdxdZOh\nHZd3KyzxJBJ6FyxVWs4xJDrq9RVPVwIgd+VVQKcR+jQQ0sNetgwnbdh6ocy+iwfa\nWocZ+0rNyeY=\n-----END PRIVATE KEY-----\n';"#);
        t.run(r#"n = hexstr_to_data("c2abb4655a528a0be0c00d997a5e1afb238d2373a619291934f50c648b99138ca79a1b937d1dc15eebad74bd750873bd0d452e1a11002698f54b44113d9e3903a0c6ecd6c4f07f006d0673be6be7937da7aefd74a582a45dfbc2f42afaccd868e4aa7d9b0fb6b1a64c9e46d7a5feeb46a570003ba1385581da6bbb30d6ee1c435aa6a1b06ce02580276f0b62869886bea2175b06b8d175cfa17d93adb0e108ce2ad1ff2f189856175d38fb783e8dcdcbbc3a69e0298ab52dea7308ae4833ac578925eda1be9990f40aee8db875b11633d440edf7ff3ca5ff977e1de0ecc6f9039795b4fbd1069a7a368d0cc33003afeef038369d14b8970441ed1f77c9ec6a39");"#);
        t.run(r#"e = hexstr_to_data("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");"#);
        t.run(r#"d = hexstr_to_data("3a881808755ce5e6e65fb8771224e365e96d91603f6bc740adfc940a5332e67edf11e602b596d1c2718848d6822ed565dd6c948cffd994c15ed78f92c37d245563ed0bdf137de021c7a62dfcee42c5c4fd3b0f38185fac7e19a9a77298d028ad793b8de2a699ded64aa93851b4b66e1562bec74326996294559118ca79854477b19656a3513f65cbb0e1f7f4eb398f437ffa42ec305c622243748dd4c325fefd0b7fdd2d0ee681b78eda554343380874cb7129de853f46344c781f702148efda7f9af0d9268d0dc40ec19489a9a16aa26a24c1d545ea4625cbaeed2989620aebda62b5c7604fce9bdbe9e1f9a2ea739af90263ee18a468523002903dbb81b5d5");"#);
        t.run(r#"enc_data = rsa_public_encrypt(data:data,n:n,e:e,pad:TRUE);"#);
        t.ok(
            r#"rsa_private_decrypt(data:enc_data,n:n,e:e,d:d,pad:TRUE);"#,
            NaslValue::Data("Message for test case!".into()),
        );
        t.run(r#"enc_data = rsa_public_encrypt(data:data,n:n,e:e,pad:FALSE);"#);
        t.ok(
            r#"rsa_private_decrypt(data:enc_data,n:n,e:e,d:d,pad:FALSE);"#,
            NaslValue::Data("Message for test case!".into()),
        );
        t.ok(r#"sign = rsa_sign(data:data,pem:priv_pem,passphrase:"");"#,decode_hex("802D2364DC1B9A99B62AFC6E5344B5682FD7742767C42EEB90E49C60281B0475984FFFA40C68CFB61D1EFAC490D4B3282F09BE84DA781D90BB356954264107D3").unwrap());
        t.run(r#"rsa_public_decrypt(sign:data,e:e,n:n);"#);
    }
}

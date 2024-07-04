// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod helper;
#[cfg(test)]
mod tests {

    use super::helper::decode_hex;
    use nasl_interpreter::*;

    #[test]
    fn rsa_public_encrypt() {
        let code = r#"
        data = raw_string("Message for test case!");
        priv_pem = raw_string("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwqu0ZVpSigvgwA2Zel4a+yONI3OmGSkZNPUMZIuZE4ynmhuTfR3BXuutdL11CHO9DUUuGhEAJpj1S0QRPZ45A6DG7NbE8H8AbQZzvmvnk32nrv10pYKkXfvC9Cr6zNho5Kp9mw+2saZMnkbXpf7rRqVwADuhOFWB2mu7MNbuHENapqGwbOAlgCdvC2KGmIa+ohdbBrjRdc+hfZOtsOEIzirR/y8YmFYXXTj7eD6Nzcu8OmngKYq1LepzCK5IM6xXiSXtob6ZkPQK7o24dbEWM9RA7ff/PKX/l34d4OzG+QOXlbT70QaaejaNDMMwA6/u8Dg2nRS4lwRB7R93yexqOQIDAQABAoIBADqIGAh1XOXm5l+4dxIk42XpbZFgP2vHQK38lApTMuZ+3xHmArWW0cJxiEjWgi7VZd1slIz/2ZTBXtePksN9JFVj7QvfE33gIcemLfzuQsXE/TsPOBhfrH4ZqadymNAorXk7jeKmmd7WSqk4UbS2bhVivsdDJplilFWRGMp5hUR3sZZWo1E/Zcuw4ff06zmPQ3/6QuwwXGIiQ3SN1MMl/v0Lf90tDuaBt47aVUNDOAh0y3Ep3oU/RjRMeB9wIUjv2n+a8NkmjQ3EDsGUiamhaqJqJMHVRepGJcuu7SmJYgrr2mK1x2BPzpvb6eH5oupzmvkCY+4YpGhSMAKQPbuBtdUCgYEA1c/nJ63RYMQn+3GvTyQPJofLdBlxvtlxzMakVimtK84MvNs+mjuwCBMV0cOmdO7M7ZZPuTvz9STe7S9fctcQYbNZW+ubcXWp3iVjCE4ZnkRQjfsZKSmRsJYlJtlYmiCvW0N1PVdCWZ4D8San4oebaXUhNCSXp1JaitBjpF7ubl8CgYEA6RTt/EhHaVL6TF4l3YifstLH20EpLzzonOEC1pYlZt34G/cX5W4dSHVV/2Wf8LSHJ9eSKOoOzMXN+d2Dke8xIzIp8nV8XhUrU3dyEu2EoJAHZJVh33/U1/cWdnwEAzdF8NvNXVlc9T1/iSdEEmJ3hmvVPy/sQZj4i07GMHedPmcCgYAtT/c8GIE0Eb4rcqdljU3Mq6C5hR7vBGQysrJnNEPn8a4PZCN7SkT/IRRRtTYUt/skKuPQbN1BycOY3p5K1zs4iWrZqS/zNq1+T8wSGYMiYHX18Q4fBBlFJDzRY+R8HYssOzqgelqsZWmOdNPFlVmhWtpjk5G0OybHHmzPi/LZ3wKBgQDnYbqbHpmdqh0F4NSQJkf6+poiQ36CAWIeEpWBts3sX2AlStczEGwLeUfk4Nq01lHxsGPNMAV/LMI8ULWDEsNh4DOaGR1cPIGlO0dIGPf3eOON62mcuMbvmb934ccN9jn9UAZ/q+3HGsTXv94org1fqP6p2oYb3KKnkIzYonW78wKBgQCVi2DOD4fwl8E2/aprCxrMJFavVFxDsSqCcqKvlUlxzOPDIFrKNY+xnrvQSUQBapdT7T4hcV7cLsKI5bLy7vuaCarwsYGeTtoOsu080Mh3kgAQ2e3WVErwKBD4mut65W4R6EqCCxyoU5DKZHT3fXwQBlSyxOENGdw4UR+4DACUyA==\n-----END RSA PRIVATE KEY-----");
        n = hexstr_to_data("c2abb4655a528a0be0c00d997a5e1afb238d2373a619291934f50c648b99138ca79a1b937d1dc15eebad74bd750873bd0d452e1a11002698f54b44113d9e3903a0c6ecd6c4f07f006d0673be6be7937da7aefd74a582a45dfbc2f42afaccd868e4aa7d9b0fb6b1a64c9e46d7a5feeb46a570003ba1385581da6bbb30d6ee1c435aa6a1b06ce02580276f0b62869886bea2175b06b8d175cfa17d93adb0e108ce2ad1ff2f189856175d38fb783e8dcdcbbc3a69e0298ab52dea7308ae4833ac578925eda1be9990f40aee8db875b11633d440edf7ff3ca5ff977e1de0ecc6f9039795b4fbd1069a7a368d0cc33003afeef038369d14b8970441ed1f77c9ec6a39");
        e = hexstr_to_data("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");
        d = hexstr_to_data("3a881808755ce5e6e65fb8771224e365e96d91603f6bc740adfc940a5332e67edf11e602b596d1c2718848d6822ed565dd6c948cffd994c15ed78f92c37d245563ed0bdf137de021c7a62dfcee42c5c4fd3b0f38185fac7e19a9a77298d028ad793b8de2a699ded64aa93851b4b66e1562bec74326996294559118ca79854477b19656a3513f65cbb0e1f7f4eb398f437ffa42ec305c622243748dd4c325fefd0b7fdd2d0ee681b78eda554343380874cb7129de853f46344c781f702148efda7f9af0d9268d0dc40ec19489a9a16aa26a24c1d545ea4625cbaeed2989620aebda62b5c7604fce9bdbe9e1f9a2ea739af90263ee18a468523002903dbb81b5d5");
        signature = hexstr_to_data("663cbd854f0ca0fc108a87ac4771254b05592120dc7a5cf27dd67b8200b4a58cc4a3053fb2fdecd93684ed13bf0d1fea51238bf9955b1dff133742dd828c0099e5ec5841c3ef8c9bdbd8dc135043bedff0c9e31658e14ec68a5538a93123a54f3ae4793768de3d0e2b8781242805caf76bebc2b3f2964e242ed407bffade1d0b4a6796c85911a194b91d569573357efec2449f53b3a9c225a994a13a7140146f93c381ddb38e346de77da6b44d9ca33e5461981009efb27cdbd5842af73a8e7d0af248589cb0fb271743638c38a49d54876d2126a65b15733f06ec6f0181245d3bb3250f3ac52b2af8f21df25101216e7a0cfe1ee12b71c786d4155408e1046a");
        enc_data = rsa_public_encrypt(data:data,n:n,e:e);
        rsa_private_decrypt(data:enc_data,n:n,e:e,d:d);
        sign = rsa_sign(data:data,priv:priv_pem,passphrase:raw_string(""));
        rsa_public_decrypt(sign:sign,e:e,n:n);
        "#;
        let register = Register::default();
        let binding = ContextFactory::default();
        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data("Message for test case!".into())))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex("663cbd854f0ca0fc108a87ac4771254b05592120dc7a5cf27dd67b8200b4a58cc4a3053fb2fdecd93684ed13bf0d1fea51238bf9955b1dff133742dd828c0099e5ec5841c3ef8c9bdbd8dc135043bedff0c9e31658e14ec68a5538a93123a54f3ae4793768de3d0e2b8781242805caf76bebc2b3f2964e242ed407bffade1d0b4a6796c85911a194b91d569573357efec2449f53b3a9c225a994a13a7140146f93c381ddb38e346de77da6b44d9ca33e5461981009efb27cdbd5842af73a8e7d0af248589cb0fb271743638c38a49d54876d2126a65b15733f06ec6f0181245d3bb3250f3ac52b2af8f21df25101216e7a0cfe1ee12b71c786d4155408e1046a").unwrap()
            )))
        );
        parser.next();
    }
}

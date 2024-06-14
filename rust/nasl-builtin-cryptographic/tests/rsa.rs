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
        data = hexstr_to_data("11111111");
        n = hexstr_to_data("cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72cc516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aefb920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a96815b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbfa2e02380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d");
        e = hexstr_to_data("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000260445");
        d = hexstr_to_data("0997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1e15f66fc9389709f8a11f3ea6a5af7effa2d01c189c50f0d5bcbe3fa272e56cfc4a4e1d388a9dcd65df8628902556c8b6bb6a641709b5a35dd2622c73d4640bfa1359d0e76e1f219f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e12e3c67cb629569c185a2e0f35a2f741644c1cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56b8af07193d0fdf3f49cd49f2ef3138b5138862f1470bd2d16e34a2b9e7777a6c8c8d4cb94b4e8b5d616cd5393753e7b0f31cc7da559ba8e98d888914e334773baf498ad88d9631eb5fe32e53a4145bf0ba548bf2b0a50c63f67b14e398a34b0d");
        enc_data = rsa_public_encrypt(data:data,n:n,e:e);
        rsa_private_decrypt(data:enc_data,n:n,e:e,d:d);
        e_sign = hexstr_to_data("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");
        n_sign = hexstr_to_data("c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991");
        s_sign = hexstr_to_data("53ab600a41c71393a271b0f32f521963087e56ebd7ad040e4ee8aa7c450ad18ac3c6a05d4ae8913e763cfe9623bd9cb1eb4bed1a38200500fa7df3d95dea485f032a0ab0c6589678f9e8391b5c2b1392997ac9f82f1d168878916aace9ac7455808056af8155231a29f42904b7ab87a5d71ed6395ee0a9d024b0ca3d01fd7150");
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL46+POylPFg+2fb6PL9DwP+exyA5F/Ly5xPTkREjpm0oWk0ZnMMx8DSzjHLWRD4r2y68wHsvr7PXSfBJ005cJ3bQQiC905+RQZhlf8M3Hc0hQ4PRs3VN7LuHBdW6PQacHkIOL2c933ijCODncTceeF5aty/Gj8Ehe/fqQ7tBuZjAgMBAAECgYBBRev5dtv7jSsGwqMGiYWW+cGVkLaMFlopqt6wtxN1M1E1T6kdrhN2mv7sgBlyJNrQxL8weGMlBvMwemr5aQ22TPnfnKEB42sw/iZcs0186ppIAHNicfAjsBb7BKrqzyL5eOQ5zZjiVKBTsppZCzOFVvP5mPYxpvbf1XFXtBv6pQJBAOoU4fUz9zH5GatgEFNxVIfdgqSK1q34RMqyRc7aT4W1O+TPwYaHde/pi7QXNvOv9MRCzg1zklQGz1Tm6U0No1cCQQDQCvEySlm/F8xAdfsurC/5yQM+TDV6Q+/Yn6K2cUTyvmh2SLs5GZ7vXbigSWidTNAZhVUcbMj9D2Cbrz30CZnVAkA+csvFatOr1VTvz3ULjdSLWqEb3J5hUzanDOBqyvskJLGR3Ys3pLPmCVxn8zmJ0YtvQJNQK2ECYb62W9Qp5lWJAkEAi/hgsOI/IYdkX5ZBSfSFTrxEV1y0ui8NJqS4t6Dbr6oV5Eco19D6ErfuqMDbBsIQXKtNSROT4la/O9+agh8XhQJAFnW9iO8ebxVDQ9AJKTkWyMQg/LJK+kf6XqvanlfNghXb0ovMkuNQ6IQMpaaByFPgRl2ElLSPcicVBS3PJfRdpw==\n-----END RSA PRIVATE KEY-----";
        msg_sign = hexstr_to_data("e8312742ae23c456ef28a23142c4490895832765dadce02afe5be5d31b0048fbeee2cf218b1747ad4fd81a2e17e124e6af17c3888e6d2d40c00807f423a233cad62ce9eaefb709856c94af166dba08e7a06965d7fc0d8e5cb26559c460e47bc088589d2242c9b3e62da4896fab199e144ec136db8d84ab84bcba04ca3b90c8e5");
        seed = hexstr_to_data("e5f707e49c4e7cc8fb202b5cd957963713f1c4726677c09b6a7f5dfe");
        rsa_public_decrypt(sign:s_sign,e:e_sign,n:n_sign);
        rsa_sign(data:seed,priv:pem,passphrase:seed);
        "#;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                decode_hex(
                    "3021300906052b0e03021a05000414b4ff848fa95a680e866656620cfc932160ef82b8"
                )
                .unwrap()
            )))
        );
    }
}

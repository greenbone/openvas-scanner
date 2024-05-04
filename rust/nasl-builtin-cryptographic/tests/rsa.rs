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
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(decode_hex("11111111").unwrap())))
        );
    }
}

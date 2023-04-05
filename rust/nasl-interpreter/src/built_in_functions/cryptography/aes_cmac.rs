use aes::Aes128;
use cmac::{Cmac, Mac};

use crate::{
    built_in_functions::cryptography::{get_data, get_key},
    Context, FunctionErrorKind, NaslFunction, NaslValue, Register,
};

/// NASL function to calculate CMAC wit AES128.
///
/// This function expects 2 named arguments key and data either in a string or data type.
/// It is important to notice, that internally the CMAC algorithm is used and not, as the name
/// suggests, CBC-MAC.
fn aes_cmac<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let key = get_key(register)?;
    let data = get_data(register)?;

    let mut mac = Cmac::<Aes128>::new_from_slice(key)?;
    mac.update(data);

    Ok(mac.finalize().into_bytes().to_vec().into())
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes_mac_cbc" => Some(aes_cmac),
        "aes_cmac" => Some(aes_cmac),
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    use nasl_syntax::parse;

    use crate::{helper::decode_hex, DefaultContext, Interpreter, Register};

    #[test]
    fn aes_mac_cbc() {
        let code = r###"
        key = hexstr_to_data("e3ceb929b52a6eec02b99b13bf30721b");
        data = hexstr_to_data("d2e8a3e86ae0b9edc7cc3116d929a16f13ee3643");
        crypt = aes_mac_cbc(key: key, data: data);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("10f3d29e89e4039b85e16438b2b2a470").unwrap()
            )))
        );
    }
}

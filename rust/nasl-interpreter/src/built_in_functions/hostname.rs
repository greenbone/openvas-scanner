use sink::Sink;
use std::str;

use crate::{error::FunctionError, lookup_keys::TARGET, NaslFunction, NaslValue, Register};

/// Resolves IP address of target to hostname
///
/// It does lookup TARGET and when not found falls back to 127.0.0.1 to resolve.
/// If the TARGET is not a IP address than we assume that it already is a fqdn or a hostname and will return that instead.
fn resolve_hostname(register: &Register) -> Result<String, FunctionError> {
    use dns_lookup::lookup_addr;

    let default_ip = "127.0.0.1";
    // currently we use shadow variables as _FC_ANON_ARGS; the original openvas uses redis for that purpose.
    let target = register.named(TARGET).map_or_else(
        || default_ip.to_owned(),
        |x| match x {
            crate::ContextType::Value(NaslValue::String(x)) => x.clone(),
            _ => default_ip.to_owned(),
        },
    );

    match target.parse() {
        Ok(addr) => lookup_addr(&addr).map_err(|x| FunctionError {
            reason: format!("Error while lookup {}: {}", addr, x),
        }),
        // assumes that target is already a hostname
        Err(_) => Ok(target),
    }
}

/// NASL function to get all stored vhosts
///
/// As of now (2023-01-20) there is no vhost handling.
/// Therefore this function does load the registered TARGET and if it is an IP Address resolves it via DNS instead.
pub fn get_host_names(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    resolve_hostname(register).map(|x| NaslValue::Array(vec![NaslValue::String(x)]))
}

/// NASL function to get the current hostname
///
/// As of now (2023-01-20) there is no vhost handling.
/// Therefore this function does load the registered TARGET and if it is an IP Address resolves it via DNS instead.
pub fn get_host_name(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    resolve_hostname(register).map(NaslValue::String)
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "get_host_name" => Some(get_host_name),
        "get_host_names" => Some(get_host_names),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{Interpreter, NaslValue, NoOpLoader, Register};

    #[test]
    fn get_host_name() {
        let code = r###"
        get_host_name();
        get_host_names();
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::String(_)))));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Array(_)))));
    }
}

// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::str;

use crate::{
    error::FunctionErrorKind, lookup_keys::TARGET, Context, NaslFunction, NaslValue, Register,
};

/// Resolves IP address of target to hostname
///
/// It does lookup TARGET and when not found falls back to 127.0.0.1 to resolve.
/// If the TARGET is not a IP address than we assume that it already is a fqdn or a hostname and will return that instead.
fn resolve_hostname(register: &Register) -> Result<String, FunctionErrorKind> {
    use std::net::ToSocketAddrs;

    let default_ip = "127.0.0.1";
    // currently we use shadow variables as _FC_ANON_ARGS; the original openvas uses redis for that purpose.
    let target = register.named(TARGET).map_or_else(
        || default_ip.to_owned(),
        |x| match x {
            crate::ContextType::Value(NaslValue::String(x)) => x.clone(),
            _ => default_ip.to_owned(),
        },
    );

    match target.to_socket_addrs() {
        Ok(mut addr) => Ok(addr.next().map_or_else(String::new, |x| x.to_string())),
        // assumes that target is already a hostname
        Err(_) => Ok(target),
    }
}

/// NASL function to get all stored vhosts
///
/// As of now (2023-01-20) there is no vhost handling.
/// Therefore this function does load the registered TARGET and if it is an IP Address resolves it via DNS instead.
pub fn get_host_names<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    resolve_hostname(register).map(|x| NaslValue::Array(vec![NaslValue::String(x)]))
}

/// NASL function to get the current hostname
///
/// As of now (2023-01-20) there is no vhost handling.
/// Therefore this function does load the registered TARGET and if it is an IP Address resolves it via DNS instead.
pub fn get_host_name<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    resolve_hostname(register).map(NaslValue::String)
}

/// Returns found function for key or None when not found
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "get_host_name" => Some(get_host_name),
        "get_host_names" => Some(get_host_names),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;

    use crate::{DefaultContext, Interpreter, NaslValue, Register};

    #[test]
    fn get_host_name() {
        let code = r###"
        get_host_name();
        get_host_names();
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::String(_)))));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Array(_)))));
    }
}

// ## ERRORS

// parameter *name* is missing

// parameter *value* is missing

// parameter *value* is *int* and its value is -1

// parameter *expire* is -1

// ## EXAMPLES

// **1**: Create an entry, which expires after 10 minutes
// ```cpp
// set_kb_item(name: "foo", value: "bar", expire: 600);
// ```

// **2**: Create an entry, which does not expire
// ```cpp
// set_kb_item(name: "age", value: "42");
// ```

// **3**: Create a list
// ```cpp
// set_kb_item(name: "hosts", value: "foo");
// set_kb_item(name: "hosts", value: "bar");
// ```
// get_kb_item("foo");
//

use std::time::{SystemTime, UNIX_EPOCH};

use storage::{Field, Kb};

use crate::{
    error::{FunctionError, FunctionErrorKind},
    Context, NaslFunction, NaslValue, Register,
};

use super::get_named_parameter;

/// NASL function to set a knowledge base
fn set_kb_item<K>(register: &Register, c: &Context<K>) -> Result<NaslValue, FunctionError> {
    let name = get_named_parameter("set_kb_item", register, "name", true)?;
    let value = get_named_parameter("set_kb_item", register, "value", true)?;
    let expires = match get_named_parameter("set_kb_item", register, "expires", false) {
        Ok(NaslValue::Number(x)) => Some(*x),
        Ok(NaslValue::Exit(0)) => None,
        Ok(x) => {
            return Err(FunctionError::new(
                "set_kb_item",
                FunctionErrorKind::Diagnostic(
                    format!("expected expires to be a number but is {x}."),
                    None,
                )
                .into(),
            ))
        }
        Err(e) => return Err(e),
    }
    .map(|seconds| {
        let start = SystemTime::now();
        match start.duration_since(UNIX_EPOCH) {
            Ok(x) => x.as_secs() + seconds as u64,
            Err(_) => 0,
        }
    });
    c.storage()
        .dispatch(
            c.key(),
            Field::KB(Kb {
                key: name.to_string(),
                value: value.clone().as_primitive(),
                expire: expires,
            }),
        )
        .map(|_| NaslValue::Null)
        .map_err(|e| FunctionError::new("set_kb_item", e.into()))
}

/// Returns found function for key or None when not found
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "set_kb_item" => Some(set_kb_item),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;

    use crate::{DefaultContext, Interpreter, NaslValue, Register};

    #[test]
    fn set_kb_item() {
        let code = r###"
        set_kb_item(name: "test", value: 1);
        set_kb_item(name: "test");
        set_kb_item(value: 1);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert!(matches!(parser.next(), Some(Err(_))));
        assert!(matches!(parser.next(), Some(Err(_))));
    }
}

/// Tests local_var behaviour

#[cfg(test)]
mod tests {

    use nasl_interpreter::{DefaultContext, Interpreter, Register};
    use nasl_interpreter::{InterpretError, NaslValue};

    use nasl_syntax::parse;

    #[test]
    fn in_if() {
        let code = r###"
a = 1;
if (a) {
    local_var a;
    a = 23;
}
a;
        "###;
        let dc = DefaultContext::default();
        let mut register = Register::default();
        let ctx = dc.as_context();
        let mut interpreter = Interpreter::new(&mut register, &ctx);
        let results = parse(code)
            .map(|stmt| match stmt {
                Ok(stmt) => interpreter.resolve(&stmt),
                Err(r) => Err(InterpretError::from(r)),
            })
            .last()
            // for the case of NaslValue that returns nothing
            .unwrap_or(Ok(NaslValue::Exit(0)));
        assert_eq!(results, Ok(NaslValue::Number(1)));
    }
}

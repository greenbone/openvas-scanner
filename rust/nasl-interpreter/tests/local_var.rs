// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

/// Tests local_var behavior

#[cfg(test)]
mod tests {

    use nasl_interpreter::*;

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
        let dc = ContextBuilder::default();
        let mut register = Register::default();
        let ctx = dc.build();
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

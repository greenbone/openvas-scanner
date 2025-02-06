use crate::nasl::test_prelude::*;

#[test]
fn in_if() {
    let t = TestBuilder::from_code(
        r###"
a = 1;
if (a) {
    local_var a;
    a = 23;
}
a;
        "###,
    );
    assert!(matches!(
        t.results().last().unwrap(),
        &Ok(NaslValue::Number(1))
    ));
}

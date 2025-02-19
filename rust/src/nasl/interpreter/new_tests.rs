use crate::nasl::test_prelude::*;

#[test]
fn forking_does_not_happen_twice() {
    let t = TestBuilder::from_code(
        r###"
        set_kb_item(name: "a", value: [1,2,3]);
        foo1 = get_kb_item(name: "a");
        foo2 = get_kb_item(name: "a");
        "###,
    );
    todo!()
}

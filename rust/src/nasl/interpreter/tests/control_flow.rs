use crate::nasl::test_prelude::*;

#[test]
fn break_loop() {
    let mut t = TestBuilder::default();
    t.run(
        "for (i = 0; i < 10; i++) {
            if (i == 5) { break; }
        }",
    );
    t.ok("i;", 5);
}

#[test]
fn break_loop_block() {
    let mut t = TestBuilder::default();
    t.run(
        "for (i = 0; i < 10; i++) {
            {
                if (i == 5) { break; }
            }
        }",
    );
    t.ok("i;", 5);
}

// Weird behavior that is currently the standard, so we test
// for it.
#[test]
fn break_function() {
    let mut t = TestBuilder::default();
    t.run("a = 0;");
    t.run(
        "function foo() {
            a = 1;
            break;
            b = 2;
        }",
    );
    t.run("foo();");
    t.ok("a;", 1);
}

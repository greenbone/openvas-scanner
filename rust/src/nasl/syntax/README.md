# nasl-syntax

`nasl-syntax` is a library to provide structured representation of NASL code.

It will return a Vec<Statement> for further execution or a list of [SyntaxError](./error.rs)s if the given code was incorrect.

## Build

Run `cargo test` to test and `cargo build --release` to build it.

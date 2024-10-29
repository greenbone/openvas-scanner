# nasl-syntax

`nasl-syntax` is a library to provide structured representation of NASL code.

It will return an Iterator with either a [statement](./statement.rs) for further execution or an [error](./error.rs) if the given code was incorrect.

Each statement is self contained and it is expected to be executed iteratively and therefore there is no visitor implementation.


## Usage

```
use scannerlib::nasl::syntax::{Statement, SyntaxError};
let statements =
scannerlib::nasl::syntax::parse("a = 23;b = 1;")
  .collect::<Vec<Result<Statement, SyntaxError>>>();
```

## Build

Run `cargo test` to test and `cargo build --release` to build it.

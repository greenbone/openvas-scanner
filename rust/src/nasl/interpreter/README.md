# nasl-interpreter

Is a library that is utilizing [nasl-syntax](../syntax/) and [storage](../../openvasd/storage/) to execute statements.

The core part is written in [interpreter.rs](./interpreter.rs) and is separated into various extensions to execute a given `Statement` when `resolve` is called.

Each resolve call will result in a [NaslValue](../syntax/naslvalue.rs) or an [InterpretError](../syntax/error.rs) return value.

An interpreter requires:

- `register: &'a mut Register` - to hold all the available data like functions or variables
- `context: &'a Context` - to hold all configuration regarding to the current context:
 - `key: &str` - is used to identify the key-value store. It is usually either an OID or a filename (on description runs). 
 - `storage: &dyn storage` - the storage implementation to be used,
 - `loader: &'a dyn Loader` - is used to load script dependencies on `include`,
 - `logger: Box<dyn NaslLogger>` - the default logger

## Example

```
use scannerlib::nasl::interpreter::{CodeInterpreter};
use scannerlib::nasl::prelude::*;
use scannerlib::storage::ContextKey;
let mut register = Register::default();
let context_builder = ContextFactory::default();
let context = context_builder.build(ContextKey::Scan("1".into(), Some("localhost".into())));
let code = "display('hi');";
let mut parser = CodeInterpreter::new(code, register, &context);
```

## Built in functions

It provides a set of builtin functionality within [built_in_functions](../builtin/) to add a new functionality you have to enhance the lookup function within [lib.rs](../../lib.rs).

Each builtin function follow the syntax of:

```text
fn(&str, &dyn storage, &Register) -> Result<NaslValue, FunctionError>
```

An example of how to write a new builtin function can be found in [misc](../builtin/misc/).

## Build

### Requirements

**Note:** It depends on pcap that cannot be installed via cargo. See [pcap#installing-dependencies](https://github.com/rust-pcap/pcap#installing-dependencies) for further details.
`nasl-interpreter` has dependencies on the following C libraries:

Run `cargo test` to test and `cargo build --release` to build it.

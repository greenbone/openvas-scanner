# nasl-interpreter


Is a library that is utilizing [nasl-syntax](../nasl-syntax/) and [storage](../storage/) to execute statements.

The core part is written in [interpreter.rs](./src/interpreter.rs) and is separated into various extensions to execute a given `Statement` when `resolve` is called.

Each resolve call will result in a [NaslValue](./src/naslvalue.rs) or an [InterpretError](./src/error.rs) return value.

An interpreter requires:

- `register: &'a mut Register` - to hold all the available data like functions or variables
- `context: &'a Context` - to hold all configuration regarding to the current context:
 - `key: &str` - is used to identify the key-value store. It is usually either an OID or a filename (on description runs). 
 - `storage: &dyn storage` - the storage implementation to be used,
 - `loader: &'a dyn Loader` - is used to load script dependencies on `include`,
 - `logger: Box<dyn NaslLogger>` - the default logger


## Example

```
use nasl_interpreter::{Interpreter, Register, ContextBuilder};
let mut register = Register::default();
let context_builder = ContextBuilder::default();
let context = context_builder.build();
let code = "display('hi');";
let mut interpreter = Interpreter::new(&mut register, &context);
let mut parser =
    nasl_syntax::parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
```


## Built in functions

It provides a set of builtin functionality within [built_in_functions](./src/built_in_functions/) to add a new functionality you have to enhance the lookup function within [lib.rs](./src/lib.rs).

Each builtin function follow the syntax of:

```text
fn(&str, &dyn storage, &Register) -> Result<NaslValue, FunctionError>
```

An example of how to write a new builtin function can be found in [misc](./src/built_in_functions/misc.rs).

## Build

### Requirements

**Note:** It depends on pcap that cannot be installed via cargo. See [pcap#installing-dependencies](https://github.com/rust-pcap/pcap#installing-dependencies) for further details.
`nasl-interpreter` has dependencies on the following C libraries:

Run `cargo test` to test and `cargo build --release` to build it.

# nasl-builtin-utils

Contains the necessary traits and helper functions to create builtin functions.

# Error handling
This section briefly describes how to handle errors that occur during builtin functions. Builtin functions return a result with an error type `FnError`. This is a type that contains metadata about the error as well as its kind, described by the `FnErrorKind` enum, which is structured as follows


```rust

type ArgumentError = String;
struct InternalError {};
type BuiltinError = &'static str;

pub enum FnErrorKind {
    Argument(ArgumentError),
    Internal(InternalError),
    Builtin(BuiltinError),
}
```

The variants represent three different kinds of errors: `ArgumentError` refers to errors caused by calling a function with the wrong arguments which typically reflect an error in the usage of the function by the script authors.

`InternalError` refers to any error caused by failure of an internal process of the scanner (such as the storage). This reflects a deeper problem and may mean we cannot simply proceed with execution of the scan.

Finally, `BuiltinError` represents any (more or less expected) error that occurred within a builtin function. This may include timeouts, authentication failures, etc..

## Metadata
As stated above, the metadata (return value, retryable) on how to handle a specific error are stored in a `FnError`. This means that authors of builtin functions always have the option of explicitly overriding any defaults for any specific case. However, in practice, the defaults should reflect the behavior what we want most of the time.

### Return behavior
The return behavior of a given error specifies how an error should be handled during execution. This is specified by the following type:
```rust
use scannerlib::nasl::NaslValue;

enum ReturnBehavior {
    ExitScript,
    ReturnValue(NaslValue),
}
```
When the interpreter encounters an error with `ReturnBehavior::ExitScript` behavior, it will unsurprisingly exit the script. If it encounters an error with `ReturnBehavior::ReturnValue(val)`, it will return `val` and continue execution.

In the corresponding `From` impls, the `Argument` and `Internal` variants of `FnError` are automatically constructed with `ReturnBehavior::ExitScript`, meaning that they abort execution of the script. The `Builtin` variant is constructed with `ReturnBehavior::ReturnValue(NaslValue::Null)` by default, but this value can easily be overwritten when the error is created, for example:
```rust,compile_fail

use scannerlib::nasl::prelude::*;
use scannerlib::nasl::builtin::http::HttpError;

let handle = "/vts".to_string();

HttpError::HandleIdNotFound(handle).with(ReturnValue(-1))
```

### Retry behavior
Certain errors can be flagged as being solvable by retrying the operation that caused them. This is represented by a `retryable` boolean on `FnError`, which is `false` by default for all variants except for a specific internal error in the storage. However, this default behavior can be overwritten at error creation if needed, for example
```rust,compile_fail

use scannerlib::nasl::prelude::*;
use scannerlib::nasl::builtin::http::HttpError;

HttpError::IO(std::io::ErrorKind::ConnectionReset).with(Retryable)
```
I also added a small test to make sure that the interpreter does actually retry retryable errors.

## How to add a new error type for a builtin module
1. Add a custom error type for the builtin module. These can be of arbitrary form but a typical error type might look like
```rust
use scannerlib::nasl::prelude::*;
use thiserror::Error;

#[derive(Debug, Error)]
enum FooError {
    #[error("Bar occurred.")]
    Bar,
    #[error("Baz occurred. Here is some more data: {0}")]
    Baz(String),
}
```
This helps with keeping the error messages all in one place to ensure a common form.

2. Add this builtin error as a variant of the `BuiltinError` type described above.
```rust,compile_fail
enum BuiltinError {
    ...
    Foo(FooError),
    ...
}
```

3. For convenience, some `From` impls and `TryFrom` impls can make the error type easier to use by enabling use of the question mark operator. I added a tiny macro that implements these traits (because the implementations are usually trivial), so this comes down to one line too:
```compile_fail
builtin_error_variant!(Foo, FooError);
```

This is all that is needed to make this error usable in NASL functions:
```rust,compile_fail
fn check(a: usize) -> Result<(), FooError> {
    if a == 0 {
        Err(FooError::Bar)
    }
    else { 
        Ok(())
    }
}

#[nasl_function]
fn foo(a: usize) -> Result<usize, FnError> {
    check(a)?;
    Ok(a)
}
```

As a side note, NASL functions can also return any concrete `impl Into<FnError>` directly, so for this case we can also write

```rust,compile_fail
#[nasl_function]
fn foo(a: usize) -> Result<usize, FooError> {
    if a == 0 { 
        Err(FooError::Bar)
    }
    else {
        Ok(a)
    }
}
```

Note that the above `From` impls that are automatically written by the `builtin_error_variant!` macro can also be manually implemented if one wants to specify defaults for a specific error variant. For example

```rust,compile_fail
impl From<FooError> for FnError {
    fn from(e: FooError) -> FnError {
        match e {
            FooError::Foo => BuiltinError::Foo(e).with(ReturnValue(-1)),
            _ => BuiltinError::Foo(e).into(),
        }
    }
}
```

# nasl-c-lib

Contains functions and structures written in c and wrapper, to be able to use them within the nasl builtin functions.

This library uses the rust cc crate, which is able to compile c code with the system standard c compiler.

For parts of the c implementation some external libraries are necessary in order to compile it. 

The following libraries are compiled as a static library:
- libgcrypt

## Add new c functions

1. Create a new c and h file in the `c` directory. Please use or create an appropriate sub-directory.
2. Configure build.rs script
   1. Add `.file("c/your/code.c")` to the cc builder
   2. Add `println!("cargo:rerun-if-changed=c/your/header.c");`
   3. Add additional needed external libraries with `println!("cargo:rustc-link-lib=static=your_lib");`. The library must be build before with a `libyourlib-sys` crate. Look into `libgcrypt-sys` for reference.
3. Write a wrapper
   1. Create a rust file in the `src` directory. Please use or create an appropriate sub-directory.
   2. Write the binding within `extern "C"`
   3. Write a public wrapper function, that can be used by other libraries

### Additional notes

- The `println!` macro is used to set flags for the rust compiler
- The external c libraries are installed and build automatically with a build script

## Use the nasl-c-lib

After the c implementation and wrapper are written, they can be used within the builtin-functions.
As the nasl-c-lib contains external dependencies, the `nasl-c-lib` is disabled by default and can be enabled with the feature of the same name:
```
cargo build --features nasl-c-lib
```

In addition everything, that uses the nasl-c-lib must be wrapped into a cfg expression, e.g:
```rust
#[cfg(feature = "nasl-c-lib")]
fn aes_gmac<K>(
    register: &nasl_builtin_utils::Register,
    _: &nasl_builtin_utils::Context<K>,
) -> Result<nasl_syntax::NaslValue, nasl_builtin_utils::FunctionErrorKind> {
    use crate::{get_data, get_iv, get_key};
    use nasl_c_lib::cryptographic::mac::aes_gmac;

    let key = get_key(register)?;
    let data = get_data(register)?;
    let iv = get_iv(register)?;

    match aes_gmac(data, key, iv) {
        Ok(val) => Ok(val.into()),
        Err(code) => Err(nasl_builtin_utils::FunctionErrorKind::GeneralError(
            nasl_builtin_utils::error::GeneralErrorType::UnexpectedData(format!(
                "Error code {}",
                code
            )),
        )),
    }
}
```

If the nasl-c-lib is used within a new builtin crate, the following must be added to the corresponding Cargo.toml:
```toml
nasl-c-lib = {path = "../nasl-c-lib", optional = true}
```
And must be added as a feature dependency in the Cargo.toml of `nasl-builtin-std`:
```toml
nasl-c-lib = ["nasl-builtin-cryptographic/nasl-c-lib", "nasl-builtin-example/nasl-c-lib"]
```

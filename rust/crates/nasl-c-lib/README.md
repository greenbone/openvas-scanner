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

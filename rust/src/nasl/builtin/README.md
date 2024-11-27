# nasl-builtin-std

Contains functions that are within the std library of nasl.

To use the std functions it is recommended to use the defined `ContextFactory` as it sets the function register to the one created in `nasl_std_functions` automatically.

All you have to do as a user is to create the builder

```
let cb = scannerlib::nasl::ContextFactory::default();
```

and set all but the functions. This will use the DefaultDispatcher as well as an empty String as a key.

For production use cases it is recommended to use new method and include a key and a storage:

```
let loader = scannerlib::nasl::FSPluginLoader::new("/feed");
let storage = scannerlib::storage::DefaultDispatcher::default();
let cb = scannerlib::nasl::ContextFactory::new(loader, storage);
```

## Add functions to std

To add a function to std you have to add function crate to the Cargo.toml

```toml
[dependencies]
nasl-builtin-string = {path = "../nasl-builtin-string"}
```

and then extend the builder within `nasl_std_functions` with the implementation of `nasl_builtin_utils::NaslFunctionExecuter` of those functions:

```text
builder = builder.push_register(nasl_builtin_string::NaslString)
```

## Add predefined variables

In some cases, from a nasl script, is desirable to have access to builtin variables or even to ones coming from libraries , like in the following nasl script

```text
display(IPPROTO_IP);
```
For this purpose, it is possible to add predefined variables to the Register. The way to do it is similar to for functions. 

All you have to do is to create a builder for the register:

```
let mut register = scannerlib::nasl::RegisterBuilder::build();
```

To add the variables to the register as global, you have to add the function crate to the Cargo.toml, which youprobably have done for adding the functions (see above),

```toml
[dependencies]
nasl-builtin-raw-ip = {path = "../nasl-builtin-raw-ip"}
```
and then extend the register builder within the [nasl_std_variables] with the implementation of the [nasl_built_uitls::NaslVarsDefiner] of those variables:

```text
builder = builder.push_register(nasl_builtin_raw_ip::RawIp)

```

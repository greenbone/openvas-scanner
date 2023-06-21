# nasl-builtin-utils

Contains the necessary traits and helper functions to create builtin functions.

To create a builtin function you have to implement the [NaslFunctionExecuter] trait for your struct.

```

use nasl_builtin_utils::{Context, Register, NaslFunctionExecuter, NaslResult, get_named_parameter};
struct Test;
impl NaslFunctionExecuter<String> for Test {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        _context: &Context<String>,
    ) -> Option<NaslResult> {
        match name {
            "test" => {
                let a: i64 = get_named_parameter(register, "a", true)
                    .unwrap()
                    .into();
                let b: i64 = get_named_parameter(register, "b", true)
                    .unwrap()
                    .into();
                Some(Ok((a + b).into()))
            }
            _ => None,
        }
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        name == "test"
    }
}
```

To register your function you have to add it into the context of an interpreter.

Usually that is done by adding it to [nasl-builtin-std::nasl_std_functions] so that it is registered on an default interpreter run.

If you want to construct it manually (e.g. for testing) you can do it by creating a context and include it as 

```

use nasl_builtin_utils::*;

struct Test;
impl NaslFunctionExecuter<String> for Test {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        _context: &Context<String>,
    ) -> Option<NaslResult> {
        match name {
            "test" => {
                let a: i64 = get_named_parameter(register, "a", true)
                    .unwrap()
                    .into();
                let b: i64 = get_named_parameter(register, "b", true)
                    .unwrap()
                    .into();
                Some(Ok((a + b).into()))
            }
            _ => None,
        }
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        name == "test"
    }
}


let key = "test".to_owned();
let target = "localhost";
let storage = storage::DefaultDispatcher::default();
let loader = nasl_syntax::NoOpLoader::default();
let logger = nasl_syntax::logger::DefaultLogger::default();
let context =
    Context::new(&key, target, &storage, &storage, &loader, &logger, &Test);
let mut register = Register::default();
register.add_local("a", 1.into());
register.add_local("b", 2.into());

assert!(context.nasl_fn_defined("test"));
assert_eq!(
    context.nasl_fn_execute("test", &register),
    Some(Ok(3.into()))
);
```

To register your function as a std checkout [nasl-builtin-std::nasl_std_functions] for more details.

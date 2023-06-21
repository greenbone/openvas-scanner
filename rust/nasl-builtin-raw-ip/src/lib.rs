mod frame_forgery;
use nasl_builtin_utils::{Context, Register};

pub struct RawIp;

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for RawIp {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        frame_forgery::lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        frame_forgery::lookup::<K>(name).is_some()
    }
}

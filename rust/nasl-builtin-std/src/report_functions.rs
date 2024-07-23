use std::sync::{Arc, RwLock};

use models::{Protocol, ResultType};
use nasl_builtin_utils::{Context, ContextType, FunctionErrorKind, Register};
use nasl_syntax::NaslValue;

#[derive(Debug, Clone, Default)]
/// The description builtin function
pub struct Reporting {
    id: Arc<RwLock<usize>>,
}

impl Reporting {
    fn id(&self) -> usize {
        let mut id = self.id.as_ref().write().expect("expected write lock");
        let result = *id;
        *id += 1;
        result
    }

    fn store_result(
        &self,
        typus: ResultType,
        register: &Register,
        context: &Context,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let data = register.named("data").map(|x| x.to_string());
        let port = register
            .named("port")
            .and_then(|x| match x {
                ContextType::Value(x) => Some(x.into()),
                _ => None,
            })
            .map(|x: i64| x as i16);

        let protocol = match register
            .named("proto")
            .map(|x| x.to_string())
            .as_ref()
            .map(|x| x as &str)
        {
            Some("udp") => Protocol::UDP,
            _ => Protocol::TCP,
        };
        let result = models::Result {
            id: self.id(),
            r_type: typus,
            ip_address: Some(context.target().to_string()),
            // TODO: where to get hostname? is it only vhost relevant?
            hostname: None,
            oid: Some(context.key().value()),
            port,
            protocol: Some(protocol),
            message: data,
            detail: None,
        };
        context.dispatcher().retry_dispatch(
            5,
            context.key(),
            storage::Field::Result(result.into()),
        )?;
        Ok(NaslValue::Null)
    }

    /// *void* **log_message**(data: *string*, port:*int* , proto: *string*, uri: *string*);
    ///
    /// Creates a log result based on the given arguments
    /// - data, is the text report
    /// - port, optional TCP or UDP port number of the service
    /// - proto is the protocol ("tcp" by default; "udp" is the other value).
    /// - uri specifies the location of a found product
    fn log_message(
        &self,
        register: &Register,
        context: &Context,
    ) -> Result<NaslValue, FunctionErrorKind> {
        self.store_result(ResultType::Log, register, context)
    }

    /// *void* **security_message**(data: *string*, port:*int* , proto: *string*, uri: *string*);
    ///
    /// Creates a alarm result based on the given arguments
    /// - data, is the text report
    /// - port, optional TCP or UDP port number of the service
    /// - proto is the protocol ("tcp" by default; "udp" is the other value).
    /// - uri specifies the location of a found product
    fn security_message(
        &self,
        register: &Register,
        context: &Context,
    ) -> Result<NaslValue, FunctionErrorKind> {
        self.store_result(ResultType::Alarm, register, context)
    }

    /// *void* **error_message**(data: *string*, port:*int* , proto: *string*, uri: *string*);
    ///
    /// Creates a error result based on the given arguments
    /// - data, is the text report
    /// - port, optional TCP or UDP port number of the service
    /// - proto is the protocol ("tcp" by default; "udp" is the other value).
    /// - uri specifies the location of a found product
    fn error_message(
        &self,
        register: &Register,
        context: &Context,
    ) -> Result<NaslValue, FunctionErrorKind> {
        self.store_result(ResultType::Error, register, context)
    }
}

impl nasl_builtin_utils::NaslFunctionExecuter for Reporting {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        match name {
            "log_message" => Some(self.log_message(register, context)),
            "security_message" => Some(self.security_message(register, context)),
            "error_message" => Some(self.error_message(register, context)),
            _ => None,
        }
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        matches!(name, "log_message" | "security_message" | "error_message")
    }
}

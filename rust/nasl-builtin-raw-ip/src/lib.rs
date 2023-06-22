mod frame_forgery;
mod packet_forgery;
mod raw_ip_utils;
use nasl_builtin_utils::{Context, NaslVars, Register};
use nasl_syntax::NaslValue;

pub struct RawIp;

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for RawIp {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        frame_forgery::lookup(name).map(|x| x(register, context))
            .or_else(|| packet_forgery::lookup(name).map(|x| x(register, context)))
            
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        frame_forgery::lookup::<K>(name)
            .or_else(|| packet_forgery::lookup::<K>(name))
            .is_some()
    }
}

impl nasl_builtin_utils::NaslVarDefiner for RawIp {
    fn nasl_var_define(&self) -> NaslVars {
        let builtin_vars: NaslVars = [
            // Hardware type ethernet
            (
                "ARPHRD_ETHER",
                NaslValue::Number(frame_forgery::ARPHRD_ETHER.into()),
            ),
            // Protocol type IP
            (
                "ETHERTYPE_IP",
                NaslValue::Number(frame_forgery::ETHERTYPE_IP.into()),
            ),
            // Protocol type ARP
            (
                "ETHERTYPE_ARP",
                NaslValue::Number(frame_forgery::ETHERTYPE_ARP.into()),
            ),
            // Length in bytes of an ethernet mac address
            (
                "ETH_ALEN",
                NaslValue::Number(frame_forgery::ETH_ALEN.into()),
            ),
            // Protocol length for ARP
            (
                "ARP_PROTO_LEN",
                NaslValue::Number(frame_forgery::ARP_PROTO_LEN.into()),
            ),
            // ARP operation request
            (
                "ARPOP_REQUEST",
                NaslValue::Number(frame_forgery::ARPOP_REQUEST.into()),
            ),
        ]
        .iter()
        .cloned()
        .collect();
        builtin_vars
    }
}

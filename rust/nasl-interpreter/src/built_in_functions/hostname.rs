use std::{
    ffi::{c_char, CStr},
    mem::{self, MaybeUninit},
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use libc::{
    getnameinfo, in6_addr, in_addr, sa_family_t, sockaddr, sockaddr_in, sockaddr_in6,
    sockaddr_storage, socklen_t, AF_INET, AF_INET6, NI_NUMERICSERV,
};
use sink::Sink;
use std::str;

use crate::{error::FunctionError, lookup_keys::TARGET, NaslFunction, NaslValue, Register};

/// Is a convenient struct to parse SocketAddr into *const sockaddr.
///
/// For DNS requests via libc it is necessary to convert an IP string into an IpAddr
/// and the IpAddr into an SocketAddr to than transform it into an *const sockaddr to
/// be useable as a const socket within the libc library.
///
/// This struct dos make the conversion from IpV4 as well as IpV6 into sockaddr_storage
/// so that it useable as:
///
/// ```ignore
/// let addr: IpAddr = "127.0.0.1".to_owned()
///        .parse()
///        .expect("127.0.0.1 must be parseable");
/// let sock: SocketAddr = (addr, 0).into();
/// let sock: LibCSock = sock.into();
/// ```
///
/// ```ignore
/// let addr: IpAddr = "::1".to_owned()
///        .parse()
///        .expect("::1 must be parseable");
/// let sock: SocketAddr = (addr, 0).into();
/// let sock: LibCSock = sock.into();
/// ```
struct LibCSock {
    storage: sockaddr_storage,
    len: socklen_t,
}

impl LibCSock {
    fn storage(&self) -> *const sockaddr {
        &self.storage as *const _ as *const _
    }
}

impl From<SocketAddr> for LibCSock {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => addr.into(),
            SocketAddr::V6(addr) => addr.into(),
        }
    }
}

impl From<SocketAddrV4> for LibCSock {
    fn from(addr: SocketAddrV4) -> Self {
        let sockaddr_in = sockaddr_in {
            sin_family: AF_INET as sa_family_t,
            sin_port: addr.port().to_be(),
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            },
            sin_zero: Default::default(),
            #[cfg(any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            sin_len: 0,
        };
        let mut storage = MaybeUninit::<sockaddr_storage>::zeroed();
        unsafe { (storage.as_mut_ptr() as *mut sockaddr_in).write(sockaddr_in) };
        Self {
            storage: unsafe { storage.assume_init() },
            len: mem::size_of::<sockaddr_in>() as socklen_t,
        }
    }
}

impl From<SocketAddrV6> for LibCSock {
    fn from(addr: SocketAddrV6) -> Self {
        let sockaddr_in6 = sockaddr_in6 {
            sin6_family: AF_INET6 as sa_family_t,
            sin6_port: addr.port().to_be(),
            sin6_addr: in6_addr {
                s6_addr: addr.ip().octets(),
            },
            sin6_flowinfo: addr.flowinfo(),
            sin6_scope_id: addr.scope_id(),
            #[cfg(any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            sin6_len: 0,
        };
        let mut storage = MaybeUninit::<sockaddr_storage>::zeroed();
        unsafe { (storage.as_mut_ptr() as *mut sockaddr_in6).write(sockaddr_in6) };
        Self {
            storage: unsafe { storage.assume_init() },
            len: mem::size_of::<sockaddr_in6>() as socklen_t,
        }
    }
}
#[inline]
#[cfg(unix)]
fn resolve_ip_to_host_and_service(addr: IpAddr) -> Result<(String, String), FunctionError> {
    use libc::EAI_AGAIN;

    let sock: SocketAddr = (addr, 0).into();
    let sock: LibCSock = sock.into();
    let c_sock = sock.storage();
    let c_sock_len = sock.len;
    let mut c_host = [0 as c_char; 1024];
    let mut c_service = [0 as c_char; 32];
    let mut result = unsafe {
        getnameinfo(
            c_sock,
            c_sock_len,
            c_host.as_mut_ptr(),
            c_host.len() as _,
            c_service.as_mut_ptr(),
            c_service.len() as _,
            NI_NUMERICSERV,
        )
    };
    while result == EAI_AGAIN {
        result = unsafe {
            getnameinfo(
                c_sock,
                c_sock_len,
                c_host.as_mut_ptr(),
                c_host.len() as _,
                c_service.as_mut_ptr(),
                c_service.len() as _,
                NI_NUMERICSERV,
            )
        };
    }
    if result != 0 {
        return Err(FunctionError::new(format!(
            "getnameinfo failed for {} -> {}",
            addr, result
        )));
    }

    let host = unsafe { CStr::from_ptr(c_host.as_ptr()) };
    let service = unsafe { CStr::from_ptr(c_service.as_ptr()) };

    let host = match str::from_utf8(host.to_bytes()) {
        Ok(name) => name.to_owned(),
        Err(_) => return Err(FunctionError::new("Host UTF8 parsing failed".to_owned())),
    };

    let service = match str::from_utf8(service.to_bytes()) {
        Ok(service) => service.to_owned(),
        Err(_) => return Err(FunctionError::new("Service UTF8 parsing failed".to_owned())),
    };
    Ok((host, service))
}

#[inline]
#[cfg(windows)]
/// Unfortunately there is currently no available rust std implementation available.
/// For that rason we are using libc and exclude windows machine for now.
/// If we ever decide to support windows we would need to implement a solution based on
/// `windows::Win32::System::SystemInformation` and `GetComputerNameExW`.
fn resolve_hostname(register: &Register) -> Result<String, FunctionError> {
    return Err(FunctionError::new(
        "resolve_hostname is not supported on Windows.".to_owned(),
    ));
}

#[inline]
#[cfg(unix)]
/// Resolves IP address of target to hostname
///
/// It uses a libc getnameinfo and therefore only works in unix environments.
/// It does lookup TARGET and when not found falls back to 127.0.0.1 to resolve.
/// If the TARGET is not a IP address than we assume that it already is a fqdn or a hostname and will return that instead.
fn resolve_hostname(register: &Register) -> Result<String, FunctionError> {
    let default_ip = "127.0.0.1";
    // currently we use shadow variables as _FC_ANON_ARGS; the original openvas uses redis for that purpose.
    let target = register.named(TARGET).map_or_else(
        || default_ip.to_owned(),
        |x| match x {
            crate::ContextType::Value(NaslValue::String(x)) => x.clone(),
            _ => default_ip.to_owned(),
        },
    );

    match target.parse() {
        Ok(addr) => {
            match resolve_ip_to_host_and_service(addr).map(|(host, _)| host) {
                Ok(v) => Ok(v),
                Err(_) => {
                    // maybe the resolv.conf needs to be reloaded
                    // See https://github.com/rust-lang/rust/issues/41570.
                    unsafe {
                        libc::res_init();
                    }
                    resolve_ip_to_host_and_service(addr).map(|(host, _)| host)
                }
            }
        }
        // assumes that target is already a hostname
        Err(_) => Ok(target),
    }
}

/// NASL function to get all stored vhosts
///
/// As of now (2023-01-20) there is no vhost handling.
/// Therefore this function does load the registered TARGET and if it is an IP Addres resolves it via DNS instead.
pub fn get_host_names(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    resolve_hostname(register).map(|x| NaslValue::Array(vec![NaslValue::String(x)]))
}

/// NASL function to get the current hostname
///
/// As of now (2023-01-20) there is no vhost handling.
/// Therefore this function does load the registered TARGET and if it is an IP Addres resolves it via DNS instead.
pub fn get_host_name(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    resolve_hostname(register).map(NaslValue::String)
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "get_host_name" => Some(get_host_name),
        "get_host_names" => Some(get_host_names),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{Interpreter, NaslValue, NoOpLoader, Register};

    #[test]
    fn get_host_name() {
        let code = r###"
        get_host_name();
        get_host_names();
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::String(_)))));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Array(_)))));
    }
}

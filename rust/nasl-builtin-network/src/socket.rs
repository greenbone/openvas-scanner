// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    io::Read,
    net::{TcpStream, UdpSocket},
    os::fd::AsRawFd,
    sync::RwLock,
    thread::sleep,
    time::{Duration, SystemTime},
};

use nasl_builtin_utils::{error::FunctionErrorKind, Context, Register};
use nasl_syntax::NaslValue;

use crate::get_kb_item;

const MTU: usize = 512 - 60 - 8;

type NaslSocketFunction<K> =
    fn(&NaslSockets, &Register, &Context<K>) -> Result<NaslValue, FunctionErrorKind>;

enum SockType {
    Tcp,
    Udp,
}

enum Handle {
    Tcp(TcpStream),
    Udp(UdpSocket, Vec<u8>),
    Close,
}

#[derive(Default)]
struct Handles {
    handles: Vec<Handle>,
    new: Vec<usize>,
}

pub struct Interval {
    interval: Duration,
    last_tick: SystemTime,
}

impl Interval {
    pub fn tick(&mut self) {
        if let Ok(since) = SystemTime::now().duration_since(self.last_tick) {
            if since < self.interval {
                sleep(self.interval - since);
            }
        }
        self.last_tick = SystemTime::now();
    }
}

#[derive(Default)]
pub struct NaslSockets {
    handles: RwLock<Handles>,
    interval: Option<RwLock<Interval>>,
}

impl NaslSockets {
    fn open(&self, hostname: String, port: u16, socket_type: SockType) -> usize {
        let socket = match socket_type {
            SockType::Tcp => Handle::Tcp(TcpStream::connect(format!("{hostname}:{port}")).unwrap()),
            SockType::Udp => Handle::Udp(
                UdpSocket::bind(format!("{hostname}:{port}")).unwrap(),
                vec![],
            ),
        };

        let mut handles = self.handles.write().unwrap();
        let ret;
        if let Some(free) = handles.new.pop() {
            handles.handles.insert(free, socket);
            ret = free;
        } else {
            ret = handles.handles.len();
            handles.handles.push(socket);
        }
        ret
    }

    /// Close a given file descriptor taken as an unnamed argument.
    fn close<K>(&self, r: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
        let args = r.positional();
        let socket = match args.get(1) {
            Some(x) => match x {
                NaslValue::Number(x) => {
                    if *x < 0 {
                        return Err(FunctionErrorKind::WrongArgument(
                            "Socket FD is smaller than 0".to_string(),
                        ));
                    }
                    *x as usize
                }
                _ => {
                    return Err(FunctionErrorKind::WrongArgument(
                        "Argument has wrong type, expected a Number".to_string(),
                    ))
                }
            },
            None => {
                return Err(FunctionErrorKind::MissingPositionalArguments {
                    expected: 1,
                    got: args.len(),
                })
            }
        };
        let mut handles = self.handles.write().unwrap();
        handles.handles[socket] = Handle::Close;
        handles.new.push(socket);
        Ok(NaslValue::Null)
    }

    /// Send data on a socket.
    /// Args:
    /// takes the following named arguments:
    /// - socket: the socket, of course.
    /// - data: the data block. A string is expected here (pure or impure, this does not matter).
    /// - length: is optional and will be the full data length if not set
    /// - option: is the flags for the send() system call. You should not use a raw numeric value here.
    /// On success the number of sent bytes is returned.
    fn send<K>(&self, r: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
        let socket = super::get_usize(r, "socket")?;
        let data = super::get_data(r)?;
        let len = super::get_opt_int(r, "length");
        let flags = super::get_opt_int(r, "option") as i32;
        let mut len = if len < 1 { data.len() } else { len as usize };

        if len == 0 || len > data.len() {
            len = data.len();
        }

        match self
            .handles
            .write()
            .unwrap()
            .handles
            .get_mut(socket)
            .ok_or(FunctionErrorKind::WrongArgument(format!(
                "the given socket FD {socket} does not exist"
            )))? {
            Handle::Tcp(stream) => {
                let fd = stream.as_raw_fd();

                if let Some(interval) = &self.interval {
                    interval.write().unwrap().tick();
                }

                let n;
                unsafe {
                    n = libc::send(fd, data.as_ptr() as *const libc::c_void, len, flags);
                };
                Ok(NaslValue::Number(n as i64))
            }
            Handle::Udp(socket, last_send) => {
                let fd = socket.as_raw_fd();

                // We restrict the MTU to 512 - 60 - 8 bytes, as this is the minimum
                if len > MTU {
                    return Err(FunctionErrorKind::Dirty(format!(
                        "udp data exceeds the maximum length of {}",
                        MTU
                    )));
                }

                let n;
                unsafe {
                    n = libc::send(fd, data.as_ptr() as *const libc::c_void, len, flags);
                };
                *last_send = data;
                Ok(NaslValue::Number(n as i64))
            }
            Handle::Close => Err(FunctionErrorKind::WrongArgument(
                "the given socket FD is already closed".to_string(),
            )),
        }
    }

    /// Receives data from a TCP or UDP socket. For a UDP socket, if it cannot read data, NASL will
    /// suppose that the last sent datagram was lost and will sent it again a couple of time.
    /// Args:
    /// - socket which was returned by an open sock function
    /// - length the number of bytes that you want to read at most. recv may return before length bytes have been read: as soon as at least one byte has been received, the timeout is lowered to 1 second. If no data is received during that time, the function returns the already read data; otherwise, if the full initial timeout has not been reached, a 1 second timeout is re-armed and the script tries to receive more data from the socket. This special feature was implemented to get a good compromise between reliability and speed when openvas-scanner talks to unknown or complex protocols. Two other optional named integer arguments can twist this behavior:
    /// - min is the minimum number of data that must be read in case the “magic read function” is activated and the timeout is lowered. By default this is 0. It works together with length. More info https://lists.archive.carbon60.com/nessus/devel/13796
    /// - timeout can be changed from the default.
    fn recv<K>(&self, r: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
        let socket = super::get_usize(r, "socket")?;
        let len = super::get_usize(r, "length")?;
        let _ = super::get_opt_int(r, "min");
        let timeout = super::get_opt_int(r, "timeout");
        let mut data = Vec::with_capacity(len);

        match self
            .handles
            .write()
            .unwrap()
            .handles
            .get_mut(socket)
            .ok_or(FunctionErrorKind::WrongArgument(format!(
                "the given socket FD {socket} does not exist"
            )))? {
            Handle::Tcp(stream) => {
                let mut old = None;
                if timeout > 0 {
                    old = stream.read_timeout().unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(timeout as u64)))?;
                }
                // TODO: process min for magic read function"
                let size = stream.read(data.as_mut_slice())?;
                data.truncate(size);

                if let Some(timeout) = old {
                    stream.set_read_timeout(Some(timeout))?;
                }

                Ok(NaslValue::Data(data))
            }
            Handle::Udp(sock, last_send) => {
                let mut timeout = libc::timeval {
                    tv_sec: timeout,
                    tv_usec: 0,
                };
                let fd = sock.as_raw_fd();
                let mut read_fd = std::mem::MaybeUninit::<libc::fd_set>::uninit();

                for _ in 0..5 {
                    let data_available = unsafe {
                        libc::FD_ZERO(read_fd.as_mut_ptr());
                        libc::FD_SET(fd, read_fd.assume_init_mut());

                        libc::select(
                            fd + 1,
                            read_fd.assume_init_mut(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            &mut timeout,
                        ) > 0
                    };

                    if data_available {
                        sock.recv(data.as_mut_slice())?;
                        return Ok(NaslValue::Data(data));
                    } else {
                        // The packet may have been lost en route - we resend it
                        sock.send(last_send)?;
                    }
                }
                Ok(NaslValue::Null)
            }
            Handle::Close => Err(FunctionErrorKind::WrongArgument(
                "the given socket FD is already closed".to_string(),
            )),
        }
    }

    /// Open a KDC socket. This function takes no arguments, but it is mandatory that keys are set. The following keys are required:
    /// - Secret/kdc_hostname
    /// - Secret/kdc_port
    /// - Secret/kdc_use_tcp
    fn open_sock_kdc<K>(
        &self,
        _: &Register,
        context: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let hostname = match get_kb_item(context, "Secret/kdc_hostname")? {
            NaslValue::String(x) => x,
            x => {
                return Err(FunctionErrorKind::Diagnostic(
                    "KB key 'Secret/kdc_hostname' is either missing or has wrong type".to_string(),
                    Some(x),
                ));
            }
        };

        let port = get_kb_item(context, "Secret/kdc_hostname")?;

        let port = match port {
            NaslValue::Number(x) => {
                if x <= 0 || x > 65535 {
                    return Err(FunctionErrorKind::Diagnostic(
                        "KB key 'Secret/kdc_port' out of range".to_string(),
                        Some(port),
                    ));
                }
                x
            }
            x => {
                return Err(FunctionErrorKind::Diagnostic(
                    "KB key 'Secret/kdc_port' is either missing or has wrong type".to_string(),
                    Some(x),
                ));
            }
        };
        if port <= 0 || port > 65535 {
            return Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/kdc_port' out of range".to_string(),
                Some(NaslValue::Number(port)),
            ));
        }

        let use_tcp: bool = get_kb_item(context, "Secret/kdc_hostname")?.into();

        let socket_type = match use_tcp {
            true => SockType::Tcp,
            false => SockType::Udp,
        };

        let ret = self.open(hostname, port as u16, socket_type);

        Ok(NaslValue::Number(ret as i64))
    }

    /// Returns found function for key or None when not found
    fn lookup<K>(key: &str) -> Option<NaslSocketFunction<K>> {
        match key {
            "open_sock_kdc" => Some(Self::open_sock_kdc),
            "close" => Some(Self::close),
            "send" => Some(Self::send),
            "recv" => Some(Self::recv),
            _ => None,
        }
    }
}

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for NaslSockets {
    fn nasl_fn_cache_clear(&self) -> Option<usize> {
        let mut data = self.handles.write().unwrap();
        if data.handles.is_empty() {
            return None;
        }
        let result = data.handles.len();
        data.handles.clear();
        data.handles.shrink_to_fit();
        Some(result)
    }

    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        NaslSockets::lookup(name).map(|x| x(self, register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        NaslSockets::lookup::<K>(name).is_some()
    }
}

// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    os::fd::AsRawFd,
    sync::{Arc, RwLock},
    thread::sleep,
    time::{Duration, SystemTime},
};

use crate::function_set;
use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::{error::FunctionErrorKind, Context};
use dns_lookup::lookup_host;
use nasl_function_proc_macro::nasl_function;
use pkcs8::der::Decode;
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, Stream,
};

use super::{
    get_kb_item, get_retry, mtu,
    network_utils::{bind_local_socket, convert_timeout, ipstr2ipaddr},
    tcp::TcpConnection,
    tls::create_tls_client,
    udp::UdpConnection,
    verify_port, OpenvasEncaps,
};

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

struct TlsConfig {
    cert_path: String,
    key_path: String,
    password: String,
    cafile_path: String,
}

enum NaslSocket {
    // The TCP Connection is boxed, because it uses allot of space
    // This way the size of the enum is reduced
    Tcp(Box<TcpConnection>),
    Udp(UdpConnection),
    Close,
}

#[derive(Default)]
struct Handles {
    handles: Vec<NaslSocket>,
    closed_fd: Vec<usize>,
}

#[derive(Default)]
pub struct NaslSockets {
    handles: RwLock<Handles>,
    interval: Option<RwLock<Interval>>,
}

impl NaslSockets {
    fn add(&self, socket: NaslSocket) -> usize {
        let mut handles = self
            .handles
            .write()
            .expect("Unable to access socket handles");
        if let Some(free) = handles.closed_fd.pop() {
            handles.handles.insert(free, socket);
            free
        } else {
            handles.handles.push(socket);
            handles.handles.len() - 1
        }
    }

    /// Close a given file descriptor taken as an unnamed argument.
    #[nasl_function]
    fn close(&self, socket_fd: usize) -> Result<NaslValue, FunctionErrorKind> {
        let mut handles = self.handles.write().unwrap();
        match handles.handles.get_mut(socket_fd) {
            Some(NaslSocket::Close) => {
                return Err(FunctionErrorKind::Diagnostic(
                    "the given socket FD is already closed".to_string(),
                    None,
                ))
            }
            Some(socket) => {
                *socket = NaslSocket::Close;
                handles.closed_fd.push(socket_fd);
            }
            None => {
                return Err(FunctionErrorKind::Diagnostic(
                    "the given socket FD does not exist".to_string(),
                    None,
                ))
            }
        }
        Ok(NaslValue::Null)
    }

    fn wait_before_next_probe(&self) {
        if let Some(interval) = &self.interval {
            interval.write().unwrap().tick();
        }
    }

    /// Send data on a socket.
    /// Args:
    /// takes the following named arguments:
    /// - socket: the socket, of course.
    /// - data: the data block. A string is expected here (pure or impure, this does not matter).
    /// - length: is optional and will be the full data length if not set
    /// - option: is the flags for the send() system call. You should not use a raw numeric value here.
    ///
    /// On success the number of sent bytes is returned.
    #[nasl_function(named(socket, data, option, len))]
    fn send(
        &self,
        socket: usize,
        data: &[u8],
        option: Option<i64>,
        len: Option<usize>,
    ) -> Result<usize, FunctionErrorKind> {
        let len = if let Some(len) = len {
            if len < 1 || len > data.len() {
                data.len()
            } else {
                len
            }
        } else {
            data.len()
        };

        let data = &data[0..len];

        match self
            .handles
            .write()
            .unwrap()
            .handles
            .get_mut(socket)
            .ok_or(FunctionErrorKind::WrongArgument(format!(
                "the given socket FD {socket} does not exist"
            )))? {
            NaslSocket::Tcp(conn) => {
                self.wait_before_next_probe();

                if !conn.is_tls() {
                    if let Some(flags) = option {
                        conn.set_flags(flags as i32);
                    }
                }

                Ok(conn.write(data)?)
            }
            NaslSocket::Udp(conn) => {
                if let Some(flags) = option {
                    conn.set_flags(flags as i32);
                }
                Ok(conn.write(data)?)
            }
            NaslSocket::Close => Err(FunctionErrorKind::WrongArgument(
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
    #[nasl_function(named(socket, length, min, timeout))]
    fn recv(
        &self,
        socket: usize,
        length: usize,
        min: Option<i64>,
        timeout: Option<i64>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let min = min
            .map(|min| if min < 0 { length } else { min as usize })
            .unwrap_or(length);
        let mut data = vec![0; length];

        match self
            .handles
            .write()
            .unwrap()
            .handles
            .get_mut(socket)
            .ok_or(FunctionErrorKind::WrongArgument(format!(
                "the given socket FD {socket} does not exist"
            )))? {
            NaslSocket::Tcp(conn) => {
                let pos = match timeout {
                    Some(timeout) => {
                        if timeout < 1 {
                            conn.read(&mut data)?
                        } else {
                            conn.read_with_timeout(&mut data, Duration::from_secs(timeout as u64))?
                        }
                    }
                    None => conn.read(&mut data)?,
                };

                Ok(NaslValue::Data(data[..pos].to_vec()))
            }
            NaslSocket::Udp(conn) => {
                let pos = match timeout {
                    Some(timeout) => {
                        if timeout < 1 {
                            conn.read(&mut data)?
                        } else {
                            conn.read_with_timeout(&mut data, Duration::from_secs(timeout as u64))?
                        }
                    }
                    None => conn.read(&mut data)?,
                };

                Ok(NaslValue::Data(data[..pos].to_vec()))
            }
            NaslSocket::Close => Err(FunctionErrorKind::WrongArgument(
                "the given socket FD is already closed".to_string(),
            )),
        }
    }

    #[nasl_function(named(socket, length, timeout))]
    fn recv_line(
        &self,
        socket: usize,
        length: usize,
        timeout: Option<i64>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let mut data = String::new();
        match self
            .handles
            .write()
            .unwrap()
            .handles
            .get_mut(socket)
            .ok_or(FunctionErrorKind::WrongArgument(format!(
                "the given socket FD {socket} does not exist"
            )))? {
            NaslSocket::Tcp(conn) => {
                let pos = match timeout {
                    Some(timeout) => {
                        if timeout < 1 {
                            conn.read_line(&mut data)?
                        } else {
                            conn.read_line_with_timeout(
                                &mut data,
                                Duration::from_secs(timeout as u64),
                            )?
                        }
                    }
                    None => conn.read_line(&mut data)?,
                };
                Ok(NaslValue::Data(data.as_bytes()[..pos].to_vec()))
            }
            NaslSocket::Udp(_) => Err(FunctionErrorKind::Diagnostic(
                "This function is only available for TCP connections".to_string(),
                None,
            )),
            NaslSocket::Close => Err(FunctionErrorKind::WrongArgument(
                "the given socket FD is already closed".to_string(),
            )),
        }
    }

    /// Open a KDC socket. This function takes no arguments, but it is mandatory that keys are set. The following keys are required:
    /// - Secret/kdc_hostname
    /// - Secret/kdc_port
    /// - Secret/kdc_use_tcp
    #[nasl_function]
    fn open_sock_kdc(&self, context: &Context) -> Result<NaslValue, FunctionErrorKind> {
        let hostname = match get_kb_item(context, "Secret/kdc_hostname")? {
            Some(x) => Ok(x.to_string()),
            None => Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/kdc_hostname' is not set".to_string(),
                None,
            )),
        }?;

        let ip = lookup_host(&hostname)
            .map_err(|_| {
                FunctionErrorKind::Diagnostic(format!("unable to lookup hostname {hostname}"), None)
            })?
            .into_iter()
            .next()
            .ok_or(FunctionErrorKind::Diagnostic(
                format!("No IP found for hostname {hostname}"),
                None,
            ))?;

        let port = get_kb_item(context, "Secret/kdc_port")?;

        let port = match port {
            Some(NaslValue::Number(x)) => {
                if x <= 0 || x > 65535 {
                    Err(FunctionErrorKind::Diagnostic(
                        "KB key 'Secret/kdc_port' out of range".to_string(),
                        port,
                    ))
                } else {
                    Ok(x as u16)
                }
            }
            Some(_) => Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/kdc_port' has wrong type".to_string(),
                port,
            )),
            None => Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/kdc_port' is not set".to_string(),
                None,
            )),
        }?;

        let use_tcp: bool = get_kb_item(context, "Secret/kdc_use_tcp")?
            .map(|x| x.into())
            .unwrap_or(false);

        let socket = if use_tcp {
            let tcp = TcpConnection::connect(
                ip,
                port,
                None,
                Duration::from_secs(30),
                None,
                get_retry(context),
            )?;
            NaslSocket::Tcp(Box::new(tcp))
        } else {
            let udp = UdpConnection::new(ip, port)?;
            NaslSocket::Udp(udp)
        };

        let ret = self.add(socket);

        Ok(NaslValue::Number(ret as i64))
    }

    /// Open a TCP socket to the target host.
    /// This function is used to create a TCP connection to the target host.  It requires the port
    /// number as its argument and has various optional named arguments to control encapsulation,
    /// timeout and buffering.
    /// It takes an unnamed integer argument (the port number) and four optional named arguments:
    /// - bufsz: An integer with the the size buffer size.  Note that by default, no buffering is
    ///   used.
    /// - timeout: An integer with the timeout value in seconds.  The default timeout is controlled
    ///   by a global value.
    /// - transport: One of the ENCAPS_* constants to force a specific encapsulation mode or force
    ///   trying of all modes (ENCAPS_AUTO). This is for example useful to select a specific TLS or
    ///   SSL version or use specific TLS connection setup priorities.  See *get_port_transport for
    ///   a description of the ENCAPS constants.
    /// - priority A string value with priorities for an TLS encapsulation. For the syntax of the
    ///   priority string see the GNUTLS manual. This argument is only used in ENCAPS_TLScustom
    ///   encapsulation.
    #[nasl_function(named(timeout, transport, bufsz))]
    fn open_sock_tcp(
        &self,
        port: i64,
        timeout: Option<i64>,
        transport: Option<i64>,
        bufsz: Option<i64>,
        // TODO: Extract information from custom priority string
        // priority: Option<&str>,
        context: &Context,
    ) -> Result<NaslValue, FunctionErrorKind> {
        // Get port
        let port = verify_port(port)?;
        let transport = transport.unwrap_or(-1);

        let addr = ipstr2ipaddr(context.target())?;

        self.wait_before_next_probe();

        let mut fds = vec![];

        let bufsz = if let Some(bufsz) = bufsz {
            if bufsz < 0 {
                None
            } else {
                Some(bufsz as usize)
            }
        } else {
            None
        };

        // TODO: set timeout to global recv timeout * 2 when available
        let timeout = if let Some(sec) = timeout {
            if sec < 1 {
                Duration::from_secs(10)
            } else {
                Duration::from_secs(sec as u64)
            }
        } else {
            Duration::from_secs(10)
        };

        // TODO: for every vhost
        let vhosts = vec!["localhost"];
        for vhost in vhosts {
            let (tcp, tls) = if transport < 0 {
                // TODO: Get port transport and open connection depending on it
                todo!()
            } else {
                match OpenvasEncaps::from_i64(transport) {
                    // Auto Detection
                    Some(OpenvasEncaps::Auto) => {
                        // Try SSL/TLS first
                        let tls = if let Ok(conf) = Self::get_tls_conf(context) {
                            create_tls_client(
                                vhost,
                                &conf.cert_path,
                                &conf.key_path,
                                &conf.password,
                                &conf.cafile_path,
                            )
                            .ok()
                        } else {
                            None
                        };
                        if let Ok(tcp) = TcpConnection::connect(
                            addr,
                            port,
                            tls,
                            timeout,
                            bufsz,
                            get_retry(context),
                        ) {
                            // TODO: Set port transport
                            tcp
                        } else {
                            continue;
                        }
                    }
                    // IP
                    Some(OpenvasEncaps::Ip) => {
                        if let Ok(tcp) = TcpConnection::connect(
                            addr,
                            port,
                            None,
                            timeout,
                            bufsz,
                            get_retry(context),
                        ) {
                            // TODO: Set port transport
                            tcp
                        } else {
                            continue;
                        }
                    }
                    // Unsupported transport layer
                    None | Some(OpenvasEncaps::Max) => {
                        return Err(FunctionErrorKind::WrongArgument(format!(
                            "unsupported transport layer: {transport}(unknown)"
                        )))
                    }
                    // TLS/SSL
                    Some(tls_version) => match tls_version {
                        OpenvasEncaps::Tls12 | OpenvasEncaps::Tls13 => {
                            if let Ok(tls) =
                                Self::create_tls_client(vhost, Self::get_tls_conf(context)?)
                            {
                                if let Ok(tcp) =
                                    Self::open_tcp_stream(addr, port, timeout, get_retry(context))
                                {
                                    (tcp, Some(tls))
                                } else {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        }
                        _ => {
                            return Err(FunctionErrorKind::WrongArgument(format!(
                                "unsupported transport layer: {transport}{tls_version}"
                            )))
                        }
                    },
                }
            };
            let fd = self.add(NaslSocket::Tcp(Box::new(TCPConnection {
                socket: tcp,
                tls_connection: tls,
                buffer: vec![],
                buffer_size: bufsz.unwrap_or(0) as usize,
                buffer_pos: 0,
            })));
            fds.push(fd);
        }

        Ok(NaslValue::Fork(
            fds.iter()
                .map(|val| NaslValue::Number(*val as i64))
                .collect(),
        ))
    }

    fn get_tls_conf(context: &Context) -> (Result<TlsConfig, FunctionErrorKind>) {
        let cert_path = match get_kb_item(context, "Secret/tls_cert")? {
            Some(x) => Ok(x.to_string()),
            None => Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/tls_cert' is not set".to_string(),
                None,
            )),
        }?;

        let key_path = match get_kb_item(context, "Secret/tls_key")? {
            Some(x) => Ok(x.to_string()),
            None => Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/tls_key' is not set".to_string(),
                None,
            )),
        }?;

        let password = match get_kb_item(context, "Secret/tls_password")? {
            Some(x) => Ok(x.to_string()),
            None => Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/tls_password' is not set".to_string(),
                None,
            )),
        }?;

        let cafile_path = match get_kb_item(context, "Secret/tls_cafile")? {
            Some(x) => Ok(x.to_string()),
            None => Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/tls_cafile' is not set".to_string(),
                None,
            )),
        }?;

        Ok(TlsConfig {
            cert_path,
            key_path,
            password,
            cafile_path,
        })
    }

    /// Open a UDP socket to the target host
    #[nasl_function]
    fn open_sock_udp(&self, port: i64, context: &Context) -> Result<NaslValue, FunctionErrorKind> {
        let port = verify_port(port)?;
        let addr = ipstr2ipaddr(context.target())?;

        let socket = NaslSocket::Udp(UdpConnection::new(addr, port)?);
        let fd = self.add(socket);

        Ok(NaslValue::Number(fd as i64))
    }

    /// Get the source port of a open socket
    #[nasl_function]
    fn get_source_port(&self, socket: usize) -> Result<NaslValue, FunctionErrorKind> {
        let handles = self.handles.read().unwrap();
        let socket = handles
            .handles
            .get(socket)
            .ok_or(FunctionErrorKind::WrongArgument(
                "the given socket FD does not exist".to_string(),
            ))?;
        let port = match socket {
            NaslSocket::Tcp(conn) => conn.local_addr()?.port(),
            NaslSocket::Udp(conn) => conn.local_addr()?.port(),
            NaslSocket::Close => {
                return Err(FunctionErrorKind::WrongArgument(
                    "the given socket FD is already closed".to_string(),
                ))
            }
        };
        Ok(NaslValue::Number(port as i64))
    }

    /// *any* **ftp_log_in**(user: *string*, pass: *string*, socket: *int*);

    /// **ftp_log_in** takes three named arguments:
    /// - user: is the user name (it has no default value like “anonymous” or “ftp”)
    /// - pass: is the password (again, no default value like the user e-mail address)
    /// - socket: an open socket.
    #[nasl_function(named(user, pass, socket))]
    fn ftp_log_in(&self, user: &str, pass: &str, socket: usize) -> Result<bool, FunctionErrorKind> {
        let mut buf = [0; 1024];
        match self
            .handles
            .write()
            .unwrap()
            .handles
            .get_mut(socket)
            .ok_or(FunctionErrorKind::WrongArgument(format!(
                "the given socket FD {socket} does not exist"
            )))? {
            NaslSocket::Tcp(conn) => {
                let n = Self::socket_recv_line(conn, &mut buf, None)?;
                if n == 0 {
                    return Err(FunctionErrorKind::Diagnostic(
                        "FTP server did not respond".to_string(),
                        None,
                    ));
                }

                // Check if buf contains 220
                if buf.windows(3).position(|window| window == b"220").is_none() {
                    return Err(FunctionErrorKind::Diagnostic(
                        "FTP server did not respond with 220".to_string(),
                        None,
                    ));
                }

                for i in 0..1024 {
                    let n = Self::socket_recv_line(conn, &mut buf, None)?;
                    if n == 0 {
                        return Err(FunctionErrorKind::Diagnostic(
                            "FTP server did not respond with 220".to_string(),
                            None,
                        ));
                    }
                    if buf[3] != b'-' {
                        break;
                    }

                    if i == 1024 {
                        return Err(FunctionErrorKind::Diagnostic(
                            "Rogue FTP server".to_string(),
                            None,
                        ));
                    }
                }
                let data = format!("USER {}\r\n", user);
                Self::send_tcp(conn, data.as_bytes(), None)?;

                let n = Self::socket_recv_line(conn, &mut buf, None)?;
                if n == 0 {
                    return Err(FunctionErrorKind::Diagnostic(
                        "FTP server did not respond to USER command".to_string(),
                        None,
                    ));
                }
                if buf.windows(3).position(|window| window == b"230").is_some() {
                    for _ in 0..1024 {
                        let n = Self::socket_recv_line(conn, &mut buf, None)?;
                        if buf[3] != b'-' || n == 0 {
                            break;
                        }
                    }
                    return Ok(true);
                }
                if buf.windows(3).position(|window| window == b"331").is_none() {
                    return Err(FunctionErrorKind::Diagnostic(
                        "Neither code 230 or 331 received".to_string(),
                        None,
                    ));
                }
                for i in 0..1024 {
                    let n = Self::socket_recv_line(conn, &mut buf, None)?;

                    if buf[3] != b'-' || n == 0 {
                        break;
                    }

                    if i == 1024 {
                        return Err(FunctionErrorKind::Diagnostic(
                            "Rogue FTP server".to_string(),
                            None,
                        ));
                    }
                }
                let data = format!("PASS {}\r\n", pass);
                Self::send_tcp(conn, data.as_bytes(), None)?;

                let n = Self::socket_recv_line(conn, &mut buf, None)?;
                if n == 0 {
                    return Err(FunctionErrorKind::Diagnostic(
                        "FTP server did not respond to USER command".to_string(),
                        None,
                    ));
                }
                if buf.windows(3).position(|window| window == b"230").is_some() {
                    return Ok(true);
                }
                for _ in 0..1024 {
                    let n = Self::socket_recv_line(conn, &mut buf, None)?;
                    if buf[3] != b'-' || n == 0 {
                        break;
                    }
                }
                Err(FunctionErrorKind::Diagnostic(
                    "FTP Server did not respond with ".to_string(),
                    None,
                ))
            }
            NaslSocket::Udp(_) => Err(FunctionErrorKind::Diagnostic(
                "This function is only available for TCP connections".to_string(),
                None,
            )),
            NaslSocket::Close => Err(FunctionErrorKind::WrongArgument(
                "the given socket FD is already closed".to_string(),
            )),
        }
    }

    /// Retrieve single line response
    pub fn read_response_in(
        conn: &mut TCPConnection,
        expected_code: &[u32],
    ) -> crate::Result<Line> {
        let mut line = String::with_capacity(5);
        self.reader.read_line(&mut line)?;

        if cfg!(feature = "debug_print") {
            print!("FTP {}", line);
        }

        if line.len() < 5 {
            return Err(FtpError::InvalidResponse(
                "error: could not read reply code".to_owned(),
            ));
        }

        let code: u32 = line[0..3].parse().map_err(|err| {
            FtpError::InvalidResponse(format!("error: could not parse reply code: {}", err))
        })?;

        // multiple line reply
        // loop while the line does not begin with the code and a space
        let expected = format!("{} ", &line[0..3]);
        while line.len() < 5 || line[0..4] != expected {
            line.clear();
            if let Err(e) = self.reader.read_line(&mut line) {
                return Err(FtpError::ConnectionError(e));
            }

            if cfg!(feature = "debug_print") {
                print!("FTP {}", line);
            }
        }

        line = String::from(line.trim());

        if expected_code.iter().any(|ec| code == *ec) {
            Ok(Line(code, line))
        } else {
            Err(FtpError::InvalidResponse(format!(
                "Expected code {:?}, got response: {}",
                expected_code, line
            )))
        }
    }
}

function_set! {
    NaslSockets,
    sync_stateful,
    (
        (NaslSockets::open_sock_kdc, "open_sock_kdc"),
        (NaslSockets::open_sock_tcp, "open_sock_tcp"),
        (NaslSockets::open_sock_udp, "open_sock_udp"),
        (NaslSockets::close, "close"),
        (NaslSockets::send, "send"),
        (NaslSockets::recv, "recv"),
        (NaslSockets::recv_line, "recv_line"),
        (NaslSockets::get_source_port, "get_source_port"),
    )
}

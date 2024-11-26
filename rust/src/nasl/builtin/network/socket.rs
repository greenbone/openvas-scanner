// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    io::{self, BufRead, Read, Write},
    net::IpAddr,
    sync::RwLock,
    thread::sleep,
    time::{Duration, SystemTime},
};

use crate::function_set;
use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::{error::FunctionErrorKind, Context};
use dns_lookup::lookup_host;
use nasl_function_proc_macro::nasl_function;
use rustls::ClientConnection;

use super::{
    get_kb_item, get_kb_item_str, get_retry,
    network_utils::{convert_timeout, ipstr2ipaddr},
    tcp::TcpConnection,
    tls::create_tls_client,
    udp::UdpConnection,
    verify_port, OpenvasEncaps,
};

/// Interval used for timing tcp requests. Any tcp request has to wait at least
/// the time defined by this interval after the last request has been sent.
struct Interval {
    interval: Duration,
    last_tick: SystemTime,
}

impl Interval {
    /// Check the time since the last tick and wait if necessary.
    pub fn tick(&mut self) {
        if let Ok(since) = SystemTime::now().duration_since(self.last_tick) {
            if since < self.interval {
                sleep(self.interval - since);
            }
        }
        self.last_tick = SystemTime::now();
    }
}

/// A small configuration Struct to store TLS relevant information
struct TlsConfig {
    cert_path: String,
    key_path: String,
    password: String,
    cafile_path: String,
}

/// Representation of a NASL socket. A NASL socket can be either TCP (including TLS),
/// UDP or Closed
enum NaslSocket {
    // The TCP Connection is boxed, because it uses a lot of space
    // This way the size of the enum is reduced
    Tcp(Box<TcpConnection>),
    Udp(UdpConnection),
    Closed,
}

/// Struct storing handles for socket operations as well as a List of Closed sockets
/// to override next.
#[derive(Default)]
struct Handles {
    handles: Vec<NaslSocket>,
    closed_fd: Vec<usize>,
}

/// The Top level struct storing all NASL sockets as well as the interval for tcp
/// requests.
#[derive(Default)]
pub struct NaslSockets {
    handles: RwLock<Handles>,
    interval: Option<RwLock<Interval>>,
}

impl NaslSockets {
    /// Adds a given NASL socket. It returns the position of the socket within the
    /// list.
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
            Some(NaslSocket::Closed) => {
                return Err(FunctionErrorKind::Diagnostic(
                    "the given socket FD is already closed".to_string(),
                    None,
                ))
            }
            Some(socket) => {
                *socket = NaslSocket::Closed;
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

    /// Check if a new tcp request can be sent and waits if necessary.
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

                if let Some(flags) = option {
                    if flags < 0 || flags > i32::MAX as i64 {
                        return Err(FunctionErrorKind::WrongArgument(
                            "the given flags value is out of range".to_string(),
                        ));
                    }
                    Ok(conn.send_with_flags(data, flags as i32)?)
                } else {
                    Ok(conn.write(data)?)
                }
            }
            NaslSocket::Udp(conn) => {
                if let Some(flags) = option {
                    conn.set_flags(flags as i32);
                }
                Ok(conn.write(data)?)
            }
            NaslSocket::Closed => Err(FunctionErrorKind::WrongArgument(
                "the given socket FD is already closed".to_string(),
            )),
        }
    }

    /// Receives data from a TCP or UDP socket. For a UDP socket, if it cannot read data, NASL will
    /// suppose that the last sent datagram was lost and will sent it again a couple of time.
    /// Args:
    /// - socket which was returned by an open sock function
    /// - length the number of bytes that you want to read at most. recv may return before length
    ///   bytes have been read: as soon as at least one byte has been received, the timeout is
    ///   lowered to 1 second. If no data is received during that time, the function returns the
    ///   already read data; otherwise, if the full initial timeout has not been reached, a
    ///   1 second timeout is re-armed and the script tries to receive more data from the socket.
    ///   This special feature was implemented to get a good compromise between reliability and
    ///   speed when openvas-scanner talks to unknown or complex protocols. Two other optional
    ///   named integer arguments can twist this behavior:
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
                let mut pos = match convert_timeout(timeout) {
                    Some(timeout) => conn.read_with_timeout(&mut data, timeout),
                    None => conn.read(&mut data),
                }?;
                let timeout = Duration::from_secs(1);
                while pos < min {
                    match conn.read_with_timeout(&mut data[pos..], timeout) {
                        Ok(n) => pos += n,
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(NaslValue::Data(data[..pos].to_vec()))
            }
            NaslSocket::Udp(conn) => {
                let pos = match convert_timeout(timeout) {
                    Some(timeout) => conn.read_with_timeout(&mut data, timeout),
                    None => conn.read(&mut data),
                }?;

                Ok(NaslValue::Data(data[..pos].to_vec()))
            }
            NaslSocket::Closed => Err(FunctionErrorKind::WrongArgument(
                "the given socket FD is already closed".to_string(),
            )),
        }
    }

    /// Receives a line from a TCP response. Note that this only works for NASL sockets
    /// of type TCP.
    /// Args:
    /// - socket which was returned by an open sock function
    /// - timeout can be changed from the default.
    #[nasl_function(named(socket, length, timeout))]
    fn recv_line(
        &self,
        socket: usize,
        #[allow(unused_variables)] length: usize,
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
                let pos = match convert_timeout(timeout) {
                    Some(timeout) => conn.read_line_with_timeout(&mut data, timeout),
                    None => conn.read_line(&mut data),
                }?;
                Ok(NaslValue::Data(data.as_bytes()[..pos].to_vec()))
            }
            NaslSocket::Udp(_) => Err(FunctionErrorKind::Diagnostic(
                "This function is only available for TCP connections".to_string(),
                None,
            )),
            NaslSocket::Closed => Err(FunctionErrorKind::WrongArgument(
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
        let hostname = get_kb_item_str(context, "Secret/kdc_hostname")?;

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

    fn make_tls_client_connection(context: &Context, vhost: &str) -> Option<ClientConnection> {
        Self::get_tls_conf(context).ok().and_then(|conf| {
            create_tls_client(
                vhost,
                &conf.cert_path,
                &conf.key_path,
                &conf.password,
                &conf.cafile_path,
            )
            .ok()
        })
    }

    fn open_sock_tcp_vhost(
        context: &Context,
        addr: IpAddr,
        timeout: Duration,
        bufsz: Option<usize>,
        port: u16,
        vhost: &str,
        transport: i64,
    ) -> Result<Option<NaslSocket>, FunctionErrorKind> {
        if transport < 0 {
            // TODO: Get port transport and open connection depending on it
            todo!()
        }
        let tls = match OpenvasEncaps::from_i64(transport) {
            // Auto Detection
            Some(OpenvasEncaps::Auto) => {
                // Try SSL/TLS first
                Self::make_tls_client_connection(context, vhost)
            }
            // IP
            Some(OpenvasEncaps::Ip) => None,
            // Unsupported transport layer
            None | Some(OpenvasEncaps::Max) => {
                return Err(FunctionErrorKind::Diagnostic(
                    format!("unsupported transport layer: {transport} (unknown)"),
                    None,
                ))
            }
            // TLS/SSL
            Some(tls_version) => match tls_version {
                OpenvasEncaps::Tls12 | OpenvasEncaps::Tls13 => {
                    Self::make_tls_client_connection(context, vhost)
                }
                _ => {
                    return Err(FunctionErrorKind::Diagnostic(
                        format!("unsupported transport layer: {transport} {tls_version}"),
                        None,
                    ))
                }
            },
        };
        Ok(
            TcpConnection::connect(addr, port, tls, timeout, bufsz, get_retry(context))
                .map(|tcp| NaslSocket::Tcp(Box::new(tcp)))
                .ok(),
        )
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
        context: &Context,
        port: i64,
        timeout: Option<i64>,
        transport: Option<i64>,
        bufsz: Option<i64>,
        // TODO: Extract information from custom priority string
        // priority: Option<&str>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        // Get port
        let port = verify_port(port)?;
        let transport = transport.unwrap_or(-1);

        let addr = ipstr2ipaddr(context.target())?;

        self.wait_before_next_probe();

        let bufsz = bufsz
            .filter(|bufsz| *bufsz >= 0)
            .map(|bufsz| bufsz as usize);

        // TODO: set timeout to global recv timeout * 2 when available
        let timeout = convert_timeout(timeout).unwrap_or(Duration::from_secs(10));
        // TODO: for every vhost
        let vhosts = ["localhost"];
        let sockets: Vec<Option<NaslSocket>> = vhosts
            .iter()
            .map(|vhost| {
                Self::open_sock_tcp_vhost(context, addr, timeout, bufsz, port, vhost, transport)
            })
            .collect::<Result<_, _>>()?;

        Ok(NaslValue::Fork(
            sockets
                .into_iter()
                .flatten()
                .map(|socket| {
                    let fd = self.add(socket);
                    NaslValue::Number(fd as i64)
                })
                .collect(),
        ))
    }

    /// Reads the information necessary for a TLS connection from the KB and
    /// return a TlsConfig on success.
    fn get_tls_conf(context: &Context) -> Result<TlsConfig, FunctionErrorKind> {
        let cert_path = get_kb_item_str(context, "SSL/cert")?;
        let key_path = get_kb_item_str(context, "SSL/key")?;
        let password = get_kb_item_str(context, "SSL/password")?;
        let cafile_path = get_kb_item_str(context, "SSL/CA")?;

        Ok(TlsConfig {
            cert_path,
            key_path,
            password,
            cafile_path,
        })
    }

    /// Open a UDP socket to the target host
    #[nasl_function]
    fn open_sock_udp(&self, context: &Context, port: i64) -> Result<NaslValue, FunctionErrorKind> {
        let port = verify_port(port)?;
        let addr = ipstr2ipaddr(context.target())?;

        let socket = NaslSocket::Udp(UdpConnection::new(addr, port)?);
        let fd = self.add(socket);

        Ok(NaslValue::Number(fd as i64))
    }

    fn connect_priv_sock(
        &self,
        addr: IpAddr,
        sport: u16,
        dport: u16,
        tcp: bool,
    ) -> Result<NaslValue, FunctionErrorKind> {
        if tcp {
            // TODO: set timeout to global recv timeout when available
            let timeout = Duration::from_secs(10);
            self.wait_before_next_probe();
            let tcp = TcpConnection::connect_priv(addr, sport, dport, timeout)?;
            Ok(NaslValue::Number(
                self.add(NaslSocket::Tcp(Box::new(tcp))) as i64
            ))
        } else {
            let udp = UdpConnection::new_priv(addr, sport, dport)?;
            Ok(NaslValue::Number(self.add(NaslSocket::Udp(udp)) as i64))
        }
    }

    fn open_priv_sock(
        &self,
        addr: IpAddr,
        dport: i64,
        sport: Option<i64>,
        tcp: bool,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let dport = verify_port(dport)?;

        if let Some(sport) = sport {
            let sport = verify_port(sport)?;
            return self.connect_priv_sock(addr, sport, dport as u16, tcp);
        }

        for sport in (1..=1023).rev() {
            let fd = if tcp {
                // TODO: set timeout to global recv timeout when available
                let timeout = Duration::from_secs(10);
                self.wait_before_next_probe();
                if let Ok(tcp) = TcpConnection::connect_priv(addr, sport, dport, timeout) {
                    self.add(NaslSocket::Tcp(Box::new(tcp)))
                } else {
                    continue;
                }
            } else if let Ok(udp) = UdpConnection::new_priv(addr, sport, dport) {
                self.add(NaslSocket::Udp(udp))
            } else {
                continue;
            };
            return Ok(NaslValue::Number(fd as i64));
        }
        Err(FunctionErrorKind::Diagnostic(
            format!(
                "Unable to open priv socket to {} on any socket from 1-1023",
                addr
            ),
            None,
        ))
    }

    /// Open a privileged socket to the target host.
    /// It takes three named integer arguments:
    /// - dport is the destination port
    /// - sport is the source port, which may be inferior to 1024. This argument is optional.
    ///   If it is not set, the function will try to open a socket on any port from 1 to 1023.
    /// - timeout: An integer with the timeout value in seconds.  The default timeout is controlled by a global value.
    #[nasl_function(named(dport, sport))]
    fn open_priv_sock_tcp(
        &self,
        context: &Context,
        dport: i64,
        sport: Option<i64>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let addr = ipstr2ipaddr(context.target())?;
        self.open_priv_sock(addr, dport, sport, true)
    }

    /// Open a privileged UDP socket to the target host.
    /// It takes three named integer arguments:
    /// - dport is the destination port
    /// - sport is the source port, which may be inferior to 1024. This argument is optional.
    ///   If it is not set, the function will try to open a socket on any port from 1 to 1023.
    #[nasl_function(named(dport, sport))]
    fn open_priv_sock_udp(
        &self,
        context: &Context,
        dport: i64,
        sport: Option<i64>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let addr = ipstr2ipaddr(context.target())?;
        self.open_priv_sock(addr, dport, sport, false)
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
            NaslSocket::Closed => {
                return Err(FunctionErrorKind::WrongArgument(
                    "the given socket FD is already closed".to_string(),
                ))
            }
        };
        Ok(NaslValue::Number(port as i64))
    }

    /// Receive a response of a FTP server and checks the status code of it.
    /// This status code is compared to a list of expected status codes and
    /// returned, if it is contained in that list.
    pub fn check_ftp_response(
        mut conn: impl BufRead,
        expected_code: &[usize],
    ) -> Result<usize, FunctionErrorKind> {
        let mut line = String::with_capacity(5);
        conn.read_line(&mut line)?;

        if line.len() < 5 {
            return Err(FunctionErrorKind::Diagnostic(
                "could not read reply code".to_owned(),
                None,
            ));
        }

        let code: usize = line[0..3].parse().map_err(|err| {
            FunctionErrorKind::Diagnostic(format!("could not parse reply code: {}", err), None)
        })?;

        // multiple line reply
        // loop while the line does not begin with the code and a space
        let expected = format!("{} ", &line[0..3]);
        while line.len() < 5 || line[0..4] != expected {
            line.clear();
            conn.read_line(&mut line)?;
        }

        line = String::from(line.trim());

        if expected_code.iter().any(|ec| code == *ec) {
            Ok(code)
        } else {
            Err(FunctionErrorKind::Diagnostic(
                format!("Expected code {:?}, got response: {}", expected_code, line),
                None,
            ))
        }
    }

    /// **ftp_log_in** takes three named arguments:
    /// - user: is the user name (it has no default value like “anonymous” or “ftp”)
    /// - pass: is the password (again, no default value like the user e-mail address)
    /// - socket: an open socket.
    #[nasl_function(named(user, pass, socket))]
    fn ftp_log_in(&self, user: &str, pass: &str, socket: usize) -> Result<bool, FunctionErrorKind> {
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
                Self::check_ftp_response(&mut *conn, &[220])?;
                let data = format!("USER {}\r\n", user);
                conn.write_all(data.as_bytes())?;

                let code = Self::check_ftp_response(&mut *conn, &[230, 331])?;
                if code == 331 {
                    let data = format!("PASS {}\r\n", pass);
                    conn.write_all(data.as_bytes())?;
                    Self::check_ftp_response(&mut *conn, &[230])?;
                }
                Ok(true)
            }
            NaslSocket::Udp(_) => Err(FunctionErrorKind::Diagnostic(
                "This function is only available for TCP connections".to_string(),
                None,
            )),
            NaslSocket::Closed => Err(FunctionErrorKind::WrongArgument(
                "the given socket FD is already closed".to_string(),
            )),
        }
    }
}

function_set! {
    NaslSockets,
    sync_stateful,
    (
        (NaslSockets::open_sock_kdc, "open_sock_kdc"),
        (NaslSockets::open_sock_tcp, "open_sock_tcp"),
        (NaslSockets::open_priv_sock_tcp, "open_priv_sock_tcp"),
        (NaslSockets::open_sock_udp, "open_sock_udp"),
        (NaslSockets::open_priv_sock_udp, "open_priv_sock_udp"),
        (NaslSockets::close, "close"),
        (NaslSockets::send, "send"),
        (NaslSockets::recv, "recv"),
        (NaslSockets::recv_line, "recv_line"),
        (NaslSockets::get_source_port, "get_source_port"),
        (NaslSockets::ftp_log_in, "ftp_log_in"),
    )
}

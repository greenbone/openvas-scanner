// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::nasl::{
    prelude::*,
    utils::{
        function::{Seconds, utils::DEFAULT_TIMEOUT},
        scan_ctx::JmpDesc,
    },
};

use crate::storage::items::kb::{self, KbKey};
use dns_lookup::lookup_host;
use lazy_regex::{Lazy, lazy_regex};
use regex::Regex;
use rustls::ClientConnection;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io::{self, BufRead, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Mutex,
    thread::sleep,
    time::{Duration, SystemTime},
};
use thiserror::Error;

use super::{
    OpenvasEncaps, Port, get_retry, network_utils::convert_timeout, tcp::TcpConnection,
    tls::create_tls_client, udp::UdpConnection,
};

static FTP_PASV: Lazy<Regex> =
    lazy_regex!(r"227 Entering Passive Mode \(\d+,\d+,\d+,\d+,(\d+),(\d+)\)");

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("Socket {0} already closed.")]
    SocketClosed(usize),
    #[error("{0}")]
    Diagnostic(String),
    #[error("{0}")]
    WrongArgument(String),
    #[error("Function {0} only supported on TCP sockets.")]
    SupportedOnlyOnTcp(String),
    #[error("Unable to lookup hostname {0}.")]
    HostnameLookupFailed(String),
    #[error("No IP found for hostname {0}.")]
    HostnameNoIpFound(String),
    #[error("Unsupported transport layer {0} (unknown).")]
    UnsupportedTransportLayerUnknown(i64),
    #[error("Unsupported transport layer {0} (tls_version).")]
    UnsupportedTransportLayerTlsVersion(i64),
    #[error("Unable to open privileged socket for address {0}.")]
    UnableToOpenPrivSocket(IpAddr),
    #[error("Failed to read response code.")]
    FailedToReadResponseCode,
    #[error("Failed to parse response code. {0}")]
    FailedToParseResponseCode(std::num::ParseIntError),
    #[error("Expected code {0:?}, got response: {1}")]
    ResponseCodeMismatch(Vec<usize>, String),
    #[error("String is not an IP address: {0}")]
    InvalidIpAddress(String),
    #[error("String is not a Multicast IP address: {0}")]
    InvalidMulticastIpAddress(String),
    #[error("Failed to join to multicast group {0}")]
    FailedToJoinMulticastGroup(String),
    #[error("Failed to leave multicast group. Never joined group")]
    FailedToLeaveMulticastGroup,
    #[error("Failed to bind socket to {1}. {0}")]
    FailedToBindSocket(io::Error, SocketAddr),
    #[error("No route to destination: {0}.")]
    NoRouteToDestination(IpAddr),
}

/// Interval used for timing tcp requests. Any tcp request has to wait at least
/// the time defined by this interval after the last request has been sent.
struct Interval {
    interval: Duration,
    last_tick: Mutex<SystemTime>,
}

impl Interval {
    /// Check the time since the last tick and wait if necessary.
    fn tick(&self) {
        let mut last_tick = self.last_tick.lock().unwrap();
        if let Ok(since) = SystemTime::now().duration_since(*last_tick) {
            if since < self.interval {
                sleep(self.interval - since);
            }
        }
        *last_tick = SystemTime::now();
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
/// or UDP.
pub enum NaslSocket {
    // The TCP Connection is boxed, because it uses a lot of space
    // This way the size of the enum is reduced
    Tcp(Box<TcpConnection>),
    Udp(UdpConnection),
}

impl NaslSocket {
    fn read_with_timeout(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        match self {
            NaslSocket::Tcp(tcp_connection) => tcp_connection.read_with_timeout(buf, timeout),
            NaslSocket::Udp(udp_connection) => udp_connection.read_with_timeout(buf, timeout),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            NaslSocket::Tcp(tcp_connection) => tcp_connection.read(buf),
            NaslSocket::Udp(udp_connection) => udp_connection.read(buf),
        }
    }

    #[cfg(feature = "nasl-builtin-raw-ip")]
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            NaslSocket::Tcp(tcp_connection) => tcp_connection.write(buf),
            NaslSocket::Udp(udp_connection) => udp_connection.write(buf),
        }
    }
}

/// The Top level struct storing all NASL sockets, a list of the
/// closed sockets which should be overwritten next, as well as the
/// interval for TCP requests.
#[derive(Default)]
pub struct NaslSockets {
    handles: Vec<Option<NaslSocket>>,
    closed_fd: Vec<usize>,
    interval: Option<Interval>,
    recv_timeout: Option<Duration>,
}

impl NaslSockets {
    fn get_socket(&self, fd: usize) -> Result<&Option<NaslSocket>, SocketError> {
        self.handles
            .get(fd)
            .ok_or_else(|| SocketError::WrongArgument("Socket does not exist".into()))
    }

    fn get_socket_mut(&mut self, fd: usize) -> Result<&mut Option<NaslSocket>, SocketError> {
        self.handles
            .get_mut(fd)
            .ok_or_else(|| SocketError::WrongArgument("Socket does not exist".into()))
    }

    fn get_open_socket(&self, fd: usize) -> Result<&NaslSocket, SocketError> {
        self.get_socket(fd)?
            .as_ref()
            .ok_or_else(|| SocketError::WrongArgument("Socket already closed".into()))
    }

    fn get_open_socket_mut(&mut self, fd: usize) -> Result<&mut NaslSocket, SocketError> {
        self.get_socket_mut(fd)?
            .as_mut()
            .ok_or_else(|| SocketError::WrongArgument("Socket already closed".into()))
    }

    /// Adds a given NASL socket. It returns the position of the socket within the
    /// list.
    fn add(&mut self, socket: NaslSocket) -> usize {
        if let Some(free) = self.closed_fd.pop() {
            self.handles.insert(free, Some(socket));
            free
        } else {
            self.handles.push(Some(socket));
            self.handles.len() - 1
        }
    }

    /// Check if a new tcp request can be sent and waits if necessary.
    fn wait_before_next_probe(&self) {
        if let Some(interval) = &self.interval {
            interval.tick();
        }
    }

    fn connect_priv_sock(
        &mut self,
        addr: IpAddr,
        sport: u16,
        dport: u16,
        tcp: bool,
    ) -> Result<NaslValue, SocketError> {
        if tcp {
            let timeout = self
                .recv_timeout
                .unwrap_or(Duration::from_secs(DEFAULT_TIMEOUT as u64));
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
        &mut self,
        addr: IpAddr,
        dport: Port,
        sport: Option<Port>,
        tcp: bool,
    ) -> Result<NaslValue, FnError> {
        if let Some(sport) = sport {
            return Ok(self.connect_priv_sock(addr, sport.0, dport.0, tcp)?);
        }

        for sport in (1..=1023).rev() {
            let fd = if tcp {
                let timeout = self
                    .recv_timeout
                    .unwrap_or(Duration::from_secs(DEFAULT_TIMEOUT as u64));
                self.wait_before_next_probe();
                match TcpConnection::connect_priv(addr, sport, dport.0, timeout) {
                    Ok(tcp) => self.add(NaslSocket::Tcp(Box::new(tcp))),
                    _ => {
                        continue;
                    }
                }
            } else {
                match UdpConnection::new_priv(addr, sport, dport.0) {
                    Ok(udp) => self.add(NaslSocket::Udp(udp)),
                    _ => {
                        continue;
                    }
                }
            };
            return Ok(NaslValue::Number(fd as i64));
        }
        Err(SocketError::UnableToOpenPrivSocket(addr).into())
    }

    pub fn with_recv_timeout(&mut self, timeout: Option<i64>) {
        if let Some(to) = timeout {
            self.recv_timeout = Some(Duration::from_secs(to as u64));
        }
    }
}

/// Close a given file descriptor taken as an unnamed argument.
#[nasl_function]
async fn close(sockets: &mut NaslSockets, socket_fd: usize) -> Result<(), FnError> {
    let socket = sockets.get_socket_mut(socket_fd)?;
    if socket.is_none() {
        return Err(SocketError::SocketClosed(socket_fd).into());
    } else {
        *socket = None;
    };
    sockets.closed_fd.push(socket_fd);
    Ok(())
}

fn send_shared(
    sockets: &mut NaslSockets,
    socket: usize,
    data: &[u8],
    option: Option<i64>,
    len: Option<usize>,
) -> Result<usize, SocketError> {
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

    // Do this before we borrow the socket mutably to make the
    // borrow checker happy. Please give me partial borrows.
    if let NaslSocket::Tcp(_) = sockets.get_open_socket(socket)? {
        sockets.wait_before_next_probe();
    }
    match sockets.get_open_socket_mut(socket)? {
        NaslSocket::Tcp(conn) => {
            if let Some(flags) = option {
                if flags < 0 || flags > i32::MAX as i64 {
                    return Err(SocketError::WrongArgument(
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
async fn send(
    sockets: &mut NaslSockets,
    socket: usize,
    data: &[u8],
    option: Option<i64>,
    len: Option<usize>,
) -> Result<usize, SocketError> {
    send_shared(sockets, socket, data, option, len)
}

fn recv_shared(
    sockets: &mut NaslSockets,
    socket: usize,
    length: usize,
    min: Option<i64>,
    timeout: Option<Seconds>,
) -> Result<Vec<u8>, SocketError> {
    let min = min
        .map(|min| if min < 0 { length } else { min as usize })
        .unwrap_or(length);
    let mut data = vec![0; length];
    let socket = sockets.get_open_socket_mut(socket)?;
    let mut pos = match timeout {
        Some(timeout) => socket.read_with_timeout(&mut data, timeout.as_duration())?,
        None => socket.read(&mut data)?,
    };
    if let NaslSocket::Tcp(conn) = socket {
        let timeout = Duration::from_secs(1);
        while pos < min {
            match conn.read_with_timeout(&mut data[pos..], timeout) {
                Ok(n) => pos += n,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
                Err(e) => return Err(SocketError::from(e)),
            }
        }
    };
    Ok(data[..pos].to_vec())
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
async fn recv(
    sockets: &mut NaslSockets,
    socket: usize,
    length: usize,
    min: Option<i64>,
    timeout: Option<Seconds>,
) -> Result<NaslValue, SocketError> {
    Ok(NaslValue::Data(recv_shared(
        sockets, socket, length, min, timeout,
    )?))
}

/// Receives a line from a TCP response. Note that this only works for NASL sockets
/// of type TCP.
/// Args:
/// - socket which was returned by an open sock function
/// - timeout can be changed from the default.
#[nasl_function(named(socket, length, timeout))]
async fn recv_line(
    sockets: &mut NaslSockets,
    socket: usize,
    #[allow(unused_variables)] length: usize,
    timeout: Option<i64>,
) -> Result<NaslValue, SocketError> {
    let mut data = String::new();
    match sockets.get_open_socket_mut(socket)? {
        NaslSocket::Tcp(conn) => {
            let pos = match convert_timeout(timeout) {
                Some(timeout) => conn.read_line_with_timeout(&mut data, timeout),
                None => conn.read_line(&mut data),
            }?;
            Ok(NaslValue::Data(data.as_bytes()[..pos].to_vec()))
        }
        NaslSocket::Udp(_) => Err(SocketError::SupportedOnlyOnTcp("recv_line".into())),
    }
}

pub fn make_tcp_socket(ip: IpAddr, port: u16, retry: u8) -> Result<NaslSocket, SocketError> {
    let tcp = TcpConnection::connect(ip, port, None, Duration::from_secs(30), None, retry)
        .map_err(SocketError::from)?;
    Ok(NaslSocket::Tcp(Box::new(tcp)))
}

/// Open a KDC socket. This function takes no arguments, but it is mandatory that keys are set. The following keys are required:
/// - Secret/kdc_hostname
/// - Secret/kdc_port
/// - Secret/kdc_use_tcp
#[nasl_function]
async fn open_sock_kdc(
    context: &ScanCtx<'_>,
    sockets: &mut NaslSockets,
) -> Result<NaslValue, FnError> {
    let hostname: String = context.get_single_kb_item(&KbKey::Kdc(kb::Kdc::Hostname))?;

    let ip = lookup_host(&hostname)
        .map_err(|_| SocketError::HostnameLookupFailed(hostname.clone()))?
        .into_iter()
        .next()
        .ok_or(SocketError::HostnameNoIpFound(hostname))?;

    let port = context
        .get_single_kb_item::<Port>(&KbKey::Kdc(kb::Kdc::Port))?
        .0;

    let use_tcp: bool = context.get_single_kb_item(&KbKey::Kdc(kb::Kdc::Protocol))?;

    let socket = if use_tcp {
        make_tcp_socket(ip, port, get_retry(context))?
    } else {
        let udp = UdpConnection::new(ip, port)?;
        NaslSocket::Udp(udp)
    };

    let ret = sockets.add(socket);

    Ok(NaslValue::Number(ret as i64))
}

fn make_tls_client_connection(context: &ScanCtx<'_>, vhost: &str) -> Option<ClientConnection> {
    get_tls_conf(context).ok().and_then(|conf| {
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
    context: &ScanCtx<'_>,
    addr: IpAddr,
    timeout: Duration,
    bufsz: Option<usize>,
    port: u16,
    vhost: &str,
    transport: i64,
) -> Result<Option<NaslSocket>, FnError> {
    let mut transport = if transport.is_negative() {
        context.get_port_transport(port).unwrap_or(1)
    } else {
        transport
    };
    let mut set_transport = false;
    let tls = match OpenvasEncaps::from_i64(transport) {
        // Auto Detection
        Some(OpenvasEncaps::Auto) => {
            set_transport = true;
            // Try SSL/TLS first
            let tls = make_tls_client_connection(context, vhost);
            if tls.is_some() {
                transport = OpenvasEncaps::TlsCustom as i64;
            } else {
                // Try TCP
                transport = OpenvasEncaps::Ip as i64;
            }
            tls
        }
        // IP
        Some(OpenvasEncaps::Ip) => None,
        // Unsupported transport layer
        None | Some(OpenvasEncaps::Max) => {
            return Err(SocketError::UnsupportedTransportLayerUnknown(transport).into());
        }
        // TLS/SSL
        Some(tls_version) => match tls_version {
            OpenvasEncaps::Tls12 | OpenvasEncaps::Tls13 => {
                make_tls_client_connection(context, vhost)
            }
            _ => return Err(SocketError::UnsupportedTransportLayerTlsVersion(transport).into()),
        },
    };

    let conn = TcpConnection::connect(addr, port, tls, timeout, bufsz, get_retry(context))
        .map(|tcp| NaslSocket::Tcp(Box::new(tcp)))
        .ok();
    if set_transport {
        context.set_port_transport(port, transport as usize)?;
    }
    Ok(conn)
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
async fn open_sock_tcp(
    context: &ScanCtx<'_>,
    nasl_sockets: &mut NaslSockets,
    port: Port,
    timeout: Option<i64>,
    transport: Option<i64>,
    bufsz: Option<i64>,
    // TODO: Extract information from custom priority string
    // priority: Option<&str>,
) -> Result<NaslValue, FnError> {
    // Get port
    let transport = transport.unwrap_or(-1);

    let addr = context.target().ip_addr();

    nasl_sockets.wait_before_next_probe();

    let bufsz = bufsz
        .filter(|bufsz| *bufsz >= 0)
        .map(|bufsz| bufsz as usize);

    let timeout = convert_timeout(timeout).unwrap_or(Duration::from_secs(
        context
            .scan_preferences
            .get_preference_int("checks_read_timeout")
            .unwrap_or(DEFAULT_TIMEOUT.into()) as u64
            * 2,
    ));
    let mut vhosts = context
        .target()
        .vhosts()
        .iter()
        .map(|v| v.hostname().to_string())
        .collect::<Vec<String>>();
    if vhosts.is_empty() {
        vhosts.push(context.target().ip_addr().to_string());
    };

    let sockets: Vec<Option<NaslSocket>> = vhosts
        .iter()
        .map(|vhost| open_sock_tcp_vhost(context, addr, timeout, bufsz, port.0, vhost, transport))
        .collect::<Result<_, _>>()?;

    Ok(NaslValue::Fork(
        sockets
            .into_iter()
            .flatten()
            .map(|socket| {
                let fd = nasl_sockets.add(socket);
                NaslValue::Number(fd as i64)
            })
            .collect(),
    ))
}

/// Reads the information necessary for a TLS connection from the KB and
/// return a TlsConfig on success.
fn get_tls_conf(context: &ScanCtx) -> Result<TlsConfig, FnError> {
    let cert_path = context.get_single_kb_item(&KbKey::Ssl(kb::Ssl::Cert))?;
    let key_path = context.get_single_kb_item(&KbKey::Ssl(kb::Ssl::Key))?;
    let password = context.get_single_kb_item(&KbKey::Ssl(kb::Ssl::Password))?;
    let cafile_path = context.get_single_kb_item(&KbKey::Ssl(kb::Ssl::Ca))?;

    Ok(TlsConfig {
        cert_path,
        key_path,
        password,
        cafile_path,
    })
}

/// Open a UDP socket to the target host
#[nasl_function]
async fn open_sock_udp(
    context: &ScanCtx<'_>,
    sockets: &mut NaslSockets,
    port: Port,
) -> Result<NaslValue, FnError> {
    let addr = context.target().ip_addr();

    let socket = NaslSocket::Udp(UdpConnection::new(addr, port.0)?);
    let fd = sockets.add(socket);

    Ok(NaslValue::Number(fd as i64))
}

/// Open a privileged socket to the target host.
/// It takes three named integer arguments:
/// - dport is the destination port
/// - sport is the source port, which may be inferior to 1024. This argument is optional.
///   If it is not set, the function will try to open a socket on any port from 1 to 1023.
/// - timeout: An integer with the timeout value in seconds.  The default timeout is controlled by a global value.
#[nasl_function(named(dport, sport))]
async fn open_priv_sock_tcp(
    context: &ScanCtx<'_>,
    sockets: &mut NaslSockets,
    dport: Port,
    sport: Option<Port>,
) -> Result<NaslValue, FnError> {
    let addr = context.target().ip_addr();
    sockets.open_priv_sock(addr, dport, sport, true)
}

/// Open a privileged UDP socket to the target host.
/// It takes three named integer arguments:
/// - dport is the destination port
/// - sport is the source port, which may be inferior to 1024. This argument is optional.
///   If it is not set, the function will try to open a socket on any port from 1 to 1023.
#[nasl_function(named(dport, sport))]
async fn open_priv_sock_udp(
    context: &ScanCtx<'_>,
    sockets: &mut NaslSockets,
    dport: Port,
    sport: Option<Port>,
) -> Result<NaslValue, FnError> {
    let addr = context.target().ip_addr();
    sockets.open_priv_sock(addr, dport, sport, false)
}

/// Get the source port of a open socket
#[nasl_function]
async fn get_source_port(sockets: &NaslSockets, socket: usize) -> Result<NaslValue, SocketError> {
    let socket = sockets.get_open_socket(socket)?;
    let port = match socket {
        NaslSocket::Tcp(conn) => conn.local_addr()?.port(),
        NaslSocket::Udp(conn) => conn.local_addr()?.port(),
    };
    Ok(NaslValue::Number(port as i64))
}

/// Receive a response of a FTP server and checks the status code of it.
/// This status code is compared to a list of expected status codes and
/// returned, if it is contained in that list.
fn check_ftp_response(
    mut conn: impl BufRead,
    expected_codes: &[usize],
) -> Result<usize, SocketError> {
    let mut line = String::with_capacity(5);
    conn.read_line(&mut line)?;

    if line.len() < 5 {
        return Err(SocketError::FailedToReadResponseCode);
    }

    let code: usize = line[0..3]
        .parse()
        .map_err(SocketError::FailedToParseResponseCode)?;

    // multiple line reply
    // loop while the line does not begin with the code and a space
    let expected = format!("{} ", &line[0..3]);
    while line.len() < 5 || line[0..4] != expected {
        line.clear();
        conn.read_line(&mut line)?;
    }

    line = String::from(line.trim());

    if expected_codes.contains(&code) {
        Ok(code)
    } else {
        Err(SocketError::ResponseCodeMismatch(
            expected_codes.to_vec(),
            line,
        ))
    }
}

/// **ftp_log_in** takes three named arguments:
/// - user: is the user name (it has no default value like “anonymous” or “ftp”)
/// - pass: is the password (again, no default value like the user e-mail address)
/// - socket: an open socket.
#[nasl_function(named(user, pass, socket))]
async fn ftp_log_in(
    sockets: &mut NaslSockets,
    user: &str,
    pass: &str,
    socket: usize,
) -> Result<bool, SocketError> {
    match sockets.get_open_socket_mut(socket)? {
        NaslSocket::Tcp(conn) => {
            check_ftp_response(&mut *conn, &[220])?;
            let data = format!("USER {user}\r\n");
            conn.write_all(data.as_bytes())?;

            let code = check_ftp_response(&mut *conn, &[230, 331])?;
            if code == 331 {
                let data = format!("PASS {pass}\r\n");
                conn.write_all(data.as_bytes())?;
                check_ftp_response(&mut *conn, &[230])?;
            }
            Ok(true)
        }
        NaslSocket::Udp(_) => Err(SocketError::SupportedOnlyOnTcp("ftp_log_in".into())),
    }
}

/// This function sets the FTP server into passive mode and returns the port
/// the server is listening on.
/// Args:
/// - socket: an open socket.
#[nasl_function(named(socket))]
async fn ftp_get_pasv_port(sockets: &mut NaslSockets, socket: usize) -> Result<u16, SocketError> {
    let conn = sockets.get_open_socket_mut(socket)?;
    let conn = match conn {
        NaslSocket::Tcp(conn) => conn,
        NaslSocket::Udp(_) => {
            return Err(SocketError::SupportedOnlyOnTcp("ftp_get_pasv_port".into()));
        }
    };

    conn.write_all(b"PASV\r\n")?;

    let mut data = String::new();
    // should be `227 Entering Passive Mode (h1, h2, h3, h4, p1, p2)`
    conn.read_line(&mut data)?;

    let captures = FTP_PASV.captures(&data).ok_or_else(|| {
        SocketError::Diagnostic(format!("Unexpected response from FTP server: {data}"))
    })?;

    let get_port = |idx: usize| {
        captures
            .get(idx)
            .unwrap()
            .as_str()
            .parse::<u16>()
            .map_err(|e| {
                SocketError::Diagnostic(format!("{e}, invalid port within response: {data}"))
            })
    };
    let p1 = get_port(1)?;
    let p2 = get_port(2)?;
    Ok((p1 << 8) | p2)
}

/// This function performs a telnet negotiation on an open socket
/// Read the data on the socket (more or less the telnet dialog plus the banner).
/// Args:
/// - socket: an open socket.
#[nasl_function]
async fn telnet_init(
    context: &ScanCtx<'_>,
    sockets: &mut NaslSockets,
    socket: usize,
) -> Result<NaslValue, SocketError> {
    struct Buffer {
        buffer: Vec<u8>,
    }

    impl Buffer {
        fn new() -> Self {
            Self {
                buffer: vec![255, 0, 0],
            }
        }

        fn iac(&self) -> u8 {
            self.buffer[0]
        }
        fn set_code(&mut self, val: u8) {
            self.buffer[1] = val;
        }
        fn code(&self) -> u8 {
            self.buffer[1]
        }
        fn set_option(&mut self, val: u8) {
            self.buffer[2] = val;
        }
    }

    if let NaslSocket::Udp(_) = sockets.get_open_socket_mut(socket)? {
        return Err(SocketError::SupportedOnlyOnTcp("telnet_init".into()));
    }
    let mut buf = Buffer::new();
    let mut opts = 0;
    let mut lm_flag = 0;

    while buf.iac() == 255 {
        let to = context
            .scan_preferences
            .get_preference_int("checks_read_timeout")
            .unwrap_or(DEFAULT_TIMEOUT.into()) as u64;
        buf.buffer = recv_shared(sockets, socket, 3, Some(3), Some(Seconds(to)))?;
        if buf.iac() != 255 || buf.buffer.is_empty() || buf.buffer.len() != 3 {
            break;
        }
        // In the Telnet protocol specification, "WILL," "WON'T," "DO," and "DON'T"
        // are commands used for negotiating options between a client and a server.
        // "WILL" indicates a desire to start using an option, while "WON'T" indicates
        // a refusal to use it. Conversely, "DO" indicates a request for the other
        // party to start using an option, and "DON'T" indicates a request for them
        // to stop using it.
        if buf.code() == 251 || buf.code() == 252 {
            buf.set_code(254); /* WILL , WONT -> DON'T */
        } else if buf.code() == 253 || buf.code() == 254 {
            buf.set_code(252); /* DO,DONT -> WONT */
        };

        send_shared(sockets, socket, &buf.buffer, None, Some(3))?;
        if lm_flag == 0 {
            buf.set_code(253);
            buf.set_option(0x22);
            send_shared(sockets, socket, &buf.buffer, None, Some(3))?;
            lm_flag += 1;
        }

        opts += 1;
        if opts > 100 {
            break;
        }
    }
    if buf.buffer.is_empty() && opts == 0 {
        return Ok(NaslValue::Null);
    }

    if opts > 100 {
        return Err(SocketError::Diagnostic(
            "More than 100 options received by telnet_init()
                                           function! exiting telnet_init."
                .to_string(),
        ));
    }
    let mut buffer2: [u8; 1024] = [0; 1024];
    let conn = sockets.get_open_socket_mut(socket)?;
    conn.read(&mut buffer2)?;

    buf.buffer.append(&mut buffer2.to_vec());
    buf.buffer.push(b'\0');
    Ok(NaslValue::Data(buf.buffer.to_vec()))
}

fn new_socket(addr: &SocketAddr) -> Result<Socket, FnError> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket =
        socket2::Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(SocketError::IO)?;

    // we're going to use read timeouts so that we don't hang waiting for packets
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(SocketError::IO)?;

    Ok(socket)
}
fn get_multicast_addr(ip: &str) -> Result<IpAddr, FnError> {
    let multicast_addr =
        IpAddr::from_str(ip).map_err(|_| SocketError::InvalidIpAddress(ip.to_string()))?;
    if !multicast_addr.is_multicast() {
        return Err(SocketError::InvalidMulticastIpAddress(ip.to_string()).into());
    };
    Ok(multicast_addr)
}

#[nasl_function]
fn join_multicast_group(script_ctx: &mut ScriptCtx, ip: String) -> Result<NaslValue, FnError> {
    const PORT: u16 = 32000;
    let multicast_addr = get_multicast_addr(ip.as_str())?;

    let mut already_in_grp = false;
    for d in script_ctx.multicast_groups.iter_mut() {
        if d.in_addr == Some(multicast_addr) && d.count > 0 {
            d.count += 1;
            already_in_grp = true;
            break;
        }
    }
    let sa = SocketAddr::new(multicast_addr, PORT);

    if !already_in_grp {
        let s = new_socket(&sa)?;
        match multicast_addr {
            IpAddr::V4(ref mdns_v4) => {
                s.join_multicast_v4(mdns_v4, &Ipv4Addr::new(0, 0, 0, 0))
                    .map_err(|e| SocketError::FailedToJoinMulticastGroup(e.to_string()))?;
            }
            IpAddr::V6(ref mdns_v6) => {
                s.join_multicast_v6(mdns_v6, 0)
                    .map_err(|e| SocketError::FailedToJoinMulticastGroup(e.to_string()))?;
            }
        }
        let new_jmp = JmpDesc {
            in_addr: Some(multicast_addr),
            count: 1,
            socket: Some(s),
        };
        script_ctx.multicast_groups.push(new_jmp);
    }
    Ok(NaslValue::Number(1))
}

#[nasl_function]
fn leave_multicast_group(script_ctx: &mut ScriptCtx, ip: String) -> Result<NaslValue, FnError> {
    let multicast_addr = get_multicast_addr(ip.as_str())?;

    let mut to_remove: Option<usize> = None;
    for (i, jmg_desc) in script_ctx.multicast_groups.iter_mut().enumerate() {
        if jmg_desc.in_addr == Some(multicast_addr) && jmg_desc.count >= 1 {
            jmg_desc.count -= 1;
            if jmg_desc.count == 0 {
                to_remove = Some(i);
            }
            break;
        }
    }
    if let Some(i) = to_remove {
        script_ctx.multicast_groups.remove(i);
        return Ok(NaslValue::Null);
    };

    Err(SocketError::FailedToLeaveMulticastGroup.into())
}

pub struct SocketFns;

function_set! {
    SocketFns,
    (
        (open_sock_kdc, "open_sock_kdc"),
        (open_sock_tcp, "open_sock_tcp"),
        (open_priv_sock_tcp, "open_priv_sock_tcp"),
        (open_sock_udp, "open_sock_udp"),
        (open_priv_sock_udp, "open_priv_sock_udp"),
        (close, "close"),
        (send, "send"),
        (recv, "recv"),
        (recv_line, "recv_line"),
        (get_source_port, "get_source_port"),
        (ftp_log_in, "ftp_log_in"),
        (ftp_get_pasv_port, "ftp_get_pasv_port"),
        join_multicast_group,
        leave_multicast_group,
        telnet_init,
    )
}

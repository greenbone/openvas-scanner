// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    fs,
    io::{self, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
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
    get_kb_item, mtu,
    network_utils::{bind_local_socket, ipstr2ipaddr},
    verify_port, OpenvasEncaps,
};

// Number of times to resend a UDP packet, when no response is received
const NUM_TIMES_TO_RESEND: usize = 5;

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

struct TLSConfig {
    config: ClientConfig,
    server: ServerName<'static>,
}

/// A TLS Connection consists of the underlying socket, an optional TLS Connection and an optional buffer
struct TCPConnection {
    socket: TcpStream,
    // Those values are currently unused, but needed for functions currently not implemented
    tls_connection: Option<ClientConnection>,
    _buffer: Option<Vec<u8>>,
}

impl TCPConnection {
    /// Send data on a TCP connection using the libc send function.
    /// To ensure safety of the function, the caller must ensure, that the given length does not
    /// exceed the length of the given data data.
    unsafe fn send(
        &self,
        mut data: &[u8],
        len: usize,
        flags: i32,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let fd = self.socket.as_raw_fd();
        let mut ret = 0;
        while !data.is_empty() {
            let n =
                unsafe { libc::send(fd, data.as_ptr() as *const libc::c_void, len - ret, flags) };
            if n < 0 {
                return Err(io::Error::last_os_error().into());
            }
            ret += n as usize;
            data = &data[n as usize..];
        }
        Ok(NaslValue::Number(ret as i64))
    }
}

struct UDPConnection {
    socket: UdpSocket,
    buffer: Vec<u8>,
}

impl UDPConnection {
    /// Send data on a UDP connection using the libc send function.
    /// To ensure safety of the function, the caller must ensure, that the given length does not
    /// exceed the length of the given data data.
    unsafe fn send(
        &mut self,
        data: &[u8],
        len: usize,
        flags: i32,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let fd = self.socket.as_raw_fd();

        let ip = self.socket.peer_addr()?.ip();

        let mtu = mtu(ip);

        if len > mtu {
            return Err(FunctionErrorKind::Diagnostic(
                format!(
                    "udp data of size {} exceeds the maximum length of {}",
                    len, mtu
                ),
                None,
            ));
        }

        let n = libc::send(fd, data.as_ptr() as *const libc::c_void, len, flags);

        self.buffer = data.to_vec();
        Ok(NaslValue::Number(n as i64))
    }
}

enum NaslSocket {
    // The TCP Connection is boxed, because it uses allot of space
    // This way the size of the enum is reduced
    Tcp(Box<TCPConnection>),
    Udp(UDPConnection),
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
    fn resolve_socket_addr(addr: IpAddr, port: u16) -> Result<SocketAddr, FunctionErrorKind> {
        (addr, port)
            .to_socket_addrs()?
            .next()
            .ok_or(FunctionErrorKind::Diagnostic(
                format!(
                    "the given address and port do not correspond to a valid address: {addr}:{port}"
                ),
                None,
            ))
    }

    fn open_udp(addr: IpAddr, port: u16) -> Result<NaslSocket, FunctionErrorKind> {
        let sock_addr = Self::resolve_socket_addr(addr, port)?;
        let socket = bind_local_socket(&sock_addr)?;
        socket.connect(sock_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        Ok(NaslSocket::Udp(UDPConnection {
            socket,
            buffer: vec![],
        }))
    }

    fn open_tcp(
        addr: IpAddr,
        port: u16,
        bufsz: Option<i64>,
        timeout: Duration,
        tls_config: Option<&TLSConfig>,
    ) -> Result<NaslSocket, FunctionErrorKind> {
        // Resolve Address and Port to SocketAddr
        let sock_addr = Self::resolve_socket_addr(addr, port)?;
        // Create Vec depending of buffer size
        let buffer = if let Some(bufsz) = bufsz {
            if bufsz > 0 {
                Some(Vec::with_capacity(bufsz as usize))
            } else {
                None
            }
        } else {
            None
        };

        let socket = TcpStream::connect_timeout(&sock_addr, timeout)?;

        // Unwrap, because it cannot fail
        socket
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(20)))
            .unwrap();

        // Create TLS Connection if requested
        let tls_connection = match tls_config {
            Some(config) => Some(
                ClientConnection::new(Arc::new(config.config.clone()), config.server.clone())
                    .map_err(|e| {
                        FunctionErrorKind::Diagnostic(
                            format!("Unable to establish TLS connection: {e}"),
                            None,
                        )
                    })?,
            ),
            None => None,
        };

        Ok(NaslSocket::Tcp(Box::new(TCPConnection {
            socket,
            tls_connection,
            _buffer: buffer,
        })))
    }

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
    #[nasl_function(named(socket, data, flags, len))]
    fn send(
        &self,
        socket: usize,
        data: &[u8],
        flags: Option<i64>,
        len: Option<usize>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let len = if let Some(len) = len {
            if len < 1 || len > data.len() {
                data.len()
            } else {
                len
            }
        } else {
            data.len()
        };

        let mut data = &data[0..len];

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
                // TCP
                self.wait_before_next_probe();

                if let Some(tls) = conn.tls_connection.as_mut() {
                    // TLS
                    let mut stream = Stream::new(tls, &mut conn.socket);
                    let mut ret = 0;
                    while !data.is_empty() {
                        let n = stream.write(data)?;
                        ret += n;
                        data = &data[n..];
                    }
                    Ok(NaslValue::Number(ret as i64))
                } else {
                    unsafe { conn.send(data, len, flags.unwrap_or(0) as i32) }
                }
            }
            NaslSocket::Udp(conn) => unsafe { conn.send(data, len, flags.unwrap_or(0) as i32) },
            NaslSocket::Close => Err(FunctionErrorKind::WrongArgument(
                "the given socket FD is already closed".to_string(),
            )),
        }
    }

    fn socket_recv<S: Read>(
        socket: &mut S,
        data: &mut [u8],
        len: usize,
        min: usize,
    ) -> Result<(), FunctionErrorKind> {
        let mut ret = 0;
        while ret < len && ret < min {
            let n = socket.read(&mut data[ret..]).or_else(|e| match e.kind() {
                io::ErrorKind::TimedOut => Ok(0),
                _ => Err(e),
            })?;
            if n == 0 {
                break;
            }
            ret += n;
        }
        Ok(())
    }

    /// Receives data from a TCP or UDP socket. For a UDP socket, if it cannot read data, NASL will
    /// suppose that the last sent datagram was lost and will sent it again a couple of time.
    /// Args:
    /// - socket which was returned by an open sock function
    /// - length the number of bytes that you want to read at most. recv may return before length bytes have been read: as soon as at least one byte has been received, the timeout is lowered to 1 second. If no data is received during that time, the function returns the already read data; otherwise, if the full initial timeout has not been reached, a 1 second timeout is re-armed and the script tries to receive more data from the socket. This special feature was implemented to get a good compromise between reliability and speed when openvas-scanner talks to unknown or complex protocols. Two other optional named integer arguments can twist this behavior:
    /// - min is the minimum number of data that must be read in case the “magic read function” is activated and the timeout is lowered. By default this is 0. It works together with length. More info https://lists.archive.carbon60.com/nessus/devel/13796
    /// - timeout can be changed from the default.
    #[nasl_function(named(socket, len, min, timeout))]
    fn recv(
        &self,
        socket: usize,
        len: usize,
        min: Option<i64>,
        timeout: Option<i64>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let min = min
            .map(|min| if min < 0 { len } else { min as usize })
            .unwrap_or(len);
        let mut data = vec![0; len];

        let mut ret = Ok(NaslValue::Null);

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
                let mut old = None;
                if let Some(timeout) = timeout {
                    old = conn.socket.read_timeout().unwrap();
                    conn.socket
                        .set_read_timeout(Some(Duration::from_secs(timeout as u64)))?;
                }
                if let Some(tls) = conn.tls_connection.as_mut() {
                    let mut socket = Stream::new(tls, &mut conn.socket);
                    Self::socket_recv(&mut socket, &mut data, len, min)?;
                } else {
                    Self::socket_recv(&mut conn.socket, &mut data, len, min)?;
                }

                if let Some(timeout) = old {
                    conn.socket.set_read_timeout(Some(timeout))?;
                }

                Ok(NaslValue::Data(data))
            }
            NaslSocket::Udp(conn) => {
                let mut old = None;
                if let Some(timeout) = timeout {
                    old = conn.socket.read_timeout().unwrap();
                    conn.socket
                        .set_read_timeout(Some(Duration::from_secs(timeout as u64)))?;
                }

                let mut result = conn.socket.recv_from(data.as_mut_slice());

                for _ in 0..NUM_TIMES_TO_RESEND {
                    match result {
                        Ok((size, origin)) => {
                            if conn.socket.peer_addr()? == origin {
                                data.truncate(size);
                                ret = Ok(NaslValue::Data(data));
                                break;
                            }
                        }
                        Err(e) => match e.kind() {
                            io::ErrorKind::TimedOut => {
                                conn.socket.send(&conn.buffer)?;
                            }
                            kind => {
                                ret = Err(FunctionErrorKind::IOError(kind));
                                break;
                            }
                        },
                    };

                    result = conn.socket.recv_from(data.as_mut_slice());
                }
                if let Some(timeout) = old {
                    conn.socket.set_read_timeout(Some(timeout))?;
                }
                ret
            }
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

        let socket = match use_tcp {
            true => Self::open_tcp(ip, port, None, Duration::from_secs(30), None),
            false => Self::open_udp(ip, port),
        }?;

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

        let addr = context.target();
        if addr.is_empty() {
            return Err(FunctionErrorKind::Dirty(
                "A target must be specified to open a socket".to_string(),
            ));
        }

        self.wait_before_next_probe();

        let mut fds = vec![];

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
        let vhost = "localhost";
        if transport < 0 {
            // TODO: Get port transport and open connection depending on it
            todo!()
        } else {
            match OpenvasEncaps::from_i64(transport) {
                // Auto Detection
                Some(OpenvasEncaps::Auto) => {
                    // Try SSL/TLS first
                    if let Ok(fd) =
                        self.open_sock_tcp_tls(context, addr, port, bufsz, timeout, vhost)
                    {
                        fds.push(self.add(fd))
                        // TODO: Set port transport
                    } else {
                        // Then try IP
                        if let Ok(fd) =
                            self.open_sock_tcp_ip(context, addr, port, bufsz, timeout, None)
                        {
                            fds.push(self.add(fd))
                            // TODO: Set port transport
                        }
                    }
                }
                // IP
                Some(OpenvasEncaps::Ip) => {
                    if let Ok(fd) = self.open_sock_tcp_ip(context, addr, port, bufsz, timeout, None)
                    {
                        fds.push(self.add(fd))
                        // TODO: Set port transport
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
                        let fd =
                            self.open_sock_tcp_tls(context, addr, port, bufsz, timeout, vhost)?;
                        fds.push(self.add(fd))
                    }
                    _ => {
                        return Err(FunctionErrorKind::WrongArgument(format!(
                            "unsupported transport layer: {transport}{tls_version}"
                        )))
                    }
                },
            }
        }

        Ok(NaslValue::Fork(
            fds.iter()
                .map(|val| NaslValue::Number(*val as i64))
                .collect(),
        ))
    }

    fn open_sock_tcp_ip(
        &self,
        context: &Context,
        addr: &str,
        port: u16,
        bufsz: Option<i64>,
        timeout: Duration,
        tls_config: Option<TLSConfig>,
    ) -> Result<NaslSocket, FunctionErrorKind> {
        let addr = ipstr2ipaddr(addr)?;
        let mut retry = super::get_kb_item(context, "timeout_retry")?
            .map(|val| match val {
                NaslValue::String(val) => val.parse::<i64>().unwrap_or_default(),
                NaslValue::Number(val) => val,
                _ => 2,
            })
            .unwrap_or(2);

        while retry >= 0 {
            match Self::open_tcp(addr, port, bufsz, timeout, tls_config.as_ref()) {
                Ok(socket) => return Ok(socket),
                Err(err) => {
                    if !matches!(err, FunctionErrorKind::IOError(io::ErrorKind::TimedOut)) {
                        return Err(err);
                    }
                    retry -= 1;
                }
            }
        }
        // TODO:
        // 1. Close port, when max attempts is reached
        // 2. Log too many timeouts
        // 3. Create result of type error with:
        //   ERRMSG|||<IP>|||<vhost>|||<port>/tcp||| ||| Too many timeouts. The port was set to closed
        Err(FunctionErrorKind::IOError(io::ErrorKind::TimedOut))
    }

    fn load_private_key(filename: &str) -> Result<PrivateKeyDer<'static>, FunctionErrorKind> {
        let keyfile = fs::File::open(filename)?;
        let mut reader = BufReader::new(keyfile);

        loop {
            match rustls_pemfile::read_one(&mut reader)? {
                Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(key.into()),
                Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(key.into()),
                Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(key.into()),
                None => break,
                _ => {}
            }
        }

        Err(FunctionErrorKind::Diagnostic(
            format!(
                "no keys found in {:?} (encrypted keys not supported)",
                filename
            ),
            None,
        ))
    }

    fn open_sock_tcp_tls(
        &self,
        context: &Context,
        addr: &str,
        port: u16,
        bufsz: Option<i64>,
        timeout: Duration,
        hostname: &str,
    ) -> Result<NaslSocket, FunctionErrorKind> {
        let cert_path = get_kb_item(context, "SSL/cert")?
            .ok_or(FunctionErrorKind::Diagnostic(
                "unable to open TLS connection: kes 'SSL/cert' is missing".to_string(),
                None,
            ))?
            .to_string();
        let key_path = get_kb_item(context, "SSL/key")?
            .ok_or(FunctionErrorKind::Diagnostic(
                "unable to open TLS connection: kes 'SSL/key' is missing".to_string(),
                None,
            ))?
            .to_string();
        let password = get_kb_item(context, "SSL/password")?
            .unwrap_or(NaslValue::Null)
            .to_string();
        let cafile_path = get_kb_item(context, "SSL/CA")?
            .ok_or(FunctionErrorKind::Diagnostic(
                "unable to open TLS connection: kes 'SSL/CA' is missing".to_string(),
                None,
            ))?
            .to_string();

        // TODO: From vhost name
        let server = ServerName::try_from(hostname.to_owned()).map_err(|_| {
            FunctionErrorKind::Dirty(format!("Given vHost Name {hostname} is not valid"))
        })?;

        let mut root_store = RootCertStore::empty();
        let ca_file = fs::File::open(cafile_path)?;
        let mut reader = BufReader::new(ca_file);
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut reader).map(|result| result.unwrap()),
        );

        let cert_file = fs::File::open(cert_path)?;
        let mut reader = BufReader::new(cert_file);
        let cert = rustls_pemfile::certs(&mut reader)
            .map(|result| result.unwrap())
            .collect();

        let mut key = Self::load_private_key(&key_path)?;

        if !password.is_empty() {
            let encrypted_key = pkcs8::EncryptedPrivateKeyInfo::from_der(key.secret_der())
                .map_err(|_| {
                    FunctionErrorKind::Diagnostic(
                        format!("Unable to decrypt private key {key_path} with given password"),
                        None,
                    )
                })?;
            let decrypted_key = encrypted_key.decrypt(password).map_err(|_| {
                FunctionErrorKind::Diagnostic(
                    format!("Unable to decrypt private key {key_path} with given password"),
                    None,
                )
            })?;

            key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                decrypted_key.as_bytes().to_owned(),
            ));
        }
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert, key)
            .map_err(|_| FunctionErrorKind::WrongArgument("Invalid Key".to_string()))?;

        self.open_sock_tcp_ip(
            context,
            addr,
            port,
            bufsz,
            timeout,
            Some(TLSConfig { config, server }),
        )
    }

    /// Open a UDP socket to the target host
    #[nasl_function]
    fn open_sock_udp(&self, context: &Context, port: i64) -> Result<NaslValue, FunctionErrorKind> {
        let port = verify_port(port)?;
        let addr = ipstr2ipaddr(context.target())?;

        let socket = Self::open_udp(addr, port)?;
        let fd = self.add(socket);

        Ok(NaslValue::Number(fd as i64))
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
    )
}

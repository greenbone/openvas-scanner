// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    fs,
    io::{self, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
    os::fd::AsRawFd,
    sync::{Arc, RwLock},
    thread::sleep,
    time::{Duration, SystemTime},
};

use nasl_builtin_utils::{error::FunctionErrorKind, Context, Register};
use nasl_syntax::NaslValue;
use pkcs8::der::Decode;
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, Stream,
};

use crate::{get_kb_item, get_pos_port, mtu, OpenvasEncaps};

// Number of times to resend a UDP packet, when no response is received
const NUM_TIMES_TO_RESEND: usize = 5;

type NaslSocketFunction =
    fn(&NaslSockets, &Register, &Context) -> Result<NaslValue, FunctionErrorKind>;

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
    /// Send data on a TCP connection using the libc send function. This function is unsafe, because
    /// the provided length can be larger than the actual data length, which can lead to a
    /// segmentation fault.
    unsafe fn send(
        &self,
        mut data: &[u8],
        len: usize,
        flags: i32,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let fd = self.socket.as_raw_fd();
        let mut ret = 0;
        while !data.is_empty() {
            let n = unsafe { libc::send(fd, data.as_ptr() as *const libc::c_void, len, flags) };
            if n < 0 {
                return Err(io::Error::last_os_error().into());
            }
            ret += n;
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
    /// Send data on a UDP connection using the libc send function. This function is unsafe, because
    /// the provided length can be larger than the actual data length, which can lead to a
    /// segmentation fault.
    unsafe fn send(
        &mut self,
        data: &[u8],
        len: usize,
        flags: i32,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let fd = self.socket.as_raw_fd();

        if len > mtu() {
            return Err(FunctionErrorKind::Dirty(format!(
                "udp data exceeds the maximum length of {}",
                mtu()
            )));
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
    fn open_udp(addr: &str, port: u16) -> Result<NaslSocket, FunctionErrorKind> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(format!("{addr}:{port}"))?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        Ok(NaslSocket::Udp(UDPConnection {
            socket,
            buffer: vec![],
        }))
    }

    fn open_tcp(
        ip: &str,
        port: u16,
        bufsz: Option<i64>,
        timeout: Duration,
        tls_config: Option<&TLSConfig>,
    ) -> Result<NaslSocket, FunctionErrorKind> {
        // Resolve Address and Port to SocketAddr
        let sock = format!("{ip}:{port}").to_socket_addrs()?.next().ok_or(
            FunctionErrorKind::WrongArgument(format!(
                "the given address and port do not correspond to a valid address: {ip}:{port}"
            )),
        )?;
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

        let socket = TcpStream::connect_timeout(&sock, timeout)?;

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
    fn close(&self, r: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
        let args = r.positional();
        let socket = match args.first() {
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
        handles.handles[socket] = NaslSocket::Close;
        handles.closed_fd.push(socket);
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
    fn send(&self, r: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
        let socket = super::get_usize(r, "socket")?;
        let data = super::get_data(r)?;
        let flags = super::get_opt_int(r, "option");
        let len = if let Some(len) = super::get_opt_int(r, "length") {
            if len < 1 {
                data.len()
            } else {
                len as usize
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
    fn recv(&self, r: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
        let socket = super::get_usize(r, "socket")?;
        let len = super::get_usize(r, "length")?;
        // TODO: process min for magic read function
        let min = super::get_opt_int(r, "min")
            .map(|x| if x <= 0 { len } else { x as usize })
            .unwrap_or(len);
        let timeout = super::get_opt_int(r, "timeout");
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
    fn open_sock_kdc(
        &self,
        _: &Register,
        context: &Context,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let hostname = match get_kb_item(context, "Secret/kdc_hostname")? {
            Some(x) => Ok(x.to_string()),
            None => Err(FunctionErrorKind::Diagnostic(
                "KB key 'Secret/kdc_hostname' is not set".to_string(),
                None,
            )),
        }?;

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
            true => Self::open_tcp(&hostname, port, None, Duration::from_secs(30), None),
            false => Self::open_udp(&hostname, port),
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
    fn open_sock_tcp(
        &self,
        register: &Register,
        context: &Context,
    ) -> Result<NaslValue, FunctionErrorKind> {
        // Get port
        let port = get_pos_port(register)?;
        let timeout = super::get_opt_int(register, "timeout");
        let transport = super::get_opt_int(register, "transport").unwrap_or(-1);
        // TODO: Extract information from custom priority string
        // let _priority = super::get_named_value(register, "priority")
        // .ok()
        // .map(|val| val.to_string());
        let bufsz =
            super::get_opt_int(register, "bufsz").and_then(|x| if x < 0 { None } else { Some(x) });

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
        let mut retry = get_kb_item(context, "timeout_retry")?
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
    fn open_sock_udp(
        &self,
        register: &Register,
        context: &Context,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let port = get_pos_port(register)?;
        let addr = context.target();

        if addr.is_empty() {
            return Err(FunctionErrorKind::Dirty(
                "A target must be specified to open a socket".to_string(),
            ));
        }

        let socket = Self::open_udp(addr, port)?;
        let fd = self.add(socket);

        Ok(NaslValue::Number(fd as i64))
    }

    /// Returns found function for key or None when not found
    fn lookup(key: &str) -> Option<NaslSocketFunction> {
        match key {
            "open_sock_kdc" => Some(Self::open_sock_kdc),
            "open_sock_tcp" => Some(Self::open_sock_tcp),
            "open_sock_udp" => Some(Self::open_sock_udp),
            "close" => Some(Self::close),
            "send" => Some(Self::send),
            "recv" => Some(Self::recv),
            _ => None,
        }
    }
}

impl nasl_builtin_utils::NaslFunctionExecuter for NaslSockets {
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
        context: &Context,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        NaslSockets::lookup(name).map(|x| x(self, register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        NaslSockets::lookup(name).is_some()
    }
}

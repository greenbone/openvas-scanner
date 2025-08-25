// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use rustls::{ClientConnection, ProtocolVersion, Stream, pki_types::CertificateDer};

use socket2::{self, Socket};

use crate::nasl::builtin::misc::{NASL_ERR_ETIMEDOUT, NASL_ERR_NOERR};

use super::{OpenvasEncaps, network_utils::get_source_ip, socket::SocketError};

pub struct TcpDataStream {
    sock: Socket,
    tls: Option<ClientConnection>,
    transport: Option<OpenvasEncaps>,
    last_err: i64,
}

impl Read for TcpDataStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.tls {
            Some(tls) => {
                let mut stream = Stream::new(tls, &mut self.sock);
                stream.read(buf)
            }
            _ => self.sock.read(buf),
        }
    }
}

impl TcpDataStream {
    pub fn set_tls(&mut self, tls: ClientConnection) {
        self.tls = Some(tls);
    }

    pub fn tls(&self) -> &Option<ClientConnection> {
        &self.tls
    }

    pub fn set_transport(&mut self, transport: OpenvasEncaps) {
        self.transport = Some(transport);
    }

    pub fn transport(&self) -> &Option<OpenvasEncaps> {
        &self.transport
    }

    pub fn set_last_err(&mut self, nasl_err: i64) {
        self.last_err = nasl_err
    }

    pub fn last_err(&self) -> i64 {
        self.last_err
    }

    pub fn get_port(&self) -> u16 {
        if let Ok(peer) = self.sock.peer_addr()
            && let Some(s) = peer.as_socket()
        {
            return s.port();
        }
        0
    }
}

pub struct TcpConnection {
    pub stream: BufReader<TcpDataStream>,
}

impl Read for TcpConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.get_mut().read(buf)
    }
}

impl BufRead for TcpConnection {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.stream.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.stream.consume(amt)
    }
}

impl Write for TcpConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let stream = self.stream.get_mut();
        match &mut stream.tls {
            Some(tls) => {
                let mut stream = Stream::new(tls, &mut stream.sock);
                stream.write(buf)
            }
            _ => stream.sock.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let stream = self.stream.get_mut();
        match &mut stream.tls {
            Some(tls) => {
                let mut stream = Stream::new(tls, &mut stream.sock);
                stream.flush()
            }
            _ => stream.sock.flush(),
        }
    }
}

impl TcpConnection {
    /// Create a new TCP connection.
    fn new(stream: TcpDataStream, bufsz: Option<usize>) -> Self {
        if let Some(bufsz) = bufsz {
            Self {
                stream: BufReader::with_capacity(bufsz, stream),
            }
        } else {
            Self {
                stream: BufReader::new(stream),
            }
        }
    }

    pub fn set_tls(&mut self, tls: ClientConnection) {
        let stream = self.stream.get_mut();
        stream.set_tls(tls);
    }

    pub fn tls(&self) -> &Option<ClientConnection> {
        let stream = self.stream.get_ref();
        stream.tls()
    }

    pub fn set_transport(&mut self, transport: OpenvasEncaps) {
        let stream = self.stream.get_mut();
        stream.set_transport(transport);
    }

    pub fn transport(&self) -> &Option<OpenvasEncaps> {
        let stream = self.stream.get_ref();
        stream.transport()
    }

    pub fn set_last_err(&mut self, nasl_err: i64) {
        let stream = self.stream.get_mut();
        stream.set_last_err(nasl_err);
    }

    pub fn last_err(&self) -> i64 {
        let stream = self.stream.get_ref();
        stream.last_err()
    }

    pub fn get_port(&self) -> u16 {
        let stream = self.stream.get_ref();
        stream.get_port()
    }

    pub fn peer_certs(&mut self) -> &[CertificateDer<'static>] {
        if let Some(tls_conn) = &self.stream.get_ref().tls
            && let Some(pc) = tls_conn.peer_certificates()
        {
            return pc;
        }
        &[]
    }

    pub fn ssl_version(&self) -> Option<i64> {
        if let Some(tls_conn) = &self.stream.get_ref().tls {
            match tls_conn.protocol_version() {
                Some(ProtocolVersion::SSLv3) => Some(OpenvasEncaps::Ssl3),
                Some(ProtocolVersion::TLSv1_0) => Some(OpenvasEncaps::Tls1),
                Some(ProtocolVersion::TLSv1_1) => Some(OpenvasEncaps::Tls11),
                Some(ProtocolVersion::TLSv1_2) => Some(OpenvasEncaps::Tls12),
                Some(ProtocolVersion::TLSv1_3) => Some(OpenvasEncaps::Tls13),
                _ => None,
            };
        }
        None
    }

    /// Create a new TCP connection.
    pub fn connect(
        addr: IpAddr,
        port: u16,
        tls: Option<ClientConnection>,
        timeout: Duration,
        bufsz: Option<usize>,
        retry: u8,
    ) -> io::Result<Self> {
        let retry = if retry == 0 { 1 } else { retry };
        let mut i = 0;
        let sock = match addr {
            IpAddr::V4(_) => Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?,
            IpAddr::V6(_) => Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?,
        };

        let sock_addr = SocketAddr::new(addr, port).into();

        loop {
            match sock.connect_timeout(&sock_addr, timeout) {
                Ok(tcp) => break tcp,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    if i == retry - 1 {
                        return Err(e);
                    }
                    i += 1;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Self::new(
            TcpDataStream {
                sock,
                tls,
                transport: None,
                last_err: NASL_ERR_NOERR,
            },
            bufsz,
        ))
    }

    pub fn connect_priv(
        addr: IpAddr,
        sport: u16,
        dport: u16,
        timeout: Duration,
    ) -> Result<Self, SocketError> {
        let sock = match addr {
            IpAddr::V4(_) => socket2::Socket::new_raw(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?,

            IpAddr::V6(_) => socket2::Socket::new_raw(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?,
        };

        let src = get_source_ip(addr, dport)?;

        sock.bind(&SocketAddr::new(src, sport).into())?;

        let err = match sock.connect_timeout(&SocketAddr::new(addr, dport).into(), timeout) {
            Ok(()) => NASL_ERR_NOERR,
            Err(_) => NASL_ERR_ETIMEDOUT,
        };

        Ok(Self::new(
            TcpDataStream {
                sock,
                tls: None,
                transport: None,
                last_err: err,
            },
            None,
        ))
    }

    /// Returns the socket address of the local half of this TCP connection.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream
            .get_ref()
            .sock
            .local_addr()
            .map(|a| a.as_socket().unwrap()) // safe to unwrap because we're dealing with a TCP socket
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream
            .get_ref()
            .sock
            .peer_addr()
            .map(|a| a.as_socket().unwrap()) // safe to unwrap because we're dealing with a TCP socket
    }

    /// Send data to the connection with flags.
    pub fn send_with_flags(&mut self, buf: &[u8], flags: i32) -> io::Result<usize> {
        self.stream.get_mut().sock.send_with_flags(buf, flags)
    }

    /// Read data from the connection with a timeout.
    pub fn read_with_timeout(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        // Get the default timeout
        let old = self.stream.get_ref().sock.read_timeout()?;
        // Set the new timeout
        self.stream.get_ref().sock.set_read_timeout(Some(timeout))?;
        let ret = self.read(buf);
        // Set the default timeout again
        self.stream.get_ref().sock.set_read_timeout(old)?;
        ret
    }

    /// Read a line from the connection with a timeout.
    pub fn read_line_with_timeout(
        &mut self,
        buf: &mut String,
        timeout: Duration,
    ) -> io::Result<usize> {
        // Get the default timeout
        let old = self.stream.get_ref().sock.read_timeout()?;
        // Set the new timeout
        self.stream.get_ref().sock.set_read_timeout(Some(timeout))?;
        let ret = self.stream.read_line(buf);
        // Set the default timeout again
        self.stream.get_ref().sock.set_read_timeout(old)?;
        ret
    }
}

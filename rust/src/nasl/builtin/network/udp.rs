// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    time::Duration,
};

use super::{mtu, network_utils::bind_local_socket, socket::SocketError};

pub struct UdpConnection {
    socket: UdpSocket,
    buffer: Vec<u8>,
    flags: Option<i32>,
}

const NUM_TIMES_TO_RESEND: usize = 5;

impl Read for UdpConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        for i in 0..NUM_TIMES_TO_RESEND {
            let result = self.socket.recv_from(buf);
            match result {
                Ok((size, origin)) => {
                    if self.socket.peer_addr()? == origin {
                        return Ok(size);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut && i != NUM_TIMES_TO_RESEND - 1 => {
                    self.socket.send(&self.buffer)?;
                }
                Err(e) => return Err(e),
            };
        }
        unreachable!()
    }
}

impl Write for UdpConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mtu = mtu(self.socket.peer_addr()?.ip());
        if buf.len() > mtu {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "UDP data of size {} exceeds the maximum length of {}",
                    buf.len(),
                    mtu
                ),
            ));
        }
        let result = unsafe {
            libc::send(
                self.socket.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                self.flags.unwrap_or_default(),
            )
        };
        self.flags = None;
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl UdpConnection {
    pub fn new(addr: IpAddr, port: u16) -> Result<Self, SocketError> {
        let sock_addr = SocketAddr::new(addr, port);
        let socket = bind_local_socket(&sock_addr)?;
        socket.connect(sock_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        Ok(Self {
            socket,
            buffer: vec![],
            flags: None,
        })
    }

    pub fn new_priv(addr: IpAddr, sport: u16, dport: u16) -> io::Result<Self> {
        let sock_addr = SocketAddr::new(addr, sport);
        let socket = match sock_addr {
            SocketAddr::V4(_) => UdpSocket::bind(format!("0.0.0.0:{}", sport)),
            SocketAddr::V6(_) => UdpSocket::bind(format!("[::]:{}", sport)),
        }?;
        socket.connect(SocketAddr::new(addr, dport))?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        Ok(Self {
            socket,
            buffer: vec![],
            flags: None,
        })
    }

    pub fn set_flags(&mut self, flags: i32) {
        self.flags = Some(flags);
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn read_with_timeout(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let old = self.socket.read_timeout()?;
        self.socket.set_read_timeout(Some(timeout))?;
        let ret = self.read(buf);
        self.socket.set_read_timeout(old)?;
        ret
    }
}

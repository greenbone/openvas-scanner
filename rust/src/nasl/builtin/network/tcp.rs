use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    os::fd::AsRawFd,
    time::Duration,
};

use rustls::{ClientConnection, Stream};

struct TcpDataStream {
    tcp: TcpStream,
    tls: Option<ClientConnection>,
}

impl Read for TcpDataStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(tls) = &mut self.tls {
            let mut stream = Stream::new(tls, &mut self.tcp);
            stream.read(buf)
        } else {
            self.tcp.read(buf)
        }
    }
}

pub struct TcpConnection {
    stream: BufReader<TcpDataStream>,
    flags: Option<i32>,
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
        let ret = if let Some(tls) = &mut stream.tls {
            let mut stream = Stream::new(tls, &mut stream.tcp);
            stream.write(buf)
        } else {
            let n = unsafe {
                libc::send(
                    stream.tcp.as_raw_fd(),
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    self.flags.unwrap_or_default(),
                )
            };
            self.flags = None;
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        };

        self.flags = None;
        ret
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let stream = self.stream.get_mut();
        if let Some(tls) = &mut stream.tls {
            let mut stream = Stream::new(tls, &mut stream.tcp);
            stream.flush()
        } else {
            stream.tcp.flush()
        }
    }
}

impl TcpConnection {
    fn new(stream: TcpDataStream, bufsz: Option<usize>) -> Self {
        if let Some(bufsz) = bufsz {
            Self {
                stream: BufReader::with_capacity(bufsz, stream),
                flags: None,
            }
        } else {
            Self {
                stream: BufReader::new(stream),
                flags: None,
            }
        }
    }

    pub fn is_tls(&self) -> bool {
        self.stream.get_ref().tls.is_some()
    }

    pub fn set_flags(&mut self, flags: i32) {
        self.flags = Some(flags);
    }

    pub fn connect(
        addr: IpAddr,
        port: u16,
        tls: Option<ClientConnection>,
        timeout: Duration,
        bufsz: Option<usize>,
        retry: u8,
    ) -> io::Result<Self> {
        let mut i = 0;
        let tcp = loop {
            match TcpStream::connect_timeout(&(addr, port).into(), timeout) {
                Ok(tcp) => break tcp,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    if i == retry - 1 {
                        return Err(e);
                    }
                    i += 1;
                }
                Err(e) => return Err(e),
            }
        };
        Ok(Self::new(TcpDataStream { tcp, tls }, bufsz))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.get_ref().tcp.local_addr()
    }

    pub fn read_with_timeout(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let old = self.stream.get_ref().tcp.read_timeout()?;
        self.stream.get_ref().tcp.set_read_timeout(Some(timeout))?;
        let ret = self.read(buf);
        self.stream.get_ref().tcp.set_read_timeout(old)?;
        ret
    }

    pub fn read_line_with_timeout(
        &mut self,
        buf: &mut String,
        timeout: Duration,
    ) -> io::Result<usize> {
        let old = self.stream.get_ref().tcp.read_timeout()?;
        self.stream.get_ref().tcp.set_read_timeout(Some(timeout))?;
        let ret = self.stream.read_line(buf);
        self.stream.get_ref().tcp.set_read_timeout(old)?;
        ret
    }
}

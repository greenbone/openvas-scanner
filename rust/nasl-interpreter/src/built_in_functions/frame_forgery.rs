// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL frame forgery and arp functions
use pnet::datalink::{interfaces, NetworkInterface};
use pnet_base::MacAddr;
use std::fmt;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    str::FromStr,
};

use pcap::{Address, Capture, Device};

use sink::Sink;

use crate::{
    error::{FunctionError, FunctionErrorKind},
    ContextType, DefaultLogger, NaslFunction, NaslLogger, NaslValue, Register,
};

const ARPHRD_ETHER: u16 = 0x0001;
const ETHERTYPE_IP: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETH_ALEN: u8 = 0x0006;
const ARP_PROTO_LEN: u8 = 0x0004;
const ARPOP_REQUEST: u16 = 0x0001;

#[derive(Debug)]
pub struct Frame {
    srchaddr: MacAddr,
    dsthaddr: MacAddr,
    ethertype: u16,
    payload: Vec<u8>,
}

impl Frame {
    pub fn new() -> Frame {
        let f = Frame {
            srchaddr: MacAddr::zero(),
            dsthaddr: MacAddr::zero(),
            ethertype: 0,
            payload: vec![],
        };
        f
    }

    pub fn set_srchaddr(&mut self, srchaddr: MacAddr) -> &Frame {
        self.srchaddr = srchaddr;
        self
    }
    pub fn set_dsthaddr(&mut self, dsthaddr: MacAddr) -> &Frame {
        self.dsthaddr = dsthaddr;
        self
    }
    pub fn set_ethertype(&mut self, ethertype: u16) -> &Frame {
        self.ethertype = ethertype;
        self
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) -> &Frame {
        self.payload = payload;
        self
    }
}

impl From<Frame> for Vec<u8> {
    fn from(f: Frame) -> Vec<u8> {
        let mut raw_frame = vec![];
        raw_frame.extend(f.dsthaddr.octets());
        raw_frame.extend(f.srchaddr.octets());
        raw_frame.extend(f.ethertype.to_ne_bytes());
        raw_frame.extend(f.payload);
        raw_frame
    }
}

impl From<&Frame> for Vec<u8> {
    fn from(f: &Frame) -> Vec<u8> {
        let mut raw_frame = vec![];
        raw_frame.extend(f.dsthaddr.octets());
        raw_frame.extend(f.srchaddr.octets());
        raw_frame.extend(f.ethertype.to_be_bytes());
        raw_frame.extend(f.payload.clone());
        raw_frame
    }
}

impl TryFrom<Vec<u8>> for Frame {
    type Error = FunctionError;

    fn try_from(f: Vec<u8>) -> Result<Self, Self::Error> {
        if f.len() < 14 {
            Err(FunctionError::new(
                "get_local_mac_address_from_ip",
                ("valid ip address").into(),
            ))
        } else {
            let mut frame = Frame::new();
            frame.set_dsthaddr(MacAddr(f[0], f[1], f[2], f[3], f[4], f[5]));
            frame.set_srchaddr(MacAddr(f[6], f[7], f[8], f[9], f[10], f[11]));
            frame.set_ethertype(u16::from_be_bytes([f[12], f[13]]));
            if f.len() >= 15 {
                frame.set_payload(f[14..].to_vec());
            }
            Ok(frame)
        }
    }
}

impl fmt::Display for Frame {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        let mut s: String = "".to_string();

        let vector: Vec<u8> = self.into();

        let mut count = 0;
        for e in vector {
            s.push_str(&format!("{:02x}", &e));
            count += 1;
            if count % 2 == 0 {
                s.push_str(" ");
            }
            if count % 16 == 0 {
                s.push_str("\n");
            }
        }
        write!(f, "{}", s)
    }
}

#[derive(Debug)]
struct ArpHeader {
    ar_hrd: u16,
    ar_pro: u16,
    ar_hln: u8,
    ar_pln: u8,
    ar_op: u16,
}

const ARP_HEADER: ArpHeader = ArpHeader {
    ar_hrd: ARPHRD_ETHER,
    ar_pro: ETHERTYPE_IP,
    ar_hln: ETH_ALEN,
    ar_pln: ARP_PROTO_LEN,
    ar_op: ARPOP_REQUEST,
};

#[derive(Debug)]
pub struct ArpFrame {
    arphdr: ArpHeader,
    srchaddr: MacAddr,
    srcip: Ipv4Addr,
    dsthaddr: MacAddr,
    dstip: Ipv4Addr,
    zero_padding: [u8; 18],
}

impl ArpFrame {
    pub fn new() -> ArpFrame {
        let af = ArpFrame {
            arphdr: ARP_HEADER,
            srchaddr: MacAddr::zero(),
            srcip: Ipv4Addr::UNSPECIFIED,
            dsthaddr: MacAddr::zero(),
            dstip: Ipv4Addr::UNSPECIFIED,
            zero_padding: [0u8; 18],
        };
        af
    }

    pub fn set_srchaddr(&mut self, srchaddr: MacAddr) -> &ArpFrame {
        self.srchaddr = srchaddr;
        self
    }
    pub fn set_srcip(&mut self, srcip: Ipv4Addr) -> &ArpFrame {
        self.srcip = srcip;
        self
    }
    pub fn set_dsthaddr(&mut self, dsthaddr: MacAddr) -> &ArpFrame {
        self.dsthaddr = dsthaddr;
        self
    }
    pub fn set_dstip(&mut self, dstip: Ipv4Addr) -> &ArpFrame {
        self.dstip = dstip;
        self
    }
}

impl From<ArpFrame> for Vec<u8> {
    fn from(f: ArpFrame) -> Vec<u8> {
        let mut arp_frame = vec![];
        arp_frame.extend(f.arphdr.ar_hrd.to_be_bytes());
        arp_frame.extend(f.arphdr.ar_pro.to_be_bytes());
        arp_frame.extend(f.arphdr.ar_hln.to_be_bytes());
        arp_frame.extend(f.arphdr.ar_pln.to_be_bytes());
        arp_frame.extend(f.arphdr.ar_op.to_be_bytes());
        arp_frame.extend(f.srchaddr.octets());
        arp_frame.extend(f.srcip.octets());
        arp_frame.extend(f.dsthaddr.octets());
        arp_frame.extend(f.dstip.octets());
        arp_frame.extend(f.zero_padding);
        arp_frame
    }
}

fn convert_vec_into_mac_address(v: &Vec<u8>) -> Result<MacAddr, FunctionError> {
    if v.len() != 6 {
        Err(FunctionError::new(
            "MacAddress converter",
            ("Invalid mac address").into(),
        ))
    } else {
        Ok(MacAddr::from([v[0], v[1], v[2], v[3], v[4], v[5]]))
    }
}

fn validate_mac_address(v: Option<&ContextType>) -> Result<MacAddr, FunctionError> {
    match v {
        Some(ContextType::Value(NaslValue::String(x))) => match MacAddr::from_str(&x) {
            Ok(macaddr) => Ok(macaddr),
            Err(_) => Err(FunctionError::new(
                "forge_frame",
                ("mac addres", "invalid mac addres").into(),
            )),
        },
        Some(ContextType::Value(NaslValue::Data(x))) => match convert_vec_into_mac_address(&x) {
            Ok(macaddr) => Ok(macaddr),
            Err(_) => Err(FunctionError::new(
                "forge_frame",
                ("mac addres", "invalid mac address").into(),
            )),
        },
        _ => {
            return Err(FunctionError::new(
                "forge_frame",
                ("mac address", "invalid mac addres").into(),
            ));
        }
    }
}

fn forge_arp_frame(eth_src: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = Frame::new();
    frame.set_srchaddr(eth_src);
    frame.set_dsthaddr(MacAddr::broadcast());
    frame.set_ethertype(ETHERTYPE_ARP.to_be());

    let mut arp_frame = ArpFrame::new();
    arp_frame.set_srchaddr(eth_src);
    arp_frame.set_srcip(src_ip);
    arp_frame.set_dsthaddr(MacAddr::broadcast());
    arp_frame.set_dstip(dst_ip);

    frame.set_payload(arp_frame.into());
    frame.into()
}
fn forge_frame(src: MacAddr, dst: MacAddr, ether_proto: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut frame = Frame::new();
    frame.set_srchaddr(src);
    frame.set_dsthaddr(dst);
    frame.set_ethertype(ether_proto.to_be());
    frame.set_payload(payload);
    frame.into()
}

/// Return the macaddr, given the iface name
fn get_local_mac_address(name: String) -> Option<MacAddr> {
    match interfaces().into_iter().filter(|x| x.name == name).next() {
        Some(dev) => dev.mac,
        _ => None,
    }
}

/// Return a Device, given the name
fn get_interface_by_name(name: String) -> Option<Device> {
    match Device::list() {
        Ok(device) => device.into_iter().filter(|x| x.name == name).next(),
        _ => None,
    }
}

/// Get the interface from the local ip
fn get_interface_by_ip(local_addr: IpAddr) -> Result<Device, FunctionError> {
    // This fake IP is used for matching (and return false)
    // during the search of the interface in case an interface
    // doesn't have an associated address.
    let fake_ip = Address {
        addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        broadcast_addr: None,
        netmask: None,
        dst_addr: None,
    };

    let ip_match = |ip: &Address| ip.addr.eq(&local_addr);

    let dev = match Device::list() {
        Ok(devices) => devices
            .into_iter()
            .filter(|x| {
                local_addr
                    == (x.addresses.clone().into_iter().filter(ip_match))
                        .next()
                        .unwrap_or(fake_ip.to_owned())
                        .addr
            })
            .next(),
        Err(_) => None,
    };

    match dev {
        Some(dev) => Ok(dev),
        _ => Err(FunctionError::new(
            "get_local_mac_address_from_ip",
            FunctionErrorKind::Diagnostic("Invalid ip address".to_string(), None),
        )),
    }
}

fn get_source_ip(dst: IpAddr, port: u32) -> Option<SocketAddr> {
    let local_socket = UdpSocket::bind("0.0.0.0:0").expect("Error binding");
    let sd = format!("{}:{}", dst, port);
    match local_socket.connect(sd) {
        Ok(_) => match local_socket.local_addr() {
            Ok(l_addr) => Some(l_addr),
            Err(_) => {
                println!("Error binding");
                None
            }
        },
        Err(_) => {
            println!("Error binding");
            None
        }
    }
}

fn recv_frame(cap: &mut Capture<pcap::Active>, filter: &String) -> Result<Frame, FunctionError> {
    let f = Frame::new();

    let p = match cap.filter(filter, true) {
        Ok(_) => cap.next_packet(),
        Err(e) => return Ok(f),
    };
    match p {
        Ok(packet) => packet.data.to_vec().try_into(),
        _ => Ok(f),
    }
}

fn send_frame(
    frame: &[u8],
    iface: &Device,
    filter: Option<&String>,
) -> Result<Frame, FunctionError> {
    let mut capture_dev = match Capture::from_device(iface.clone()) {
        Ok(c) => match c.promisc(true).timeout(10).snaplen(5000).open() {
            Ok(mut capture) => {
                capture.sendpacket(frame);
                capture
            }
            Err(_) => return Ok(Frame::new()),
        },
        Err(_) => return Ok(Frame::new()),
    };

    // if pcap enabled and a filter was given
    match filter {
        Some(f) => {
            let frame = recv_frame(&mut capture_dev, f)?;
            Ok(frame)
        }
        _ => Ok(Frame::new()),
    }
}

fn ipstr2ipaddr(ip_addr: String) -> Result<IpAddr, FunctionError> {
    match IpAddr::from_str(&ip_addr) {
        Ok(ip) => Ok(ip),
        Err(_) => Err(FunctionError::new(
            "ipstr2ipaddr",
            FunctionErrorKind::Diagnostic("Invalid IP address".to_string(), Some(NaslValue::Null)),
        )),
    }
}

/// This function creates a datalink layer frame for an arp request and sends it to the currently scanned host.
///  
/// It takes the following argument:
/// - cap_timeout: time to wait for answer in seconds, 5 by default
fn nasl_send_arp_request(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Get the MAC address of a local IP address.
/// The first positional argument is a local IP address as string.
fn nasl_get_local_mac_address_from_ip(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
    if positional.is_empty() {
        return Ok(NaslValue::Null);
    }

    match &positional[0] {
        NaslValue::String(x) => {
            let ip = ipstr2ipaddr(x.to_string())?;
            let iface = get_interface_by_ip(ip)?;
            match get_local_mac_address(iface.name) {
                Some(mac) => Ok(NaslValue::String(mac.to_string())),
                _ => {
                    return Ok(NaslValue::Null);
                }
            }
        }
        _ => Err(FunctionError::new(
            "get_local_mac_address_from_ip",
            FunctionErrorKind::WrongArgument("valid ip address".to_string()),
        )),
    }
}

///This function forges a datalink layer frame.
/// - src_haddr: is a string containing the source MAC address
/// - dst_haddr: is a string containing the destination MAC address
/// -ether_proto: is an int containing the ethernet type (normally given as hexadecimal). It is optional and its default value is 0x0800. A list of Types can be e.g. looked up here.
/// -payload: is any data, which is then attached as payload to the frame.
fn nasl_forge_frame(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    let src_haddr = validate_mac_address(register.named("src_haddr"))?;
    let dst_haddr = validate_mac_address(register.named("dst_haddr"))?;
    let ether_proto = match register.named("ether_proto") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
        _ => ETHERTYPE_IP,
    };

    let payload: Vec<u8> = match register.named("payload") {
        Some(ContextType::Value(NaslValue::String(x))) => x.clone().into_bytes(),
        Some(ContextType::Value(NaslValue::Data(x))) => x.clone(),
        _ => vec![],
    };

    Ok(NaslValue::Data(forge_frame(
        src_haddr,
        dst_haddr,
        ether_proto,
        payload,
    )))
}

///Send a frame to the currently scanned host with the option to listen to the answer.
/// This function receives the following named parameters
/// - frame: the frame to send, created with forge_frame
/// - pcap_active: option to capture the answer, default is TRUE
/// - pcap_filter: filter for the answer
/// - pcap_timeout: time to wait for the answer in seconds, default 5
fn nasl_send_frame(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Print a datalink layer frame in its hexadecimal representation.
/// The named argument frame is a string representing the datalink layer frame. A frame can be created with forge_frame(3).
/// This function is meant to be used for debugging.
fn nasl_dump_frame(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let frame: Frame = match register.named("frame") {
        Some(ContextType::Value(NaslValue::Data(x))) => x.clone().try_into()?,
        _ => {
            return Err(FunctionError::new(
                "forge_frame",
                ("Data", "Invalid data type").into(),
            ))
        }
    };

    // TODO: make NaslLogger to get a generic value, not only string
    //let logger = DefaultLogger::new();
    //logger.set_mode(Mode::Debug);
    //logger.info(frame);
    println!("Frame:\n{}", frame);
    Ok(NaslValue::Null)
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "send_frame" => Some(nasl_send_frame),
        "dump_frame" => Some(nasl_dump_frame),
        "forge_frame" => Some(nasl_forge_frame),
        "get_local_mac_address_from_ip" => Some(nasl_get_local_mac_address_from_ip),
        "send_arp_request" => Some(nasl_send_arp_request),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Interpreter, NaslValue, NoOpLoader, Register};
    use nasl_syntax::parse;
    use pnet_base::MacAddr;
    use sink::DefaultSink;

    use super::convert_vec_into_mac_address;

    #[test]
    fn get_local_mac_address_from_ip() {
        let code = r###"
        get_local_mac_address_from_ip(127.0.0.1);
        get_local_mac_address_from_ip("127.0.0.1");
        get_local_mac_address_from_ip("::1");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String("00:00:00:00:00:00".to_string())))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String("00:00:00:00:00:00".to_string())))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String("00:00:00:00:00:00".to_string())))
        );
    }

    #[test]
    fn forge_frame() {
        let code = r###"
        src = raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        dst = "0a:0b:0c:0d:0e:0f";
        a = forge_frame(src_haddr: src , dst_haddr: dst,
        ether_proto: 0x0806, payload: "abcd" );
        dump_frame(frame:a);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(vec![
                0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x06,
                0x61, 0x62, 0x63, 0x64
            ])))
        );
        // This dumps the forged frame. To see it in the tests output, run the tests with
        // `cargo test -- --nocapture`
        parser.next();
    }

    #[test]
    fn test_mac_converter() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mac = MacAddr::from_str("1:2:3:4:5:6").unwrap();
        assert_eq!(convert_vec_into_mac_address(&data), Ok(mac));
    }
}

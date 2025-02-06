// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL frame forgery and arp functions

use pnet::datalink::interfaces;
use pnet_base::MacAddr;
use std::fmt;
use std::{net::Ipv4Addr, str::FromStr};

use pcap::{Capture, Device};

use super::super::host::get_host_ip;

use super::raw_ip_utils::{get_interface_by_local_ip, get_source_ip, ipstr2ipaddr};
use super::RawIpError;

use tracing::info;

use crate::nasl::prelude::*;
use crate::nasl::utils::NaslVars;

/// Hardware type ethernet
pub const ARPHRD_ETHER: u16 = 0x0001;
/// Protocol type IP
pub const ETHERTYPE_IP: u16 = 0x0800;
/// Protocol type ARP
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// Length in bytes of an ethernet mac address
pub const ETH_ALEN: u8 = 0x0006;
/// Protocol length for ARP
pub const ARP_PROTO_LEN: u8 = 0x0004;
/// ARP operation request
pub const ARPOP_REQUEST: u16 = 0x0001;
/// Default Timeout for received
pub const DEFAULT_TIMEOUT: i32 = 5000;

#[derive(Debug)]
/// Structure to hold a datalink layer frame
pub struct Frame {
    /// Source MAC address
    srchaddr: MacAddr,
    /// Destination MAC address
    dsthaddr: MacAddr,
    /// Protocol type to defined the type of the payload data
    ethertype: u16,
    /// Carries the data from the network layer.
    payload: Vec<u8>,
}

impl Frame {
    pub fn new() -> Frame {
        Frame {
            srchaddr: MacAddr::zero(),
            dsthaddr: MacAddr::zero(),
            ethertype: 0,
            payload: vec![],
        }
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

impl Default for Frame {
    fn default() -> Self {
        Self::new()
    }
}
impl From<Frame> for Vec<u8> {
    fn from(f: Frame) -> Vec<u8> {
        let mut raw_frame = vec![];
        raw_frame.extend(f.dsthaddr.octets());
        raw_frame.extend(f.srchaddr.octets());
        raw_frame.extend(f.ethertype.to_be_bytes());
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

impl TryFrom<&[u8]> for Frame {
    type Error = FnError;

    fn try_from(f: &[u8]) -> Result<Self, Self::Error> {
        if f.len() < 14 {
            Err(FnError::missing_argument("valid ip address"))
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
        let mut s: String = "".to_string();
        let vector: Vec<u8> = self.into();
        let mut count = 0;

        for e in vector {
            s.push_str(&format!("{:02x}", &e));
            count += 1;
            if count % 2 == 0 {
                s.push(' ');
            }
            if count % 16 == 0 {
                s.push('\n');
            }
        }
        write!(f, "{}", s)
    }
}

#[derive(Debug)]
/// Structure to hold an ARP header
struct ArpHeader {
    /// Hardware type
    hrd: u16,
    /// Protocol type
    pro: u16,
    /// Hardware length
    hln: u8,
    /// Protocol length
    pln: u8,
    /// operation: request, reply
    op: u16,
}

const ARP_HEADER: ArpHeader = ArpHeader {
    hrd: ARPHRD_ETHER,
    pro: ETHERTYPE_IP,
    hln: ETH_ALEN,
    pln: ARP_PROTO_LEN,
    op: ARPOP_REQUEST,
};

#[derive(Debug)]
/// Struct to hold a ARP network packet
pub struct ArpFrame {
    /// ARP header
    arphdr: ArpHeader,
    /// Source ethernet MAC address
    srchaddr: MacAddr,
    /// Source IP address
    srcip: Ipv4Addr,
    /// Destination ethernet MAC address (broadcast)
    dsthaddr: MacAddr,
    /// Destination IP address
    dstip: Ipv4Addr,
    /// Padding
    zero_padding: [u8; 18],
}

impl ArpFrame {
    pub fn new() -> ArpFrame {
        ArpFrame {
            arphdr: ARP_HEADER,
            srchaddr: MacAddr::zero(),
            srcip: Ipv4Addr::UNSPECIFIED,
            dsthaddr: MacAddr::zero(),
            dstip: Ipv4Addr::UNSPECIFIED,
            zero_padding: [0u8; 18],
        }
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

impl Default for ArpFrame {
    fn default() -> Self {
        Self::new()
    }
}

impl From<ArpFrame> for Vec<u8> {
    fn from(f: ArpFrame) -> Vec<u8> {
        let mut arp_frame = vec![];
        arp_frame.extend(f.arphdr.hrd.to_be_bytes());
        arp_frame.extend(f.arphdr.pro.to_be_bytes());
        arp_frame.extend(f.arphdr.hln.to_be_bytes());
        arp_frame.extend(f.arphdr.pln.to_be_bytes());
        arp_frame.extend(f.arphdr.op.to_be_bytes());
        arp_frame.extend(f.srchaddr.octets());
        arp_frame.extend(f.srcip.octets());
        arp_frame.extend(f.dsthaddr.octets());
        arp_frame.extend(f.dstip.octets());
        arp_frame.extend(f.zero_padding);
        arp_frame
    }
}

/// Forge a data link layer frame with an ARP request in the payload
fn forge_arp_frame(eth_src: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = Frame::new();
    frame.set_srchaddr(eth_src);
    frame.set_dsthaddr(MacAddr::broadcast());
    frame.set_ethertype(ETHERTYPE_ARP.to_le());

    let mut arp_frame = ArpFrame::new();
    arp_frame.set_srchaddr(eth_src);
    arp_frame.set_srcip(src_ip);
    arp_frame.set_dsthaddr(MacAddr::zero());
    arp_frame.set_dstip(dst_ip);

    frame.set_payload(arp_frame.into());
    frame.into()
}

/// Forge a datalink layer frame with data in the payload
fn forge_frame(src: MacAddr, dst: MacAddr, ether_proto: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut frame = Frame::new();
    frame.set_srchaddr(src);
    frame.set_dsthaddr(dst);
    frame.set_ethertype(ether_proto);
    frame.set_payload(payload);
    frame.into()
}

fn convert_vec_into_mac_address(v: &[u8]) -> Option<MacAddr> {
    if v.len() != 6 {
        None
    } else {
        Some(MacAddr::from([v[0], v[1], v[2], v[3], v[4], v[5]]))
    }
}

fn validate_mac_address(v: Option<&ContextType>) -> Result<MacAddr, FnError> {
    let mac_addr = match v {
        Some(ContextType::Value(NaslValue::String(x))) => MacAddr::from_str(x).ok(),
        Some(ContextType::Value(NaslValue::Data(x))) => convert_vec_into_mac_address(x),
        _ => None,
    };
    mac_addr.ok_or_else(|| FnError::wrong_unnamed_argument("mac address", "invalid mac address"))
}

/// Return the MAC address, given the interface name
fn get_local_mac_address(name: &str) -> Result<MacAddr, FnError> {
    interfaces()
        .into_iter()
        .find(|x| x.name == *name)
        .and_then(|dev| dev.mac)
        .ok_or_else(|| RawIpError::FailedToGetLocalMacAddress.into())
}

/// Return a frame given a capture device and a filter. It returns an empty frame in case
/// there was no response or anything was filtered.
fn recv_frame(cap: &mut Capture<pcap::Active>, filter: &str) -> Result<Frame, FnError> {
    let f = Frame::new();

    let p = match cap.filter(filter, true) {
        Ok(_) => cap.next_packet(),
        Err(_) => return Ok(f),
    };
    match p {
        Ok(packet) => packet.data.try_into(),
        Err(_) => Ok(f),
    }
}

/// Send a frame. If pcap_active flag is given, it returns a captured frame, or an empty one.
fn send_frame(
    frame: &[u8],
    iface: &Device,
    pcap_active: &bool,
    filter: Option<&String>,
    timeout: i32,
) -> Result<Option<Frame>, FnError> {
    let mut capture_dev = match Capture::from_device(iface.clone()) {
        Ok(c) => match c.promisc(true).timeout(timeout).open() {
            Ok(mut capture) => match capture.sendpacket(frame) {
                Ok(_) => capture,
                Err(_) => return Ok(None),
            },
            Err(_) => return Ok(None),
        },
        Err(_) => return Ok(None),
    };

    if !(*pcap_active) {
        return Ok(None);
    }

    // if pcap enabled use the filter or get first received frame.
    match filter {
        Some(f) => {
            let frame = recv_frame(&mut capture_dev, f)?;
            Ok(Some(frame))
        }
        _ => {
            let frame = recv_frame(&mut capture_dev, "")?;
            Ok(Some(frame))
        }
    }
}

/// This function creates a datalink layer frame for an arp request and sends it to the currently scanned host.
///  
/// It takes the following argument:
/// - cap_timeout: time to wait for answer in seconds, 5 by default
#[nasl_function]
fn nasl_send_arp_request(register: &Register, context: &Context) -> Result<NaslValue, FnError> {
    let timeout = match register.named("pcap_timeout") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as i32 * 1000i32, // to milliseconds
        None => DEFAULT_TIMEOUT,
        _ => {
            return Err(FnError::wrong_unnamed_argument(
                "Integer",
                "Invalid timeout value",
            ))
        }
    };

    let target_ip = get_host_ip(context)?;

    if target_ip.is_ipv6() {
        return Err(FnError::wrong_unnamed_argument(
            "IPv4",
            "IPv6 does not support ARP protocol.",
        ));
    }
    let local_ip = get_source_ip(target_ip, 50000u16)?;
    let iface = get_interface_by_local_ip(local_ip)?;
    let local_mac_address = get_local_mac_address(&iface.name)?;

    let src_ip = match Ipv4Addr::from_str(&local_ip.to_string()) {
        Ok(x) => x,
        Err(_) => {
            return Err(FnError::missing_argument(
                "Not possible to parse the src IP address.",
            ))
        }
    };

    let dst_ip = match Ipv4Addr::from_str(&target_ip.to_string()) {
        Ok(x) => x,
        Err(_) => {
            return Err(FnError::missing_argument(
                "Not possible to parse the dst IP address.",
            ))
        }
    };

    let arp_frame = forge_arp_frame(local_mac_address, src_ip, dst_ip);
    let filter = format!("arp and src host {}", target_ip);
    // send the frame and get a response if pcap_active enabled
    match send_frame(&arp_frame, &iface, &true, Some(&filter), timeout)? {
        Some(f) => Ok(NaslValue::String(format!("{}", f.srchaddr))),
        None => Ok(NaslValue::Null),
    }
}

/// Get the MAC address of a local IP address.
/// The first positional argument is a local IP address as string.
#[nasl_function]
fn nasl_get_local_mac_address_from_ip(register: &Register) -> Result<NaslValue, FnError> {
    let positional = register.positional();
    if positional.is_empty() {
        return Err(ArgumentError::MissingPositionals {
            expected: 1,
            got: 0,
        }
        .into());
    }

    match &positional[0] {
        NaslValue::String(x) => {
            let ip = ipstr2ipaddr(x)?;
            let iface = get_interface_by_local_ip(ip)?;
            get_local_mac_address(&iface.name).map(|mac| mac.to_string().into())
        }
        _ => Err(ArgumentError::WrongArgument(
            "Expected String containing a valid IP address.".to_string(),
        )
        .into()),
    }
}

///This function forges a datalink layer frame.
/// - src_haddr: is a string containing the source MAC address
/// - dst_haddr: is a string containing the destination MAC address
/// - ether_proto: is an int containing the ethernet type (normally given as hexadecimal).
///   It is optional and its default value is 0x0800. A list of Types can be e.g. looked up here.
/// - payload: is any data, which is then attached as payload to the frame.
#[nasl_function]
fn nasl_forge_frame(register: &Register) -> Result<NaslValue, FnError> {
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
#[nasl_function]
fn nasl_send_frame(register: &Register, context: &Context) -> Result<NaslValue, FnError> {
    let frame = match register.named("frame") {
        Some(ContextType::Value(NaslValue::Data(x))) => x,
        _ => return Err(FnError::wrong_unnamed_argument("Data", "Invalid data type")),
    };

    let pcap_active = match register.named("pcap_active") {
        Some(ContextType::Value(NaslValue::Boolean(x))) => x,
        None => &true,
        _ => {
            return Err(FnError::wrong_unnamed_argument(
                "Boolean",
                "Invalid pcap_active value",
            ))
        }
    };

    let filter = match register.named("pcap_filter") {
        Some(ContextType::Value(NaslValue::String(x))) => Some(x),
        None => None,
        _ => {
            return Err(FnError::wrong_unnamed_argument(
                "String",
                "Invalid pcap_filter value",
            ))
        }
    };

    let timeout = match register.named("pcap_timeout") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as i32 * 1000i32, // to milliseconds
        None => DEFAULT_TIMEOUT,
        _ => {
            return Err(FnError::wrong_unnamed_argument(
                "Integer",
                "Invalid timeout value",
            ))
        }
    };

    let target_ip = get_host_ip(context)?;

    let local_ip = get_source_ip(target_ip, 50000u16)?;
    let iface = get_interface_by_local_ip(local_ip)?;

    // send the frame and get a response if pcap_active enabled
    match send_frame(frame, &iface, pcap_active, filter, timeout)? {
        Some(f) => Ok(NaslValue::Data(f.into())),
        None => Ok(NaslValue::Null),
    }
}

/// Print a datalink layer frame in its hexadecimal representation.
/// The named argument frame is a string representing the datalink layer frame. A frame can be created with forge_frame(3).
/// This function is meant to be used for debugging.
#[nasl_function]
fn nasl_dump_frame(register: &Register) -> Result<NaslValue, FnError> {
    let frame: Frame = match register.named("frame") {
        Some(ContextType::Value(NaslValue::Data(x))) => (x as &[u8]).try_into()?,
        _ => return Err(FnError::wrong_unnamed_argument("Data", "Invalid data type")),
    };

    info!(frame=%frame);
    Ok(NaslValue::Null)
}

/// Returns a NaslVars with all predefined variables which must be expose to nasl script
pub fn expose_vars() -> NaslVars<'static> {
    let builtin_vars: NaslVars = [
        // Hardware type ethernet
        ("ARPHRD_ETHER", NaslValue::Number(ARPHRD_ETHER.into())),
        // Protocol type IP
        ("ETHERTYPE_IP", NaslValue::Number(ETHERTYPE_IP.into())),
        // Protocol type ARP
        ("ETHERTYPE_ARP", NaslValue::Number(ETHERTYPE_ARP.into())),
        // Length in bytes of an ethernet mac address
        ("ETH_ALEN", NaslValue::Number(ETH_ALEN.into())),
        // Protocol length for ARP
        ("ARP_PROTO_LEN", NaslValue::Number(ARP_PROTO_LEN.into())),
        // ARP operation request
        ("ARPOP_REQUEST", NaslValue::Number(ARPOP_REQUEST.into())),
    ]
    .iter()
    .cloned()
    .collect();
    builtin_vars
}

pub struct FrameForgery;

function_set! {
    FrameForgery,
    (
        (nasl_send_frame, "send_frame"),
        (nasl_dump_frame, "dump_frame"),
        (nasl_forge_frame, "forge_frame"),
        (nasl_get_local_mac_address_from_ip, "get_local_mac_address_from_ip"),
        (nasl_send_arp_request, "send_arp_request"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mac_converter() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mac = MacAddr::from_str("1:2:3:4:5:6").unwrap();
        assert_eq!(convert_vec_into_mac_address(&data), Some(mac));
    }

    #[test]
    fn forge_arpframe() {
        let src = MacAddr(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        let local_ip = Ipv4Addr::new(192, 168, 0, 10);
        let current_target = Ipv4Addr::new(192, 168, 0, 1);
        let arp_frame = forge_arp_frame(src, local_ip, current_target);
        let raw_arp_frame = vec![
            0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8,
            0x06u8, 0x08u8, 0x06u8, 0x00u8, 0x01u8, 0x08u8, 0x00u8, 0x06u8, 0x04u8, 0x00u8, 0x01u8,
            0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0xc0u8, 0xa8u8, 0x00u8, 0x0au8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xc0u8, 0xa8u8, 0x00u8, 0x01u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        ];
        assert_eq!(arp_frame, raw_arp_frame);
    }

    #[test]
    fn get_local_mac() {
        if cfg!(target_os = "macos") {
            assert!(matches!(get_local_mac_address("lo"), Err(_)));
        } else {
            assert_eq!(get_local_mac_address("lo").unwrap(), MacAddr::zero());
        }
    }
}

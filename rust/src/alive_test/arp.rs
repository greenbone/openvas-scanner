// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::raw_ip_utils::raw_ip_utils::forge_arp_frame;
use crate::nasl::raw_ip_utils::raw_ip_utils::get_interface_by_local_ip;
use crate::nasl::raw_ip_utils::raw_ip_utils::get_local_mac_address;
use std::net::Ipv4Addr;

use crate::nasl::raw_ip_utils::raw_ip_utils::get_source_ipv4;

use crate::nasl::utils::function::utils::DEFAULT_TIMEOUT;

use super::AliveTestError;
use pcap::Capture;

pub fn forge_arp_request(dst_ip: Ipv4Addr) -> Result<(), AliveTestError> {
    let src_ip = get_source_ipv4(dst_ip)
        .map_err(|e| AliveTestError::InvalidDestinationAddr(e.to_string()))?;
    let iface = get_interface_by_local_ip(src_ip.into())
        .map_err(|e| AliveTestError::GetDeviceList(e.to_string()))?;
    let local_mac_address = get_local_mac_address(&iface.name)
        .map_err(|e| AliveTestError::GetMacAddress(e.to_string()))?;

    let arp_frame = forge_arp_frame(local_mac_address, src_ip, dst_ip);

    let capture = Capture::from_device(iface.clone())
        .map_err(|e| AliveTestError::NoValidInterface(e.to_string()))?;
    let mut capture = capture
        .timeout(DEFAULT_TIMEOUT)
        .open()
        .map_err(|e| AliveTestError::OpenCapture(e.to_string()))?;
    capture
        .sendpacket(arp_frame)
        .map_err(|e| AliveTestError::SendArpRequest(e.to_string()))
}

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
    let src_ip = get_source_ipv4(dst_ip).map_err(|_| AliveTestError::InvalidDestinationAddr)?;
    let iface =
        get_interface_by_local_ip(src_ip.into()).map_err(|_| AliveTestError::GetDeviceList)?;
    let local_mac_address =
        get_local_mac_address(&iface.name).map_err(|_| AliveTestError::GetMacAddress)?;

    let arp_frame = forge_arp_frame(local_mac_address, src_ip, dst_ip);

    if let Ok(capture) = Capture::from_device(iface.clone()) {
        if let Ok(mut capture) = capture.timeout(DEFAULT_TIMEOUT).open() {
            if let Ok(_) = capture.sendpacket(arp_frame) {
                return Ok(());
            }
        };
    };

    Err(AliveTestError::SendArpRequest)
}

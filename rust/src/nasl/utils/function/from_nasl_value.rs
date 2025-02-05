// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::HashMap, path::Path};

use crate::nasl::prelude::*;
#[cfg(feature = "nasl-builtin-raw-ip")]
use crate::nasl::builtin::{RawIp, RawIpError, PacketForgeryError};
#[cfg(feature = "nasl-builtin-raw-ip")]
use pnet::packet::{
    self,
    ethernet::EthernetPacket,
    icmp::*,
    icmpv6::{
        echo_request::MutableEchoRequestPacket,
        ndp::{
            MutableNeighborAdvertPacket, MutableNeighborSolicitPacket, MutableRouterAdvertPacket,
            MutableRouterSolicitPacket,
        },
        Icmpv6Types,
    },
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{checksum, Ipv4Packet, MutableIpv4Packet},
    ipv6::MutableIpv6Packet,
    tcp::{TcpOption, TcpOptionNumbers, TcpPacket, *},
    udp::UdpPacket,
    Packet, PrimitiveValues,
};

/// A type that can be converted from a NaslValue.
/// The conversion may fail.
pub trait FromNaslValue<'a>: Sized {
    /// Perform the conversion
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError>;
}

impl<'a> FromNaslValue<'a> for NaslValue {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        Ok(value.clone())
    }
}

impl<'a> FromNaslValue<'a> for &'a NaslValue {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        Ok(value)
    }
}

impl FromNaslValue<'_> for String {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        match value {
            NaslValue::String(string) => Ok(string.to_string()),
            _ => Err(ArgumentError::WrongArgument("Expected string.".to_string()).into()),
        }
    }
}

impl<'a> FromNaslValue<'a> for &'a str {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        match value {
            NaslValue::String(string) => Ok(string),
            _ => Err(ArgumentError::WrongArgument("Expected string.".to_string()).into()),
        }
    }
}

impl<'a> FromNaslValue<'a> for &'a [u8] {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        match value {
            NaslValue::Data(bytes) => Ok(bytes),
            _ => Err(ArgumentError::WrongArgument("Expected byte data.".to_string()).into()),
        }
    }
}

impl<'a> FromNaslValue<'a> for &'a Path {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        match value {
            NaslValue::String(s) => Ok(Path::new(s)),
            _ => Err(ArgumentError::WrongArgument(
                "Expected a string specifying a path.".to_string(),
            )
            .into()),
        }
    }
}

impl<'a, T: FromNaslValue<'a>> FromNaslValue<'a> for Vec<T> {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        match value {
            NaslValue::Array(vals) => Ok(vals
                .iter()
                .map(T::from_nasl_value)
                .collect::<Result<Vec<T>, FnError>>()?),
            _ => Err(ArgumentError::WrongArgument("Expected an array..".to_string()).into()),
        }
    }
}

impl<'a, T: FromNaslValue<'a>> FromNaslValue<'a> for HashMap<String, T> {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        match value {
            NaslValue::Dict(map) => Ok(map
                .iter()
                .map(|(k, v)| T::from_nasl_value(v).map(|v| (k.clone(), v)))
                .collect::<Result<HashMap<_, _>, _>>()?),
            _ => Err(ArgumentError::WrongArgument("Expected a dictionary.".to_string()).into()),
        }
    }
}

impl<'a> FromNaslValue<'a> for bool {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        match value {
            NaslValue::Boolean(b) => Ok(*b),
            NaslValue::Number(n) => Ok(*n != 0),
            _ => Err(ArgumentError::WrongArgument("Expected bool.".to_string()).into()),
        }
    }
}
#[cfg(feature = "nasl-builtin-raw-ip")]
impl<'a> FromNaslValue<'a> for Ipv4Packet<'a> {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let buf: &[u8] = <&[u8]>::from_nasl_value(val)?;
        let ip = Ipv4Packet::new(&buf)
            .ok_or_else(|| BuiltinError::RawIp(RawIpError::PacketForgery(PacketForgeryError::CreatePacket)))?;
        Ok(ip)
    }
}
#[cfg(feature = "nasl-builtin-raw-ip")]
impl<'a> FromNaslValue<'a> for UdpPacket<'a> {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let ip: Ipv4Packet = Ipv4Packet::from_nasl_value(val)?;
        let udp = UdpPacket::owned(ip.payload().to_vec())
            .ok_or_else(|| BuiltinError::RawIp(RawIpError::PacketForgery(PacketForgeryError::CreatePacket)))?;

        Ok(udp)
    }
}

macro_rules! impl_from_nasl_value_for_numeric_type {
    ($ty: ty) => {
        impl<'a> FromNaslValue<'a> for $ty {
            fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
                match value {
                    NaslValue::Number(num) => Ok(<$ty>::try_from(*num).map_err(|_| {
                        ArgumentError::WrongArgument("Expected positive number.".into())
                    })?),
                    e => Err(ArgumentError::WrongArgument(format!(
                        "Expected a number, found '{}'.",
                        e
                    ))
                    .into()),
                }
            }
        }
    };
}

impl_from_nasl_value_for_numeric_type!(u8);
impl_from_nasl_value_for_numeric_type!(u16);
impl_from_nasl_value_for_numeric_type!(i32);
impl_from_nasl_value_for_numeric_type!(i64);
impl_from_nasl_value_for_numeric_type!(u32);
impl_from_nasl_value_for_numeric_type!(u64);
impl_from_nasl_value_for_numeric_type!(isize);
impl_from_nasl_value_for_numeric_type!(usize);

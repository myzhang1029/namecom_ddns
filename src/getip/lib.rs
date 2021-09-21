/// Asynchronous library for retrieving IP address information
//
//  Copyright (C) 2021 Zhang Maiyun <myzhang1029@hotmail.com>
//
//  This file is part of DNS updater.
//
//  DNS updater is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  DNS updater is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with DNS updater.  If not, see <https://www.gnu.org/licenses/>.
extern crate async_trait;
extern crate derive_deref;
extern crate log;
extern crate pnet;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate thiserror;
extern crate tokio;
extern crate trust_dns_resolver;

pub mod gip;
pub mod hostip;

use async_trait::async_trait;
use serde::Deserialize;
use std::net::IpAddr;
use thiserror::Error;

/// Scope of the IP to be received.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
pub enum IpScope {
    /// Address as found by an external service
    Global,
    /// Address of the NIC (Permanent/secured if IPv6)
    Local,
}

/// Type of global address
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
pub enum IpType {
    #[serde(rename = "IPv4")]
    Ipv4,
    #[serde(rename = "IPv6")]
    Ipv6,
}

/// Errors that can happen.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    GlobalIpError(#[from] crate::gip::GlobalIpError),
    #[error(transparent)]
    HelperError(#[from] crate::hostip::IpCommandError),
    #[error("no address returned")]
    NoAddress,
}

/// A Result alias where the Err case is `getip::Error`.
pub type Result<R> = std::result::Result<R, Error>;

/// Any IP Provider
#[async_trait]
pub trait Provider: Sized {
    /// Get the address
    async fn get_addr(&self) -> Result<IpAddr>;
    fn get_type(&self) -> IpType;
}

/// Receive a IP address with the specified type.
///
/// ip_type: Type of the IP address.
/// nic: Name of the interface, Ignored if ip_type is Global
pub async fn get_ip(ip_type: IpType, ip_scope: IpScope, nic: Option<&str>) -> Result<IpAddr> {
    match (ip_type, ip_scope) {
        (IpType::Ipv4, IpScope::Global) => {
            // Get a global IPv4 address
            let p = gip::ProviderMultiple::default();
            p.get_addr().await
        }
        (IpType::Ipv6, IpScope::Global) => {
            // Get a global IPv6 address
            let p = gip::ProviderMultiple::default_v6();
            // TODO: An local address is likely global in the case of IPv6 as well
            p.get_addr().await
        }
        (IpType::Ipv4, IpScope::Local) => hostip::get_local_ipv4(nic).await,
        (IpType::Ipv6, IpScope::Local) => hostip::get_local_ipv6(nic).await,
    }
}

#[cfg(test)]
mod test {
    use crate::{get_ip, IpScope, IpType};
    use pnet::datalink::interfaces;
    use std::net::IpAddr;

    /// Test if any IPv6 address is available on an interface
    /// If not, the test is skipped
    fn has_any_ipv6_address(iface_name: Option<&str>, global: bool) -> bool {
        for iface in interfaces() {
            // If iface_name is present but does not match, skip
            if let Some(iface_name) = iface_name {
                if iface.name != iface_name {
                    continue;
                }
            }
            let anyone = iface
                .ips
                .iter()
                .filter(|nw| {
                    let ip = nw.ip();
                    ip.is_ipv6()
                        && !ip.is_loopback()
                        && !ip.is_unspecified()
                        && if global {
                            if let IpAddr::V6(dcasted) = ip {
                                // !is_unicast_link_local
                                (dcasted.segments()[0] & 0xffc0) != 0xfe80
                                // !is_unique_local
                                && (dcasted.segments()[0] & 0xfe00) != 0xfc00
                            } else {
                                unreachable!()
                            }
                        } else {
                            true
                        }
                })
                .next()
                .is_some();
            if anyone {
                return true;
            }
        }
        false
    }

    #[tokio::test]
    async fn test_global_ipv4_is_any() {
        let addr = get_ip(IpType::Ipv4, IpScope::Global, None).await;
        assert!(addr.is_ok(), "The result of get_addr() should be Ok()");
        if let IpAddr::V4(addr) = addr.unwrap() {
            assert!(
                !addr.is_private(),
                "The result of get_addr() should not be private"
            );
            assert!(
                !addr.is_loopback(),
                "The result of get_addr() should not be loopback"
            );
        } else {
            assert!(false, "The result of get_addr() should be an IPv4 address");
        }
    }

    #[tokio::test]
    async fn test_global_ipv6_is_any() {
        let addr = get_ip(IpType::Ipv6, IpScope::Global, None).await;
        assert!(addr.is_ok(), "The result of get_addr() should be Ok()");
        if let IpAddr::V6(addr) = addr.unwrap() {
            assert!(
                !addr.is_loopback(),
                "The result of get_addr() should not be loopback"
            );
            assert!(
                !addr.is_unspecified(),
                "The result of get_addr() should not be unspecified"
            );
        } else {
            if has_any_ipv6_address(None, true) {
                assert!(false, "The result of get_addr() should be an IPv6 address");
            }
        }
    }

    #[tokio::test]
    async fn test_local_ipv4_is_any() {
        let addr = get_ip(IpType::Ipv4, IpScope::Local, None).await;
        assert!(addr.is_ok(), "The result of get_addr() should be Ok()");
        if !addr.unwrap().is_ipv4() {
            assert!(false, "The result of get_addr() should be an IPv4 address");
        }
    }

    #[tokio::test]
    async fn test_local_ipv6_is_any() {
        let addr = get_ip(IpType::Ipv6, IpScope::Local, None).await;
        assert!(addr.is_ok(), "The result of get_addr() should be Ok()");
        if !addr.unwrap().is_ipv6() {
            if has_any_ipv6_address(None, false) {
                assert!(false, "The result of get_addr() should be an IPv6 address");
            }
        }
    }
}

//! Asynchronous library for retrieving IP address information
//!
//! For retrieval of a single address, simply use `get_ip` and set
//! appropriate parameters.
//!
//! In case a finer-grained control over the source of addresses is required,
//! individual `Providers` on which `get_ip` is based can be found in `gip`
//! (for global) and `hostip` (for local).
//!
//! Module `libc_getips` contains a low-level function to receive all addresses
//! directly from the interfaces/adapters.
//
//  Copyright (C) 2021 Zhang Maiyun <me@maiyun.me>
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
//

#![warn(
    clippy::pedantic,
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_op_in_unsafe_fn,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    variant_size_differences
)]
#![allow(clippy::no_effect_underscore_binding)]

pub mod gip;
pub mod hostip;
pub mod libc_getips;

use async_trait::async_trait;
use serde::Deserialize;
use std::net::IpAddr;
use thiserror::Error;

/// Scope of the IP to be received.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum IpScope {
    /// Address as found by an external service.
    /// If used behind NAT, the address outside the NAT is received.
    /// If IPv6 private address extension is enabled, the preferred address is usually used.
    Global,
    /// Address of the NIC.
    /// If `IpType` is `Ipv6`, the permanent or secured address is preferred.
    /// If `IpType` is `Ipv4`, the first address is used.
    Local,
}

/// Type of global address.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum IpType {
    /// An IPv4 address.
    #[serde(rename = "IPv4")]
    Ipv4,
    /// An IPv6 address.
    #[serde(rename = "IPv6")]
    Ipv6,
}

/// Error type of IP retrieval methods.
#[derive(Debug, Error)]
pub enum Error {
    /// Error from a global IP provider.
    #[error(transparent)]
    GlobalIpError(#[from] gip::GlobalIpError),

    /// Cannot parse string as an IP.
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),

    /// Cannot parse data as UTF-8.
    #[error(transparent)]
    UnicodeParseError(#[from] std::string::FromUtf8Error),

    /// Command exited with a non-zero status.
    #[error("Command exited with status {0}")]
    NonZeroExit(std::process::ExitStatus),

    /// All libc-related errors.
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// No address found.
    #[error("no address returned")]
    NoAddress,
}

/// A `Result` alias where the `Err` variant is `getip::Error`.
pub type Result<R> = std::result::Result<R, Error>;

/// Any IP Provider.
#[async_trait]
pub trait Provider: Sized {
    /// Get the address provided by this provider.
    async fn get_addr(&self) -> Result<IpAddr>;
    /// Get the `IpType` that this provider gives.
    fn get_type(&self) -> IpType;
}

/// Receive a IP address of family `ip_type` that has a scope of `ip_scope` on an interface named `nic`.
///
/// If `ip_scope` is `Global`, the address is received from an external service, and `nic` is ignored.
/// If `nic` is `None`, this function uses the first one returned by the OS.
///
/// # Examples
///
/// Get an global IPv4 address:
///
/// ```
/// use getip::get_ip;
/// use getip::{IpScope, IpType, Result};
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let address = get_ip(IpType::Ipv4, IpScope::Global, None).await?;
///     println!("{}", address);
///     Ok(())
/// }
/// ```
///
/// # Errors
///
/// Any errors returned by the underlying provider is propagated here.
///
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
            p.get_addr().await
        }
        (IpType::Ipv4, IpScope::Local) => {
            // Get a local IPv4 address
            let p = hostip::LocalLibcProvider::new(nic, IpType::Ipv4);
            p.get_addr().await
        }
        (IpType::Ipv6, IpScope::Local) => {
            // Get a local IPv6 address
            if let Some(nic) = nic {
                let command_provider = hostip::LocalIpv6CommandProvider::new(nic, true);
                let command_result = command_provider.get_addr().await;
                if command_result.is_ok() || matches!(command_result, Err(Error::NoAddress)) {
                    return command_result;
                }
            }
            let p = hostip::LocalLibcProvider::new(nic, IpType::Ipv6);
            p.get_addr().await
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{get_ip, gip::ProviderMultiple, libc_getips, IpScope, IpType, Provider};
    use std::net::IpAddr;

    /// Test if any IPv6 address is available on an interface
    /// If not, the test is skipped
    fn has_any_ipv6_address(iface_name: Option<&str>, global: bool) -> bool {
        libc_getips::get_iface_addrs(Some(IpType::Ipv6), iface_name).is_ok_and(|addresses| {
            addresses.iter().any(|ip| {
                !ip.is_loopback()
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
        })
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
            panic!("The result of get_addr() should be an IPv4 address");
        }
    }

    #[tokio::test]
    async fn test_global_ipv4_just_dns_is_any() {
        const DNS_PROVIDERS: &str = r#"[
            {
              "method": "dns",
              "name": "opendns.com",
              "type": "IPv4",
              "url": "myip.opendns.com@resolver1.opendns.com"
            },
            {
              "method": "dns",
              "name": "opendns.com",
              "type": "IPv6",
              "url": "myip.opendns.com@resolver1.opendns.com"
            },
            {
              "method": "dns",
              "name": "akamai.com",
              "type": "IPv4",
              "url": "whoami.akamai.com@ns1-1.akamaitech.net"
            }
          ]"#;
        let provider = ProviderMultiple::from_json(DNS_PROVIDERS).unwrap();
        let addr = provider.get_addr().await;
        assert!(addr.is_ok(), "The result of get_addr() should be Ok()");
    }

    #[tokio::test]
    async fn test_global_ipv6_is_any() {
        if !has_any_ipv6_address(None, true) {
            return;
        }
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
            panic!("The result of get_addr() should be an IPv6 address");
        }
    }

    #[tokio::test]
    async fn test_local_ipv4_is_any() {
        let addr = get_ip(IpType::Ipv4, IpScope::Local, None).await;
        assert!(addr.is_ok(), "The result of get_addr() should be Ok()");
        assert!(
            addr.unwrap().is_ipv4(),
            "The result of get_addr() should be an IPv4 address"
        );
    }

    #[tokio::test]
    async fn test_local_ipv6_is_any() {
        if !has_any_ipv6_address(None, true) {
            return;
        }
        let addr = get_ip(IpType::Ipv6, IpScope::Local, None).await;
        assert!(addr.is_ok(), "The result of get_addr() should be Ok()");
        assert!(
            addr.unwrap().is_ipv6(),
            "The result of get_addr() should be an IPv6 address"
        );
    }
}

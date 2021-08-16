/// Helper to receive the IP of the local machine.
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
//
use gip::{Provider, ProviderDefaultV4, ProviderDefaultV6};
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::str::FromStr;
use subprocess::{Exec, PopenError};
use thiserror::Error;

/// Errors that can happen.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    GlobalIpError(#[from] gip::Error),
    #[error(transparent)]
    HelperError(#[from] PopenError),
    #[error("no address returned")]
    NoAddress,
}

/// Type of the IP to be received.
#[derive(Debug)]
pub enum IpType {
    /// IPv4 address as found by an external service
    GlobalIpv4,
    /// IPv6 address as found by an external service
    GlobalIpv6,
    /// IPv4 address of the NIC
    LocalIpv4,
    /// (Permanent/secured) IPv6 address of the NIC
    LocalIpv6,
}

/// Get the networks on the interface with the specified name.
fn get_iface_ips(iface_name: &str) -> Vec<IpNetwork> {
    for iface in interfaces() {
        if iface.name == iface_name {
            return iface.ips;
        }
    }
    vec![]
}

/// Try to get a IPv6 address from a interface with `ifconfig` or `ip` if possible.
/// Two Results are used to indicate a "determining error", with which no other
/// backends will be tried, or simply an error with the current IP backend.
fn get_ipv6_ifconfig_ip(nic: &str, permanent: bool) -> Result<Result<IpAddr, Error>, PopenError> {
    // First try to use `ip`
    let out = Exec::cmd("ip")
        .args(&[
            "address",
            "show",
            "dev",
            nic,
            "scope",
            "global",
            "permanent",
        ])
        .stream_stdout()
        // If that failed, try ifconfig
        .or_else(|_| Exec::cmd("ifconfig").args(&[nic, "inet6"]).stream_stdout())?;
    // Extract output
    let out_br = BufReader::new(out);
    // Some systems use temporary addresses and one permanent address.
    // The second fields indicates whether the "secured"/permanent flag is present.
    let mut addrs: Vec<(IpAddr, bool)> = Vec::with_capacity(4);
    // Extract addresses line by line
    for line in out_br.lines() {
        let line = line?;
        let fields: Vec<String> = line.split_whitespace().map(|x| x.to_string()).collect();
        // A shorter one is certainly not an entry
        // Check if the label is "inet6"
        if fields.len() > 1 && fields[0] == "inet6" {
            let address_stripped = match fields[1].split_once("/") {
                // `ip` includes the prefix length in the address
                Some((addr, _prefixlen)) => addr,
                // but `ifconfig` doesn't
                None => &fields[1],
            };
            if let Ok(addr6) = IpAddr::from_str(address_stripped) {
                // If "secured" is in the flags, it is permanent
                let is_perm = fields.iter().any(|f| f == "secured");
                if !addr6.is_loopback() {
                    addrs.push((addr6, is_perm));
                }
            }
        }
    }
    if addrs.is_empty() {
        Ok(Err(Error::NoAddress))
    } else {
        Ok(Ok(addrs
            .iter()
            // If is_perm == permanent, it is the one we are looking for
            .filter(|(_, is_perm)| *is_perm == permanent)
            .map(|(addr, _)| *addr)
            .next()
            .unwrap_or(addrs[0].0)))
    }
}

/// Force-cast $id: IpAddr to Ipv4Addr
macro_rules! cast_ipv4 {
    ($id: expr) => {
        if let IpAddr::V4(ip) = $id {
            ip
        } else {
            unreachable!()
        }
    };
}

/// Get a local IPv4 address on the specified interface.
fn get_local_ipv4(nic: Option<&str>) -> Result<IpAddr, Error> {
    match nic {
        // Interface specified
        Some(iface) => {
            let ips = get_iface_ips(iface);
            // Get the first IPv4 network on this interface
            let first_ipv4 = ips.iter().find(|addr| addr.is_ipv4());
            // Return the first address in the network
            if let Some(network) = first_ipv4 {
                Ok(network.ip())
            } else {
                Err(Error::NoAddress)
            }
        }
        None => {
            // No interface specified, iterate to find the first one with IPv4 addresses (and preferably a configured one)
            let ifaces = interfaces();
            let ipv4_addrs: Vec<IpAddr> = ifaces
                .iter()
                // Filter out non-v4 addresses
                .flat_map(|iface| iface.ips.iter().filter(|nw| nw.is_ipv4()))
                // Turn networks into addresses
                .map(|nw| nw.ip())
                // Remove loopback, link local, and unspecified
                .filter(|addr| {
                    !(addr.is_loopback()
                        || cast_ipv4!(addr).is_link_local()
                        || addr.is_unspecified())
                })
                // Must be collected to use it twice
                .collect();
            // Find the ones that are likely global
            // XXX: IpAddr::is_global is probably a better choice but it's currently unstable.
            let non_local_addrs: Vec<&IpAddr> = ipv4_addrs
                .iter()
                .filter(|addr| !cast_ipv4!(addr).is_private())
                .collect();
            if !non_local_addrs.is_empty() {
                Ok(*non_local_addrs[0])
            } else if !ipv4_addrs.is_empty() {
                Ok(ipv4_addrs[0])
            } else {
                Err(Error::NoAddress)
            }
        }
    }
}

/// Get a local IPv6 address on the specified interface.
fn get_local_ipv6(nic: Option<&str>) -> Result<IpAddr, Error> {
    match nic {
        Some(nic) => {
            get_ipv6_ifconfig_ip(nic, true).unwrap_or_else(|_| {
                // TODO: pnet and ipconfig.exe IPv6 backend
                unimplemented!()
            })
        }
        None => todo!(),
    }
}

/// Receive a IP address with the specified type.
///
/// ip_type: Type of the IP address.
/// nic: Name of the interface, Ignored if ip_type is Global
pub fn get_ip(ip_type: IpType, nic: Option<&str>) -> Result<IpAddr, Error> {
    match ip_type {
        IpType::GlobalIpv4 => {
            // Get a global IPv4 address
            let mut p = ProviderDefaultV4::new();
            if let Some(ipv4) = p.get_addr()?.v4addr {
                Ok(IpAddr::V4(ipv4))
            } else {
                Err(Error::NoAddress)
            }
        }
        IpType::GlobalIpv6 => {
            let mut p = ProviderDefaultV6::new();
            if let Some(ipv6) = p.get_addr()?.v6addr {
                Ok(IpAddr::V6(ipv6))
            } else {
                // An local address is likely global in the case of IPv6 as well
                Err(Error::NoAddress)
            }
        }
        IpType::LocalIpv4 => get_local_ipv4(nic),
        IpType::LocalIpv6 => get_local_ipv6(nic),
    }
}

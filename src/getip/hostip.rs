//! Implementations of `Provider` that receive local IP addresses of the machine
//! from `libc` APIs and command-line helper programs (if available).
//
//  Copyright (C) 2021 Zhang Maiyun <me@myzhangll.xyz>
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

use crate::libc_getips::get_iface_addrs;
use crate::Provider;
use crate::{Error, IpType, Result};
use async_trait::async_trait;
use log::{debug, info};
use std::net::IpAddr;
use std::process::{Output, Stdio};
use std::str::FromStr;
use tokio::process::Command;

/// IPv6 Provider that queries information from `ip` or `ifconfig`.
#[derive(Debug, Clone)]
pub struct LocalIpv6CommandProvider {
    nic: String,
    // XXX: follow address selection algorithm for non-permanent
    prefer_permanent: bool,
}

impl LocalIpv6CommandProvider {
    /// Create a new `LocalIpv6CommandProvider`.
    #[must_use]
    pub fn new(nic: &str, permanent: bool) -> Self {
        Self {
            nic: nic.to_string(),
            prefer_permanent: permanent,
        }
    }
}

#[async_trait]
impl Provider for LocalIpv6CommandProvider {
    /// Get a local IPv6 address on the specified interface with `ip` or `ifconfig`.
    ///
    /// # Errors
    ///
    /// This function returns `NoAddress` if the IP commands return no addresses.
    /// In case that none of those commands succeed, it returns the last process execution error.
    async fn get_addr(&self) -> Result<IpAddr> {
        let out = chain_ip_cmd_until_succeed(&self.nic).await?;
        // Extract output
        let out_br = out.stdout.split(|c| *c == b'\n');
        // Some systems use temporary addresses and one permanent address.
        // The second fields indicates whether the "secured"/permanent flag is present.
        let mut addrs: Vec<(IpAddr, bool)> = Vec::with_capacity(4);
        // Extract addresses line by line
        for line in out_br {
            let line = String::from_utf8(line.to_vec())?;
            let fields: Vec<String> = line
                .split_whitespace()
                .map(std::string::ToString::to_string)
                .collect();
            // A shorter one is certainly not an entry
            // Check if the label is "inet6"
            if fields.len() > 1 && fields[0] == "inet6" {
                let address_stripped = match fields[1].split_once('/') {
                    // `ip` includes the prefix length in the address
                    Some((addr, _prefixlen)) => addr,
                    // but `ifconfig` doesn't
                    None => &fields[1],
                };
                if let Ok(addr6) = IpAddr::from_str(address_stripped) {
                    // If "secured" (for RFC 3041, ifconfig) or "mngtmpaddr" (RFC 3041, ip) is in the flags, it is permanent
                    let is_perm = fields.iter().any(|f| f == "secured" || f == "mngtmpaddr")
                    // But any "temporary" tells us it is not.
                        && fields.iter().all(|f| f != "temporary");
                    // Treating non-RFC-3041 interface's addresses all the same
                    if !addr6.is_loopback() {
                        addrs.push((addr6, is_perm));
                    }
                }
            }
        }
        if addrs.is_empty() {
            debug!("Short-circuting NoAddress because an ip command succeeded without addresses");
            Err(crate::Error::NoAddress)
        } else {
            Ok(addrs
                .iter()
                // If is_perm == permanent, it is the one we are looking for
                .filter(|(_, is_perm)| *is_perm == self.prefer_permanent)
                .map(|(addr, _)| *addr)
                .next()
                .unwrap_or(addrs[0].0))
        }
    }

    fn get_type(&self) -> IpType {
        // This Provider only has IPv6 capabilities
        IpType::Ipv6
    }
}

/// Run a chain of ip/ifconfig commands and returns the output of first succeeded one
async fn chain_ip_cmd_until_succeed(nic: &str) -> Result<Output> {
    // TODO: netsh.exe IPv6 backend
    // netsh interface ipv6 show addresses interface="Ethernet" level=normal
    // TODO: Enable IPv4 to be queried like this
    let commands = [
        // First try to use `ip`
        (
            "ip",
            vec![
                "address", "show", "dev", nic,
                // This scope filters out unique-local addresses
                "scope", "global",
            ],
        ),
        // If that failed, try (BSD) ifconfig
        ("ifconfig", vec!["-L", nic, "inet6"]),
        // Linux ifconfig cannot distinguish between RFC 3041 temporary/permanent addresses
        ("ifconfig", vec![nic]),
    ];
    // Record only the last failure
    let mut last_error: Option<Error> = None;
    for (cmd, args) in commands {
        let mut command = Command::new(cmd);
        command.stdout(Stdio::piped());
        debug!("Running command {:?} with arguments {:?}", cmd, args);
        let output = command.args(&args).output().await;
        match output {
            Ok(output) => {
                if output.status.success() {
                    return Ok(output);
                }
                // Since a chain of commands are executed, these are not really errors
                debug!(
                    "Command {:?} failed with status: {}",
                    command, output.status
                );
                last_error = Some(Error::NonZeroExit(output.status));
            }
            Err(exec_error) => {
                debug!(
                    "Command {:?} failed to be executed: {}",
                    command, exec_error
                );
                last_error = Some(Error::IoError(exec_error));
            }
        }
    }
    info!("None of the commands to extract the IPv6 address succeeded.");
    // Not failable
    Err(last_error.unwrap())
}

/// Force-cast $id: `IpAddr` to `Ipv4Addr`
macro_rules! cast_ipv4 {
    ($id: expr) => {
        if let IpAddr::V4(ip) = $id {
            ip
        } else {
            unreachable!()
        }
    };
}

/// Force-cast $id: `IpAddr` to `Ipv6Addr`
macro_rules! cast_ipv6 {
    ($id: expr) => {
        if let IpAddr::V6(ip) = $id {
            ip
        } else {
            unreachable!()
        }
    };
}

/// Filter function that removes loopback/link local/unspecified IPv4 addresses
#[allow(clippy::trivially_copy_pass_by_ref)]
fn filter_nonroute_ipv4(addr: &&IpAddr) -> bool {
    let remove = !addr.is_loopback() && !cast_ipv4!(addr).is_link_local() && !addr.is_unspecified();
    if remove {
        debug!(
            "Removing address {:?} because it is loopback/link local/unspecified",
            addr
        );
    }
    remove
}

/// Filter function that removes loopback/link local/unspecified IPv6 addresses
#[allow(clippy::trivially_copy_pass_by_ref)]
fn filter_nonroute_ipv6(addr: &&IpAddr) -> bool {
    !addr.is_loopback()
        && !addr.is_unspecified()
        && (cast_ipv6!(addr).segments()[0] & 0xffc0) != 0xfe80
}

/// Filter function that prefers global IPv4 addresses
#[allow(clippy::trivially_copy_pass_by_ref)]
fn filter_nonlocal_ipv4(addr: &&&IpAddr) -> bool {
    !cast_ipv4!(addr).is_private()
}

/// Filter function that prefers global IPv6 addresses
#[allow(clippy::trivially_copy_pass_by_ref)]
fn filter_nonlocal_ipv6(_addr: &&&IpAddr) -> bool {
    // XXX: `IpAddr::is_global` is probably a better choice but it's currently unstable.
    false
}

/// Provider that queries information from libc interface.
#[derive(Debug, Clone)]
pub struct LocalLibcProvider {
    nic: Option<String>,
    ip_type: IpType,
}

impl<'a> LocalLibcProvider {
    #[must_use]
    /// Create a new `LocalLibcProvider`.
    pub fn new(nic: Option<&'a str>, ip_type: IpType) -> Self {
        Self {
            nic: nic.map(std::string::ToString::to_string),
            ip_type,
        }
    }
}

#[async_trait]
impl Provider for LocalLibcProvider {
    /// Get a local address on the specified interface.
    ///
    /// # Errors
    ///
    /// This function propagates the error from `libc_getips::get_iface_addrs`.
    async fn get_addr(&self) -> Result<IpAddr> {
        let addrs = get_iface_addrs(Some(self.ip_type), self.nic.as_deref())?;
        let addrs: Vec<&IpAddr> = addrs
            .iter()
            // Remove loopback, link local, and unspecified
            .filter(if self.ip_type == IpType::Ipv4 {
                filter_nonroute_ipv4
            } else {
                filter_nonroute_ipv6
            })
            .collect();
        // Prefer the ones that are likely global
        let first_non_local_addr: Option<&&IpAddr> =
            addrs.iter().find(if self.ip_type == IpType::Ipv4 {
                filter_nonlocal_ipv4
            } else {
                filter_nonlocal_ipv6
            });
        first_non_local_addr.map_or_else(|| Ok(*addrs[0]), |addr| Ok(**addr))
    }

    fn get_type(&self) -> IpType {
        self.ip_type
    }
}

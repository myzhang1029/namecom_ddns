//! Helper to receive the IP of the local machine.
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

use crate::libc_getips::get_iface_addrs;
use crate::{Error, IpType, Result};
use log::{debug, info};
use std::net::IpAddr;
use std::process::{Output, Stdio};
use std::str::FromStr;
use tokio::process::Command;

/// Run a chain of ip/ifconfig commands and returns the output of first succeeded one
async fn chain_ip_cmd_until_succeed(nic: &str) -> Result<Output> {
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

/// Try to get a IPv6 address from a interface with `ifconfig` or `ip` if possible.
/// Two Results are used to indicate a "determining error":
/// if the outer Result is an Err variant, it indicates an error with the current IP backend.
/// But if the inner Result is an Err variant, no other backends will be tried.
async fn get_ipv6_ifconfig_ip(nic: &str, permanent: bool) -> Result<Result<IpAddr>> {
    let out = chain_ip_cmd_until_succeed(nic).await?;
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
            let address_stripped = match fields[1].split_once("/") {
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
        Ok(Err(crate::Error::NoAddress))
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

/// Force-cast $id: IpAddr to Ipv6Addr
macro_rules! cast_ipv6 {
    ($id: expr) => {
        if let IpAddr::V6(ip) = $id {
            ip
        } else {
            unreachable!()
        }
    };
}

/// Get a local IPv4 address on the specified interface.
pub fn get_local_ipv4(nic: Option<&str>) -> Result<IpAddr> {
    let ipv4_addrs = get_iface_addrs(Some(IpType::Ipv4), nic)?;
    let ipv4_addrs: Vec<&IpAddr> = ipv4_addrs
        .iter()
        // Remove loopback, link local, and unspecified
        .filter(|addr| {
            !addr.is_loopback() && !cast_ipv4!(addr).is_link_local() && !addr.is_unspecified()
        })
        .collect();
    if ipv4_addrs.is_empty() {
        Err(Error::NoAddress)
    } else {
        // Prefer the ones that are likely global
        // XXX: `IpAddr::is_global` is probably a better choice but it's currently unstable.
        let first_non_local_addr: Option<&&IpAddr> = ipv4_addrs
            .iter()
            .find(|addr| !cast_ipv4!(addr).is_private());
        first_non_local_addr.map_or_else(|| Ok(*ipv4_addrs[0]), |addr| Ok(**addr))
    }
}

/// Get a local IPv6 address on the specified interface.
pub async fn get_local_ipv6(nic: Option<&str>) -> Result<IpAddr> {
    if let Some(nic) = nic {
        if let Ok(command_result) = get_ipv6_ifconfig_ip(nic, true).await {
            // TODO: ipconfig.exe IPv6 backend
            return command_result;
        }
    };
    let ipv6_addrs = get_iface_addrs(Some(IpType::Ipv6), nic)?;
    let ipv6_addrs: Vec<&IpAddr> = ipv6_addrs
        .iter()
        // Remove loopback, link local, and unspecified
        .filter(|addr| {
            !addr.is_loopback()
                && !addr.is_unspecified()
                && !(cast_ipv6!(addr).segments()[0] & 0xffc0) == 0xfe80
        })
        .collect();
    if ipv6_addrs.is_empty() {
        Err(Error::NoAddress)
    } else {
        // TODO: Prefer the ones that are likely global
        // `IpAddr::is_global` is currently unstable.
        Ok(*ipv6_addrs[0])
    }
}

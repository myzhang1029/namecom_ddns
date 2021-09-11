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

use crate::Result;
use log::{debug, info};
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use std::io;
use std::net::IpAddr;
use std::process::{self, Output, Stdio};
use std::str::FromStr;
use thiserror::Error;
use tokio::process::Command;

/// A error indicating the failure of ip/ifconfig commands
#[derive(Debug, Error)]
pub enum IpCommandError {
    /// Command exited with a non-zero status
    #[error("Command exited with status {0}")]
    NonZeroExit(process::ExitStatus),
    /// Failed to start the command
    #[error(transparent)]
    StartCommandFailure(#[from] io::Error),
    /// Command stdout not UTF-8
    #[error(transparent)]
    DecodeError(#[from] std::string::FromUtf8Error),
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

/// Run a chain of ip/ifconfig commands and returns the output of first succeeded one
async fn chain_ip_cmd_until_succeed(nic: &str) -> std::result::Result<Output, IpCommandError> {
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
    // Record all failures
    let mut last_error: Option<IpCommandError> = None;
    for (cmd, args) in commands {
        let mut command = Command::new(cmd);
        command.stdout(Stdio::piped());
        let output = command.args(&args).output().await;
        match output {
            Ok(output) => {
                if output.status.success() {
                    return Ok(output);
                } else {
                    // Since a chain of commands are executed, these are not really errors
                    debug!(
                        "Command {:?} failed with status: {}",
                        command, output.status
                    );
                    last_error = Some(IpCommandError::NonZeroExit(output.status));
                }
            }
            Err(exec_error) => {
                debug!(
                    "Command {:?} failed to be executed: {}",
                    command, exec_error
                );
                last_error = Some(IpCommandError::StartCommandFailure(exec_error));
            }
        }
    }
    info!("None of the commands to extract the IPv6 address succeeded.");
    // Not failable
    Err(last_error.unwrap())
}

/// Try to get a IPv6 address from a interface with `ifconfig` or `ip` if possible.
/// Two Results are used to indicate a "determining error", with which no other
/// backends will be tried, or simply an error with the current IP backend.
async fn get_ipv6_ifconfig_ip(
    nic: &str,
    permanent: bool,
) -> std::result::Result<Result<IpAddr>, IpCommandError> {
    let out = chain_ip_cmd_until_succeed(nic).await?;
    // Extract output
    let out_br = out.stdout.split(|c| *c == b'\n');
    // Some systems use temporary addresses and one permanent address.
    // The second fields indicates whether the "secured"/permanent flag is present.
    let mut addrs: Vec<(IpAddr, bool)> = Vec::with_capacity(4);
    // Extract addresses line by line
    for line in out_br {
        let line = String::from_utf8(line.to_vec())?;
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

/// Get a local IPv4 address on the specified interface.
pub async fn get_local_ipv4(nic: Option<&str>) -> Result<IpAddr> {
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
                Err(crate::Error::NoAddress)
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
                Err(crate::Error::NoAddress)
            }
        }
    }
}

/// Get a local IPv6 address on the specified interface.
pub async fn get_local_ipv6(nic: Option<&str>) -> Result<IpAddr> {
    match nic {
        Some(nic) => {
            get_ipv6_ifconfig_ip(nic, true).await.unwrap_or_else(|_| {
                // TODO: pnet and ipconfig.exe IPv6 backend
                unimplemented!()
            })
        }
        None => todo!(),
    }
}

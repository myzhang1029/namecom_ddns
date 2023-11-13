//! Receive IP addresses of NICs with `libc` APIs.
//! - On Windows, API `GetAdaptersAddresses` is used.
//! - On unix-like systems, `getifaddrs` and `getnameinfo` are used.
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

use crate::IpType;
use crate::{Error, Result};
#[cfg(windows)]
use log::error;
use log::{debug, trace};
use std::convert::TryInto;
use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
#[cfg(unix)]
use std::str::FromStr;
#[cfg(windows)]
use winapi::{
    shared::{
        minwindef::DWORD,
        ntdef::{ULONG, VOID},
        winerror, ws2def,
        ws2def::{SOCKADDR, SOCKADDR_IN},
        ws2ipdef::SOCKADDR_IN6,
    },
    um::{
        heapapi::{GetProcessHeap, HeapAlloc, HeapFree},
        iphlpapi::GetAdaptersAddresses,
        iptypes::{
            GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
            IP_ADAPTER_ADDRESSES, IP_ADAPTER_ANYCAST_ADDRESS, IP_ADAPTER_UNICAST_ADDRESS,
        },
    },
};
#[cfg(windows)]
const INITIAL_ALLOC_SIZE: ULONG = 15000;
#[cfg(windows)]
const MAX_TRIES: usize = 5;

/// Fail with errno
macro_rules! fail_os_err {
    () => {
        Err(Error::IoError(std::io::Error::last_os_error()))
    };
}

/// Get an address of an interface
#[cfg(unix)]
fn get_addr_for_ifa_unix(addr: libc::ifaddrs, ip_type: Option<IpType>) -> Result<IpAddr> {
    let sockaddr = addr.ifa_addr;
    assert!(!sockaddr.is_null());
    let family = libc::c_int::from(unsafe { *sockaddr }.sa_family);
    // Has a IP family filter
    if let Some(ip_type) = ip_type {
        if (ip_type == IpType::Ipv4 && family != libc::AF_INET)
            || (ip_type == IpType::Ipv6 && family != libc::AF_INET6)
        {
            trace!("Short-circuiting NoAddress: addr family does not match requested type");
            return Err(Error::NoAddress);
        }
    } else if family != libc::AF_INET && family != libc::AF_INET6 {
        trace!(
            "Short-circuiting NoAddress: family type {:?} not address",
            family
        );
        return Err(Error::NoAddress);
    }
    // Length for `getnameinfo`
    let socklen: libc::socklen_t = match family {
        libc::AF_INET => mem::size_of::<libc::sockaddr_in>(),
        libc::AF_INET6 => mem::size_of::<libc::sockaddr_in6>(),
        _ => unreachable!(),
    }
    .try_into()
    // socklen_t should be sufficient by design
    .unwrap_or_else(|_| unreachable!());
    // Allocating on stack, so only when necessary
    {
        const MAXHOST: usize = libc::NI_MAXHOST as usize;
        let mut host: [libc::c_char; MAXHOST] = [0; MAXHOST];
        if unsafe {
            libc::getnameinfo(
                sockaddr,
                socklen,
                host.as_mut_ptr(),
                libc::NI_MAXHOST,
                ptr::null_mut(),
                0,
                libc::NI_NUMERICHOST,
            )
        } == 0
        {
            let address = unsafe { CStr::from_ptr(host.as_ptr()).to_bytes() };
            let address = unsafe { std::str::from_utf8_unchecked(address) };
            Ok(match family {
                libc::AF_INET => IpAddr::V4(Ipv4Addr::from_str(address)?),
                libc::AF_INET6 => IpAddr::V6(Ipv6Addr::from_str(address)?),
                _ => unreachable!(),
            })
        } else {
            fail_os_err!()
        }
    }
}

/// Get all assigned IP addresses of family `ip_type` on the interface named `iface_name`.
///
/// Both parameters can be `None`, in which case that filter is not applied.
///
/// If the result is an `Ok` variant, the vector is guaranteed to be non-empty.
///
/// # Errors
///
/// This function fails with the `IoError` variant if an underlying OS operation
/// failed, or `NoAddress` if no matching addresses found.
#[cfg(unix)]
pub fn get_iface_addrs(ip_type: Option<IpType>, iface_name: Option<&str>) -> Result<Vec<IpAddr>> {
    // Hold all found addresses
    let mut result: Vec<IpAddr> = Vec::new();
    // Save for freeifaddrs()
    let mut save_addrs: *mut libc::ifaddrs = unsafe { mem::zeroed() };
    if unsafe { libc::getifaddrs(&mut save_addrs) } != 0 {
        return fail_os_err!();
    }
    let mut addrs = save_addrs;
    // Walk through the linked list
    while !addrs.is_null() {
        let addr = unsafe { *addrs };
        // Interface name
        let ifa_name = unsafe { CStr::from_ptr(addr.ifa_name).to_bytes() };
        let ifa_name = unsafe { std::str::from_utf8_unchecked(ifa_name) };
        trace!("Got interface {:?}", ifa_name);
        // Filter iface name
        let address = iface_name.map_or_else(
            || get_addr_for_ifa_unix(addr, ip_type),
            |expected_ifa_name| {
                if ifa_name == expected_ifa_name {
                    get_addr_for_ifa_unix(addr, ip_type)
                } else {
                    Err(Error::NoAddress)
                }
            },
        );
        if let Ok(address) = address {
            trace!(
                "Found good addresses of type {:?} for interface {:?}: {:?}",
                ip_type,
                iface_name,
                address
            );
            result.push(address);
        }
        addrs = addr.ifa_next;
    }
    unsafe { libc::freeifaddrs(save_addrs) };
    if result.is_empty() {
        debug!("No address becase none of the interfaces has a matching one");
        Err(Error::NoAddress)
    } else {
        Ok(result)
    }
}

/// Convert raw pointer `raw_addr` of type `*SOCKADDR` to Rust `IpAddr`.
/// `raw_addr` must not be `NULL`.
#[cfg(windows)]
unsafe fn sockaddr_to_ipaddr(raw_addr: *mut SOCKADDR) -> IpAddr {
    if i32::from(unsafe { *raw_addr }.sa_family) == ws2def::AF_INET {
        #[allow(clippy::cast_ptr_alignment)]
        let saddr_in = raw_addr.cast::<SOCKADDR_IN>();
        let saddr_in_addr = unsafe { (*saddr_in).sin_addr.S_un.S_addr() };
        IpAddr::V4(Ipv4Addr::from(*saddr_in_addr))
    } else {
        #[allow(clippy::cast_ptr_alignment)]
        let saddr_in = raw_addr.cast::<SOCKADDR_IN6>();
        let saddr_in_addr = unsafe { (*saddr_in).sin6_addr.u.Byte() };
        IpAddr::V6(Ipv6Addr::from(*saddr_in_addr))
    }
}

/// Extract all addresses from an adapter.
/// `adapter` must not be `NULL`.
#[cfg(windows)]
unsafe fn extract_addresses(adapter: *mut IP_ADAPTER_ADDRESSES) -> Vec<IpAddr> {
    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut cur_unicast: *mut IP_ADAPTER_UNICAST_ADDRESS = unsafe { *adapter }.FirstUnicastAddress;
    while !cur_unicast.is_null() {
        let raw_addr = unsafe { *cur_unicast }.Address.lpSockaddr;
        assert!(!raw_addr.is_null());
        let ipaddr = unsafe { sockaddr_to_ipaddr(raw_addr) };
        debug!(
            "Found good unicast address on adapter {:?}: {:?}",
            unsafe { *adapter }.FriendlyName,
            ipaddr
        );
        addresses.push(ipaddr);
        cur_unicast = unsafe { *cur_unicast }.Next;
    }
    let mut cur_anycast: *mut IP_ADAPTER_ANYCAST_ADDRESS = unsafe { *adapter }.FirstAnycastAddress;
    while !cur_anycast.is_null() {
        let raw_addr = unsafe { *cur_anycast }.Address.lpSockaddr;
        assert!(!raw_addr.is_null());
        let ipaddr = unsafe { sockaddr_to_ipaddr(raw_addr) };
        debug!(
            "Found good anycast address on adapter {:?}: {:?}",
            unsafe { *adapter }.FriendlyName,
            ipaddr
        );
        addresses.push(ipaddr);
        cur_anycast = unsafe { *cur_anycast }.Next;
    }
    addresses
}

/// Get all assigned IP addresses of family `ip_type` on the interface named `iface_name`.
///
/// Both parameters can be `None`, in which case that filter is not applied.
///
/// If the result is an `Ok` variant, the vector is guaranteed to be non-empty.
///
/// # Errors
///
/// This function fails with the `IoError` variant if an underlying OS operation
/// failed, or `NoAddress` if no matching addresses found.
///
/// # See also
///
/// MSDN documentation on `GetAdaptersAddresses`: <https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses>.
#[cfg(windows)]
pub fn get_iface_addrs(ip_type: Option<IpType>, iface_name: Option<&str>) -> Result<Vec<IpAddr>> {
    let family: u32 = match ip_type {
        Some(IpType::Ipv4) => ws2def::AF_INET,
        Some(IpType::Ipv6) => ws2def::AF_INET6,
        None => ws2def::AF_UNSPEC,
    }
    .try_into()
    // I know the values of those constants, so they are safe.
    .unwrap_or_else(|_| unreachable!());
    let flags: ULONG = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST;
    // Allocate a 15 KB buffer to start with.
    let mut allocated_size: ULONG = INITIAL_ALLOC_SIZE;
    // Silence maybe uninitialized error
    let mut adapter_addresses: *mut IP_ADAPTER_ADDRESSES = unsafe { mem::zeroed() };
    let mut return_value: DWORD = 0;
    // Try several times to query the resources as suggested by doc
    for trial in 0..MAX_TRIES {
        adapter_addresses = unsafe { HeapAlloc(GetProcessHeap(), 0, allocated_size as usize) }
            .cast::<IP_ADAPTER_ADDRESSES>();
        if adapter_addresses.is_null() {
            error!("Raw heap allocation failed");
            return fail_os_err!();
        }
        return_value = unsafe {
            GetAdaptersAddresses(
                family,
                flags,
                ptr::null_mut(),
                adapter_addresses,
                &mut allocated_size,
            )
        };
        debug!(
            "GetAdaptersAddresses returned {:?} on the {}th trial",
            return_value, trial
        );
        if return_value == winerror::ERROR_BUFFER_OVERFLOW {
            unsafe { HeapFree(GetProcessHeap(), 0, adapter_addresses.cast::<VOID>()) };
        } else {
            break;
        }
    }
    let result = if return_value == winerror::NO_ERROR {
        let mut addresses: Vec<IpAddr> = Vec::new();
        let mut curr_adapter = adapter_addresses;
        while !curr_adapter.is_null() {
            let adapter_name = unsafe { *curr_adapter }.FriendlyName as *const libc::c_char;
            let adapter_name = unsafe { CStr::from_ptr(adapter_name).to_bytes() };
            let adapter_name = unsafe { std::str::from_utf8_unchecked(adapter_name) };
            trace!("Examining adpater {:?}", adapter_name);
            if let Some(expected_adapter_name) = iface_name {
                if adapter_name == expected_adapter_name {
                    let mut addrs = unsafe { extract_addresses(curr_adapter) };
                    addresses.append(&mut addrs);
                }
            } else {
                let mut addrs = unsafe { extract_addresses(curr_adapter) };
                addresses.append(&mut addrs);
            }
            curr_adapter = unsafe { *curr_adapter }.Next;
        }
        if addresses.is_empty() {
            debug!("No address becase none of the adapters has a matching one");
            Err(Error::NoAddress)
        } else {
            Ok(addresses)
        }
    } else {
        // Let Rust interpret the error for me
        Err(Error::IoError(std::io::Error::from_raw_os_error(
            // Windows system error code has range 0-15999
            return_value.try_into().unwrap_or_else(|_| unreachable!()),
        )))
    };
    unsafe {
        HeapFree(GetProcessHeap(), 0, adapter_addresses.cast::<VOID>());
    }
    result
}

#[cfg(test)]
mod test {
    use super::get_iface_addrs;
    use crate::Error;
    use crate::IpType;

    #[test]
    fn test_get_iface_addrs_ipv4() {
        // There is no reliable way to find the name of an interface
        // So `iface_name` is None.
        match get_iface_addrs(Some(IpType::Ipv4), None) {
            Ok(addresses) => {
                assert!(!addresses.is_empty(), "Addresses should not be empty");
                for address in &addresses {
                    assert!(address.is_ipv4(), "Address not IPv4: {:?}", address);
                }
            }
            Err(error) => {
                assert!(
                    matches!(error, Error::NoAddress),
                    "get_iface_addrs failed because of reasons other than NoAddress: {:?}",
                    error
                );
            }
        }
    }

    #[test]
    fn test_get_iface_addrs_ipv6() {
        match get_iface_addrs(Some(IpType::Ipv6), None) {
            Ok(addresses) => {
                assert!(!addresses.is_empty(), "Addresses should not be empty");
                for address in &addresses {
                    assert!(address.is_ipv6(), "Address not IPv6: {:?}", address);
                }
            }
            Err(error) => {
                assert!(
                    matches!(error, Error::NoAddress),
                    "get_iface_addrs failed because of reasons other than NoAddress: {:?}",
                    error
                );
            }
        }
    }

    #[test]
    fn test_get_iface_addrs_any() {
        match get_iface_addrs(None, None) {
            Ok(addresses) => {
                assert!(!addresses.is_empty(), "Addresses should not be empty");
            }
            Err(error) => {
                assert!(
                    matches!(error, Error::NoAddress),
                    "get_iface_addrs failed because of reasons other than NoAddress: {:?}",
                    error
                );
                // It does not make sense if this one if NoAddress but individual ones succeed
                assert!(
                    matches!(
                        get_iface_addrs(Some(IpType::Ipv6), None),
                        Err(Error::NoAddress)
                    ) || matches!(
                        get_iface_addrs(Some(IpType::Ipv4), None),
                        Err(Error::NoAddress)
                    ),
                    "Individual get_iface_addrs succeeded but generic one didn't"
                );
            }
        }
    }
}

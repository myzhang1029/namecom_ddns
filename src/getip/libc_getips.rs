use crate::IpType;
use crate::{Error, Result};
use libc;
use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::str::FromStr;
#[cfg(windows)]
use winapi::{
    shared::{
        ntdef::{DWORD, ULONG},
        winerror, ws2def,
        ws2def::{SOCKADDR_IN, SOCKADDR_IN6},
    },
    um::{
        heapapi::{GetProcessHeap, HeapAlloc, HeapFree},
        iphlpapi::GetAdaptersAddresses,
        iptypes::{
            GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST,
            IP_ADAPTER_ADDRESSES, IP_ADAPTER_ANYCAST_ADDRESS, IP_ADAPTER_UNICAST_ADDRESS,
        },
    },
};
#[cfg(windows)]
const INITIAL_ALLOC_SIZE: usize = 15000;
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
unsafe fn get_addr_for_ifa_unix(addr: libc::ifaddrs, ip_type: Option<IpType>) -> Result<IpAddr> {
    let sockaddr = addr.ifa_addr;
    let family = libc::c_int::from((*sockaddr).sa_family);
    // Has a IP family filter
    if let Some(ip_type) = ip_type {
        if (ip_type == IpType::Ipv4 && family != libc::AF_INET)
            || (ip_type == IpType::Ipv6 && family != libc::AF_INET6)
        {
            return Err(Error::NoAddress);
        }
    } else if family != libc::AF_INET && family != libc::AF_INET6 {
        return Err(Error::NoAddress);
    }
    // Length for `getnameinfo`
    let socklen = match family {
        libc::AF_INET => mem::size_of::<libc::sockaddr_in>(),
        libc::AF_INET6 => mem::size_of::<libc::sockaddr_in6>(),
        _ => unreachable!(),
    } as libc::socklen_t;
    // Allocating on stack, so only when necessary
    {
        const MAXHOST: usize = libc::NI_MAXHOST as usize;
        let mut host: [libc::c_char; MAXHOST] = [0; MAXHOST];
        if libc::getnameinfo(
            sockaddr,
            socklen,
            host.as_mut_ptr(),
            libc::NI_MAXHOST,
            ptr::null_mut(),
            0,
            libc::NI_NUMERICHOST,
        ) == 0
        {
            let address = CStr::from_ptr(host.as_ptr()).to_bytes();
            let address = std::str::from_utf8_unchecked(address);
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

/// Get all assigned ip addresses of the specified type on the specified interface
/// Both parameters can be None, in which case that filter is not applied.
#[cfg(unix)]
pub fn get_iface_addrs(ip_type: Option<IpType>, iface_name: Option<&str>) -> Result<Vec<IpAddr>> {
    // Hold all found addresses
    let mut result: Vec<IpAddr> = Vec::new();
    unsafe {
        // Save for freeifaddrs()
        let mut save_addrs: *mut libc::ifaddrs = mem::zeroed();
        if libc::getifaddrs(&mut save_addrs) != 0 {
            return fail_os_err!();
        }
        let mut addrs = save_addrs;
        // Walk through the linked list
        while !addrs.is_null() {
            let addr = *addrs;
            // Interface name
            let ifa_name = addr.ifa_name as *const libc::c_char;
            let ifa_name = CStr::from_ptr(ifa_name).to_bytes();
            let ifa_name = std::str::from_utf8_unchecked(ifa_name);
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
                result.push(address);
            }
            addrs = addr.ifa_next;
        }
        libc::freeifaddrs(save_addrs);
    }
    if result.is_empty() {
        Err(Error::NoAddress)
    } else {
        Ok(result)
    }
}

/// Extract all addresses from an adapter
#[cfg(windows)]
fn extract_addresses(adapter: &IP_ADAPTER_ADDRESSES) -> Vec<IpAddr> {
    let addresses: Vec<IpAddr> = Vec::new();
    let mut cur_unicast: *mut IP_ADAPTER_UNICAST_ADDRESS = adapter.FirstUnicastAddress;
    while (!cur_unicast.is_null()) {
        let raw_addr = (*cur_unicast).Address.lpSockaddr;
        if (*raw_addr).sa_family == ws2def.AF_INET {
            let saddr_in = raw_addr as *mut SOCKADDR_IN;
            let saddr_in_addr = saddr_in.sin_addr.S_un.S_un_b();
            addresses.push(IpAddr::V4(Ipv4Addr::from(saddr_in_addr)));
        } else {
            let saddr_in = raw_addr as *mut SOCKADDR_IN6;
            let saddr_in_addr = saddr_in.sin6_addr.u.Byte();
            addresses.push(IpAddr::V6(Ipv6Addr::from(saddr_in_addr)));
        }
        cur_unicast = (*cur_unicast).Next;
    }
    let mut cur_anycast: *mut IP_ADAPTER_ANYCAST_ADDRESS = adapter.FirstAnycastAddress;
    while (!cur_anycast.is_null()) {
        let raw_addr = (*cur_anycast).Address.lpSockaddr;
        if (*raw_addr).sa_family == ws2def.AF_INET {
            let saddr_in = raw_addr as *mut SOCKADDR_IN;
            let saddr_in_addr = saddr_in.sin_addr.S_un.S_un_b();
            addresses.push(IpAddr::V4(Ipv4Addr::from(saddr_in_addr)));
        } else {
            let saddr_in = raw_addr as *mut SOCKADDR_IN6;
            let saddr_in_addr = saddr_in.sin6_addr.u.Byte();
            addresses.push(IpAddr::V6(Ipv6Addr::from(saddr_in_addr)));
        }
        cur_anycast = (*cur_anycast).Next;
    }
    addresses
}

/// Get all assigned ip addresses of the specified type on the specified interface
/// Both parameters can be None, in which case that filter is not applied.
///
/// See also:
/// https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
#[cfg(windows)]
pub fn get_iface_addrs(ip_type: Option<IpType>, iface_name: Option<&str>) -> Result<Vec<IpAddr>> {
    let family = match ip_type {
        Some(IpType::Ipv4) => ws2def::AF_INET,
        Some(IpType::Ipv6) => ws2def::AF_INET6,
        None => ws2def::AF_UNSPEC,
    };
    let flags: ULONG = GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    // Allocate a 15 KB buffer to start with.
    let mut allocated_size: ULONG = INITIAL_ALLOC_SIZE;
    let adapter_addresses: PIP_ADAPTER_ADDRESSES;
    let return_value: DWORD = 0;
    unsafe {
        // Try several times to query the resources as suggested by doc
        for _ in 0..MAX_TRIES {
            adapter_addresses =
                HeapAlloc(GetProcessHeap(), 0, allocated_size) as PIP_ADAPTER_ADDRESSES;
            if adapter_addresses.is_null() {
                return fail_os_err!();
            }
            return_value = GetAdaptersAddresses(
                family,
                flags,
                ptr::null_mut(),
                adapter_addresses,
                &mut allocated_size,
            );
            if return_value == ERROR_BUFFER_OVERFLOW {
                HeapFree(GetProcessHeap(), 0, adapter_addresses);
            } else {
                break;
            }
        }
    }
    let result = if return_value == winerror::NO_ERROR {
        let addresses: Vec<IpAddr> = Vec::new();
        let mut curr_adapter = adapter_addresses;
        while !curr_adapter.is_null() {
            let adapter_name = (*curr_adapter).AdapterName as *const libc::c_char;
            let adapter_name = CStr::from_ptr(adapter_name).to_bytes();
            let adapter_name = std::str::from_utf8_unchecked(adapter_name);
            if let Some(expected_adapter_name) = iface_name {
                if adapter_name == expected_adapter_name {
                    addresses.append(extract_addresses(curr_adapter));
                }
            } else {
                addresses.append(extract_addresses(curr_adapter));
            }
            curr_adapter = (*curr_adapter).Next;
        }
        Ok(addresses)
    } else {
        // Let Rust interpret the error for me
        Err(std::io::Error::from_raw_os_error(return_value));
    };
    HeapFree(GetProcessHeap(), 0, adapter_addresses);
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

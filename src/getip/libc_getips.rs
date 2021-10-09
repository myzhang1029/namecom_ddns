use crate::IpType;
use crate::{Error, Result};
use libc;
use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Get an address of an interface
#[cfg(target_family = "unix")]
unsafe fn get_addr_for_ifa_unix(addr: libc::ifaddrs, ip_type: Option<IpType>) -> Result<IpAddr> {
    let sockaddr = addr.ifa_addr;
    let family =  libc::c_int::from((*sockaddr).sa_family);
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
            std::ptr::null_mut(),
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
            Err(Error::IoError(std::io::Error::last_os_error()))
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
            return Err(Error::IoError(std::io::Error::last_os_error()));
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

/// Get all assigned ip addresses of the specified type on the specified interface
/// Both parameters can be None, in which case that filter is not applied.
#[cfg(windows)]
pub fn get_iface_addrs(ip_type: Option<IpType>, iface_name: Option<&str>) -> Result<Vec<IpAddr>> {
    todo!("Windows not ready");
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

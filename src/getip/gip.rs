//! Asynchronous rewrite of dalance/gip
//! Receive global IP addresses from online services
//
//  Copyright (C) 2018 dalance
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

use crate::{IpType, Provider, Result};
use async_trait::async_trait;
use derive_deref::Deref;
use reqwest::{Client, Proxy};
use serde::Deserialize;
use serde_json::Value;
use std::default::Default;
use std::net::{self, IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::ResolveError,
    TokioAsyncResolver,
};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
pub enum ProviderMethod {
    // Plain text HTTP request
    #[serde(rename = "plain")]
    Plain,
    // HTTP JSON response
    #[serde(rename = "json")]
    Json,
    // DNS Queries
    #[serde(rename = "dns")]
    Dns,
}

/// Information of a provider
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ProviderInfo {
    /// Provider name
    name: String,
    /// Provider type of its address
    #[serde(rename = "type")]
    addr_type: IpType,
    /// Provider
    method: ProviderMethod,
    url: String,
    key: Option<String>,
}

impl Default for ProviderInfo {
    fn default() -> Self {
        Self {
            name: String::default(),
            addr_type: IpType::Ipv4,
            method: ProviderMethod::Plain,
            url: String::default(),
            key: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum GlobalIpError {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    AddrParseError(#[from] net::AddrParseError),
    #[error(transparent)]
    JsonParseError(#[from] serde_json::Error),
    #[error("field `{0}' does not exist in response")]
    JsonNotFoundError(String),
    #[error("field `{0}' in response can't be decoded")]
    JsonDecodeError(String),
    #[error(transparent)]
    DnsError(#[from] Box<ResolveError>),
    #[error("specified DNS server `{0}' has no address")]
    DnsNoServerError(String),
}

macro_rules! make_get_type {
    () => {
        /// Get the IP type that this provider returns
        fn get_type(&self) -> IpType {
            self.info.addr_type
        }
    };
}

macro_rules! make_new {
    ($name: ident) => {
        impl $name {
            /// Create a new $name
            fn new(info: &ProviderInfo, timeout: u64, proxy: &Option<(String, u16)>) -> Self {
                Self(AbstractProvider {
                    info: info.clone(),
                    timeout,
                    proxy: proxy.clone(),
                })
            }
        }
    };
}

/// All providers have those fields
#[derive(Clone, Debug)]
pub struct AbstractProvider {
    pub info: ProviderInfo,
    pub timeout: u64,
    pub proxy: Option<(String, u16)>,
}

impl Default for AbstractProvider {
    fn default() -> Self {
        Self {
            info: ProviderInfo::default(),
            timeout: 1000,
            proxy: None,
        }
    }
}

/// Build a new request client with timeout and proxy
async fn build_client(timeout: u64, proxy: &Option<(String, u16)>) -> reqwest::Result<Client> {
    let client = match (timeout, proxy) {
        (0, None) => Client::new(),
        (0, Some((host, port))) => Client::builder()
            .proxy(Proxy::all(&format!("http://{}:{}", host, port))?)
            .build()?,
        (_, None) => Client::builder()
            .timeout(Duration::from_millis(timeout))
            .build()?,
        (_, Some((host, port))) => Client::builder()
            .proxy(Proxy::all(&format!("http://{}:{}", host, port))?)
            .timeout(Duration::from_millis(timeout))
            .build()?,
    };
    Ok(client)
}

/// Build a new request with timeout and proxy and return the response
async fn build_client_get(
    url: &str,
    timeout: u64,
    proxy: &Option<(String, u16)>,
) -> Result<String> {
    let client = build_client(timeout, proxy)
        .await
        .map_err(GlobalIpError::ReqwestError)?;
    Ok(client
        .get(url)
        .send()
        .await
        .map_err(GlobalIpError::ReqwestError)?
        .text()
        .await
        .map_err(GlobalIpError::ReqwestError)?)
}

/// Create a getip::Result containing the IP address
fn create_ipaddr(addr: &str, addr_type: IpType) -> Result<IpAddr> {
    Ok(match addr_type {
        IpType::Ipv4 => IpAddr::V4(
            Ipv4Addr::from_str(addr).map_err(GlobalIpError::AddrParseError)?,
        ),
        IpType::Ipv6 => IpAddr::V6(
            Ipv6Addr::from_str(addr).map_err(GlobalIpError::AddrParseError)?,
        ),
    })
}

/// Plain text provider
#[derive(Clone, Debug, Deref)]
struct ProviderPlain(AbstractProvider);

make_new! {ProviderPlain}

#[async_trait]
impl Provider for ProviderPlain {
    async fn get_addr(&self) -> Result<IpAddr> {
        let addr = build_client_get(&self.info.url, self.timeout, &self.proxy).await?;
        create_ipaddr(&addr, self.info.addr_type)
    }

    make_get_type! {}
}

/// JSON provider
#[derive(Clone, Debug, Deref)]
pub struct ProviderJson(AbstractProvider);

make_new! {ProviderJson}

#[async_trait]
impl Provider for ProviderJson {
    async fn get_addr(&self) -> Result<IpAddr> {
        let resp = build_client_get(&self.info.url, self.timeout, &self.proxy).await?;
        // Try to parse the response as JSON
        let json: Value =
            serde_json::from_str(&resp).map_err(GlobalIpError::JsonParseError)?;
        let key = self
            .info
            .key
            .clone()
            .expect("`key' should exist for JSON providers");
        // Extract ip from response
        let addr = json
            .get(&key)
            .ok_or_else(|| GlobalIpError::JsonNotFoundError(key.clone()))?
            .as_str()
            .ok_or(GlobalIpError::JsonDecodeError(key))?;
        create_ipaddr(addr, self.info.addr_type)
    }

    make_get_type! {}
}

#[derive(Clone, Debug, Deref)]
pub struct ProviderDns(AbstractProvider);

make_new! {ProviderDns}

/// Resolve host to address with a resolver
async fn host_to_addr(
    resolver: TokioAsyncResolver,
    host: &str,
    addr_type: IpType,
) -> std::result::Result<Option<IpAddr>, ResolveError> {
    Ok(match addr_type {
        IpType::Ipv4 => {
            let srv = resolver.ipv4_lookup(host).await?;
            // Trick to unpack None
            (|| Some(IpAddr::V4(*srv.iter().next()?)))()
        }
        IpType::Ipv6 => {
            let srv = resolver.ipv6_lookup(host).await?;
            (|| Some(IpAddr::V6(*srv.iter().next()?)))()
        }
    })
}

#[async_trait]
impl Provider for ProviderDns {
    async fn get_addr(&self) -> Result<IpAddr> {
        let (query, server) = self
            .info
            .url
            .split_once('@')
            .expect("DNS Provider URL should be like query@server");
        let opts = ResolverOpts {
            timeout: Duration::from_millis(self.timeout),
            ..Default::default()
        };
        // First get the address of the DNS server
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::new(), opts)
            .map_err(|e| GlobalIpError::DnsError(Box::new(e)))?;
        // Get Resolver's address
        let server_addr = host_to_addr(resolver, server, self.info.addr_type)
            .await
            // Deal with errors
            .map_err(|e| GlobalIpError::DnsError(Box::new(e)))?
            // Deal with Nones
            .ok_or_else(|| GlobalIpError::DnsNoServerError(server.to_string()))?;
        // Construct Resolve config
        let ns = NameServerConfig {
            socket_addr: std::net::SocketAddr::new(server_addr, 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
        };
        let mut config = ResolverConfig::new();
        config.add_name_server(ns);
        // Create new resolver
        let resolver =
            TokioAsyncResolver::tokio(config, opts).map_err(|e| GlobalIpError::DnsError(Box::new(e)))?;
        let addr = host_to_addr(resolver, query, self.info.addr_type)
            .await
            .map_err(|e| GlobalIpError::DnsError(Box::new(e)))?
            // Deal with Nones
            .ok_or_else(|| GlobalIpError::DnsNoServerError(server.to_string()))?;
        Ok(addr)
    }

    make_get_type! {}
}

/// Try multiple providers until anyone succeeds
pub struct ProviderMultiple {
    providers: Vec<ProviderInfo>,
    addr_type: IpType,
    timeout: u64,
    proxy: Option<(String, u16)>,
}

impl Default for ProviderMultiple {
    fn default() -> Self {
        let providers: Vec<ProviderInfo> = serde_json::from_str(PROVIDERS).unwrap();
        Self {
            providers,
            addr_type: IpType::Ipv4,
            timeout: 1000,
            proxy: None,
        }
    }
}

impl ProviderMultiple {
    /// A default IPv6 provider
    pub fn default_v6() -> Self {
        Self {
            addr_type: IpType::Ipv6,
            ..Default::default()
        }
    }
}

#[async_trait]
impl Provider for ProviderMultiple {
    async fn get_addr(&self) -> Result<IpAddr> {
        let mut result: Result<IpAddr> = Err(crate::Error::NoAddress);
        for info in &self.providers {
            let this_result = match info.method {
                ProviderMethod::Plain => {
                    let provider = ProviderPlain::new(info, self.timeout, &self.proxy);
                    provider.get_addr().await
                }
                ProviderMethod::Json => {
                    let provider = ProviderJson::new(info, self.timeout, &self.proxy);
                    provider.get_addr().await
                }
                ProviderMethod::Dns => {
                    let provider = ProviderDns::new(info, self.timeout, &self.proxy);
                    provider.get_addr().await
                }
            };
            if this_result.is_ok() {
                result = this_result;
                break;
            }
        }
        result
    }

    fn get_type(&self) -> IpType {
        self.addr_type
    }
}

const PROVIDERS: &str = r#"[
  {
    "method": "plain",
    "name": "ipv6-test",
    "type": "IPv4",
    "url": "http://v4.ipv6-test.com/api/myip.php"
  },
  {
    "method": "plain",
    "name": "ipv6-test",
    "type": "IPv6",
    "url": "http://v6.ipv6-test.com/api/myip.php"
  },
  {
    "method": "plain",
    "name": "ident.me",
    "type": "IPv4",
    "url": "http://v4.ident.me/"
  },
  {
    "method": "plain",
    "name": "ident.me",
    "type": "IPv6",
    "url": "http://v6.ident.me/"
  },
  {
    "key": "ip",
    "method": "json",
    "name": "test-ipv6",
    "padding": "callback",
    "type": "IPv4",
    "url": "http://ipv4.test-ipv6.com/ip/"
  },
  {
    "key": "ip",
    "method": "json",
    "name": "test-ipv6",
    "padding": "callback",
    "type": "IPv6",
    "url": "http://ipv6.test-ipv6.com/ip/"
  },
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
  },
  {
    "method": "plain",
    "name": "akamai.com",
    "type": "IPv4",
    "url": "http://whatismyip.akamai.com"
  },
  {
    "method": "plain",
    "name": "akamai.com",
    "type": "IPv6",
    "url": "http://ipv6.whatismyip.akamai.com"
  }
]"#;

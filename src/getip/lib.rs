extern crate async_trait;
extern crate derive_deref;
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
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate thiserror;
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

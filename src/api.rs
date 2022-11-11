//! Name.com DNS API helper.
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
use log::{debug, trace};
use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::time::Duration;
use strum_macros::{Display, EnumString};

/// Deserializer for `reqwest::Response` of record listings.
#[derive(Deserialize, Debug)]
pub struct ListingResponse {
    records: Vec<NameComRecord>,
}

impl Deref for ListingResponse {
    type Target = Vec<NameComRecord>;

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

/// Type of DNS records.
#[derive(Copy, Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
pub enum RecordType {
    A,
    #[strum(serialize = "AAAA")]
    #[serde(rename = "AAAA")]
    Aaaa,
    #[strum(serialize = "ANAME")]
    #[serde(rename = "ANAME")]
    Aname,
    #[strum(serialize = "CNAME")]
    #[serde(rename = "CNAME")]
    Cname,
    #[strum(serialize = "MX")]
    #[serde(rename = "MX")]
    Mx,
    #[strum(serialize = "NS")]
    #[serde(rename = "NS")]
    Ns,
    #[strum(serialize = "SRV")]
    #[serde(rename = "SRV")]
    Srv,
    #[strum(serialize = "TXT")]
    #[serde(rename = "TXT")]
    Txt,
}

/// DNS record entry on name.com.
#[derive(Clone, Debug, Deserialize)]
pub struct NameComRecord {
    id: i32,
    #[serde(rename = "domainName")]
    #[allow(unused)]
    domain_name: String,
    // None or "@" means apex
    host: Option<String>,
    fqdn: String,
    #[allow(unused)]
    answer: String,
    #[serde(rename = "type")]
    rec_type: RecordType,
    #[allow(unused)]
    ttl: u32,
    #[allow(unused)]
    // Only for MX or SRV
    priority: Option<u32>,
}

/// Record entry for update. (A `NameComRecord` without readonly fields.)
#[derive(Debug, Deserialize, Serialize)]
pub struct NameComNewRecord {
    /// Host name below zone. None or "@" means apex.
    pub host: Option<String>,
    /// Record type.
    #[serde(rename = "type")]
    pub rec_type: RecordType,
    /// Record value.
    pub answer: String,
    /// Record Time To Live.
    pub ttl: u32,
    /// Priority. Only for `MX` or `SRV` records.
    pub priority: Option<u32>,
}

/// name.com API client.
#[allow(clippy::module_name_repetitions)]
pub struct NameComDnsApi {
    /// API endpoint URL.
    url: String,
    /// API username.
    username: String,
    /// API password.
    password: String,
    /// `reqwest::Client` for operations.
    client: Client,
}

/// Name.com DNS API helper.
///
/// `_get_record` and `_delete_record` are not used by this program, but kept for completeness.
///
/// # See Also
///
/// API Documentation: <https://www.name.com/api-docs/DNS>.
impl NameComDnsApi {
    /// Create a DNS API helper.
    ///
    /// - `username`: API username.
    /// - `password`: API key.
    /// - `api_url`: API endpoint like <https://api.name.com/>.
    /// - `timeout`: HTTP timeout in seconds, 0 means no timeout.
    pub fn create(
        username: &str,
        password: &str,
        api_url: &str,
        timeout: u64,
    ) -> reqwest::Result<Self> {
        let client = match timeout {
            0 => Client::new(),
            _ => Client::builder()
                .timeout(Duration::from_secs(timeout))
                .build()?,
        };
        Ok(Self {
            url: api_url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            client,
        })
    }

    /// Create a request with appropriate parameters.
    ///
    /// - `method`: Method of this request.
    /// - `path`: /v4/{} url path.
    fn with_param(&self, method: Method, path: &str) -> RequestBuilder {
        let url = format!("{}/v4/{}", self.url, path);
        debug!("Creating reqwest client: {:?}", url);
        self.client
            .request(method, &url)
            .basic_auth(&self.username, Some(&self.password))
    }

    /// List the records on a zone.
    ///
    /// - `domain`: The zone that the querying records belong to.
    ///
    /// Returns a `ListingResponse` if succeeded.
    pub async fn list_records(&self, domain: &str) -> reqwest::Result<ListingResponse> {
        self.with_param(Method::GET, &format!("domains/{}/records", domain))
            .send()
            .await?
            .error_for_status()?
            .json::<ListingResponse>()
            .await
    }

    /// Get the information of a record.
    ///
    /// - `domain`: The zone that the querying record belongs to.
    /// - `id`: Identifier of the record.
    ///
    /// Returns a `NameComRecord` if succeeded.
    pub async fn _get_record(&self, domain: &str, id: i32) -> reqwest::Result<NameComRecord> {
        self.with_param(Method::GET, &format!("domains/{}/records/{}", domain, id))
            .send()
            .await?
            .error_for_status()?
            .json::<NameComRecord>()
            .await
    }

    /// Create a new record.
    ///
    /// - `domain`: The zone that the record belongs to.
    /// - `record`: The new record.
    ///
    /// Returns a `NameComRecord` if succeeded.
    pub async fn create_record(
        &self,
        domain: &str,
        record: &NameComNewRecord,
    ) -> reqwest::Result<NameComRecord> {
        self.with_param(Method::POST, &format!("domains/{}/records", domain))
            .json(&record)
            .send()
            .await?
            .error_for_status()?
            .json::<NameComRecord>()
            .await
    }

    /// Update a record.
    ///
    /// - `domain`: The zone that the record belongs to.
    /// - `id`: Identifier of the record.
    /// - `record`: The new record.
    ///
    /// Returns a `NameComRecord` if succeeded.
    pub async fn update_record(
        &self,
        domain: &str,
        id: i32,
        record: &NameComNewRecord,
    ) -> reqwest::Result<NameComRecord> {
        self.with_param(Method::PUT, &format!("domains/{}/records/{}", domain, id))
            .json(&record)
            .send()
            .await?
            .error_for_status()?
            .json::<NameComRecord>()
            .await
    }

    /// Delete a record.
    ///
    /// - `domain`: The zone that the record belongs to.
    /// - `id`: Identifier of the record.
    pub async fn _delete_record(&self, domain: &str, id: i32) -> reqwest::Result<()> {
        self.with_param(
            Method::DELETE,
            &format!("domains/{}/records/{}", domain, id),
        )
        .send()
        .await?
        .error_for_status()?;
        Ok(())
    }

    /// Search for records with the same type and host.
    /// Note that only exact matches will be returned.
    ///
    /// - `domain`: The zone that the record belongs to.
    /// - `rec_type`: The type to search for.
    /// - `host`: The host to search for.
    ///
    /// Returns a vector of matching ids if succeeded.
    pub async fn search_records(
        &self,
        domain: &str,
        rec_type: RecordType,
        host: Option<&str>,
    ) -> reqwest::Result<Vec<i32>> {
        Ok(self
            .list_records(domain)
            .await?
            .iter()
            .filter_map(|record| {
                // Try not to leak too much information
                trace!("Found record {:?}", record.fqdn);
                if (record.host.as_deref() == host) && record.rec_type == rec_type {
                    Some(record.id)
                } else {
                    None
                }
            })
            .collect())
    }
}

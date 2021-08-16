/// Name.com DNS API helper.
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
use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use strum_macros::{Display, EnumString};

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

/// Type of the records
#[derive(Copy, Clone, Debug, Deserialize, Display, EnumString, Eq, PartialEq, Serialize)]
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

/// Record item
#[derive(Clone, Debug, Deserialize)]
pub struct NameComRecord {
    id: i32,
    #[serde(rename = "domainName")]
    domain_name: String,
    // None or "@" means apex
    host: Option<String>,
    fqdn: String,
    answer: String,
    #[serde(rename = "type")]
    rec_type: RecordType,
    ttl: u32,
    // Only for MX or SRV
    priority: Option<u32>,
}

/// Record item for update (readonly fields removed)
#[derive(Debug, Deserialize, Serialize)]
pub struct NameComNewRecord {
    // None or "@" means apex
    pub host: Option<String>,
    #[serde(rename = "type")]
    pub rec_type: RecordType,
    pub answer: String,
    pub ttl: u32,
    // Only for MX or SRV
    pub priority: Option<u32>,
}

pub struct NameComDnsApi {
    url: String,
    username: String,
    password: String,
    client: Client,
}

/// Name.com DNS API helper
///
/// get_record() and delete_record() are not used by this program,
/// but kept for completeness.
/// Reference: https://www.name.com/api-docs/DNS
impl NameComDnsApi {
    /// Create a DNS API helper.
    ///
    /// username: API username.
    /// password: API key.
    /// api_url: Optional API endpoint. Defaults to https://api.name.com/.
    pub fn create(username: &str, password: &str, api_url: &str) -> Self {
        Self {
            url: api_url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            client: Client::new(),
        }
    }

    /// Create a request with appropriate parameters.
    ///
    /// method: Method of this request.
    /// path: /v4/{} url path.
    fn with_param(&self, method: Method, path: &str) -> RequestBuilder {
        self.client
            .request(method, format!("{}/v4/{}", self.url, path))
            .basic_auth(&self.username, Some(&self.password))
    }

    /// List the records on a zone.
    ///
    /// domain: The zone that the querying records belong to.
    ///
    /// Returns a ListingResponse if succeeded.
    pub async fn list_records(&self, domain: &str) -> reqwest::Result<ListingResponse> {
        Ok(self
            .with_param(Method::GET, &format!("domains/{}/records", domain))
            .send()
            .await?
            .json::<ListingResponse>()
            .await?)
    }

    /// Get the information of a record.
    ///
    /// domain: The zone that the querying record belongs to.
    /// id: Identifier of the record.
    ///
    /// Returns a NameComRecord if succeeded.
    pub async fn _get_record(&self, domain: &str, id: i32) -> reqwest::Result<NameComRecord> {
        Ok(self
            .with_param(Method::GET, &format!("domains/{}/records/{}", domain, id))
            .send()
            .await?
            .json::<NameComRecord>()
            .await?)
    }

    /// Create a new record.
    ///
    /// domain: The zone that the record belongs to.
    /// record: The new record.
    ///
    /// Returns a NameComRecord if succeeded.
    pub async fn create_record(
        &self,
        domain: &str,
        record: &NameComNewRecord,
    ) -> reqwest::Result<NameComRecord> {
        Ok(self
            .with_param(Method::POST, &format!("domains/{}/records", domain))
            .json(&record)
            .send()
            .await?
            .json::<NameComRecord>()
            .await?)
    }

    /// Update a record.
    ///
    /// domain: The zone that the record belongs to.
    /// id: Identifier of the record.
    /// record: The new record.
    ///
    /// Returns a NameComRecord if succeeded.
    pub async fn update_record(
        &self,
        domain: &str,
        id: i32,
        record: &NameComNewRecord,
    ) -> reqwest::Result<NameComRecord> {
        Ok(self
            .with_param(Method::PUT, &format!("domains/{}/records/{}", domain, id))
            .json(&record)
            .send()
            .await?
            .json::<NameComRecord>()
            .await?)
    }

    /// Delete a record.
    ///
    /// domain: The zone that the record belongs to.
    /// id: Identifier of the record.
    pub async fn _delete_record(&self, domain: &str, id: i32) -> reqwest::Result<()> {
        self.with_param(
            Method::DELETE,
            &format!("domains/{}/records/{}", domain, id),
        )
        .send()
        .await?;
        Ok(())
    }

    /// Create or update a record. The record is left intact if the new record is identical.
    /// Note that if multiple records with the same type and name exists, the first one
    /// (by the order returned by name.com) will be updated.
    ///
    /// domain: The zone that the record belongs to.
    /// new_record: The new record.
    ///
    /// Returns a NameComRecord if succeeded.
    pub async fn set_record(
        &self,
        domain: &str,
        new_record: &NameComNewRecord,
    ) -> reqwest::Result<NameComRecord> {
        let records = self.list_records(domain).await?;
        // Iterate over existing records to see if update is possible
        for record in records.iter() {
            if record.host == new_record.host && record.rec_type == new_record.rec_type {
                return if record.answer == new_record.answer
                    && record.ttl == new_record.ttl
                    && record.priority == new_record.priority
                {
                    Ok(record.clone())
                } else {
                    self.update_record(domain, record.id, new_record).await
                };
            }
        }
        self.create_record(domain, new_record).await
    }
}

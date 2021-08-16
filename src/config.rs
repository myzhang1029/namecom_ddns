/// Configuration reader.
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
use crate::api::RecordType;
use serde::Deserialize;
use std::fs::File;
use std::io;
use std::io::prelude::*;

/// Account spec
#[derive(Debug, Deserialize)]
pub struct NameComConfigCore {
    pub url: Option<String>,
    pub username: String,
    pub key: String,
    pub interval: u32,
}

/// Method to get the ip from
#[derive(Copy, Clone, Debug, Deserialize)]
pub enum NameComConfigMethod {
    #[serde(rename = "global")]
    Global,
    #[serde(rename = "local")]
    Local,
}

/// Record spec
#[derive(Clone, Debug, Deserialize)]
pub struct NameComConfigRecord {
    pub host: String,
    pub zone: String,
    #[serde(rename = "type")]
    pub rec_type: RecordType,
    pub ttl: u32,
    pub method: NameComConfigMethod,
    pub interface: String,
}

#[derive(Debug, Deserialize)]
pub struct NameComDdnsConfig {
    pub core: NameComConfigCore,
    pub records: Vec<NameComConfigRecord>,
}

impl NameComDdnsConfig {
    pub fn from_file(path: &str) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut file_content = String::new();
        file.read_to_string(&mut file_content)?;
        Ok(toml::from_str(&file_content)?)
    }
}

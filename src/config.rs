/// Configuration reader.
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
use crate::api::RecordType;
use log::{debug, trace};
use serde::Deserialize;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::Path;

/// Account spec
#[derive(Debug, Deserialize)]
pub struct NameComConfigCore {
    #[serde(default = "default_url")]
    pub url: String,
    pub username: String,
    pub key: String,
    /// Update interval in minutes
    #[serde(default = "default_interval")]
    pub interval: u64,
    /// Timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_url() -> String {
    String::from("https://api.name.com/")
}

fn default_interval() -> u64 {
    60
}

fn default_timeout() -> u64 {
    30
}

/// Method to get the ip from
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
pub enum NameComConfigMethod {
    #[serde(rename = "global")]
    Global,
    #[serde(rename = "local")]
    Local,
    #[serde(rename = "script")]
    Script,
}

/// Record spec
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
pub struct NameComConfigRecord {
    pub host: String,
    pub zone: String,
    #[serde(rename = "type")]
    pub rec_type: RecordType,
    pub ttl: u32,
    pub method: NameComConfigMethod,
    pub interface: Option<String>,
    pub command: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct NameComDdnsConfig {
    pub core: NameComConfigCore,
    pub records: Vec<NameComConfigRecord>,
}

impl NameComDdnsConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::open(path)?;
        debug!("Opened file {:?}", file);
        let mut file_content = String::new();
        file.read_to_string(&mut file_content)?;
        trace!("Configuration contains {:?}", file_content);
        Ok(toml::from_str(&file_content)?)
    }
}

#[cfg(test)]
mod test {
    use crate::api::RecordType;
    use crate::config::{NameComConfigMethod, NameComDdnsConfig};
    use std::path::PathBuf;

    #[test]
    fn test_config_parser() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("examples/namecom_ddns.toml");
        let config = NameComDdnsConfig::from_file(&path).expect("Cannot open example file");
        let core = config.core;
        let record1 = &config.records[0];
        let record2 = &config.records[1];
        // Set values
        assert_eq!(core.username, "example", "core.username mismatch");
        assert_eq!(core.key, "40-char Name.com API key", "core.key mismatch");
        // Default values
        assert_eq!(core.url, "https://api.name.com/", "core.url mismatch");
        assert_eq!(core.timeout, 30, "core.timeout mismatch");
        assert_eq!(core.interval, 60, "core.interval mismatch");
        // Record 1
        assert_eq!(record1.host, "ddns", "record[0].host mismatch");
        assert_eq!(record1.zone, "example.com", "record[0].zone mismatch");
        assert_eq!(record1.rec_type, RecordType::A, "record[0].type mismatch");
        assert_eq!(record1.ttl, 300, "record[0].ttl mismatch");
        assert_eq!(
            record1.method,
            NameComConfigMethod::Global,
            "record[0].method mismatch"
        );
        assert_eq!(
            record1.interface.as_ref().unwrap(),
            "en0",
            "record[0].interface mismatch"
        );
        assert_eq!(
            record1.command.as_deref().unwrap(),
            vec!["/bin/get_an_ip"],
            "record[0].command mismatch"
        );
        // Record 2
        assert_eq!(record2.host, "ddns", "record[0].host mismatch");
        assert_eq!(record2.zone, "example.com", "record[0].zone mismatch");
        assert_eq!(
            record2.rec_type,
            RecordType::Aaaa,
            "record[0].type mismatch"
        );
        assert_eq!(record2.ttl, 300, "record[0].ttl mismatch");
        assert_eq!(
            record2.method,
            NameComConfigMethod::Local,
            "record[0].method mismatch"
        );
        assert_eq!(
            record2.interface.as_ref().unwrap(),
            "en0",
            "record[0].interface mismatch"
        );
    }
}

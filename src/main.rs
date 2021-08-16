/// Dynamic DNS with the Name.com API.
/// Run periodically to set DNS records to the local IP.
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
extern crate gip;
extern crate log;
extern crate pnet;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate simplelog;
extern crate subprocess;
extern crate thiserror;
extern crate tokio;
extern crate toml;

mod api;
mod config;
mod ip;

use log::{debug, error, info};
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::time;

#[tokio::main]
async fn main() {
    // Currently the path is hard-coded
    let configuration = config::NameComDdnsConfig::from_file("namecom_ddns.toml").unwrap();

    // Initialize logger
    let log_format = ConfigBuilder::new()
        .set_time_to_local(true)
        .set_time_format_str("[%Y-%m-%d %H:%M:%S]")
        .build();

    if let Err(e) = TermLogger::init(
        LevelFilter::Info,
        log_format,
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ) {
        panic!("Cannot create logger: {:?}", e);
    }

    // Check and update the DNS according to the config
    let mut interval = time::interval(time::Duration::from_secs(
        configuration.core.interval as u64 * 60,
    ));
    debug!("Configuration: {:?}", configuration);
    let url = configuration
        .core
        .url
        .unwrap_or_else(|| "https://api.name.com/".to_string());
    // Create a API client
    let client =
        api::NameComDnsApi::create(&configuration.core.username, &configuration.core.key, &url);
    updater_loop(&mut interval, &client, &configuration.records).await
}

async fn updater_loop(
    interval: &mut time::Interval,
    client: &api::NameComDnsApi,
    records: &[config::NameComConfigRecord],
) {
    loop {
        interval.tick().await;
        info!("Checking and updating addresses");
        // Update each record
        for item in records.iter() {
            let answer = match (item.rec_type, item.method) {
                (api::RecordType::A, config::NameComConfigMethod::Global) => {
                    ip::get_ip(ip::IpType::GlobalIpv4, None)
                }
                (api::RecordType::Aaaa, config::NameComConfigMethod::Global) => {
                    ip::get_ip(ip::IpType::GlobalIpv6, None)
                }
                (api::RecordType::A, config::NameComConfigMethod::Local) => {
                    ip::get_ip(ip::IpType::LocalIpv4, Some(&item.interface))
                }
                (api::RecordType::Aaaa, config::NameComConfigMethod::Local) => {
                    ip::get_ip(ip::IpType::LocalIpv6, Some(&item.interface))
                }
                _ => panic!(
                    "Record type {} is not one of \"A\" and \"AAAA\"",
                    item.rec_type
                ),
            };
            if let Ok(addr) = answer {
                info!("Received answer for {} is {}", item.host, addr);
                let new_record = api::NameComNewRecord {
                    host: Some(item.host.clone()),
                    rec_type: item.rec_type,
                    answer: addr.to_string(),
                    ttl: item.ttl,
                    priority: None,
                };
                if let Err(error) = client.set_record(&item.zone, &new_record).await {
                    error!(
                        "Failed to update the record for {} via API: {:?}",
                        item.host, error
                    );
                }
            } else {
                error!(
                    "Failed to receive the IP for {}: {:?}",
                    item.host,
                    answer.unwrap_err()
                );
            }
        }
        info!("Finished checking and updating addresses");
    }
}

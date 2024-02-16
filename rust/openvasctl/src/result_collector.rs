// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

/// This file contains structs and methods for retrieve scan information from redis
/// and store it into the given storage to be collected later for the clients.
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use crate::openvas_redis::{KbAccess, VtHelper};
use osp::{ScanResult, StringF32};
use redis_storage::dberror::RedisStorageResult;

/// Structure to hold the results retrieve from redis main kb
#[derive(Default, Debug)]
pub struct Results {
    /// The list of results retrieve
    results: Vec<ScanResult>,
    /// The number of new dead hosts found during this retrieve. New dead hosts can be found
    /// during the scan    
    new_dead: i64,
    /// Total amount of alive hosts found. This is sent once for scan, as it is the
    /// the alive host found by Boreas at the start of the scan.
    count_total: i64,
}

pub struct ResultHelper<H> {
    redis_connector: H,
    results: Arc<Mutex<Results>>,
}

impl<H> ResultHelper<H>
where
    H: KbAccess + VtHelper,
{
    pub fn init(redis_connector: H) -> Self {
        Self {
            redis_connector,
            results: Arc::new(Mutex::new(Results::default())),
        }
    }

    fn process_results(&self, results: Vec<String>) -> RedisStorageResult<Results> {
        let mut new_dead = 0;
        let mut count_total = 0;
        let mut scan_results: Vec<ScanResult> = Vec::new();
        for result in results.iter() {
            //result_type|||host ip|||hostname|||port|||OID|||value[|||uri]
            let res_fields: Vec<&str> = result.split("|||").collect();

            let result_type = res_fields[0].trim().to_owned();
            let host_ip = res_fields[1].trim().to_owned();
            let host_name = res_fields[2].trim().to_owned();
            let port = res_fields[3].trim().to_owned();
            let oid = res_fields[4].trim().to_owned();
            let value = res_fields[5].trim().to_owned();
            let uri = {
                if res_fields.len() > 6 {
                    Some(res_fields[6].trim().to_owned())
                } else {
                    None
                }
            };

            let roid = oid.trim();

            let current_host = if !host_ip.is_empty() {
                host_ip
            } else {
                String::new()
            };

            let host_is_dead = value.contains("Host dead") || result_type == "DEADHOST";

            let host_deny = value.contains("Host access denied");
            let start_end_msg = result_type == "HOST_START" || result_type == "HOST_END";
            let host_count = result_type == "HOST_COUNT";
            let error_msg = result_type == "ERRMSG";

            // TODO: do we need the URI?
            let _uri = if let Some(uri) = uri {
                uri
            } else {
                "".to_string()
            };

            let mut rname = String::new();
            if !host_is_dead && !host_deny && !start_end_msg && !host_count {
                if roid.is_empty() && !error_msg {
                    tracing::warn!("Missing VT oid for a result");
                };

                let vt_aux = self.redis_connector.get_vt(roid)?;
                match vt_aux {
                    None => tracing::warn!("Invalid oid"),
                    Some(vt) => {
                        rname = vt.name;
                    }
                };
            }

            if error_msg {
                scan_results.push(ScanResult {
                    result_type: osp::ResultType::Error,
                    host: current_host,
                    hostname: host_name,
                    port,
                    test_id: roid.to_string(),
                    description: value,
                    severity: StringF32::from(0.0),
                    name: rname,
                });
            } else if start_end_msg || result_type == "LOG" {
                scan_results.push(ScanResult {
                    result_type: osp::ResultType::Log,
                    host: current_host,
                    hostname: host_name,
                    port,
                    test_id: roid.to_string(),
                    description: value,
                    severity: StringF32::from(0.0),
                    name: rname,
                });
            } else if result_type == "ALARM" {
                scan_results.push(ScanResult {
                    result_type: osp::ResultType::Alarm,
                    host: current_host,
                    hostname: host_name,
                    port,
                    test_id: roid.to_string(),
                    description: value,
                    severity: StringF32::from(0.0),
                    name: rname,
                });
            } else if result_type == "DEADHOST" {
                println!("AAAAAAAAAAAAAAAAAAAAAAA");
                new_dead += i64::from_str(&value).expect("Valid number of dead hosts");
            } else if host_count {
                count_total = i64::from_str(&value).expect("Valid number of dead hosts");
            }
        }

        Ok(Results {
            results: scan_results,
            new_dead,
            count_total,
        })
    }

    pub async fn results(&mut self) -> RedisStorageResult<()> {
        if let Ok(results) = self.redis_connector.results() {
            if let Ok(mut res) = Arc::as_ref(&self.results).lock() {
                if let Ok(res_updates) = self.process_results(results) {
                    res.count_total = res_updates.count_total;
                    res.new_dead = res_updates.new_dead;
                    res.results.extend(res_updates.results);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::openvas_redis::FakeRedis;
    use models::Result;
    use std::collections::HashMap;

    use super::ResultHelper;
    #[test]
    fn test_results() {
        let results = vec![
            "LOG|||127.0.0.1||| localhost ||||||||| HOST_START".to_string(),
            "ERRMSG|||127.0.0.1||| localhost ||||||1.2.3.4.5.6||| NVT timeout".to_string(),
            "ALARM|||127.0.0.1||| example.com |||22/tcp|||12.11.10.9.8.7||| Something wrong|||/var/lib/lib1.jar".to_string(),
            "DEADHOST||| ||| ||| ||| |||3".to_string(),
            "HOST_COUNT||| ||| ||| ||| |||12".to_string(),
            "DEADHOST||| ||| ||| ||| |||1".to_string(),

        ];

        let rc = FakeRedis {
            data: HashMap::new(),
        };

        let resh = ResultHelper::init(rc);

        let res_updates = resh.process_results(results).unwrap();

        let single_r = Result {
            id: 0,
            r_type: models::ResultType::Log,
            ip_address: Some("127.0.0.1".to_string()),
            hostname: Some("localhost".to_string()),
            oid: Some("".to_string()),
            port: None,
            protocol: None,
            message: Some("HOST_START".to_string()),
            detail: None,
        };

        let b = res_updates.results.get(0).unwrap();
        assert_eq!(models::Result::from(b), single_r);

        let single_r = Result {
            id: 0,
            r_type: models::ResultType::Error,
            ip_address: Some("127.0.0.1".to_string()),
            hostname: Some("localhost".to_string()),
            oid: Some("1.2.3.4.5.6".to_string()),
            port: None,
            protocol: None,
            message: Some("NVT timeout".to_string()),
            detail: None,
        };

        let b = res_updates.results.get(1).unwrap();
        assert_eq!(models::Result::from(b), single_r);

        let single_r = Result {
            id: 0,
            r_type: models::ResultType::Alarm,
            ip_address: Some("127.0.0.1".to_string()),
            hostname: Some("example.com".to_string()),
            oid: Some("12.11.10.9.8.7".to_string()),
            port: Some(i16::from(22i16)),
            protocol: Some(models::Protocol::TCP),
            message: Some("Something wrong".to_string()),
            detail: None,
        };

        let b = res_updates.results.get(2).unwrap();
        assert_eq!(models::Result::from(b), single_r);

        assert_eq!(res_updates.new_dead, 4);
        assert_eq!(res_updates.count_total, 12);
    }
}

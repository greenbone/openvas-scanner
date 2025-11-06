// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

/// This file contains structs and methods for retrieve scan information from redis
/// and store it into the given storage to be collected later for the clients.
use std::{collections::HashMap, str::FromStr};

use crate::openvas::openvas_redis::{KbAccess, VtHelper};
use crate::osp::{OspResultType, OspScanResult};
use crate::storage::redis::RedisStorageResult;

/// Structure to hold the results retrieve from redis main kb
#[derive(Default, Debug, Clone)]
pub struct Results {
    /// The list of results retrieve
    pub results: Vec<OspScanResult>,
    /// Total amount of alive hosts found. This is sent once for scan, as it is the
    /// the alive host found by Boreas at the start of the scan.
    pub count_total: i64,
    /// Total amount of excluded hosts.
    pub count_excluded: i64,
    /// The number of new alive hosts that already finished.
    pub count_alive: i64,
    /// The number of new dead hosts found during this retrieve. New dead hosts can be found
    /// during the scan    
    pub count_dead: i64,
    /// Current hosts status
    pub host_status: HashMap<String, i32>,
    /// The scan status
    pub scan_status: String,
}

impl Results {
    pub fn extend(&mut self, other: Results) {
        self.results.extend(other.results);
        self.count_total += other.count_total;
        self.count_excluded += other.count_excluded;
        self.count_alive += other.count_alive;
        self.count_dead += other.count_dead;
        self.host_status.extend(other.host_status);
        if !other.scan_status.is_empty() {
            self.scan_status = other.scan_status;
        };
    }
}

pub struct ResultHelper<'a, H> {
    pub redis_connector: &'a mut H,
}

impl<'a, H> ResultHelper<'a, H>
where
    H: KbAccess + VtHelper,
{
    pub fn init(redis_connector: &'a mut H) -> Self {
        Self { redis_connector }
    }

    fn process_results(&mut self, ov_results: Vec<String>) -> RedisStorageResult<Results> {
        let mut new_dead = 0;
        let mut count_total = 0;
        let mut count_excluded = 0;

        let mut scan_results: Vec<OspScanResult> = Vec::new();
        for result in ov_results.iter() {
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
            let host_count = result_type == "HOSTS_COUNT";
            let error_msg = result_type == "ERRMSG";
            let excluded_hosts = result_type == "HOSTS_EXCLUDED";

            // TODO: do we need the URI?
            let _uri = if let Some(uri) = uri {
                uri
            } else {
                "".to_string()
            };

            let mut rname = String::new();
            if !host_is_dead && !host_deny && !start_end_msg && !host_count && !excluded_hosts {
                if roid.is_empty() && !error_msg {
                    tracing::warn!("Missing VT oid for a result");
                };

                let vt_aux = self.redis_connector.get_vt(roid)?;
                match vt_aux {
                    None => tracing::warn!(roid, "Invalid oid"),
                    Some(vt) => {
                        rname = vt.name;
                    }
                };
            }
            let mut push_result = |x| {
                scan_results.push(OspScanResult {
                    result_type: x,
                    host: Some(current_host.clone()),
                    hostname: Some(host_name.clone()),
                    port: Some(port.clone()),
                    test_id: Some(roid.to_string()),
                    description: value.clone(),
                    severity: None,
                    name: rname.clone(),
                });
            };

            if error_msg {
                push_result(OspResultType::Error);
            } else if result_type == "LOG" {
                push_result(OspResultType::Log);
            } else if result_type == "HOST_START" {
                push_result(OspResultType::HostStart);
            } else if result_type == "HOST_END" {
                push_result(OspResultType::HostEnd);
            } else if result_type == "ALARM" {
                push_result(OspResultType::Alarm);
            } else if result_type == "DEADHOST" {
                new_dead += i64::from_str(&value).expect("Valid amount of dead hosts");
            } else if host_count {
                count_total = i64::from_str(&value).expect("Valid amount of dead hosts");
            } else if excluded_hosts {
                count_excluded = i64::from_str(&value).expect("Valid amount of excluded hosts");
            }
        }

        // TODO: create specialized struct for easier handling
        Ok(Results {
            results: scan_results,
            count_dead: new_dead,
            count_excluded,
            count_total,
            ..Default::default()
        })
    }

    pub async fn collect_results(&mut self) -> RedisStorageResult<Results> {
        let redis_results = self.redis_connector.results()?;
        self.process_results(redis_results)
    }

    fn process_status(&self, redis_status: Vec<String>) -> RedisStorageResult<Results> {
        enum ScanProgress {
            DeadHost = -1,
        }
        let mut new_dead = 0;
        let mut new_alive = 0;
        let mut all_hosts: HashMap<String, i32> = HashMap::new();
        for res in redis_status {
            let mut fields = res.splitn(3, '/');
            let current_host = fields.next().expect("Valid status value");
            let launched = fields.next().expect("Valid status value");
            let total = fields.next().expect("Valid status value");

            let host_progress: i32 = match i32::from_str(total) {
                // No plugins
                Ok(0) => {
                    continue;
                }
                // Host Dead
                Ok(-1) => ScanProgress::DeadHost as i32,
                Ok(n) => ((f32::from_str(launched).expect("Integer") / n as f32) * 100.0) as i32,
                _ => {
                    continue;
                }
            };

            if host_progress == -1 {
                new_dead += 1;
            } else if host_progress == 100 {
                new_alive += 1;
            }
            all_hosts.insert(current_host.to_string(), host_progress);

            tracing::debug!("Host {} has progress: {}", current_host, host_progress);
        }
        Ok(Results {
            host_status: all_hosts,
            count_alive: new_alive,
            count_dead: new_dead,
            ..Default::default()
        })
    }

    pub async fn collect_host_status(&mut self) -> RedisStorageResult<Results> {
        let redis_status = self.redis_connector.status()?;
        self.process_status(redis_status)
    }

    pub async fn collect_scan_status(&mut self, scan_id: String) -> RedisStorageResult<String> {
        self.redis_connector.scan_status(scan_id)
    }
}

#[cfg(test)]
mod tests {
    use greenbone_scanner_framework::models::{self, Protocol, Result, ResultType};
    use std::collections::HashMap;

    use crate::openvas::openvas_redis::test::FakeRedis;

    use super::ResultHelper;
    #[test]
    fn test_results() {
        let results = vec![
            "LOG|||127.0.0.1||| localhost ||||||||| HOST_START".to_string(),
            "ERRMSG|||127.0.0.1||| localhost ||||||1.2.3.4.5.6||| NVT timeout".to_string(),
            "ALARM|||127.0.0.1||| example.com |||22/tcp|||12.11.10.9.8.7||| Something wrong|||/var/lib/lib1.jar".to_string(),
            "DEADHOST||| ||| ||| ||| |||3".to_string(),
            "HOSTS_COUNT||| ||| ||| ||| |||12".to_string(),
            "DEADHOST||| ||| ||| ||| |||1".to_string(),
            "HOSTS_EXCLUDED||| ||| ||| ||| |||4".to_string(),

        ];

        let mut rc = FakeRedis {
            data: HashMap::new(),
        };

        let mut resh = ResultHelper::init(&mut rc);

        let results = resh.process_results(results).unwrap();

        let single_r = Result {
            id: 0,
            r_type: ResultType::Log,
            ip_address: Some("127.0.0.1".to_string()),
            hostname: Some("localhost".to_string()),
            oid: Some("".to_string()),
            port: None,
            protocol: None,
            message: Some("HOST_START".to_string()),
            detail: None,
        };
        assert_eq!(
            models::Result::from(results.results.first().unwrap()),
            single_r
        );

        let single_r = Result {
            id: 0,
            r_type: ResultType::Error,
            ip_address: Some("127.0.0.1".to_string()),
            hostname: Some("localhost".to_string()),
            oid: Some("1.2.3.4.5.6".to_string()),
            port: None,
            protocol: None,
            message: Some("NVT timeout".to_string()),
            detail: None,
        };
        assert_eq!(
            models::Result::from(results.results.get(1).unwrap()),
            single_r
        );

        let single_r = Result {
            id: 0,
            r_type: ResultType::Alarm,
            ip_address: Some("127.0.0.1".to_string()),
            hostname: Some("example.com".to_string()),
            oid: Some("12.11.10.9.8.7".to_string()),
            port: Some(22i16),
            protocol: Some(Protocol::TCP),
            message: Some("Something wrong".to_string()),
            detail: None,
        };
        assert_eq!(
            models::Result::from(results.results.get(2).unwrap()),
            single_r
        );

        assert_eq!(results.count_dead, 4);
        assert_eq!(results.count_total, 12);
    }

    #[test]
    fn test_status() {
        let status = vec![
            "127.0.0.1/0/1000".to_string(),
            "127.0.0.2/15/1000".to_string(),
            "127.0.0.3/750/1000".to_string(),
            "127.0.0.2/0/-1".to_string(),
            "127.0.0.4/500/1000".to_string(),
            "127.0.0.1/128/1000".to_string(),
            "127.0.0.4/1000/1000".to_string(),
            "127.0.0.5/0/-1".to_string(),
        ];

        let mut rc = FakeRedis {
            data: HashMap::new(),
        };

        let resh = ResultHelper::init(&mut rc);
        let results = resh.process_status(status).unwrap();

        let mut r = HashMap::new();
        r.insert("127.0.0.1".to_string(), 12);
        r.insert("127.0.0.3".to_string(), 75);
        r.insert("127.0.0.4".to_string(), 100);
        r.insert("127.0.0.2".to_string(), -1);
        r.insert("127.0.0.5".to_string(), -1);

        assert_eq!(results.host_status, r);
        assert_eq!(results.count_alive, 1);
        assert_eq!(results.count_dead, 2);
    }
}

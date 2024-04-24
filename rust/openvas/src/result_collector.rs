// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

/// This file contains structs and methods for retrieve scan information from redis
/// and store it into the given storage to be collected later for the clients.
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
};

use crate::openvas_redis::{KbAccess, VtHelper};
use osp::{ScanResult, StringF32};
use redis_storage::dberror::RedisStorageResult;

/// Structure to hold the results retrieve from redis main kb
#[derive(Default, Debug, Clone)]
pub struct Results {
    /// The list of results retrieve
    pub results: Vec<ScanResult>,
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

pub struct ResultHelper<'a, H> {
    pub redis_connector: &'a mut H,
    pub results: Arc<Mutex<Results>>,
}

impl<'a, H> ResultHelper<'a, H>
where
    H: KbAccess + VtHelper,
{
    pub fn init(redis_connector: &'a mut H) -> Self {
        Self {
            redis_connector,
            results: Arc::new(Mutex::new(Results::default())),
        }
    }

    fn process_results(&mut self, ov_results: Vec<String>) -> RedisStorageResult<()> {
        let mut new_dead = 0;
        let mut count_total = 0;
        let mut count_excluded = 0;

        let mut scan_results: Vec<ScanResult> = Vec::new();
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
                new_dead += i64::from_str(&value).expect("Valid amount of dead hosts");
            } else if host_count {
                count_total = i64::from_str(&value).expect("Valid amount of dead hosts");
            } else if excluded_hosts {
                count_excluded = i64::from_str(&value).expect("Valid amount of excluded hosts");
            }
        }
        if let Ok(mut results) = Arc::as_ref(&self.results).lock() {
            results.results = scan_results;
            results.count_dead += new_dead;
            results.count_excluded = count_excluded;
            results.count_total = count_total;
        }

        Ok(())
    }

    pub async fn collect_results(&mut self) -> RedisStorageResult<()> {
        if let Ok(redis_results) = self.redis_connector.results() {
            self.process_results(redis_results)?;
        }
        Ok(())
    }

    fn process_status(&self, redis_status: Vec<String>) -> RedisStorageResult<()> {
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
        if let Ok(mut results) = Arc::as_ref(&self.results).lock() {
            results.host_status.extend(all_hosts);
            results.count_alive += new_alive;
            results.count_dead += new_dead;
        }

        Ok(())
    }

    pub async fn collect_host_status(&mut self) -> RedisStorageResult<()> {
        if let Ok(redis_status) = self.redis_connector.status() {
            self.process_status(redis_status)?;
        }
        Ok(())
    }

    pub async fn collect_scan_status(&mut self, scan_id: String) -> RedisStorageResult<()> {
        if let Ok(scan_status) = self.redis_connector.scan_status(scan_id) {
            if let Ok(mut results) = Arc::as_ref(&self.results).lock() {
                results.scan_status = scan_status.to_string();
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
            "HOSTS_COUNT||| ||| ||| ||| |||12".to_string(),
            "DEADHOST||| ||| ||| ||| |||1".to_string(),
            "HOSTS_EXCLUDED||| ||| ||| ||| |||4".to_string(),

        ];

        let mut rc = FakeRedis {
            data: HashMap::new(),
        };

        let mut resh = ResultHelper::init(&mut rc);

        resh.process_results(results).unwrap();

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
        assert_eq!(
            models::Result::from(
                resh.results
                    .as_ref()
                    .lock()
                    .unwrap()
                    .results
                    .first()
                    .unwrap()
            ),
            single_r
        );

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
        assert_eq!(
            models::Result::from(
                resh.results
                    .as_ref()
                    .lock()
                    .unwrap()
                    .results
                    .get(1)
                    .unwrap()
            ),
            single_r
        );

        let single_r = Result {
            id: 0,
            r_type: models::ResultType::Alarm,
            ip_address: Some("127.0.0.1".to_string()),
            hostname: Some("example.com".to_string()),
            oid: Some("12.11.10.9.8.7".to_string()),
            port: Some(22i16),
            protocol: Some(models::Protocol::TCP),
            message: Some("Something wrong".to_string()),
            detail: None,
        };
        assert_eq!(
            models::Result::from(
                resh.results
                    .as_ref()
                    .lock()
                    .unwrap()
                    .results
                    .get(2)
                    .unwrap()
            ),
            single_r
        );

        assert_eq!(resh.results.as_ref().lock().unwrap().count_dead, 4);
        assert_eq!(resh.results.as_ref().lock().unwrap().count_total, 12);
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
        resh.process_status(status).unwrap();

        let mut r = HashMap::new();
        r.insert("127.0.0.1".to_string(), 12);
        r.insert("127.0.0.3".to_string(), 75);
        r.insert("127.0.0.4".to_string(), 100);
        r.insert("127.0.0.2".to_string(), -1);
        r.insert("127.0.0.5".to_string(), -1);

        assert_eq!(resh.results.as_ref().lock().unwrap().host_status, r);
        assert_eq!(resh.results.as_ref().lock().unwrap().count_alive, 1);
        assert_eq!(resh.results.as_ref().lock().unwrap().count_dead, 2);
    }
}

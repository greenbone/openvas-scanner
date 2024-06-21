// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
use configparser::ini::Ini;
use redis::{Commands, RedisResult};

use std::process::Command;
use std::time::{Duration, Instant};
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
};
use std::{env, process};
fn get_all(con: &mut redis::Connection) -> RedisResult<HashMap<String, Vec<String>>> {
    let keys: Vec<String> = con.keys("*")?;
    Ok(keys
        .into_iter()
        .map(|k| {
            let values: Vec<String> = match con.lrange(&k, 0, -1) {
                Ok(v) => v,
                Err(e) => match e.kind() {
                    // openvas doesn't store as UTF-8 therefore we have to react on type errors
                    // since the new implementation does use UTF-8 we cannot blindly assume that
                    // each byte is infact a character therefore we try first the standard parsing
                    // and again in u8.
                    redis::ErrorKind::TypeError => {
                        let values: Vec<Vec<u8>> = match con.lrange(&k, 0, -1) {
                            Ok(x) => x,
                            Err(e) => panic!("{e}"),
                        };
                        let values: Vec<String> = values
                            .iter()
                            .map(|x| x.iter().map(|x| *x as char).collect())
                            .collect();
                        values
                    }
                    _ => panic!("{e}"),
                },
            };
            (k, values)
        })
        .collect())
}

fn tabula_rasa(con: &mut redis::Connection) -> RedisResult<()> {
    redis::Cmd::new().arg("FLUSHALL").query(con)
}

fn get(con: &mut redis::Connection) -> RedisResult<HashMap<String, Vec<String>>> {
    let (_, max_db) = redis::Cmd::new()
        .arg("CONFIG")
        .arg("GET")
        .arg("databases")
        .query::<(String, u32)>(con)?;
    for i in 1..max_db {
        redis::Cmd::new()
            .arg("SELECT")
            .arg(i.to_string())
            .query(con)?;
        let result = get_all(con)?;
        if result.len() > 1 {
            return Ok(result);
        }
    }
    Err(Error::new(ErrorKind::NotFound, "No values are found").into())
}

// Although does differentiate between ' and " to handle escaping in
// openvas c impl the script_parameter does treat it the same.
// However we are not planing to handle ' " differently based on a built-in function
// therefore we make those changes to reduce the amount of false positives.
fn normalize_values(v: &str) -> String {
    let mut v = v.to_owned();

    v = v.replace(r"\n", "\n");
    v = v.replace(r"\\", "\\");
    v = v.replace(r#"\""#, "\"");
    v = v.replace(r"\'", "'");
    v = v.replace(r"\r", "\r");
    v = v.replace(r"\t", "\t");
    v = v.replace('\\', "");
    v
}

trait TagPair {
    fn as_tag_pair(&self) -> Option<(String, String)>;
}

impl TagPair for &str {
    fn as_tag_pair(&self) -> Option<(String, String)> {
        let v: Vec<&str> = self.splitn(2, '=').collect();
        if v.len() == 2 {
            Some((v[0].to_owned(), v[1].to_owned()))
        } else {
            eprint!("{self} split len is {}", v.len());
            None
        }
    }
}

fn run_get(
    kb: &mut redis::Connection,
    cmd: &str,
) -> RedisResult<(Duration, HashMap<String, Vec<String>>)> {
    tabula_rasa(kb).unwrap();
    println!("Executing: {cmd}");
    let mut args: Vec<&str> = cmd.split(' ').collect();
    args.reverse();
    let program = args.pop().unwrap_or_default();
    args.reverse();
    let start = Instant::now();
    let status = Command::new(program)
        .args(args)
        .status()
        .expect("program should be executable");
    let elapsed = start.elapsed();
    println!("{cmd} took {elapsed:?}");
    if !status.success() {
        panic!("failed to execute {cmd}: {cmd}")
    }
    get(kb).map(|x| (elapsed, x))
}

fn print_error(t: &str) -> i32 {
    eprintln!("{t}");
    1
}

fn main() {
    let oconfig = process::Command::new("openvas")
        .arg("-s")
        .output()
        .expect("openvas -s should function");

    let mut config = Ini::new();
    let oconfig = oconfig.stdout.iter().map(|x| *x as char).collect();
    config
        .read(oconfig)
        .expect("openvas -s output should be ini format.");
    let redis_url = {
        let dba = config
            .get("default", "db_address")
            .expect("openvas -s must contain db_address");
        if dba.starts_with("redis://") || dba.starts_with("unix://") {
            dba
        } else if dba.starts_with("tcp://") {
            dba.replace("tcp://", "redis://")
        } else {
            format!("unix://{dba}")
        }
    };

    let client = redis::Client::open(redis_url).unwrap();
    let mut kb = client.get_connection().unwrap();
    let (od, openvas) = run_get(&mut kb, "openvas -u").expect("results");

    let nasl_cli = match env::current_exe() {
        Ok(mut x) => {
            x.pop();
            x.push("scannerctl");
            x
        }
        Err(x) => panic!("This test program is assuming that scannerctl is in the same dir: {x}"),
    };
    let (ncd, nasl_cli) = run_get(
        &mut kb,
        &format!(
            "{} feed update --vts-only",
            nasl_cli.to_str().unwrap_or_default()
        ),
    )
    .expect("results");
    let mut errors = 0;
    if ncd > od {
        errors += print_error(&format!(
            "openvas ({od:?}) was faster than scannerctl ({ncd:?})"
        ));
    }

    let (left, right) = {
        println!("scannerctl: {} entries", nasl_cli.len());
        println!("openvas: {} entries", openvas.len());
        if nasl_cli.len() > openvas.len() {
            println!("scannerctl is left");
            (nasl_cli, openvas)
        } else {
            println!("openvas is left");
            (openvas, nasl_cli)
        }
    };
    for (key, left_vals) in left {
        // we don't store filename: since it is an unused function within ospd-openvas
        // it was used to get the modification time of a nvt plugin and put into the
        // artificial hash calculation.
        // However that proved to be error prone and was dismissed without ever removing the functionality
        // within openvas.
        if key.starts_with("filename:") {
            continue;
        }
        if key.ends_with(":prefs") {
            // The ordering doesn't seem to be reliable, most of the times it is reversed id, but sometimes it is not.
            // Therefore we currently stick with reversed id ordering and just verify if the values are equal.
            match right.get(&key) {
                Some(right) => {
                    for r in right {
                        if !left_vals.contains(r) {
                            errors += print_error(&format!("{key} value not found in left"));
                        }
                    }
                }
                None => {
                    errors += print_error(&format!("{key} not found in right"));
                }
            }
        } else {
            match right.get(&key) {
                Some(vs) => {
                    if left_vals.len() != vs.len() {
                        errors +=
                            print_error(&format!("{key} value length differs in left and right "));
                    } else {
                        for (i, v) in vs.iter().enumerate() {
                            if &left_vals[i] != v {
                                // those are tags, although the " quotation in NASL means to not interpret escape characters
                                // in script_tags within openvas it seems that they are partially treated.
                                // To ignore false positives we need to verify each split value and find a way to normalize this behaviour.
                                if i == 7 {
                                    let left: HashMap<String, String> = left_vals[i]
                                        .split('|')
                                        .filter_map(|x| x.as_tag_pair())
                                        .collect();
                                    let right: HashMap<String, String> =
                                        v.split('|').filter_map(|x| x.as_tag_pair()).collect();
                                    for (k, v) in left {
                                        let v = normalize_values(&v);
                                        match right.get(&k).cloned() {
                                            Some(x) => {
                                                let x = normalize_values(&x);
                                                if v != x {
                                                    errors += print_error(&format!(
                                                        "{key}[{i}]->{k}: {v} \n!=\n {x}"
                                                    ));
                                                }
                                            }
                                            None => {
                                                errors += print_error(&format!(
                                                    "{key}[{i}]->{k} not found in right."
                                                ));
                                            }
                                        }
                                    }
                                } else {
                                    errors += print_error(&format!(
                                        "{key}[{i}]\n{v}\n!=\n{}",
                                        &left_vals[i]
                                    ));
                                }
                            }
                        }
                    }
                }
                None => {
                    errors += print_error(&format!("{key} not found."));
                }
            }
        }
    }
    std::process::exit(errors);
}

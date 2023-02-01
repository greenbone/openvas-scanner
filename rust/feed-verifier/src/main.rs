use redis::{Commands, RedisResult};
use std::collections::HashSet;
use std::process::Command;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
};
use std::{thread, time};

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
    Err(Error::new(ErrorKind::NotFound, "").into())
}

// Although does differentiate between ' and " to handle escaping in
// openvas c impl the script_parameter does treat it the same.
// However we are not planing to handle ' " differently based on a built-in function
// therefore we make those changes to reduce the amount of false positives.
fn normalize_values(v: &str) -> String {
    let mut v = v.to_owned();

    v = v.replace(r#"\n"#, "\n");
    v = v.replace(r#"\\"#, "\\");
    v = v.replace(r#"\""#, "\"");
    v = v.replace(r#"\'"#, "'");
    v = v.replace(r#"\r"#, "\r");
    v = v.replace(r#"\t"#, "\t");
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

fn main() {
    let client = redis::Client::open("unix:///run/redis/redis.sock").unwrap();
    let mut kb = client.get_connection().unwrap();
    println!("execxuting openvas");

    let _ = Command::new("openvas")
        .arg("-u")
        .output()
        .expect("Failed to execute openvas");

    thread::sleep(time::Duration::from_millis(100));
    println!("getting results");
    let result1 = get(&mut kb).unwrap();
    tabula_rasa(&mut kb).unwrap();

    // feed -v -r "unix:///run/redis/redis.sock" -p /var/lib/openvas/plugins/
    println!("execxuting nasl-cli");
    let o = Command::new("/home/philipp/src/openvas-scanner/rust/target/release/nasl-cli")
        .arg("feed")
        .arg("-r")
        .arg("unix:///run/redis/redis.sock")
        .arg("-p")
        .arg("/var/lib/openvas/plugins/")
        .output()
        .expect("Failed to execute openvas");

    println!("getting results");
    let result2 = get(&mut kb).unwrap();
    tabula_rasa(&mut kb).unwrap();
    let (left, right) = {
        println!("nasl-cli: {}", result2.len());
        println!("openvas: {}", result1.len());
        if result2.len() > result1.len() {
            println!("fist nasl-cli");
            (result2, result1)
        } else {
            println!("fist openvas");
            (result1, result2)
        }
    };
    for (key, values) in left {
        // we don't store filename: since it is an unused function within ospd-openvas
        // it was used to get the modification time of a nvt plugin and put into the
        // artificial hash calulation.
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
                        if !values.contains(r) {
                            println!("{key} {r} not found in {}", values.join(","));
                        }
                    }
                }
                None => println!("{key} not found."),
            }
        } else {
            match right.get(&key) {
                Some(vs) => {
                    if values.len() != vs.len() {
                        println!(
                            "{key}: larger values {} smaller values {}",
                            values.len(),
                            vs.len()
                        );
                    } else {
                        for (i, v) in vs.iter().enumerate() {
                            if &values[i] != v {
                                // those are tags, although the " quotation in NASL means to not interpret escape characters
                                // in script_tags within openvas it seems that they are partially treated.
                                // To ignore false positives we need to verify each split value and find a way to normalize this behaviour.
                                if i == 7 {
                                    let left: HashMap<String, String> = values[i]
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
                                                    println!("{key}[{i}]->{k}: {v} \n!=\n {x}");
                                                }
                                            }
                                            None => println!("{key}[{i}]->{k} not found in right."),
                                        }
                                    }
                                } else {
                                    println!("{key}[{i}] {v} \n!=\n {}", values[i]);
                                }
                            }
                        }
                    }
                }
                None => println!("{key} not found."),
            }
        }
    }
}

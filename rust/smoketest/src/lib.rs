use reqwest::header;
use std::collections::HashMap;
use std::{fs::File};
use std::io::prelude::*;
use models::{Status, Phase, Result as ScanResult};
use serde_json;

/// Creates a new client setting the header, API-KEY and Certs if existing
pub fn new_client(apikey: &Option<String>, cert: &Option<String>, key: &Option<String> ) -> reqwest::Client {
    let mut headers = header::HeaderMap::new();
    if let Some(k) = apikey {
        headers.insert("X-API-KEY", header::HeaderValue::from_str(&k).unwrap());
    }
    headers.insert("Content-Type", header::HeaderValue::from_static("application/json"));
    let cli = reqwest::Client::builder()
        .default_headers(headers);

    let mut ckey:Vec<u8> = Vec::new();
    let mut ccert = String::new();
    if let Some(k) = key {
        if let Some(c) = cert {
            let mut cfile = File::open(&c).unwrap();
            let mut ccontent = String::new();
            cfile.read_to_string(&mut ccontent).unwrap();
            ccert = ccontent;   

            File::open(k).unwrap()
                .read_to_end(&mut ckey).unwrap();
        }
    }
    
    if ckey.is_empty() && ccert.is_empty() {
        cli.build().unwrap()
    } else{

        let ccert = reqwest::tls::Identity::from_pem(&ccert.clone().into_bytes()).unwrap();

        let ckey = reqwest::tls::Identity::from_pem(&ckey).unwrap();

        println!("ESTOY ACAAAAAAAAAAAAA");
        cli.identity(ckey).identity(ccert).build().unwrap()
    }

}

/// Stores the Scan Config and returns the received ScanID, to be used in further requests.
pub async fn create_scan(cli: &reqwest::Client, server: &String, scan_config: &String) -> Option<String> {
    let mut file = File::open(&scan_config).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();

    let mut path = String::from(server);
    path.push_str("/scans");
    let res = cli.post(path)
        .body(content)
        .send().await.unwrap();
        
    
    if res.status().is_success()  {
        tracing::info!("\tCreating scan config OK");
        let id = res.json().await.unwrap();
        return Some(id);
    }

    tracing::info!("\tCreating scan config '{scan_config}' FAILED");
    None
}

/// Sends an action for the given ScanID.
pub async fn scan_action(cli: &reqwest::Client, server: &String, id: &String, action: String) -> bool {
    let mut path = String::from(server);
    path.push_str("/scans/");
    path.push_str(id.as_str());

    let mut data = HashMap::new();
    data.insert("action", action.as_str());
    let res = cli.post(path)
        .json(&data)
        .send().await.unwrap();
        
    
    if res.status().is_success()  {
        tracing::info!("\tSend scan action {action} OK");
        return true;
    }

    tracing::info!("\tSend scan action {action} FAILED");
    false
}

/// Given an ScanID, it fetchs the current scan status.
pub async fn scan_status(cli: &reqwest::Client, server: &String, id: &String) -> Option<Phase> {
    let mut path = String::from(server);
    path.push_str("/scans/");
    path.push_str(id.as_str());
    path.push_str("/status");

    let res = cli.get(path)
        .send().await.unwrap();
    
    if res.status().is_success() {
        let data = res.text().await.unwrap();
        if data.is_empty() {
            return None;
        }
        let status: Result<Status, _> = serde_json::from_str(data.as_str());
        match status {
            Ok(st) =>  {return Some(st.status); },
            Err(err) => {
                println!("{:?}", err);
                return None;                    
            },
        }      
    }
    tracing::info!("\tGet scan status FAILED");
    None
}

/// Given an ScanID, it fetchs the current scan results.
pub async fn scan_results(cli: &reqwest::Client, server: &String, id: &String) -> Option<Vec<ScanResult>> {
    let mut path = String::from(server);
    path.push_str("/scans/");
    path.push_str(id.as_str());
    path.push_str("/results");

    let res = cli.get(path)
        .send().await.unwrap();
    
    if res.status().is_success() {
        let data = res.text().await.unwrap();
        if data.is_empty() {
            return None;
        }
        let results: Result<Vec<ScanResult>, _> = serde_json::from_str(data.as_str());
        match results {
            Ok(res) =>  {return Some(res); },
            Err(err) => {
                println!("{:?}", err);
                return None;                    
            },
        }      
    }
    tracing::info!("\tGet scan results FAILED");
    None
}

pub async fn delete_scan (cli: &reqwest::Client, server: &String, id: &String) -> bool {
    let mut path = String::from(server);
    path.push_str("/scans/");
    path.push_str(id.as_str());

    let res = cli.delete(path)
        .send().await.unwrap();
   
    if res.status().is_success()  {
        tracing::info!("\tDelete scan OK");
        return true;
    }
    tracing::info!("\tDelete scan FAILED");
    false
}

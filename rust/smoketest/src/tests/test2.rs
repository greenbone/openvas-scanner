use models::Phase;
use smoketest::*;

/// Run a successful scan. Get results and delete the scan
pub async fn run_scan(cli: &reqwest::Client, server: &String, scan_config: &String) -> bool {
    if let Some(id) = create_scan(cli, server, scan_config).await {
        if !scan_action(cli, server, &id, "start".to_string()).await {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        let mut counter = 0;
        loop {
            match scan_status(cli, server, &id).await {
                Some(Phase::Succeeded) => {
                    tracing::info!("\tRun scan succeeded OK");

                    if let Some(results) = scan_results(cli, server, &id).await {
                        if results.is_empty() {
                            tracing::info!("\tScan results FAILED");
                        } else {
                            tracing::info!("\tScan results {} OK", results.len());
                        }
                    } else {
                        tracing::info!("\tScan results FAILED");
                    }

                    delete_scan(cli, server, &id).await;
                    return true;
                }
                None => {
                    tracing::info!("\tRun scan succeeded FAILED");
                    return false;
                }
                _ => {
                    std::thread::sleep(std::time::Duration::from_secs(10));
                    counter += 1;
                    if counter >= 360 {
                        tracing::info!("\tRun scan timeout FAILED");
                        return false;
                    }
                }
            }
        }
    }
    false
}

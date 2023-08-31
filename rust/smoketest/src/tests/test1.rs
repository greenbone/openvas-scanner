/// Check the server sending the HEAD request
pub async fn check_server(cli: &reqwest::Client, server: &String) -> bool {
    match cli.head(server).send().await {
        Ok(res) => {
            if res.status().is_success() {
                tracing::info!("\tChecking openvasd server OK");
                true
            } else {
                tracing::info!("\tChecking openvasd server FAILED");
                false
            }
        }
        Err(e) => {
            tracing::info!("\tChecking openvasd server FAILED\n {}", e);
            false
        }
    }
}

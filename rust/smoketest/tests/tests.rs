// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod tests {
    use models::Phase;
    use smoketest::*;
    //use crate::tests::*;
    use smoketest::config::Args;
    use smoketest::new_client;

    /// Check the server sending the HEAD request
    #[tokio::test]
    async fn check_server() {
        let args = Args::get_all();
        let cli = new_client(args.api_key(), args.cert(), args.key());
       
        let status = match cli.head(args.openvasd()).send().await {
            Ok(res) => {
                if res.status().is_success() {
                    true
                } else {
                    false
                }
            }
            Err(_) => {
                false
            }
        };
        assert_eq!(status, true);
        
    }
    
    #[tokio::test]
    /// Run a successful scan. Get results and delete the scan
    async fn run_scan() {
        let args = Args::get_all();
        let cli = new_client(args.api_key(), args.cert(), args.key());
        let mut counter = 0;
        let mut success = false;
        if let Some(id) = create_scan(&cli, args.openvasd(), args.scan_config()).await {
            if !scan_action(&cli, args.openvasd(), &id, "start".to_string()).await {
                assert!(success);
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                match scan_status(&cli, args.openvasd(), &id).await {
                    Some(Phase::Succeeded) => {
                        if let Some(results) = scan_results(&cli, args.openvasd(), &id).await {
                            assert_eq!(results.is_empty(), false)
                        }
                        assert!(delete_scan(&cli, args.openvasd(), &id).await);
                        success = true;
                        break;
                    }
                    None => {
                        success = false;
                        break;
                    }
                    Some(_) => {
                        counter += 1;
                        assert!(counter <= 360);
                    }
                }
            }
        }
        assert!(success)
    }
}

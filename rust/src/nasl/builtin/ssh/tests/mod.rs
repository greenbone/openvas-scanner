mod server;

use std::sync::Arc;
use std::time::Duration;

use russh::server::Server as _;
use server::TestServer;

use crate::nasl::test_prelude::TestBuilder;
use crate::nasl::NoOpLoader;
use crate::storage::DefaultDispatcher;

const PORT: u16 = 2223;

#[tokio::test]
async fn ssh_connect() {
    run_test(|mut t| {
        t.ok(format!("id = ssh_connect(port:{});", PORT), 9000);
        t.ok(format!("id = ssh_connect(port:{});", PORT), 9001);
    })
    .await
}

async fn run_test(f: impl Fn(TestBuilder<NoOpLoader, DefaultDispatcher>) -> () + Send + 'static) {
    let server = tokio::time::timeout(Duration::from_millis(2000), run_server());
    let client = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(1000));
        let t = TestBuilder::default();
        f(t)
    });
    let (ser, res) = futures::join!(server, client);
    assert!(ser.is_err());
    res.unwrap()
}

async fn run_server() {
    let config = russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![russh_keys::key::KeyPair::generate_ed25519().unwrap()],
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut server = TestServer::default();
    server
        .run_on_address(config, ("0.0.0.0", PORT))
        .await
        .unwrap();
}

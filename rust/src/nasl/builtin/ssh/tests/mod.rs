mod server;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use russh::server::Config as ServerConfig;
use russh::server::Server as _;
use russh_keys::key::KeyPair;
use server::TestServer;

use crate::check_err_matches;
use crate::nasl::builtin::ssh::MIN_SESSION_ID;
use crate::nasl::builtin::SshError;
use crate::nasl::test_prelude::*;
use crate::nasl::NoOpLoader;
use crate::storage::DefaultDispatcher;

use once_cell::sync::Lazy;

static LOCK: Lazy<Mutex<()>> = Lazy::new(Mutex::default);

const PORT: u16 = 2222;

fn default_config() -> ServerConfig {
    ServerConfig {
        keys: vec![KeyPair::generate_ed25519().unwrap()],
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        ..Default::default()
    }
}

async fn run_test(
    f: impl Fn(TestBuilder<NoOpLoader, DefaultDispatcher>) -> () + Send + 'static,
    config: ServerConfig,
) {
    // Acquire the global lock to prevent multiple
    // tests from opening a server at the same time.
    let _guard = LOCK.lock();
    let server = tokio::spawn(run_server(config));
    let client = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(200));
        let t = TestBuilder::default();
        f(t)
    });
    // Simply wait for whatever the test does on the client side
    let res = client.await;
    // and then abort the server, to make sure we do not run it for
    // all eternity.
    server.abort();
    res.unwrap()
}

async fn run_server(config: ServerConfig) {
    let config = Arc::new(config);
    let mut sh = TestServer::default();
    sh.run_on_address(config, ("0.0.0.0", PORT)).await.unwrap();
}

#[tokio::test]
async fn ssh_connect() {
    run_test(
        |mut t| {
            t.ok(
                format!(r#"id = ssh_connect(port:{});"#, PORT),
                MIN_SESSION_ID,
            );
            check_err_matches!(
                t,
                format!(r#"id = ssh_connect(port:{}, keytype: "foo");"#, PORT),
                FunctionErrorKind::WrongArgument(_)
            );
            // Without a matching key algorithm, we should not be able to connect
            check_err_matches!(
                t,
                format!(r#"id = ssh_connect(port:{}, keytype: "ssh-rsa");"#, PORT),
                FunctionErrorKind::Ssh(SshError::Connect(_, _))
            );
        },
        default_config(),
    )
    .await
}

#[tokio::test]
async fn ssh_userauth() {
    run_test(
        |mut t| {
            t.ok(
                format!(r#"session_id = ssh_connect(port: {});"#, PORT),
                MIN_SESSION_ID,
            );
            check_err_matches!(
                t,
                r#"ssh_userauth(session_id);"#,
                FunctionErrorKind::Ssh(SshError::NoAuthenticationGiven(_)),
            );
            t.run(r#"ssh_userauth(session_id, login: "user", password: "pass");"#);
        },
        default_config(),
    )
    .await
}

#[tokio::test]
async fn ssh_request_exec() {
    run_test(
        |mut t| {
            t.ok(
                format!(r#"session_id = ssh_connect(port: {});"#, PORT),
                MIN_SESSION_ID,
            );
            t.ok(
                r#"auth = ssh_userauth(session_id, login: "user", password: "pass");"#,
                NaslValue::Null,
            );
            t.ok(
                r#"auth = ssh_request_exec(session_id, stdout: 1, stderr: 0, cmd: "ls");"#,
                15,
            );
        },
        default_config(),
    )
    .await
}

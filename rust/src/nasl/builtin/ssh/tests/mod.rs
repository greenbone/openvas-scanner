// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod server;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use russh::server::Config as ServerConfig;
use russh::server::Server as _;
use russh_keys::key::KeyPair;
use server::AuthConfig;
use server::TestServer;

use crate::check_err_matches;
use crate::nasl::builtin::ssh::error::SshErrorKind;
use crate::nasl::builtin::ssh::sessions::MIN_SESSION_ID;
use crate::nasl::builtin::ssh::SshError;
use crate::nasl::test_prelude::*;
use crate::nasl::NoOpLoader;
use crate::storage::DefaultDispatcher;

use once_cell::sync::Lazy;

static LOCK: Lazy<Mutex<()>> = Lazy::new(Mutex::default);

const PORT: u16 = 2223;

fn default_config() -> ServerConfig {
    ServerConfig {
        keys: vec![KeyPair::generate_ed25519()],
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        ..Default::default()
    }
}

async fn run_test(
    f: impl Fn(&mut TestBuilder<NoOpLoader, DefaultDispatcher>) + Send + Sync + 'static,
    config: ServerConfig,
) {
    // Acquire the global lock to prevent multiple
    // tests from opening a server at the same time.
    let _guard = LOCK.lock();
    let server = tokio::task::spawn(async move { run_server(config).await });
    let client = tokio::task::spawn_blocking(move || run_client(f));
    // Simply wait for whatever the test does on the client side
    let res = client.await;
    // and then abort the server, to make sure we do not run it for
    // all eternity.
    server.abort();
    // Even if we abort it, we still need to make sure it finishes.
    // We ignore the result here because we dont care about the
    // JoinError::Cancelled (which is actually the expected result,
    // since we aborted).
    let _ = server.await;
    res.unwrap()
}

#[tokio::main]
async fn run_client(
    f: impl Fn(&mut TestBuilder<NoOpLoader, DefaultDispatcher>) + Send + Sync + 'static,
) {
    std::thread::sleep(Duration::from_millis(100));
    let mut t = TestBuilder::default();
    f(&mut t);
    t.async_verify().await;
}

async fn run_server(config: ServerConfig) {
    let config = Arc::new(config);
    let mut sh = TestServer::new(AuthConfig::default());
    sh.run_on_address(config, ("0.0.0.0", PORT)).await.unwrap();
}

#[tokio::test]
async fn ssh_connect() {
    run_test(
        |t| {
            t.ok(
                format!(
                    r#"id = ssh_connect(port:{}, keytype: "ssh-ed25519");"#,
                    PORT
                ),
                MIN_SESSION_ID,
            );
            check_err_matches!(
                t,
                format!(r#"id = ssh_connect(port:{}, keytype: "foo");"#, PORT),
                ArgumentError::WrongArgument(_)
            );
            // Without a matching key algorithm, we should not be able to connect
            check_err_matches!(
                t,
                format!(r#"id = ssh_connect(port:{}, keytype: "ssh-rsa");"#, PORT),
                SshError {
                    kind: SshErrorKind::Connect,
                    ..
                }
            );
        },
        default_config(),
    )
    .await
}

fn userauth(t: &mut DefaultTestBuilder) {
    let user = AuthConfig::default().user;
    let password = AuthConfig::default().password;
    t.run(format!(
        r#"ssh_userauth(session_id, login: "{user}", password: "{password}");"#,
        user = user,
        password = password
    ));
}

#[tokio::test]
async fn ssh_userauth() {
    run_test(
        |t| {
            t.ok(
                format!(
                    r#"session_id = ssh_connect(port: {}, keytype: "ssh-ed25519");"#,
                    PORT
                ),
                MIN_SESSION_ID,
            );
            check_err_matches!(
                t,
                r#"ssh_userauth(session_id);"#,
                SshError {
                    kind: SshErrorKind::NoAuthenticationGiven,
                    ..
                },
            );
            userauth(t);
        },
        default_config(),
    )
    .await
}

#[tokio::test]
// This test is disabled for libssh for now, since the
// `request_pty` call stalls for the test server. This
// is probably a bug in the test server itself, since
// the bug does not appear when connected to an openssh
// server. To fix this, I'd need to understand the
// russh server code in more detail.
#[cfg_attr(feature = "nasl-builtin-libssh", ignore)]
async fn ssh_request_exec() {
    run_test(
        |t| {
            t.ok(
                format!(r#"session_id = ssh_connect(port: {}, keytype: "ssh-ed25519");"#, PORT),
                MIN_SESSION_ID,
            );
            userauth(t);
            t.ok(
                r#"auth = ssh_request_exec(session_id, stdout: 1, stderr: 0, cmd: "write_foo_stdout");"#,
                "foo",
            );
            t.ok(
                r#"auth = ssh_request_exec(session_id, stdout: 0, stderr: 1, cmd: "write_bar_stderr");"#,
                "bar",
            );
            t.ok(
                r#"auth = ssh_request_exec(session_id, stdout: 1, stderr: 1, cmd: "write_both");"#,
                "barfoo",
            );
        },
        default_config(),
    )
    .await
}

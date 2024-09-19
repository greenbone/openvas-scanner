// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{env, path::PathBuf};

use crate::storage::DefaultDispatcher;
use crate::{
    feed::{HashSumNameLoader, Update},
    nasl::syntax::FSPluginLoader,
};
use futures::StreamExt;

fn loader() -> FSPluginLoader {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("data/feed/")
        .to_owned();
    FSPluginLoader::new(root)
}

#[test]
fn verify_hashsums() {
    let loader = loader();
    let verifier = HashSumNameLoader::sha256(&loader).expect("sha256sums should be available");
    let files = verifier
        .filter_map(|x| x.ok())
        .map(|x| x.get_filename())
        .collect::<Vec<String>>();
    assert_eq!(
        &files,
        &[
            "plugin_feed_info.inc".to_owned(),
            "test.inc".to_owned(),
            "test.nasl".to_owned()
        ]
    );
}

#[tokio::test]
async fn verify_feed() {
    let loader = loader();
    let storage: DefaultDispatcher = DefaultDispatcher::new();
    let verifier = HashSumNameLoader::sha256(&loader).expect("sha256sums should be available");
    let updater = Update::init("1", 1, &loader, &storage, verifier);
    let files = updater
        .stream()
        .filter_map(|x| async { x.ok() })
        .collect::<Vec<String>>()
        .await;
    // feed version and filename of script
    assert_eq!(
        &files,
        &["test.nasl".to_owned(), "plugin_feed_info.inc".to_owned()]
    );
}

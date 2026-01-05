// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{env, path::Path};

use crate::{
    feed::{HashSumNameLoader, Update},
    nasl::syntax::Loader,
    storage::inmemory::InMemoryStorage,
};
use futures::StreamExt;

fn loader() -> Loader {
    Loader::from_feed_path(Path::new(env!("CARGO_MANIFEST_DIR")).join("data/feed/"))
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
    let storage: InMemoryStorage = InMemoryStorage::new();
    let mut verifier = HashSumNameLoader::sha256(&loader).expect("sha256sums should be available");
    let updater = Update::init("1", 1, loader.clone(), &storage, &mut verifier);
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

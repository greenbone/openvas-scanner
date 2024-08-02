// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod test {
    use std::{env, path::PathBuf};

    use feed::{HashSumNameLoader, Update};
    use nasl_interpreter::FSPluginLoader;
    use storage::DefaultDispatcher;

    fn loader() -> FSPluginLoader<PathBuf> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/")
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
    #[test]
    fn verify_feed() {
        let loader = loader();
        let storage: DefaultDispatcher = DefaultDispatcher::new(true);
        let verifier = HashSumNameLoader::sha256(&loader).expect("sha256sums should be available");
        let updater = Update::init("1", 1, &loader, &storage, verifier);
        let files = updater.filter_map(|x| x.ok()).collect::<Vec<String>>();
        // feed version and filename of script
        assert_eq!(
            &files,
            &["test.nasl".to_owned(), "plugin_feed_info.inc".to_owned()]
        );
    }
}

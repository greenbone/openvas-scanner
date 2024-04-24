// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod test {
    use std::env;

    use feed::{HashSumNameLoader, Update};
    use nasl_interpreter::FSPluginLoader;
    use storage::DefaultDispatcher;

    #[test]
    fn verify_hashsums() {
        let root = match env::current_exe() {
            Ok(mut x) => {
                // target/debug/deps/testname
                for _ in 0..4 {
                    x.pop();
                }
                x.push("feed");
                x.push("tests");
                x
            }
            Err(x) => panic!("expected to contain current_exe: {x:?}"),
        };
        let loader = FSPluginLoader::new(&root);
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
        let root = match env::current_exe() {
            Ok(mut x) => {
                // target/debug/deps/testname
                for _ in 0..4 {
                    x.pop();
                }
                x.push("feed");
                x.push("tests");
                x
            }
            Err(x) => panic!("expected to contain current_exe: {x:?}"),
        };
        let loader = FSPluginLoader::new(&root);
        let storage: DefaultDispatcher<String> = DefaultDispatcher::new(true);
        let verifier = HashSumNameLoader::sha256(&loader).expect("sha256sums should be available");
        let updater = Update::init("1", 1, loader.clone(), storage, verifier);
        let files = updater.filter_map(|x| x.ok()).collect::<Vec<String>>();
        // feed version and filename of script
        assert_eq!(
            &files,
            &["test.nasl".to_owned(), "plugin_feed_info.inc".to_owned()]
        );
    }
}

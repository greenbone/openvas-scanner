use std::path::Path;

use scannerlib::nasl::{Loader, error::emit_errors_str};

use crate::linter::{Linter, Statistics, ctx::Cache, lints::all_lints};

pub fn lint(file_name: &str, code: &str) -> String {
    lint_files(&[(Path::new(file_name), code)])
}

pub fn lint_files(files: &[(&Path, &str)]) -> String {
    let feed = tempfile::tempdir().unwrap();
    for (name, code) in files {
        let path = feed.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, code).unwrap();
    }
    let loader = Loader::from_feed_path(feed.path());
    let mut linter = Linter {
        verbose: false,
        quiet: false,
        only_syntax: false,
        loader,
        stats: Statistics::default(),
        lints: all_lints(),
        cache: Cache::default(),
    };

    files
        .iter()
        .filter(|(name, _)| {
            Path::new(name)
                .extension()
                .map(|x| x.to_string_lossy() == "nasl")
                .unwrap_or(false)
        })
        .map(|(root, _)| {
            let result = linter.lint_file(root).unwrap();
            emit_errors_str(&result.file, result.msgs.into_iter())
        })
        .collect()
}

#[macro_export]
macro_rules! linter_test {
    ($name: ident, $code: literal) => {
        #[test]
        fn $name() {
            insta::assert_snapshot!($crate::linter::tests::lint(
                &format!("{}.nasl", stringify!($name)),
                $code,
            ));
        }
    };
}

#[macro_export]
macro_rules! linter_test_multi {
    (
        $name:ident,
        files: {$($file:literal => $code:literal),+ $(,)?} $(,)?
    ) => {
        #[test]
        fn $name() {
            insta::assert_snapshot!($crate::linter::tests::lint_files(
                &[$((Path::new($file), $code)),+],
            ));
        }
    };
}

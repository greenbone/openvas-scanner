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

    let roots: Vec<_> = files
        .iter()
        .filter(|(name, _)| {
            Path::new(name)
                .extension()
                .map(|x| x.to_string_lossy() == "nasl")
                .unwrap_or(false)
        })
        .map(|(root, _)| root.to_path_buf())
        .collect();
    let mut output = String::new();
    let _ = linter.run_with_emit(&roots, |result| {
        output.push_str(&emit_errors_str(&result.file, result.msgs.into_iter()));
    });
    output
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

linter_test_multi!(
    included_parse_error_uses_included_source,
    files: {
        "root.nasl" => "include(\"broken.inc\");",
        "broken.inc" => "function foo(",
    },
);

linter_test_multi!(
    transitive_parse_error_uses_included_source,
    files: {
        "root.nasl" => "include(\"outer.inc\");",
        "outer.inc" => "include(\"broken.inc\");",
        "broken.inc" => "function foo(",
    },
);

linter_test_multi!(
    transitive_load_error_uses_including_source,
    files: {
        "root.nasl" => "include(\"outer.inc\");",
        "outer.inc" => "include(\"missing.inc\");",
    },
);

linter_test_multi!(
    load_errors_continue_discovery,
    files: {
        "root.nasl" => "include(\"missing.inc\"); include(\"broken.inc\");",
        "broken.inc" => "function foo(",
    },
);

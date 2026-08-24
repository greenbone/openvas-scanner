use scannerlib::nasl::{Loader, error::emit_errors_str};

use crate::linter::{Linter, Statistics, ctx::Cache, lints::all_lints};

pub fn lint(file_name: &str, code: &str) -> String {
    lint_files(&[file_name], &[(file_name, code)])
}

pub fn lint_files(roots: &[&str], files: &[(&str, &str)]) -> String {
    let loader = files
        .iter()
        .fold(Loader::test(), |loader, (name, code)| {
            loader.with_file(name, (*code).into())
        })
        .build();
    let mut linter = Linter {
        verbose: false,
        quiet: false,
        only_syntax: false,
        loader,
        stats: Statistics::default(),
        lints: all_lints(),
        cache: Cache::default(),
    };

    roots
        .iter()
        .map(|root| {
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
            insta::assert_snapshot!($crate::linter::tests::lint(stringify!($name), $code,));
        }
    };
}

#[macro_export]
macro_rules! linter_test_multi {
    (
        $name:ident,
        roots: [$($root:literal),+ $(,)?],
        files: {$($file:literal => $code:literal),+ $(,)?} $(,)?
    ) => {
        #[test]
        fn $name() {
            insta::assert_snapshot!($crate::linter::tests::lint_files(
                &[$($root),+],
                &[$(($file, $code)),+],
            ));
        }
    };
}

linter_test_multi!(
    included_parse_error_uses_included_source,
    roots: ["root.nasl"],
    files: {
        "root.nasl" => "include(\"broken.inc\");",
        "broken.inc" => "function foo(",
    },
);

linter_test_multi!(
    function_definitions_do_not_leak_between_files,
    roots: ["first.nasl", "second.nasl"],
    files: {
        "first.nasl" => "function leaked() {}",
        "second.nasl" => "leaked();",
    },
);

linter_test_multi!(
    resolves_direct_include,
    roots: ["root.nasl"],
    files: {
        "root.nasl" => "include(\"functions.inc\"); foo();",
        "functions.inc" => "function foo() {}",
    },
);

linter_test_multi!(
    resolves_transitive_include,
    roots: ["root.nasl"],
    files: {
        "root.nasl" => "include(\"first.inc\"); foo();",
        "first.inc" => "include(\"second.inc\");",
        "second.inc" => "function foo() {}",
    },
);

linter_test_multi!(
    handles_include_cycle,
    roots: ["root.nasl"],
    files: {
        "root.nasl" => "include(\"first.inc\");",
        "first.inc" => "include(\"root.nasl\");",
    },
);

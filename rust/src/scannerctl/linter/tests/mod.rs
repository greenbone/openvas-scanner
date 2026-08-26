use std::{
    collections::{HashMap, HashSet},
    fs,
};

use scannerlib::nasl::{Loader, error::emit_errors_str};

use crate::linter::{Linter, Statistics, ctx::Cache, lints::all_lints};

fn make_linter(loader: Loader) -> Linter {
    Linter {
        verbose: false,
        quiet: false,
        only_syntax: false,
        loader,
        stats: Statistics::default(),
        lints: all_lints(),
        cache: Cache::default(),
        parsed_includes: HashMap::new(),
        lint_msgs: HashSet::new(),
    }
}

pub fn lint(file_name: &str, code: &str) -> String {
    lint_files(&[file_name], &[(file_name, code)])
}

pub fn lint_files(roots: &[&str], files: &[(&str, &str)]) -> String {
    lint_files_with_options(roots, files, false)
}

pub fn lint_files_with_options(
    roots: &[&str],
    files: &[(&str, &str)],
    only_syntax: bool,
) -> String {
    let loader = files
        .iter()
        .fold(Loader::test(), |loader, (name, code)| {
            loader.with_file(name, (*code).into())
        })
        .build();
    let mut linter = make_linter(loader);
    linter.only_syntax = only_syntax;

    roots
        .iter()
        .map(|root| {
            let result = linter.lint_file(root).unwrap();
            let result = linter.deduplicate(result);
            result
                .into_iter()
                .map(|msg| {
                    let file = msg.file().clone();
                    emit_errors_str(&file, std::iter::once(msg))
                })
                .collect::<String>()
        })
        .collect()
}

#[test]
fn parsed_include_is_reused_between_roots() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("first.nasl"),
        "include(\"functions.inc\"); helper();",
    )
    .unwrap();
    fs::write(
        directory.path().join("second.nasl"),
        "include(\"functions.inc\"); helper();",
    )
    .unwrap();
    let include = directory.path().join("functions.inc");
    fs::write(&include, "function helper() {}").unwrap();

    let mut linter = make_linter(Loader::from_feed_path(directory.path()));
    assert!(linter.lint_file("first.nasl").unwrap().is_empty());
    assert_eq!(
        linter.parsed_includes.keys().collect::<Vec<_>>(),
        vec!["functions.inc"]
    );

    fs::write(include, "function helper(").unwrap();
    assert!(linter.lint_file("second.nasl").unwrap().is_empty());
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
        only_syntax: $only_syntax:literal,
        roots: [$($root:literal),+ $(,)?],
        files: {$($file:literal => $code:literal),+ $(,)?} $(,)?
    ) => {
        #[test]
        fn $name() {
            insta::assert_snapshot!($crate::linter::tests::lint_files_with_options(
                &[$($root),+],
                &[$(($file, $code)),+],
                $only_syntax,
            ));
        }
    };
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
    syntax_checks_included_files,
    only_syntax: true,
    roots: ["root.nasl"],
    files: {
        "root.nasl" => "include(\"broken.inc\");",
        "broken.inc" => "function broken(",
    },
);

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

linter_test_multi!(
    shared_include_parse_error_is_emitted_once,
    roots: ["a.nasl", "b.nasl"],
    files: {
        "a.nasl" => "include(\"common.inc\");",
        "b.nasl" => "include(\"common.inc\");",
        "common.inc" => "function broken(",
    },
);

linter_test_multi!(
    duplicate_function_declaration_across_includes,
    roots: ["a.nasl", "b.nasl"],
    files: {
        "a.nasl" => "include(\"first.inc\"); include(\"second.inc\"); foo();",
        "b.nasl" => "include(\"second.inc\"); include(\"first.inc\"); foo();",
        "first.inc" => "function foo() {}",
        "second.inc" => "function foo() {}",
    },
);

linter_test_multi!(
    variable_declared_in_include,
    roots: ["root.nasl"],
    files: {
        "root.nasl" => "include(\"globals.inc\"); display(shared);",
        "globals.inc" => "shared = 1;",
    },
);

linter_test_multi!(
    variable_used_before_declaring_include,
    roots: ["root.nasl"],
    files: {
        "root.nasl" => "display(shared); include(\"globals.inc\");",
        "globals.inc" => "shared = 1;",
    },
);

linter_test_multi!(
    undeclared_variable_in_shared_include_is_emitted_once,
    roots: ["a.nasl", "b.nasl"],
    files: {
        "a.nasl" => "include(\"common.inc\");",
        "b.nasl" => "include(\"common.inc\");",
        "common.inc" => "display(missing);",
    },
);

linter_test_multi!(
    function_call_lints_in_include,
    roots: ["root.nasl"],
    files: {
        "root.nasl" => "include(\"calls.inc\");",
        "calls.inc" => "missing(value: 1, value: 2);",
    },
);

linter_test_multi!(
    function_call_lints_in_shared_include_are_emitted_once,
    roots: ["a.nasl", "b.nasl"],
    files: {
        "a.nasl" => "include(\"calls.inc\");",
        "b.nasl" => "include(\"calls.inc\");",
        "calls.inc" => "missing(value: 1, value: 2);",
    },
);

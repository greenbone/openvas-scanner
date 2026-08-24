use scannerlib::nasl::{Code, Loader, error::emit_errors_str};

use crate::linter::{
    Linter, Statistics,
    ctx::{Cache, CachedFile, LintCtx},
    lints::all_lints,
};

pub fn lint(file_name: &str, code: &str) -> String {
    let parsed = Code::from_string_filename(code, file_name).parse();
    let file = parsed.file().clone();
    let ast = match parsed.result() {
        Ok(ast) => ast,
        Err(errs) => {
            return emit_errors_str(&file, errs.into_iter());
        }
    };
    let mut cache = Cache::default();
    cache.insert(file_name, CachedFile::new(&ast));
    let ctx = LintCtx::new(&ast, &mut cache);
    let msgs: Vec<_> = all_lints()
        .iter()
        .flat_map(|lint| lint.lint(&ctx))
        .collect();
    emit_errors_str(&file, msgs.into_iter())
}

#[test]
fn included_parse_error_uses_included_source() {
    let loader = Loader::test()
        .with_file("root.nasl", "include(\"broken.inc\");".into())
        .with_file("broken.inc", "function foo(".into())
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

    let result = linter.lint_file("root.nasl").unwrap();
    let output = emit_errors_str(&result.file, result.msgs.into_iter());

    assert!(output.contains("broken.inc"), "{output}");
    assert!(!output.contains("root.nasl"), "{output}");
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

use std::path::Path;

use scannerlib::nasl::{Loader, error::emit_errors_str};

use crate::linter::{
    ctx::{Cache, CachedFile, LintCtx},
    lints::all_lints,
};

pub fn lint(file_name: &str, code: &str) -> String {
    let loader = Loader::test().with_file(file_name, code.into()).build();
    let file = loader.load_nasl(file_name).unwrap();
    let ast = match file.parse().result() {
        Ok(ast) => ast,
        Err(errs) => {
            return emit_errors_str(&file.source(), errs.into_iter());
        }
    };
    let mut cache = Cache::default();
    let file_name = Path::new(file_name);
    cache.insert(file_name, CachedFile::new(&ast));
    let ctx = LintCtx::new(&ast, &mut cache);
    let msgs: Vec<_> = all_lints()
        .iter()
        .flat_map(|lint| lint.lint(&ctx))
        .collect();
    emit_errors_str(&file.source(), msgs.into_iter())
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

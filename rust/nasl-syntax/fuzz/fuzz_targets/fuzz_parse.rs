#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _stmt = nasl_syntax::parse(&s).collect::<Vec<Result<nasl_syntax::Statement, nasl_syntax::SyntaxError>>>();
    }
});

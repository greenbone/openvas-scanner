use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use futures::StreamExt;
use scannerlib::nasl::syntax::Loader;
use scannerlib::nasl::utils::scan_ctx::{CtxTargets, Ports, Target};
use scannerlib::nasl::{Code, ScanCtx, nasl_std_executor};
use scannerlib::nasl::{Register, interpreter::ForkingInterpreter};
use scannerlib::scanner::preferences::preference::ScanPrefs;
use scannerlib::storage::ScanID;
use scannerlib::storage::inmemory::InMemoryStorage;

pub fn run_interpreter_in_description_mode(c: &mut Criterion) {
    let code = include_str!("../data/nasl_syntax/simple_parse.nasl");
    let variables = vec![("description".to_owned(), true.into())];
    c.bench_function("interpreter", |b| {
        b.iter(|| {
            futures::executor::block_on(async {
                let register = Register::from_global_variables(&variables);
                let executor = nasl_std_executor();
                let loader = Loader::test_empty();
                let in_memory_storage = InMemoryStorage::default();
                let targets = CtxTargets::single(Target::localhost(), Ports::default());
                let ctx = ScanCtx::new(
                    ScanID("test.nasl".to_string()),
                    targets,
                    "".into(),
                    &in_memory_storage,
                    &loader,
                    &executor,
                    ScanPrefs::new(),
                    Vec::new(),
                    None,
                );
                let code = Code::from_string(code)
                    .parse_description_block()
                    .emit_errors()
                    .unwrap();
                let parser = ForkingInterpreter::new(code, register, &ctx);
                let _: Vec<_> = black_box(parser.stream().collect().await);
            });
        })
    });
}

criterion_group!(benches, run_interpreter_in_description_mode);
criterion_main!(benches);

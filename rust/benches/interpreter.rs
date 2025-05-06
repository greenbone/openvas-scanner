use criterion::{Criterion, black_box, criterion_group, criterion_main};
use futures::StreamExt;
use scannerlib::nasl::utils::context::Target;
use scannerlib::nasl::{ContextBuilder, Register, interpreter::ForkingInterpreter};
use scannerlib::nasl::{NoOpLoader, nasl_std_functions};
use scannerlib::storage::ScanID;
use scannerlib::storage::inmemory::InMemoryStorage;

pub fn run_interpreter_in_description_mode(c: &mut Criterion) {
    let code = include_str!("../data/nasl_syntax/simple_parse.nasl");
    let variables = vec![("description".to_owned(), true.into())];
    c.bench_function("interpreter", |b| {
        b.iter(|| {
            futures::executor::block_on(async {
                let register = Register::root_initial(&variables);
                let cb = ContextBuilder {
                    scan_id: ScanID("test.nasl".to_string()),
                    filename: "",
                    target: Target::localhost(),
                    storage: &InMemoryStorage::default(),
                    executor: &nasl_std_functions(),
                    loader: &NoOpLoader::default(),
                    scan_preferences: Vec::new(),
                };
                let context = cb.build();
                let parser = ForkingInterpreter::new(code, register, &context);
                let _: Vec<_> = black_box(parser.stream().collect().await);
            });
        })
    });
}

criterion_group!(benches, run_interpreter_in_description_mode);
criterion_main!(benches);

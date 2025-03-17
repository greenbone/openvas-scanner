use criterion::{Criterion, black_box, criterion_group, criterion_main};
use futures::StreamExt;
use scannerlib::nasl::Code;
use scannerlib::nasl::{ContextFactory, Register, interpreter::ForkingInterpreter};
use scannerlib::storage::ScanID;

pub fn run_interpreter_in_description_mode(c: &mut Criterion) {
    let code = include_str!("../data/nasl_syntax/simple_parse.nasl");
    let variables = vec![("description".to_owned(), true.into())];
    c.bench_function("interpreter", |b| {
        b.iter(|| {
            futures::executor::block_on(async {
                let register = Register::root_initial(&variables);
                let context_factory = ContextFactory::default();
                let scan_id = ScanID("".to_string());
                let context = context_factory.build(scan_id, "localhost", "test.nasl".into());
                let code = Code::from_string(code).parse().emit_errors().unwrap();
                let parser = ForkingInterpreter::new(code, register, &context);
                let _: Vec<_> = black_box(parser.stream().collect().await);
            });
        })
    });
}

criterion_group!(benches, run_interpreter_in_description_mode);
criterion_main!(benches);

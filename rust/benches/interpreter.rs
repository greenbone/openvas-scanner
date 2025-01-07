use criterion::{black_box, criterion_group, criterion_main, Criterion};
use futures::StreamExt;
use scannerlib::{
    nasl::{interpreter::CodeInterpreter, ContextFactory, Register},
    storage::ContextKey,
};

pub fn run_interpreter_in_description_mode(c: &mut Criterion) {
    let code = include_str!("../data/nasl_syntax/simple_parse.nasl");
    let variables = vec![("description".to_owned(), true.into())];
    c.bench_function("interpreter", |b| {
        b.iter(|| {
            futures::executor::block_on(async {
                let register = Register::root_initial(&variables);
                let context_factory = ContextFactory::default();
                let context =
                    context_factory.build(ContextKey::FileName("test.nasl".to_string()));
                let parser = CodeInterpreter::new(&code, register, &context);
                let _: Vec<_> = black_box(parser.stream().collect().await);
            });
        })
    });
}

criterion_group!(benches, run_interpreter_in_description_mode);
criterion_main!(benches);

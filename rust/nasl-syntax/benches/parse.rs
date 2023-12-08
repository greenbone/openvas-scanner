// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nasl_syntax::parse;

pub fn simple_parse_benchmark(c: &mut Criterion) {
    let code = include_str!("simple_parse.nasl");
    c.bench_function("simple_parse", |b| {
        b.iter(|| parse(black_box(&code)).map(|x| x.unwrap()).count())
    });
}

pub fn parse_large_benchmark(c: &mut Criterion) {
    let code = include_str!("smb_nt.inc");
    c.bench_function(&format!("smb_nt.inc {}", code.len()), |b| {
        b.iter(|| parse(black_box(&code)).map(|x| x.unwrap()).count())
    });
}

criterion_group!(benches, simple_parse_benchmark, parse_large_benchmark);
criterion_main!(benches);

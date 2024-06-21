// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nasl_syntax::parse;

pub fn simple_parse_benchmark(c: &mut Criterion) {
    let code = include_str!("simple_parse.nasl");
    c.bench_function("simple_parse", |b| {
        b.iter(|| {
            if let Some(err) = parse(black_box(code)).find_map(|x| x.err()) {
                panic!("Unexpected error: {err}");
            }
        })
    });
}

pub fn parse_large_benchmark(c: &mut Criterion) {
    let code = include_str!("smb_nt.inc");
    c.bench_function(&format!("smb_nt.inc {}", code.len()), |b| {
        b.iter(|| {
            if let Some(err) = parse(black_box(code)).find_map(|x| x.err()) {
                panic!("Unexpected error: {err}");
            }
        })
    });
}

criterion_group!(benches, simple_parse_benchmark, parse_large_benchmark);
criterion_main!(benches);

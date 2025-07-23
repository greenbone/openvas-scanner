// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use scannerlib::nasl::Code;

pub fn simple_parse_benchmark(c: &mut Criterion) {
    let code = include_str!("../data/nasl_syntax/simple_parse.nasl");
    c.bench_function("simple_parse", |b| {
        b.iter(|| Code::from_string(black_box(code)).parse())
    });
}

fn parse_large_benchmark(c: &mut Criterion) {
    let code = include_str!("../data/nasl_syntax/smb_nt.inc");
    c.bench_function(&format!("smb_nt.inc {}", code.len()), |b| {
        b.iter(|| Code::from_string(black_box(code)).parse())
    });
}

criterion_group!(benches, simple_parse_benchmark, parse_large_benchmark);
criterion_main!(benches);

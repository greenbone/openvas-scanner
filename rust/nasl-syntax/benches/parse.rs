// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{env, fs, path::PathBuf};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nasl_syntax::parse;

fn loadfile(filename: &str) -> PathBuf {
    let mut current = env::current_dir().unwrap();
    let reset = current.clone();
    // move to nasl-syntax
    current.push("nasl-syntax");
    if !current.is_dir() {
        // we were already in nasl-syntax and have to reset
        current = reset;
    }
    current.push("benches");
    current.push(filename);
    current
}

pub fn simple_parse_benchmark(c: &mut Criterion) {
    let code: String = fs::read(loadfile("simple_parse.nasl"))
        .map(|bs| bs.iter().map(|&b| b as char).collect())
        .unwrap();
    c.bench_function("simple_parse", |b| b.iter(|| parse(black_box(&code))));
}

criterion_group!(benches, simple_parse_benchmark);
criterion_main!(benches);

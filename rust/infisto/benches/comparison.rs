// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use infisto::base::{CachedIndexFileStorer, IndexedByteStorage};
use rand::distributions::Alphanumeric;
use rand::Rng;

const BASE: &str = "/tmp/openvasd";

pub fn reading(c: &mut Criterion) {
    let amount = 1000000;
    fn random_data() -> Vec<u8> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut data = vec![0; 1024];
        rng.fill_bytes(&mut data);
        data
    }
    let mut data = Vec::with_capacity(amount);
    for _ in 0..amount {
        data.push(random_data());
    }

    let fname = |pre: &str| {
        format!(
            "{}{}",
            pre,
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(7)
                .map(char::from)
                .collect::<String>()
        )
    };
    // prepare data
    let cached_name = fname("cached");
    let mut store = CachedIndexFileStorer::init(BASE).unwrap();
    store.append_all(&cached_name, &data).unwrap();
    let uncached_name = fname("uncached");
    let mut store = infisto::base::IndexedFileStorer::init(BASE).unwrap();
    store.append_all(&uncached_name, &data).unwrap();
    // to be useable in openvasd we must create Stream interface to allow polling
    // on ranges otherwise the use has to wait until the whole file is read
    let crypto_name = fname("crypto");
    let mut store = infisto::crypto::ChaCha20IndexFileStorer::new(
        CachedIndexFileStorer::init(BASE).unwrap(),
        infisto::crypto::Key::default(),
    );
    store.append_all(&crypto_name, &data).unwrap();
    let mut group = c.benchmark_group("reading");
    group.sample_size(10);
    let store = CachedIndexFileStorer::init(BASE).unwrap();
    group.bench_with_input("cached", &cached_name, move |b, key| {
        b.iter(|| {
            store
                .by_range::<Vec<u8>>(black_box(key), infisto::base::Range::All)
                .unwrap();
        })
    });
    let store = infisto::base::IndexedFileStorer::init(BASE).unwrap();
    group.bench_with_input("uncached", &uncached_name, move |b, key| {
        b.iter(|| {
            store
                .by_range::<Vec<u8>>(black_box(key), infisto::base::Range::All)
                .unwrap();
        })
    });
    let store = infisto::crypto::ChaCha20IndexFileStorer::new(
        CachedIndexFileStorer::init(BASE).unwrap(),
        infisto::crypto::Key::default(),
    );
    group.bench_with_input("crypto", &crypto_name, move |b, key| {
        b.iter(|| {
            store
                .by_range::<Vec<u8>>(black_box(key), infisto::base::Range::All)
                .unwrap();
        })
    });

    group.finish();
    let mut clean_up_store = CachedIndexFileStorer::init(BASE).unwrap();
    clean_up_store.remove(&crypto_name).unwrap();
    clean_up_store.remove(&uncached_name).unwrap();
    clean_up_store.remove(&cached_name).unwrap();
}
pub fn storing(c: &mut Criterion) {
    let amount = 100000;
    fn random_data() -> Vec<u8> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut data = vec![0; 1024];
        rng.fill_bytes(&mut data);
        data
    }
    let mut data = Vec::with_capacity(amount);
    for _ in 0..amount {
        data.push(random_data());
    }

    let fname = |pre: &str| {
        format!(
            "{}{}",
            pre,
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(7)
                .map(char::from)
                .collect::<String>()
        )
    };
    let mut group = c.benchmark_group("storing");
    group.sample_size(10);
    let cached_name = fname("cached");
    group.bench_with_input(
        BenchmarkId::new("cached", "1million times 1MB"),
        &(&cached_name, &data),
        move |b, (key, data)| {
            let mut store = CachedIndexFileStorer::init(BASE).unwrap();
            b.iter(|| {
                store.append_all(black_box(key), black_box(data)).unwrap();
            })
        },
    );
    let uncached_name = fname("uncached");
    group.bench_with_input(
        "uncached",
        &(&uncached_name, &data),
        move |b, (key, data)| {
            let mut store = infisto::base::IndexedFileStorer::init(BASE).unwrap();
            b.iter(|| {
                store.append_all(black_box(key), black_box(data)).unwrap();
            })
        },
    );
    let crypto_name = fname("crypto");
    group.bench_with_input("crypto", &(&crypto_name, &data), move |b, (key, data)| {
        let mut store = infisto::crypto::ChaCha20IndexFileStorer::new(
            CachedIndexFileStorer::init(BASE).unwrap(),
            infisto::crypto::Key::default(),
        );
        b.iter(|| {
            store.append_all(black_box(key), black_box(data)).unwrap();
        })
    });
    group.finish();
    let mut clean_up_store = CachedIndexFileStorer::init(BASE).unwrap();
    clean_up_store.remove(&crypto_name).unwrap();
    clean_up_store.remove(&uncached_name).unwrap();
    clean_up_store.remove(&cached_name).unwrap();
    reading(c);
}

criterion_group!(benches, storing);

criterion_main!(benches);

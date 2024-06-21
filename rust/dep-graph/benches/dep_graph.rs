// SPDX-FileCopyrightText: 2023 Greenbone AG
// SPDX-FileCopyrightText: 2018 Nicolas Moutschen
//
// SPDX-License-Identifier: (GPL-2.0-or-later WITH x11vnc-openssl-exception) AND MIT

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dep_graph::{DepGraph, Node};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::thread;
use std::time::Duration;

/// Create a layer of nodes that don't have any dependencies
fn root_layer(count: usize) -> Vec<Node<String>> {
    (0..count)
        .map(|i| Node::new(format!("node0_{}", i)))
        .collect()
}

/// Utility function that adds a layer of nodes depending on the provided
/// layer and returns them.
fn add_layer(index: usize, count: usize) -> Vec<Node<String>> {
    (0..count)
        .map(|i| {
            let mut node = Node::new(format!("node{}_{}", index, i));
            // Mark the entire previous layer as a dependency of this node
            for j in 0..count {
                node.add_dep(format!("node{}_{}", index - 1, j));
            }
            node
        })
        .collect()
}

pub fn parallel_benchmark(c: &mut Criterion) {
    const NUM_LAYERS: usize = 20;
    #[cfg(feature = "parallel")]
    fn par_no_op(nodes: &[Node<String>]) {
        DepGraph::new(nodes)
            .into_par_iter()
            .for_each(|_node| thread::sleep(Duration::from_nanos(100)))
    }
    fn seq_no_op(nodes: &[Node<String>]) {
        DepGraph::new(nodes)
            .into_iter()
            .for_each(|_node| thread::sleep(Duration::from_nanos(100)))
    }

    {
        // Create a graph with the same number of nodes per layer as the number
        // of cores.
        let count = num_cpus::get();
        let mut nodes = root_layer(count);
        (1..NUM_LAYERS).for_each(|i| {
            add_layer(i, count)
                .iter()
                .for_each(|node| nodes.push(node.clone()))
        });

        // Run the resolver
        #[cfg(feature = "parallel")]
        c.bench_function("par_same_nodes", |b| {
            b.iter(|| par_no_op(black_box(&nodes)))
        });
        c.bench_function("seq_same_nodes", |b| {
            b.iter(|| seq_no_op(black_box(&nodes)))
        });
    }

    {
        // Create a graph with a graph twice as broad but half as deep
        let count = num_cpus::get();
        let mut nodes = root_layer(count * 2);
        (1..NUM_LAYERS / 2).for_each(|i| {
            add_layer(i, count * 2)
                .iter()
                .for_each(|node| nodes.push(node.clone()))
        });

        // Run the resolver
        #[cfg(feature = "parallel")]
        c.bench_function("par_double_nodes", |b| {
            b.iter(|| par_no_op(black_box(&nodes)))
        });
        c.bench_function("seq_double_nodes", |b| {
            b.iter(|| seq_no_op(black_box(&nodes)))
        });
    }

    {
        // Create a graph with a graph half as broad but twice as deep
        let count = num_cpus::get();
        let mut nodes = root_layer(count / 2);
        (1..NUM_LAYERS * 2).for_each(|i| {
            add_layer(i, count / 2)
                .iter()
                .for_each(|node| nodes.push(node.clone()))
        });

        // Run the resolver
        #[cfg(feature = "parallel")]
        c.bench_function("par_half_nodes", |b| {
            b.iter(|| par_no_op(black_box(&nodes)))
        });
        c.bench_function("seq_half_nodes", |b| {
            b.iter(|| seq_no_op(black_box(&nodes)))
        });
    }

    {
        // Create a graph with 100 nodes per layer
        let count = 100;
        let mut nodes = root_layer(count);
        (1..NUM_LAYERS).for_each(|i| {
            add_layer(i, count)
                .iter()
                .for_each(|node| nodes.push(node.clone()))
        });

        // Run the resolver
        #[cfg(feature = "parallel")]
        c.bench_function("par_100_nodes", |b| b.iter(|| par_no_op(black_box(&nodes))));
        c.bench_function("seq_100_nodes", |b| b.iter(|| seq_no_op(black_box(&nodes))));
    }
}

criterion_group!(benches, parallel_benchmark);
criterion_main!(benches);

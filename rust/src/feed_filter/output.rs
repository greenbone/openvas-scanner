// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use scannerlib::models::{Scan, VT};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Error};
use std::path::{Path, PathBuf};

use crate::dep_filter::DepMap;
use crate::script::{RunnableScripts, ScriptPath};

pub fn copy_feed(
    runnable: &RunnableScripts,
    feed_path: &Path,
    output_path: &Path,
) -> Result<(), io::Error> {
    fs::create_dir_all(output_path)?;
    for (path, _) in runnable.iter() {
        let src = feed_path.join(&path.0);
        let dst = output_path.join(&path.0);
        fs::create_dir_all(dst.parent().unwrap())?;
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

pub fn print_scripts(runnable: &RunnableScripts) {
    for (path, _) in runnable.iter() {
        println!("{path:?}");
    }
}

pub fn write_scan_config(
    runnable: &RunnableScripts,
    feed_path: &Path,
    scan_config: &PathBuf,
) -> Result<(), Error> {
    let scan = get_scan_config(feed_path, runnable);
    fs::write(scan_config, serde_json::to_string(&scan).unwrap())
}

fn get_scan_config(_feed_path: &Path, runnable: &RunnableScripts) -> Scan {
    let vts: Vec<_> = runnable
        .iter()
        .filter_map(|(_, script)| {
            script.oid.as_ref().map(|oid| VT {
                oid: oid.clone(),
                parameters: vec![],
            })
        })
        .collect();
    Scan {
        vts,
        ..Default::default()
    }
}

/// Copy a set of scripts (given as relative `ScriptPath`s) from `feed_path`
/// into `output_path`, recreating the directory structure.
pub fn copy_dep_feed(
    paths: &HashSet<ScriptPath>,
    feed_path: &Path,
    output_path: &Path,
) -> Result<(), io::Error> {
    fs::create_dir_all(output_path)?;
    for path in paths {
        let src = feed_path.join(&path.0);
        let dst = output_path.join(&path.0);
        fs::create_dir_all(dst.parent().unwrap())?;
        fs::copy(src, dst)?;
    }
    Ok(())
}

/// Print the relative path of every collected script to stdout.
pub fn print_dep_scripts(paths: &HashSet<ScriptPath>) {
    let mut sorted: Vec<&str> = paths.iter().map(|p| p.0.as_str()).collect();
    sorted.sort_unstable();
    for p in sorted {
        println!("{p}");
    }
}

/// Write a scan-config JSON containing the OIDs of all collected scripts.
pub fn write_dep_scan_config(
    paths: &HashSet<ScriptPath>,
    dep_map: &DepMap,
    scan_config: &PathBuf,
) -> Result<(), Error> {
    let vts: Vec<_> = paths
        .iter()
        .filter_map(|p| {
            dep_map.get(p)?.oid.as_ref().map(|oid| VT {
                oid: oid.clone(),
                parameters: vec![],
            })
        })
        .collect();
    let scan = Scan {
        vts,
        ..Default::default()
    };
    fs::write(scan_config, serde_json::to_string(&scan).unwrap())
}

/// Write a Graphviz DOT dependency graph to `dot_path`.
///
/// Nodes are arranged in **layers** using longest-path from the root scripts:
/// - Layer 0: scripts that nothing else in the collected set depends on (the roots).
/// - Layer N: the deepest layer from which a script is reachable + 1.
///
/// If a script is a dependency of both a layer-2 and a layer-7 script it will
/// appear on layer 8, keeping all arrows pointing strictly downward.
///
/// Edge styles:
/// - `#include` edges: dashed gray arrows
/// - `script_dependencies` edges: solid black arrows
pub fn write_dep_dot(dep_map: &DepMap, dot_path: &PathBuf) -> Result<(), Error> {
    fn escape(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }

    // Build a &str-keyed view of the map so we can look up nodes without
    // constructing owned ScriptPath values in hot loops.
    let info_map: HashMap<&str, _> = dep_map.iter().map(|(k, v)| (k.0.as_str(), v)).collect();

    // --- Step 1: count incoming edges for each node (Kahn's in-degree) ---
    let mut in_deg: HashMap<&str, usize> = info_map.keys().map(|&k| (k, 0usize)).collect();
    for info in info_map.values() {
        for dep in info.all_deps() {
            if let Some(d) = in_deg.get_mut(dep.0.as_str()) {
                *d += 1;
            }
        }
    }

    // --- Step 2: Kahn's topological sort (sorted for determinism) ---
    let mut deg_work = in_deg.clone();
    let mut init: Vec<&str> = deg_work
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(k, _)| *k)
        .collect();
    init.sort_unstable();
    let mut queue: VecDeque<&str> = init.into();
    let mut topo: Vec<&str> = Vec::with_capacity(info_map.len());

    while let Some(node) = queue.pop_front() {
        topo.push(node);
        if let Some(info) = info_map.get(node) {
            let mut promoted: Vec<&str> = Vec::new();
            for dep in info.all_deps() {
                let dep_str = dep.0.as_str();
                if let Some(d) = deg_work.get_mut(dep_str) {
                    *d -= 1;
                    if *d == 0 {
                        promoted.push(dep_str);
                    }
                }
            }
            promoted.sort_unstable();
            queue.extend(promoted);
        }
    }

    // --- Step 3: longest-path DP → layer for every node ---
    let mut layer: HashMap<&str, usize> = info_map.keys().map(|&k| (k, 0usize)).collect();
    for &node in &topo {
        let cur = layer[node];
        if let Some(info) = info_map.get(node) {
            for dep in info.all_deps() {
                let dep_str = dep.0.as_str();
                if let Some(l) = layer.get_mut(dep_str)
                    && cur + 1 > *l
                {
                    *l = cur + 1;
                }
            }
        }
    }
    // Nodes inside dependency cycles (not reached by Kahn's) get a fallback
    // layer beyond the maximum so they at least appear in the graph.
    let max_layer = layer.values().copied().max().unwrap_or(0);
    for node in dep_map.keys() {
        if deg_work.get(node.0.as_str()).copied().unwrap_or(0) > 0 {
            *layer.get_mut(node.0.as_str()).unwrap() = max_layer + 1;
        }
    }

    // --- Step 4: group nodes by layer (sorted for determinism) ---
    let mut by_layer: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
    for (&node, &l) in &layer {
        by_layer.entry(l).or_default().push(node);
    }
    for nodes in by_layer.values_mut() {
        nodes.sort_unstable();
    }

    // --- Step 5: emit DOT ---
    let mut out = String::from(
        "digraph feed {\n    rankdir=TB;\n    concentrate=true;\n    node [shape=box, fontsize=10];\n\n",
    );

    // rank=same subgraphs enforce the layer structure.
    for (l, nodes) in &by_layer {
        out.push_str(&format!("    // Layer {l}\n    {{ rank=same;"));
        for node in nodes {
            out.push_str(&format!(" \"{}\"; ", escape(node)));
        }
        out.push_str("}\n");
    }
    out.push('\n');

    // --- Step 6: merge parallel edges between the same (src, dst) pair ---
    // Bit flags: 1 = include, 2 = script_dep
    let mut edge_flags: BTreeMap<(&str, &str), u8> = BTreeMap::new();
    for (src, info) in dep_map.iter() {
        for dep in info.includes.iter() {
            *edge_flags
                .entry((src.0.as_str(), dep.0.as_str()))
                .or_insert(0) |= 1;
        }
        for dep in info.script_dependencies.iter() {
            *edge_flags
                .entry((src.0.as_str(), dep.0.as_str()))
                .or_insert(0) |= 2;
        }
    }

    // Emit one edge per (src, dst) pair with the appropriate style.
    let mut edges: Vec<String> = edge_flags
        .iter()
        .map(|((src, dst), &flags)| {
            let attrs = match flags {
                1 => r#"style=dashed, color=gray, label="include""#,
                2 => r#"style=solid, color=black, label="script_dep""#,
                _ => r#"style=solid, color=purple, penwidth=2, label="both""#,
            };
            format!(
                "    \"{}\" -> \"{}\" [{attrs}];\n",
                escape(src),
                escape(dst)
            )
        })
        .collect();
    edges.sort_unstable();
    for edge in edges {
        out.push_str(&edge);
    }

    out.push_str("}\n");
    fs::write(dot_path, out)
}

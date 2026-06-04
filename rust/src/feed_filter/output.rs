// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use scannerlib::models::{Scan, VT};
use std::collections::HashSet;
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

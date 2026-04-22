// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    env,
    path::{Path, PathBuf},
};

pub struct ArchiveConfig<'a> {
    pub bundle_env: &'a str,
    pub archives_env: &'a str,
    pub include_env: &'a str,
    pub bundled_archives: &'a [&'a str],
}

impl<'a> ArchiveConfig<'a> {
    pub fn emit_rerun_if_env_changed(&self) {
        println!("cargo:rerun-if-env-changed={}", self.bundle_env);
        println!("cargo:rerun-if-env-changed={}", self.archives_env);
        println!("cargo:rerun-if-env-changed={}", self.include_env);
    }

    pub fn resolve(&self) -> ResolvedArchives {
        ResolvedArchives {
            include_dir: self.resolve_include_dir(),
            archives: self.resolve_archive_list(),
        }
    }

    fn resolve_default_lookup() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or_else(|| {
                panic!(
                    "{} should contain a parent. Build layout changed.",
                    env!("CARGO_MANIFEST_DIR")
                )
            })
            .join("build-cache")
            .join("archives")
    }

    fn resolve_include_dir(&self) -> PathBuf {
        let result = env::var_os(self.include_env)
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os(self.bundle_env).map(|path| PathBuf::from(path).join("include"))
            })
            .unwrap_or_else(|| Self::resolve_default_lookup().join("include"));
        if !result.is_dir() {
            panic!(
                "{} is not a directory; no include directory available",
                result.display()
            )
        }
        result
    }

    fn resolve_archive_list(&self) -> Vec<PathBuf> {
        let archives = if let Some(value) = env::var_os(self.archives_env) {
            let archives: Vec<_> = env::split_paths(&value).collect();
            archives
        } else if let Some(bundle_dir) = env::var_os(self.bundle_env) {
            let bundle_dir = PathBuf::from(bundle_dir);
            self.bundled_archives
                .iter()
                .map(|archive| bundle_dir.join(archive))
                .collect()
        } else {
            let bundle_dir = Self::resolve_default_lookup();
            self.bundled_archives
                .iter()
                .map(|archive| bundle_dir.join(archive))
                .collect()
        };

        assert!(!archives.is_empty(), "{} is empty", self.archives_env);
        archives
    }
}

pub struct ResolvedArchives {
    pub include_dir: PathBuf,
    pub archives: Vec<PathBuf>,
}

impl ResolvedArchives {
    pub fn assert_archives_present(&self, env_name: &str, file_names: &[&str]) {
        for file_name in file_names {
            assert!(
                self.archives
                    .iter()
                    .any(|archive| archive.file_name().is_some_and(|name| name == *file_name)),
                "{} must contain {}",
                env_name,
                file_name
            );
        }
    }

    pub fn assert_headers_present(&self, env_name: &str, headers: &[&str]) {
        for header in headers {
            let path = self.include_dir.join(header);
            assert!(
                path.exists(),
                "{} must provide header {}",
                env_name,
                path.display()
            );
        }
    }

    pub fn emit_link_directives(&self) {
        let mut link_search_dirs: Vec<&Path> = Vec::new();

        for archive in &self.archives {
            let dir = archive
                .parent()
                .unwrap_or_else(|| panic!("{} has no parent directory", archive.display()));
            if !link_search_dirs.contains(&dir) {
                link_search_dirs.push(dir);
                println!("cargo:rustc-link-search=native={}", dir.display());
            }

            let file_stem = archive
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_else(|| panic!("Invalid archive path: {}", archive.display()));
            let link_name = file_stem.strip_prefix("lib").unwrap_or_else(|| {
                panic!("Archive does not start with lib: {}", archive.display())
            });
            println!("cargo:rustc-link-lib=static={}", link_name);
        }
    }
}

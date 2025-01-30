mod all_builtins;

use all_builtins::ALL_BUILTINS;
use regex::Regex;
use scannerlib::nasl::nasl_std_functions;
use std::io::{self};
use std::path::PathBuf;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};
use tracing::error;
use walkdir::WalkDir;

use crate::CliError;

#[derive(clap::Parser)]
pub struct FilterArgs {
    feed_path: PathBuf,
    output_file: PathBuf,
}

struct Builtins {
    builtins: Vec<String>,
    counts: HashMap<String, usize>,
}

impl Builtins {
    fn unimplemented() -> Self {
        let exec = nasl_std_functions();
        let implemented: Vec<_> = exec.iter().collect();
        let mut unimplemented: HashSet<_> = ALL_BUILTINS.iter().map(|x| x.to_string()).collect();
        for f in implemented {
            unimplemented.remove(f);
        }
        let counts = unimplemented.iter().map(|name| (name.clone(), 0)).collect();
        Self {
            builtins: unimplemented.into_iter().collect(),
            counts,
        }
    }

    fn script_is_runnable(&mut self, contents: &str) -> bool {
        let mut is_runnable = true;
        for builtin in self.builtins.iter() {
            if contents.contains(builtin) {
                is_runnable = false;
                *self.counts.get_mut(builtin).unwrap() += 1;
            }
        }
        is_runnable
    }

    fn print_counts(&self) {
        let mut sorted: Vec<_> = self.counts.iter().collect();
        sorted.sort_by_key(|(_, count)| **count);
        for (builtin, count) in sorted.iter() {
            println!("{builtin} {count}");
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Script {
    Runnable,
    NotRunnable,
    Dependencies(Vec<ScriptPath>),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScriptPath(String);

impl ScriptPath {
    fn new(feed_path: &Path, path: &Path) -> Self {
        let relative = pathdiff::diff_paths(path, feed_path).unwrap();
        Self(relative.as_os_str().to_str().unwrap().to_string())
    }
}

impl Script {
    fn iter_dependencies(&self) -> impl Iterator<Item = &ScriptPath> {
        if let Self::Dependencies(dependencies) = self {
            dependencies.iter()
        } else {
            panic!("iter_dependencies() called on non-dependencies variant")
        }
    }
}

struct FeedFilter {
    builtins: Builtins,
    feed_path: PathBuf,
    output_path: PathBuf,
    script_dependencies_regex: Regex,
    include_regex: Regex,
}

impl FeedFilter {
    fn new(feed_path: PathBuf, output_path: PathBuf) -> Self {
        let builtins = Builtins::unimplemented();
        let include_regex = Regex::new(r#"\binclude\("([^"]+)"\)"#).unwrap();
        let script_dependencies_regex =
            Regex::new(r#"\bscript_dependencies\("([^"]+)"\)"#).unwrap();
        Self {
            builtins,
            feed_path,
            output_path,
            script_dependencies_regex,
            include_regex,
        }
    }

    fn script_from_path(&mut self, path: &Path) -> Option<Script> {
        let contents = fs::read_to_string(path);
        match contents {
            Err(e) => {
                error!("Error reading file {path:?}: {e:?}");
                return None;
            }
            Ok(contents) => Some(self.script_from_contents(&contents)),
        }
    }

    pub fn script_from_contents(&mut self, contents: &str) -> Script {
        let is_runnable = self.builtins.script_is_runnable(contents);
        let includes = self.get_dependencies(contents);
        if !is_runnable {
            Script::NotRunnable
        } else if includes.is_empty() {
            Script::Runnable
        } else {
            Script::Dependencies(includes)
        }
    }

    fn get_dependency(&self, line: &str, fn_str: &str, regex: &Regex) -> Option<ScriptPath> {
        if !line.contains(fn_str) {
            return None;
        }
        if let Some(capture) = regex.captures_iter(line).next() {
            if let Some(match_) = capture.get(1) {
                return Some(ScriptPath(match_.as_str().to_string()));
            }
        }
        None
    }

    fn get_dependencies(&self, contents: &str) -> Vec<ScriptPath> {
        let mut dependencies = vec![];
        for line in contents.lines() {
            if let Some(dep) = self.get_dependency(line, "include", &self.include_regex) {
                dependencies.push(dep);
            }
            if let Some(dep) =
                self.get_dependency(line, "script_dependencies", &self.script_dependencies_regex)
            {
                dependencies.push(dep);
            }
        }
        dependencies
    }

    fn copy_feed(&self, resolved: HashMap<ScriptPath, Script>) -> Result<(), io::Error> {
        fs::create_dir_all(&self.output_path)?;
        for (path, script) in resolved {
            if matches!(script, Script::Runnable) {
                let src = self.feed_path.join(&path.0);
                let dst = self.output_path.join(&path.0);
                fs::create_dir_all(dst.parent().unwrap())?;
                std::fs::copy(src, dst)?;
            }
        }
        Ok(())
    }
}

fn resolve_includes(mut unresolved: HashMap<ScriptPath, Script>) -> HashMap<ScriptPath, Script> {
    let mut resolved: HashMap<ScriptPath, Script> = HashMap::default();
    loop {
        let (newly_resolved, newly_unresolved) = unresolved
            .into_iter()
            .partition::<HashMap<_, _>, _>(|(_, script)| {
                matches!(script, Script::Runnable | Script::NotRunnable)
            });
        unresolved = newly_unresolved;
        let new_length = newly_resolved.len();
        resolved.extend(newly_resolved.into_iter());
        if unresolved.is_empty() {
            return resolved;
        }
        if new_length == 0 {
            panic!("Unresolvable.");
        }
        for v in unresolved.values_mut() {
            let any_not_runnable = v
                .iter_dependencies()
                .any(|include| matches!(resolved.get(include), Some(Script::NotRunnable)));
            if any_not_runnable {
                *v = Script::NotRunnable;
                continue;
            }
            let all_resolved = v
                .iter_dependencies()
                .all(|include| resolved.contains_key(include));
            if !all_resolved {
                continue;
            }
            *v = Script::Runnable;
        }
    }
}

pub fn run(args: FilterArgs) -> Result<(), CliError> {
    let mut filter = FeedFilter::new(args.feed_path.to_owned(), args.output_file.to_owned());
    let mut scripts = HashMap::new();
    for entry in WalkDir::new(&args.feed_path).into_iter() {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            let path = entry.path();
            let script_path = ScriptPath::new(&args.feed_path, path);
            if let Some(script) = filter.script_from_path(path) {
                scripts.insert(script_path, script);
            } else {
                // If a script cant be read due to non-utf8, we assume
                // its not runnable.
                scripts.insert(script_path, Script::NotRunnable);
            }
        }
    }
    let resolved = resolve_includes(scripts);
    filter.copy_feed(resolved)?;
    filter.builtins.print_counts();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::feed::filter::{resolve_includes, ScriptPath};

    use super::Script;
    use super::Script::*;

    fn path(path_str: &str) -> ScriptPath {
        ScriptPath(path_str.to_string())
    }

    fn includes(paths: &[&str]) -> Script {
        Dependencies(paths.into_iter().map(|p| path(p)).collect())
    }

    fn make_scripts(scripts: &[(&str, Script)]) -> HashMap<ScriptPath, Script> {
        scripts
            .into_iter()
            .map(|(name, script)| (ScriptPath(name.to_string()), script.clone()))
            .collect()
    }

    #[test]
    fn resolution() {
        let scripts = [
            ("a", Runnable),
            ("b", Runnable),
            ("c", NotRunnable),
            ("d", includes(&["a", "b", "c"])),
        ];
        let resolved = resolve_includes(make_scripts(&scripts));
        assert_eq!(resolved[&path("a")], Runnable);
        assert_eq!(resolved[&path("b")], Runnable);
        assert_eq!(resolved[&path("c")], NotRunnable);
        assert_eq!(resolved[&path("d")], NotRunnable);
    }

    #[test]
    fn transitive_resolution() {
        let scripts = [
            ("a1", Runnable),
            ("b1", Dependencies(vec![path("a1")])),
            ("c1", Dependencies(vec![path("b1")])),
            ("d1", Dependencies(vec![path("c1")])),
            ("a2", NotRunnable),
            ("b2", Dependencies(vec![path("a2")])),
            ("c2", Dependencies(vec![path("b2")])),
            ("d2", Dependencies(vec![path("c2")])),
        ];
        let resolved = resolve_includes(make_scripts(&scripts));
        assert_eq!(resolved[&path("a1")], Runnable);
        assert_eq!(resolved[&path("b1")], Runnable);
        assert_eq!(resolved[&path("c1")], Runnable);
        assert_eq!(resolved[&path("d1")], Runnable);
        assert_eq!(resolved[&path("a2")], NotRunnable);
        assert_eq!(resolved[&path("b2")], NotRunnable);
        assert_eq!(resolved[&path("c2")], NotRunnable);
        assert_eq!(resolved[&path("d2")], NotRunnable);
    }
}

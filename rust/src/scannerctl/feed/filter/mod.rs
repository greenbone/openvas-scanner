mod all_builtins;

use all_builtins::ALL_BUILTINS;
use regex::Regex;
use scannerlib::models::{Scan, VT};
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
    /// Path to the feed that should be read and filtered.
    feed_path: PathBuf,
    /// Output path: If present, a copy of the feed containing only
    /// the runnable scripts will be copied to this directory. If
    /// the directory does not exist, it will be created.
    #[clap(short, long)]
    output_path: Option<PathBuf>,
    /// If present, a template scan json containing the OIDs of all
    /// runnable scripts will be written to this path.
    #[clap(short, long)]
    scan_config: Option<PathBuf>,
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

type Scripts = HashMap<ScriptPath, Script>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Script {
    Runnable,
    NotRunnable,
    Dependencies(Vec<ScriptPath>),
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScriptPath(String);

impl ScriptPath {
    fn new(feed_path: &Path, path: &Path) -> Self {
        let relative = pathdiff::diff_paths(path, feed_path).unwrap();
        Self(relative.as_os_str().to_str().unwrap().to_string())
    }
}

struct ScriptReader {
    builtins: Builtins,
    feed_path: PathBuf,
    script_dependencies_regex: Regex,
    include_regex: Regex,
}

impl ScriptReader {
    fn new(feed_path: PathBuf) -> Scripts {
        let builtins = Builtins::unimplemented();
        let include_regex = Regex::new(r#"\binclude\("([^"]+)"\)"#).unwrap();
        let script_dependencies_regex =
            Regex::new(r#"\bscript_dependencies\("([^"]+)"\)"#).unwrap();
        let mut reader = Self {
            builtins,
            feed_path,
            script_dependencies_regex,
            include_regex,
        };
        let scripts = reader.read_scripts();
        reader.builtins.print_counts();
        scripts
    }

    fn read_scripts(&mut self) -> Scripts {
        let mut scripts = HashMap::default();
        for entry in WalkDir::new(&self.feed_path).into_iter() {
            let entry = entry.unwrap();
            if entry.file_type().is_file() {
                let path = entry.path();
                let script_path = ScriptPath::new(&self.feed_path, path);
                if let Some(script) = self.script_from_path(path) {
                    scripts.insert(script_path, script);
                } else {
                    // If a script cant be read due to non-utf8, we assume
                    // its not runnable.
                    scripts.insert(script_path, Script::NotRunnable);
                }
            }
        }
        scripts
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
}

pub struct RunnableScripts(Scripts);

impl RunnableScripts {
    fn new(unresolved: Scripts) -> Self {
        let resolved = Self::resolve(unresolved);
        Self(
            resolved
                .into_iter()
                .filter(|(_, script)| matches!(script, Script::Runnable))
                .collect(),
        )
    }

    fn resolve(mut unresolved: Scripts) -> Scripts {
        let mut resolved: Scripts = HashMap::default();
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

    fn iter(&self) -> impl Iterator<Item = (&ScriptPath, &Script)> {
        self.0.iter()
    }
}

fn read_oid(feed_path: &Path, path: &ScriptPath) -> Option<String> {
    // We already read this file at this point, so it's utf8, so
    // unwrapping feels like the correct choice.
    let oid_regex = Regex::new(r#"\bscript_oid\("([^"]+)"\)"#).unwrap();
    let contents = fs::read_to_string(feed_path.join(&path.0)).unwrap();
    let mut captures = oid_regex.captures_iter(&contents);
    captures
        .next()
        .and_then(|capture| capture.get(1))
        .map(|match_| match_.as_str().to_string())
}

fn copy_feed(
    runnable: &RunnableScripts,
    feed_path: &Path,
    output_path: &Path,
) -> Result<(), io::Error> {
    fs::create_dir_all(&output_path)?;
    for (path, _) in runnable.iter() {
        let src = feed_path.join(&path.0);
        let dst = output_path.join(&path.0);
        fs::create_dir_all(dst.parent().unwrap())?;
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

fn print_scripts(runnable: &RunnableScripts) {
    for (path, _) in runnable.iter() {
        println!("{:?}", path);
    }
}

fn write_scan_config(
    runnable: &RunnableScripts,
    feed_path: &Path,
    scan_config: &PathBuf,
) -> Result<(), io::Error> {
    let scan = get_scan_config(feed_path, runnable);
    fs::write(scan_config, serde_json::to_string(&scan).unwrap())
}

fn get_scan_config(feed_path: &Path, runnable: &RunnableScripts) -> Scan {
    let vts: Vec<_> = runnable
        .iter()
        .filter_map(|(path, _)| {
            read_oid(feed_path, path).map(|oid| VT {
                oid,
                parameters: vec![],
            })
        })
        .collect();
    Scan {
        vts,
        ..Default::default()
    }
}

pub fn run(args: FilterArgs) -> Result<(), CliError> {
    let scripts = ScriptReader::new(args.feed_path.to_owned());
    let runnable = RunnableScripts::new(scripts);
    if let Some(ref output_path) = args.output_path {
        copy_feed(&runnable, &args.feed_path, &output_path)?;
    } else {
        print_scripts(&runnable);
    }
    if let Some(ref scan_config) = args.scan_config {
        write_scan_config(&runnable, &args.feed_path, scan_config)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::feed::filter::{RunnableScripts, ScriptPath};

    use super::Script::*;
    use super::{Script, Scripts};

    fn path(path_str: &str) -> ScriptPath {
        ScriptPath(path_str.to_string())
    }

    fn includes(paths: &[&str]) -> Script {
        Dependencies(paths.into_iter().map(|p| path(p)).collect())
    }

    fn make_scripts(scripts: &[(&str, Script)]) -> Scripts {
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
        let resolved = RunnableScripts::resolve(make_scripts(&scripts));
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
        let resolved = RunnableScripts::resolve(make_scripts(&scripts));
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

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use scannerlib::nasl::{
    SourceFile, nasl_std_executor,
    syntax::{
        Visitor,
        grammar::{Ast, FnDecl},
        walk_ast,
    },
    utils::Executor,
};

/// Names supplied by the script execution context or accepted for C-linter compatibility,
/// rather than registered as globals by Rust builtin function sets.
const PREDEFINED_VARS: [&str; 5] = [
    "ACT_UNKNOWN",
    "COMMAND_LINE",
    "OPENVAS_VERSION",
    "SCRIPT_NAME",
    "description",
];

/// Functions registered by the C NASL interpreter but not by `nasl_std_executor`.
/// Keep this list synchronized with `libfuncs` in `nasl/nasl_init.c`.
const C_COMPAT_BUILTINS: [&str; 42] = [
    "dsa_do_sign",
    "dsa_do_verify",
    "exit",
    "file_close",
    "file_open",
    "file_read",
    "file_seek",
    "file_write",
    "get_host_kb_index",
    "psrp_cli",
    "script_get_preference_file_location",
    "smb_close",
    "smb_connect",
    "smb_file_SDDL",
    "smb_file_group_sid",
    "smb_file_owner_sid",
    "smb_file_trustee_rights",
    "socket_check_ssl_safe_renegotiation",
    "socket_ssl_do_handshake",
    "tls1_prf",
    "update_table_driven_lsc_data",
    "win_cmd_exec",
    "wmi_close",
    "wmi_connect",
    "wmi_connect_reg",
    "wmi_connect_rsop",
    "wmi_query",
    "wmi_query_rsop",
    "wmi_reg_create_key",
    "wmi_reg_delete_key",
    "wmi_reg_enum_key",
    "wmi_reg_enum_value",
    "wmi_reg_get_bin_val",
    "wmi_reg_get_dword_val",
    "wmi_reg_get_ex_string_val",
    "wmi_reg_get_mul_string_val",
    "wmi_reg_get_qword_val",
    "wmi_reg_get_sz",
    "wmi_reg_set_dword_val",
    "wmi_reg_set_ex_string_val",
    "wmi_reg_set_qword_val",
    "wmi_reg_set_string_val",
];

fn predefined_vars(executor: &Executor) -> HashSet<String> {
    executor
        .iter_global_var_names()
        .chain(PREDEFINED_VARS)
        .map(str::to_owned)
        .collect()
}

fn builtin_fns(executor: &Executor) -> HashSet<String> {
    executor
        .iter()
        .chain(C_COMPAT_BUILTINS)
        .map(str::to_owned)
        .collect()
}

pub(crate) struct CachedFile {
    ast: Ast,
    file: SourceFile,
    fns: HashMap<String, FnDecl>,
}

impl CachedFile {
    pub(crate) fn new(file: SourceFile, ast: &Ast) -> Self {
        let mut collector = FnDefinitionCollector::default();
        walk_ast(&mut collector, ast);

        CachedFile {
            ast: ast.clone(),
            file,
            fns: collector.functions,
        }
    }

    pub(crate) fn ast(&self) -> &Ast {
        &self.ast
    }

    pub(crate) fn file(&self) -> &SourceFile {
        &self.file
    }

    pub(crate) fn functions(&self) -> impl Iterator<Item = (&str, &FnDecl)> {
        self.fns
            .iter()
            .map(|(name, declaration)| (name.as_str(), declaration))
    }
}

pub(crate) struct Cache {
    files: HashMap<String, Arc<CachedFile>>,
    /// Resolves an include as written in a parent AST to its feed-relative path.
    include_paths: HashMap<IncludeKey, String>,
    builtin_fns: HashSet<String>,
    predefined_vars: HashSet<String>,
}

#[derive(Eq, Hash, PartialEq)]
struct IncludeKey {
    parent_path: String,
    include_path: String,
}

impl IncludeKey {
    fn new(parent_path: &str, include_path: &str) -> Self {
        Self {
            parent_path: parent_path.to_owned(),
            include_path: include_path.to_owned(),
        }
    }
}

impl Default for Cache {
    fn default() -> Self {
        let executor = nasl_std_executor();
        let builtin_fns = builtin_fns(&executor);
        let predefined_vars = predefined_vars(&executor);
        Self {
            files: HashMap::new(),
            include_paths: HashMap::new(),
            builtin_fns,
            predefined_vars,
        }
    }
}

impl Cache {
    pub(crate) fn clear_files(&mut self) {
        self.files.clear();
        self.include_paths.clear();
    }

    pub(crate) fn insert(&mut self, rel_path: &str, file: Arc<CachedFile>) {
        self.files.insert(rel_path.to_owned(), file);
    }

    pub(crate) fn files(&self) -> impl Iterator<Item = (&str, &CachedFile)> {
        self.files
            .iter()
            .map(|(path, file)| (path.as_str(), file.as_ref()))
    }

    pub(crate) fn file(&self, path: &str) -> Option<&CachedFile> {
        self.files.get(path).map(Arc::as_ref)
    }

    pub(crate) fn record_include(
        &mut self,
        parent_path: &str,
        include_path: &str,
        resolved_path: &str,
    ) {
        self.include_paths.insert(
            IncludeKey::new(parent_path, include_path),
            resolved_path.to_owned(),
        );
    }

    pub(crate) fn included_path(&self, parent_path: &str, include_path: &str) -> Option<&str> {
        self.include_paths
            .get(&IncludeKey::new(parent_path, include_path))
            .map(String::as_str)
    }

    pub(crate) fn included_file(
        &self,
        parent_path: &str,
        include_path: &str,
    ) -> Option<(&str, &CachedFile)> {
        let path = self.included_path(parent_path, include_path)?;
        self.file(path).map(|file| (path, file))
    }

    pub(crate) fn predefined_vars(&self) -> impl Iterator<Item = &str> {
        self.predefined_vars.iter().map(String::as_str)
    }
}

pub(crate) struct LintCtx<'a> {
    pub cache: &'a mut Cache,
    pub ast: &'a Ast,
    pub file: &'a SourceFile,
}

impl<'a> LintCtx<'a> {
    pub fn new(ast: &'a Ast, file: &'a SourceFile, cache: &'a mut Cache) -> Self {
        Self { cache, ast, file }
    }

    pub fn fn_defined(&self, fn_name: &str) -> bool {
        self.cache
            .files
            .values()
            .any(|file| file.fns.contains_key(fn_name))
    }

    pub(crate) fn builtin_defined(&self, fn_name: &str) -> bool {
        self.cache.builtin_fns.contains(fn_name)
    }
}

#[derive(Default)]
pub(crate) struct FnDefinitionCollector {
    pub functions: HashMap<String, FnDecl>,
}

impl<'ast> Visitor<'ast> for FnDefinitionCollector {
    fn visit_fn_decl(&mut self, decl: &'ast FnDecl) {
        let fn_name = decl.fn_name.to_string();
        self.functions
            .entry(fn_name)
            .or_insert_with(|| decl.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_compat_builtins_are_not_in_rust_executor() {
        let executor = nasl_std_executor();
        let executor_builtins = executor.iter().collect::<HashSet<_>>();

        for name in C_COMPAT_BUILTINS {
            assert!(
                !executor_builtins.contains(name),
                "C-compatible builtin `{name}` is already registered by the Rust executor"
            );
        }
    }
}

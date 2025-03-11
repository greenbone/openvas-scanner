use std::path::Path;

use codespan_reporting::files::SimpleFiles;

pub fn read_single_files(file_name: &Path, code: &str) -> (SimpleFiles<String, String>, usize) {
    let mut files = SimpleFiles::new();
    let file_id = files.add(
        file_name.as_os_str().to_string_lossy().to_string(),
        code.to_owned(),
    );
    (files, file_id)
}

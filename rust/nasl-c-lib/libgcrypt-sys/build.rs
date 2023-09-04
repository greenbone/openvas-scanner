use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=install_lib.sh");
    let out = Command::new("sh").arg("install_lib.sh").output();
    match out {
        Ok(out) => {
            if let Some(status) = out.status.code() {
                panic!(
                    "Script exited with {status}:\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
        Err(e) => panic!("Unexpected error: {e}"),
    }
}

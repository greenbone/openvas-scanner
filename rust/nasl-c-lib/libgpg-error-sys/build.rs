use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=install_lib.sh");

    if let Some(status) = Command::new("sh")
        .arg("install_lib.sh")
        .output()
        .unwrap()
        .status
        .code()
    {
        if status != 0 {
            panic!("Unable to run script: exit code {}", status);
        }
    }
}

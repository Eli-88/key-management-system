extern crate cc;

use std::env;

fn main() {
    match env::var("CARGO_CFG_TARGET_OS") {
        Ok(target_os) => match target_os.as_str() {
            "macos" => {
                println!("cargo:rustc-link-lib=framework=CoreFoundation");
                println!("cargo:rerun-if-changed=build.rs");
                println!("cargo:rustc-link-lib=framework=Security");

                cc::Build::new()
                    .file("src/kms_core.c")
                    .compile("kms_core");
            }
            _ => panic!("Unsupported OS"),
        }
        _ => {
            panic!("Target OS not found");
        }
    }
}
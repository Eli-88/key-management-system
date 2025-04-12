extern crate cc;

use std::env;

fn main() {
    let Ok(target_os) = env::var("CARGO_CFG_TARGET_OS") else {
        panic!("Target OS not found");
    };

    match target_os.as_str() {
        "macos" => {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rerun-if-changed=build.rs");
            println!("cargo:rustc-link-lib=framework=Security");

            cc::Build::new()
                .files(["src/kms_core.c", "src/kms_core_mac.c"])
                .compile("kms_core");
        }
        "linux" => {
            println!("cargo:rerun-if-changed=build.rs");

            cc::Build::new()
                .files(["src/kms_core.c", "src/kms_core_linux.c"])
                .compile("kms_core");

            println!("cargo:rustc-link-lib=ssl");
            println!("cargo:rustc-link-lib=crypto");
        }
        _ => panic!("Unsupported OS"),
    }
}

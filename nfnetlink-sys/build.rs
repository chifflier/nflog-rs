extern crate pkg_config;
extern crate cc;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap();
    if !target.contains("linux") {
        panic!("libnfnetlink can only be built for linux");
    }

    if !cfg!(feature = "static-nfnetlink") {
        if try_pkg_config() {
            return;
        }
    }

    if !Path::new("src/libnfnetlink/.git").exists() {
        let _ = Command::new("git").args(&["submodule", "update", "--init"])
            .status();
    }

    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let include = dst.join("include");
    let build = dst.join("build");
    let src = Path::new("src/libnfnetlink/src");
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}", include.display());
    println!("cargo:static=1");
    fs::create_dir_all(include.join("libnfnetlink")).unwrap();
    fs::copy("src/libnfnetlink/include/libnfnetlink/libnfnetlink.h", include.join("libnfnetlink/libnfnetlink.h")).unwrap();
    fs::copy("src/libnfnetlink/include/libnfnetlink/linux_nfnetlink.h", include.join("libnfnetlink/linux_nfnetlink.h")).unwrap();
    fs::copy("src/libnfnetlink/include/libnfnetlink/linux_nfnetlink_compat.h", include.join("libnfnetlink/linux_nfnetlink_compat.h")).unwrap();

    let mut cfg = cc::Build::new();
    cfg.out_dir(&build)
        .warnings(false)
        .include(&include)
        .include("src/libnfnetlink/include")
        .flag("-fvisibility=hidden")
        .define("NFNL_EXPORT", "__attribute__((visibility(\"default\")))")
        .file(src.join("libnfnetlink.c"))
        .file(src.join("iftable.c"))
        .file(src.join("rtnl.c"));

    cfg.compile("nfnetlink");
}

fn try_pkg_config() -> bool {
    pkg_config::probe_library("libnfnetlink").is_ok()
}

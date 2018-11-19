extern crate cc;
extern crate pkg_config;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap();
    if !target.contains("linux") {
        panic!("nflog can only be built for linux");
    }

    if !cfg!(feature = "static-nflog") {
        if try_pkg_config() {
            return;
        }
    }

    if !Path::new("src/libnetfilter_log/.git").exists() {
        let _ = Command::new("git")
            .args(&["submodule", "update", "--init"])
            .status();
    }

    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let include = dst.join("include");
    let build = dst.join("build");
    let src = Path::new("src/libnetfilter_log/src");
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}", include.display());
    println!("cargo:static=1");
    fs::create_dir_all(include.join("libnetfilter_log")).unwrap();
    fs::copy(
        "src/libnetfilter_log/include/libnetfilter_log/libnetfilter_log.h",
        include.join("libnetfilter_log/libnetfilter_log.h"),
    ).unwrap();
    fs::copy(
        "src/libnetfilter_log/include/libnetfilter_log/linux_nfnetlink_log.h",
        include.join("libnetfilter_log/linux_nfnetlink_log.h"),
    ).unwrap();

    let mut cfg = cc::Build::new();
    cfg.out_dir(&build)
        .flag("-lnfnetlink")
        .warnings(false)
        .include(&include)
        .file(src.join("libnetfilter_log.c"));

    if let Some(nfnetlink_include) = env::var_os("DEP_NFNETLINK_INCLUDE") {
        cfg.include(nfnetlink_include);
    }

    cfg.compile("netfilter_log");
}

fn try_pkg_config() -> bool {
    pkg_config::probe_library("libnetfilter_log").is_ok()
}

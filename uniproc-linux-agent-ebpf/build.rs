use std::env;
use libbpf_cargo::SkeletonBuilder;
use std::path::PathBuf;

const SRC: &str = "src/prog.bpf.c";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-Isrc"])
        .build_and_generate(&out_dir.join("prog.skel.rs"))
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/maps.h");
    println!("cargo:rerun-if-changed=src/constants.h");
    println!("cargo:rerun-if-changed=src/utils.h");
    println!("cargo:rerun-if-changed=src/sockets.h");
    println!("cargo:rerun-if-changed=src/disk.h");
    println!("cargo:rerun-if-changed=src/processes.h");
    println!("cargo:rerun-if-changed=src/globals.h");
}
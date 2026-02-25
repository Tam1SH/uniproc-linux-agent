use std::env;
use std::path::PathBuf;
use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "../uniproc-linux-agent-ebpf/src/prog.bpf.c";
fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-I../uniproc-linux-agent-ebpf/src"])
        .build_and_generate(&out_dir.join("prog.skel.rs"))
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
}

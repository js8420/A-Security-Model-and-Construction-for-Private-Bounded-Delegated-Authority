fn main() {
    println!("cargo:rerun-if-changed=../../src");
    sp1_build::build_program("../program-keccak");
}

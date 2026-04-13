use std::path::PathBuf;

fn main() {
    let proto = PathBuf::from("../../proto/anthill.proto");
    let include = PathBuf::from("../../proto");

    prost_build::Config::new()
        .compile_protos(&[&proto], &[&include])
        .expect("protobuf compilation failed");
}

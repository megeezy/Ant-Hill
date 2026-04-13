use std::path::PathBuf;

fn main() {
    let proto = PathBuf::from("../protocol/anthill.proto");
    let include = PathBuf::from("../protocol");

    prost_build::Config::new()
        .compile_protos(&[&proto], &[&include])
        .expect("protobuf compilation failed");
}

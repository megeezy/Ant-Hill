// Proto-generated code is placed here by build.rs.
// Re-export everything from the generated module.

#[allow(clippy::all)]
pub mod anthill {
    pub mod v1 {
        use prost;
        include!(concat!(env!("OUT_DIR"), "/anthill.v1.rs"));
    }
}

pub use anthill::v1::*;

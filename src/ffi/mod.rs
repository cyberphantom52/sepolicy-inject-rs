use cxx::UniquePtr;
pub use ffi::*;

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("sepolicy-inject-rs/src/ffi/sepolicy.hpp");

        type SePolicyImpl;

        fn from_file_impl(path: &str) -> UniquePtr<SePolicyImpl>;
    }
}

pub struct SePolicy {
    inner: UniquePtr<ffi::SePolicyImpl>,
}

impl SePolicy {}

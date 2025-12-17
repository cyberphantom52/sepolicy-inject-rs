use cxx::UniquePtr;
use std::path::Path;

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

impl SePolicy {
    /// Load policy from a file
    pub fn from_file(path: impl AsRef<Path>) -> Option<Self> {
        let path_str = path
            .as_ref()
            .to_str()
            .expect("path contains invalid UTF-8 characters");
        let inner = ffi::from_file_impl(path_str);
        if inner.is_null() {
            None
        } else {
            Some(SePolicy { inner })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn integration_from_file_opens_policy() {
        // Prefer env var so CI can inject the right path.
        let path = fixture_path("precompiled_sepolicy");
        assert!(
            path.exists(),
            "precompiled sepolicy file does not exist: {}",
            path.display()
        );

        let _ = SePolicy::from_file(path).expect("failed to load precompiled sepolicy");
    }
}

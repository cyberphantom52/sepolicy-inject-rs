use cxx::UniquePtr;
use std::path::Path;

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("sepolicy-inject-rs/src/ffi/sepolicy.hpp");

        type SePolicyImpl;

        fn from_file_impl(path: &str) -> UniquePtr<SePolicyImpl>;

        fn attributes_impl(impl_: &SePolicyImpl) -> Vec<String>;
        fn types_impl(impl_: &SePolicyImpl) -> Vec<String>;
        fn type_transitions_impl(impl_: &SePolicyImpl) -> Vec<String>;
        fn genfs_ctx_impl(impl_: &SePolicyImpl) -> Vec<String>;
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

    fn attributes(&self) -> Vec<String> {
        ffi::attributes_impl(&self.inner)
    }

    fn types(&self) -> Vec<String> {
        ffi::types_impl(&self.inner)
    }

    fn avtabs(&self) -> Vec<String> {
        todo!()
    }

    fn transitions(&self) -> Vec<String> {
        ffi::type_transitions_impl(&self.inner)
    }

    fn genfs_contexts(&self) -> Vec<String> {
        ffi::genfs_ctx_impl(&self.inner)
    }

    pub fn rules(&self) -> Vec<String> {
        let mut out = Vec::new();

        out.extend(self.attributes());
        out.extend(self.types());
        // out.extend(self.avtabs());
        out.extend(self.transitions());
        out.extend(self.genfs_contexts());

        out
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

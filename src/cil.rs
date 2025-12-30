use std::path::Path;

use crate::ffi::{CilPolicy, cil_new_impl};

impl CilPolicy {
    /// Create a new empty CIL policy
    pub fn new() -> Self {
        let inner = cil_new_impl();
        CilPolicy { inner }
    }

    /// Add a CIL file to the policy
    ///
    /// # Panics
    /// Panics if the file cannot be loaded or added to the policy.
    pub fn add_file(mut self, path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let path_str = path
            .as_ref()
            .to_str()
            .expect("path contains invalid UTF-8 characters");
        if !self.inner.pin_mut().add_file(path_str) {
            return Err(format!("failed to add CIL file: {}", path.as_ref().display()).into());
        }
        Ok(self)
    }
}

use std::path::Path;

use crate::{
    SePolicy,
    ffi::{CilPolicy, cil_new_impl},
};

impl CilPolicy {
    /// Create a new empty CIL policy
    pub fn new() -> Self {
        let inner = cil_new_impl();
        CilPolicy { inner }
    }

    /// Compile the loaded CIL database into a [`SePolicy`].
    pub fn compile(&mut self) -> Result<SePolicy, Box<dyn std::error::Error>> {
        let inner = self.inner.pin_mut().compile();

        if inner.is_null() {
            return Err(format!("failed to compile CIL into a sepolicy").into());
        }

        Ok(SePolicy { inner })
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

    /// Compile an ordered list of CIL files directly into a [`SePolicy`].
    ///
    /// Files are added to the underlying CIL database in the exact order they
    /// are yielded by the iterator.
    pub fn compile_split<P, I>(paths: I) -> Result<SePolicy, Box<dyn std::error::Error>>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let mut policy = Self::new();

        for path in paths {
            policy = policy.add_file(path)?;
        }

        policy.compile()
    }
}

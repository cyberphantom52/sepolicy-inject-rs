use std::error::Error;
use std::path::Path;

use crate::ffi::{CilPolicy, SePolicy, cil_new_impl};

type DynError = Box<dyn Error>;

fn invalid_input(message: impl Into<String>) -> DynError {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into()).into()
}

fn other(message: impl Into<String>) -> DynError {
    std::io::Error::new(std::io::ErrorKind::Other, message.into()).into()
}

fn path_to_str(path: &Path) -> Result<&str, DynError> {
    path.to_str().ok_or_else(|| {
        invalid_input(format!(
            "path contains invalid UTF-8 characters: {}",
            path.display()
        ))
    })
}

impl Default for CilPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl CilPolicy {
    /// Create a new empty CIL policy.
    pub fn new() -> Self {
        let inner = cil_new_impl();
        CilPolicy { inner }
    }

    /// Create a new CIL policy loaded from a single file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, DynError> {
        Self::new().add_file(path)
    }

    /// Compile a single CIL file directly into a [`SePolicy`].
    pub fn compile_file(path: impl AsRef<Path>) -> Result<SePolicy, DynError> {
        let mut policy = Self::from_file(path)?;
        policy.compile()
    }

    /// Convenience helper to load a single CIL file and extract all statements
    /// related to `label`.
    pub fn extract_label_from_file(
        path: impl AsRef<Path>,
        label: &str,
    ) -> Result<Vec<String>, DynError> {
        let mut policy = Self::from_file(path)?;
        policy.extract_label(label)
    }

    /// Add a CIL file to the policy and return the updated builder.
    pub fn add_file(mut self, path: impl AsRef<Path>) -> Result<Self, DynError> {
        self.add_file_mut(path)?;
        Ok(self)
    }

    /// Add a CIL file to the policy in place.
    pub fn add_file_mut(&mut self, path: impl AsRef<Path>) -> Result<(), DynError> {
        let path_ref = path.as_ref();
        let path_str = path_to_str(path_ref)?;

        if !self.inner.pin_mut().add_file(path_str) {
            return Err(other(format!(
                "failed to add CIL file: {}",
                path_ref.display()
            )));
        }

        Ok(())
    }

    /// Compile the loaded CIL database into a [`SePolicy`].
    pub fn compile(&mut self) -> Result<SePolicy, DynError> {
        let inner = self.inner.pin_mut().compile();
        if inner.is_null() {
            return Err(other("failed to compile CIL into a sepolicy"));
        }

        Ok(SePolicy { inner })
    }

    /// Extract all rendered CIL AST statements related to `label`.
    ///
    /// The returned strings are produced from libsepol's CIL AST and may include
    /// source location prefixes when available. If no matching statements are
    /// found, an empty vector is returned.
    pub fn extract_label(&mut self, label: &str) -> Result<Vec<String>, DynError> {
        let label = label.trim();
        if label.is_empty() {
            return Err(invalid_input("label must not be empty"));
        }

        Ok(self.inner.pin_mut().extract_label(label))
    }
}

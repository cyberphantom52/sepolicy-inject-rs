use std::path::Path;

use crate::{
    SePolicy,
    ffi::{CilPolicy, cil_new_impl},
    parser::{ToCil, ast::Policy},
};

impl CilPolicy {
    /// Create a new empty CIL policy
    pub fn new() -> Self {
        let inner = cil_new_impl();
        CilPolicy { inner }
    }

    /// Create a new CIL policy seeded from a single file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let source = std::fs::read_to_string(path.as_ref())?;
        Self::new().add_file(&source)
    }

    /// Compile the loaded CIL database into a [`SePolicy`].
    pub fn compile(&mut self) -> Result<SePolicy, Box<dyn std::error::Error>> {
        let inner = self.inner.pin_mut().compile();

        if inner.is_null() {
            return Err(format!("failed to compile CIL into a sepolicy").into());
        }

        Ok(SePolicy { inner })
    }

    /// Add CIL source text to the policy database.
    pub fn add_file(mut self, source: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if !self.inner.pin_mut().add_file(source) {
            return Err("failed to add CIL source".into());
        }
        Ok(self)
    }

    /// Render a parsed TE policy into CIL and add it to the policy database.
    pub fn add_policy(self, policy: &Policy) -> Result<Self, Box<dyn std::error::Error>> {
        let rendered = match policy.to_cil() {
            Some(rendered) => rendered,
            None => {
                return Err("failed to render policy patch into CIL".into());
            }
        };

        if rendered.is_empty() {
            return Err("rendered policy patch is empty".into());
        }

        let source = rendered.join("\n");
        self.add_file(&source)
    }

    /// Write the loaded CIL database back out as merged CIL source.
    pub fn write(&mut self, path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
        let path_str = path
            .as_ref()
            .to_str()
            .expect("path contains invalid UTF-8 characters");
        if !self.inner.pin_mut().write(path_str) {
            return Err(format!("failed to write CIL file: {}", path.as_ref().display()).into());
        }
        Ok(())
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
            let source = std::fs::read_to_string(path.as_ref())?;
            policy = policy.add_file(&source)?;
        }

        policy.compile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn cil_fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("selinux")
            .join("libsemanage")
            .join("tests")
            .join(name)
    }

    struct TempOutput {
        path: PathBuf,
    }

    impl TempOutput {
        fn new(stem: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos();

            let path = std::env::temp_dir().join(format!(
                "sepolicy-inject-rs-{}-{}-{}.cil",
                stem,
                std::process::id(),
                unique
            ));

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempOutput {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn test_single_file_cil_patch_writes_rendered_patch() {
        let source = cil_fixture_path("test_handle.cil");
        let patch = crate::parser::parse(
            "attribute cil_patch_test_attr;\ntype cil_patch_test_t, cil_patch_test_attr;\nallow cil_patch_test_t self:test_class test_perm;",
        )
        .expect("failed to parse TE patch");
        let output = TempOutput::new("single-file-cil-patch-write");

        let mut policy = CilPolicy::from_file(&source)
            .expect("failed to load base CIL fixture")
            .add_policy(&patch)
            .expect("failed to apply TE patch to CIL");

        policy
            .write(output.path())
            .expect("failed to write merged CIL policy");

        let written =
            std::fs::read_to_string(output.path()).expect("failed to read merged CIL output");

        assert!(
            written.contains("(typeattribute cil_patch_test_attr)"),
            "patched CIL output should contain the new attribute declaration"
        );
        assert!(
            written.contains("(type cil_patch_test_t)"),
            "patched CIL output should contain the new type declaration"
        );
        assert!(
            written.contains("(typeattributeset cil_patch_test_attr (cil_patch_test_t))"),
            "patched CIL output should contain the rendered typeattribute link"
        );
        assert!(
            written.contains("(allow cil_patch_test_t self (test_class (test_perm)))"),
            "patched CIL output should contain the rendered allow rule"
        );
    }

    #[test]
    fn test_single_file_cil_patch_output_recompiles() {
        let source = cil_fixture_path("test_handle.cil");
        let patch = crate::parser::parse(
            "attribute cil_patch_recompile_attr;\ntype cil_patch_recompile_t, cil_patch_recompile_attr;\nallow cil_patch_recompile_t self:test_class test_perm;",
        )
        .expect("failed to parse TE patch");
        let output = TempOutput::new("single-file-cil-patch-recompile");

        let mut policy = CilPolicy::from_file(&source)
            .expect("failed to load base CIL fixture")
            .add_policy(&patch)
            .expect("failed to apply TE patch to CIL");

        policy
            .write(output.path())
            .expect("failed to write merged CIL policy");

        let compiled = CilPolicy::compile_split(std::iter::once(output.path()))
            .expect("failed to recompile patched CIL output");

        let types = compiled.types();
        assert!(
            types.iter().any(|line| {
                line.contains("cil_patch_recompile_t") && line.contains("cil_patch_recompile_attr")
            }),
            "recompiled policy should contain the patched type and attribute mapping"
        );

        let avtabs = compiled.avtabs();
        assert!(
            avtabs.iter().any(|rule| {
                rule.starts_with("allow cil_patch_recompile_t cil_patch_recompile_t test_class")
                    && rule.contains("test_perm")
            }),
            "recompiled policy should contain the patched allow rule"
        );
    }
}

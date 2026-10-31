use std::path::Path;
use std::pin::Pin;

use cxx::UniquePtr;

use crate::{
    SePolicy,
    error::{Error, Result, read_to_string},
    ffi::{CilPolicyImpl, cil_new_impl},
    lock,
    parser::{ToCil, ast::Policy},
};

/// A CIL policy database that sources are added to before validating,
/// writing, or compiling it.
///
/// # Thread safety
///
/// Every call that reaches libsepol takes a crate-wide lock, so separate
/// instances can be used from different threads at the same time. A
/// `CilPolicy` itself is neither `Send` nor `Sync`: create it on the thread that
/// uses it.
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<sepolicy::CilPolicy>();
/// ```
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<sepolicy::CilPolicy>();
/// ```
pub struct CilPolicy {
    inner: UniquePtr<CilPolicyImpl>,
}

impl CilPolicy {
    /// Create a new empty CIL policy
    pub fn new() -> Self {
        let _guard = lock::libsepol();
        let inner = cil_new_impl();
        CilPolicy { inner }
    }

    /// Run `f` against the database while holding the libsepol lock.
    fn with<R>(&self, f: impl FnOnce(&CilPolicyImpl) -> R) -> R {
        let _guard = lock::libsepol();
        f(&self.inner)
    }

    /// Run `f` against the mutable database while holding the libsepol lock.
    fn with_mut<R>(&mut self, f: impl FnOnce(Pin<&mut CilPolicyImpl>) -> R) -> R {
        let _guard = lock::libsepol();
        f(self.inner.pin_mut())
    }

    /// Create a new CIL policy seeded from a single file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_files(std::iter::once(path))
    }

    /// Create a new CIL policy seeded from an ordered list of files.
    ///
    /// Files are loaded in the exact order they are yielded by the iterator.
    /// This is useful for validation where a patched single-file CIL needs
    /// extra context from other CIL files.
    pub fn from_files<P, I>(paths: I) -> Result<Self>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let mut policy = Self::new();

        for path in paths {
            let source = read_to_string(path.as_ref())?;
            policy = policy.add_file(&source)?;
        }

        Ok(policy)
    }

    /// Validate the loaded CIL database by building and resolving its AST.
    pub fn validate(&mut self) -> Result<()> {
        if !self.with_mut(|p| p.validate()) {
            return Err(Error::CilValidate);
        }

        Ok(())
    }

    /// Compile the loaded CIL database into a [`SePolicy`].
    pub fn compile(&mut self) -> Result<SePolicy> {
        SePolicy::from_impl(self.with_mut(|p| p.compile())).ok_or(Error::CilCompile)
    }

    /// Add CIL source text to the policy database.
    pub fn add_file(mut self, source: &str) -> Result<Self> {
        if !self.with_mut(|p| p.add_file(source)) {
            return Err(Error::CilAdd);
        }
        Ok(self)
    }

    /// Render a parsed TE policy into CIL and add it to the policy database.
    pub fn add_policy(self, policy: &Policy) -> Result<Self> {
        let rendered = policy.to_cil().ok_or(Error::CilRender)?;

        if rendered.is_empty() {
            return Err(Error::EmptyPatch);
        }

        let source = rendered.join("\n");
        self.add_file(&source)
    }

    /// Render the loaded CIL database as merged CIL source.
    pub fn to_cil(&self) -> Result<String> {
        let mut out = String::new();
        if !self.with(|p| p.to_cil(&mut out)) {
            return Err(Error::CilSerialize);
        }
        Ok(out)
    }

    /// Write the loaded CIL database back out as merged CIL source.
    pub fn write(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        std::fs::write(path, self.to_cil()?).map_err(|source| Error::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Validate an ordered list of CIL files by building and resolving their
    /// combined AST.
    pub fn validate_files<P, I>(paths: I) -> Result<()>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let mut policy = Self::from_files(paths)?;
        policy.validate()
    }

    /// Compile an ordered list of CIL files directly into a [`SePolicy`].
    ///
    /// Files are added to the underlying CIL database in the exact order they
    /// are yielded by the iterator.
    pub fn compile_split<P, I>(paths: I) -> Result<SePolicy>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let mut policy = Self::from_files(paths)?;
        policy.compile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ast::GenfsFileType;
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
            .expect("failed to apply TE patch to CIL")
            // Retain the attribute so the compiler does not optimize away the mapping under test.
            .add_file("(expandtypeattribute (cil_patch_recompile_attr) false)")
            .expect("failed to retain test attribute");

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
            "recompiled policy should contain the patched type and attribute mapping: {types:?}"
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

    #[test]
    fn test_operations_are_repeatable_on_one_policy() {
        let source = cil_fixture_path("test_handle.cil");
        let patch = crate::parser::parse(
            "type cil_repeat_t;\nallow cil_repeat_t self:test_class test_perm;",
        )
        .expect("failed to parse TE patch");
        let output = TempOutput::new("repeatable-operations");

        // validate, write and compile each consume libsepol's parse tree, so
        // every step after the first used to dereference a destroyed tree.
        let mut policy = CilPolicy::from_file(&source)
            .expect("failed to load base CIL fixture")
            .add_policy(&patch)
            .expect("failed to apply TE patch to CIL");

        policy.validate().expect("first validate failed");
        policy
            .write(output.path())
            .expect("write after validate failed");

        let mut policy = policy
            .add_file("(type cil_repeat_extra_t)\n(roletype object_r cil_repeat_extra_t)")
            .expect("add_file after write failed");
        policy.validate().expect("validate after add_file failed");

        for _ in 0..2 {
            let compiled = policy.compile().expect("compile failed");
            assert!(
                compiled
                    .avtabs()
                    .iter()
                    .any(|rule| rule.starts_with("allow cil_repeat_t cil_repeat_t test_class")),
                "compiled policy should contain the patched allow rule"
            );
        }

        let written =
            std::fs::read_to_string(output.path()).expect("failed to read merged CIL output");
        assert!(
            written.contains("(type cil_repeat_t)"),
            "merged CIL output should contain the patched type"
        );
    }

    #[test]
    fn test_to_cil_is_repeatable() {
        let source = cil_fixture_path("test_handle.cil");
        let patch = crate::parser::parse("type cil_to_cil_t;").expect("failed to parse TE patch");

        let policy = CilPolicy::from_file(&source)
            .expect("failed to load base CIL fixture")
            .add_policy(&patch)
            .expect("failed to apply TE patch to CIL");

        // Rendering consumes libsepol's parse tree, so a second render used to
        // dereference a destroyed tree.
        let rendered = policy.to_cil().expect("failed to render CIL");
        assert!(
            rendered.contains("(type cil_to_cil_t)"),
            "rendered CIL should contain the patched type"
        );
        assert_eq!(
            rendered,
            policy.to_cil().expect("failed to render CIL twice"),
            "rendering should be repeatable"
        );
    }

    #[test]
    fn test_to_cil_round_trips_through_compile() {
        let source = cil_fixture_path("test_handle.cil");
        let patch = crate::parser::parse(
            "type cil_round_trip_t;\nallow cil_round_trip_t self:test_class test_perm;",
        )
        .expect("failed to parse TE patch");

        let rendered = CilPolicy::from_file(&source)
            .expect("failed to load base CIL fixture")
            .add_policy(&patch)
            .expect("failed to apply TE patch to CIL")
            .to_cil()
            .expect("failed to render CIL");

        let compiled = CilPolicy::new()
            .add_file(&rendered)
            .expect("rendered CIL should parse")
            .compile()
            .expect("rendered CIL should compile");

        assert!(
            compiled
                .avtabs()
                .iter()
                .any(|rule| rule.starts_with("allow cil_round_trip_t cil_round_trip_t test_class")),
            "compiled policy should contain the patched allow rule"
        );
    }

    #[test]
    fn test_contexts_render_as_valid_cil_levelranges() {
        let source = cil_fixture_path("test_handle.cil");
        // Categories and a user whose range covers them.
        let mls = "(category c0)\n(category c1)\n(category c2)\n(categoryorder (c0 c1 c2))\n\
                   (sensitivitycategory s0 (range c0 c2))\n(user mls_u)\n(userrole mls_u object_r)\n\
                   (userlevel mls_u (s0))\n(userrange mls_u ((s0) (s0 (range c0 c2))))";
        let mut policy = CilPolicy::from_file(&source)
            .expect("failed to load base CIL fixture")
            .add_file(mls)
            .expect("failed to add MLS declarations");
        for statement in [
            "genfscon sysfs /mls/single mls_u:object_r:test_t:s0",
            "genfscon sysfs /mls/range mls_u:object_r:test_t:s0-s0:c0.c2",
            "genfscon sysfs /mls/list mls_u:object_r:test_t:s0:c0,c1",
        ] {
            let patch = crate::parser::parse(statement).expect("failed to parse TE patch");
            policy = policy
                .add_policy(&patch)
                .expect("failed to apply TE patch to CIL");
        }

        policy.validate().expect("rendered contexts should resolve");
        let genfs = policy
            .compile()
            .expect("rendered contexts should compile")
            .genfs_contexts();

        for expected in [
            "genfscon sysfs /mls/single mls_u:object_r:test_t:s0",
            "genfscon sysfs /mls/range mls_u:object_r:test_t:s0-s0:c0.c2",
            "genfscon sysfs /mls/list mls_u:object_r:test_t:s0:c0,c1",
        ] {
            assert!(
                genfs.iter().any(|line| line == expected),
                "missing {expected:?} in {genfs:?}"
            );
        }
    }

    #[test]
    fn test_genfscon_file_types_render_as_cil_keywords() {
        let source = cil_fixture_path("test_handle.cil");
        let classes =
            "(class dir (getattr))\n(class file (getattr))\n(classorder (test_class dir file))";
        let patch = crate::parser::parse(
            "genfscon sysfs /typed/dir -d system_u:object_r:test_t:s0\n\
             genfscon sysfs /typed/file - - system_u:object_r:test_t:s0",
        )
        .expect("failed to parse TE patch");

        let mut policy = CilPolicy::from_file(&source)
            .expect("failed to load base CIL fixture")
            .add_file(classes)
            .expect("failed to add classes")
            .add_policy(&patch)
            .expect("failed to apply TE patch to CIL");

        let compiled = policy.compile().expect("typed genfscon should compile");
        let types: Vec<_> = compiled
            .genfs()
            .filter(|genfs| genfs.path.starts_with("/typed/"))
            .map(|genfs| (genfs.path.into_owned(), genfs.file_type))
            .collect();
        assert!(types.contains(&("/typed/dir".to_string(), Some(GenfsFileType::Dir))));
        assert!(types.contains(&("/typed/file".to_string(), Some(GenfsFileType::File))));
    }
}

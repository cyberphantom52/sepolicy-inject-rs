//! CIL policies: [`CilPolicy`], and reading CIL text without one.

use std::path::Path;
use std::pin::Pin;

use cxx::UniquePtr;

use crate::{
    SePolicy,
    error::{CilDiagnostic, CilError, Error, Result, read_to_string},
    ffi::{CilPolicyImpl, cil_new_impl},
    lock,
    parser::{ToCil, ast::Policy},
};

/// A CIL policy database that sources are added to before validating,
/// writing, or compiling it.
///
/// Each source is parsed once, when it is added. Cloning a policy is cheap:
/// the clone shares the parsed sources, so a base such as the platform policy
/// can be loaded once and each variant built on a clone of it.
///
/// ```no_run
/// # fn main() -> sepolicy::Result<()> {
/// use sepolicy::CilPolicy;
///
/// let base = CilPolicy::from_files(["plat_sepolicy.cil", "plat_pub_versioned.cil"])?;
/// for (name, patch) in [("a.cil", "(type a_t)"), ("b.cil", "(type b_t)")] {
///     let compiled = base.clone().add_file_named(name, patch)?.compile()?;
///     # drop(compiled);
/// }
/// # Ok(())
/// # }
/// ```
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

impl Clone for CilPolicy {
    /// A policy holding the same sources, sharing their parse trees.
    fn clone(&self) -> Self {
        CilPolicy {
            inner: self.with(|p| p.clone()),
        }
    }
}

impl Drop for CilPolicy {
    fn drop(&mut self) {
        // Freeing the parsed sources reaches libsepol.
        let _guard = lock::libsepol();
        drop(std::mem::replace(&mut self.inner, UniquePtr::null()));
    }
}

impl Default for CilPolicy {
    fn default() -> Self {
        Self::new()
    }
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
    /// extra context from other CIL files. Each file is added under its path,
    /// as given, which errors then name it by; a path given twice is added
    /// the second time under a generated name.
    pub fn from_files<P, I>(paths: I) -> Result<Self>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let mut policy = Self::new();

        for path in paths {
            let path = path.as_ref();
            let source = read_to_string(path)?;
            let name = path.display().to_string();
            policy = if policy.has_input(&name) {
                policy.add_file(&source)?
            } else {
                policy.add_file_named(&name, &source)?
            };
        }

        Ok(policy)
    }

    /// Validate the loaded CIL database by building and resolving its AST.
    pub fn validate(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if !self.with_mut(|p| p.validate(&mut errors)) {
            return Err(Error::CilValidate(self.diagnose(errors, None)));
        }

        Ok(())
    }

    /// Compile the loaded CIL database into a [`SePolicy`].
    ///
    /// On failure the error carries what libsepol reported, with the input,
    /// line and statement each message points at; see [`CilError`].
    pub fn compile(&mut self) -> Result<SePolicy> {
        let mut errors = Vec::new();
        let compiled = self.with_mut(|p| p.compile(&mut errors));
        SePolicy::from_impl(compiled).ok_or_else(|| Error::CilCompile(self.diagnose(errors, None)))
    }

    /// Add CIL source text to the policy database under a generated name,
    /// `input_<n>.cil`, numbered within this policy.
    pub fn add_file(self, source: &str) -> Result<Self> {
        let name = self.with(|p| p.next_name());
        self.add_file_named(&name, source)
    }

    /// Add CIL source text to the policy database under `name`.
    ///
    /// Errors from [`validate`](Self::validate) and [`compile`](Self::compile)
    /// name the input a failing statement came from, so a caller adding one
    /// input per patch can tell which patch broke the policy. Names must be
    /// unique within a policy.
    pub fn add_file_named(mut self, name: &str, source: &str) -> Result<Self> {
        if name.is_empty() || self.has_input(name) {
            return Err(Error::CilInputName(name.to_owned()));
        }
        if source.is_empty() {
            return Err(Error::CilAdd(CilError {
                diagnostics: vec![CilDiagnostic {
                    message: format!("CIL input {name} is empty"),
                    input: Some(name.to_owned()),
                    line: None,
                    statement: None,
                }],
            }));
        }

        let mut errors = Vec::new();
        if !self.with_mut(|p| p.add_file(name, source, &mut errors)) {
            return Err(Error::CilAdd(self.diagnose(errors, Some((name, source)))));
        }
        Ok(self)
    }

    /// Render a parsed TE policy into CIL and add it to the policy database
    /// under a generated name.
    pub fn add_policy(self, policy: &Policy) -> Result<Self> {
        let source = render_policy(policy)?;
        self.add_file(&source)
    }

    /// Render a parsed TE policy into CIL and add it to the policy database
    /// under `name`, as [`add_file_named`](Self::add_file_named) does.
    pub fn add_policy_named(self, name: &str, policy: &Policy) -> Result<Self> {
        let source = render_policy(policy)?;
        self.add_file_named(name, &source)
    }

    /// Whether an input called `name` is loaded.
    fn has_input(&self, name: &str) -> bool {
        self.with(|p| !p.source_text(name).is_empty())
    }

    /// Turn the error messages libsepol logged into a [`CilError`], locating
    /// each in the loaded inputs or in `pending`, an input being added.
    fn diagnose(&self, errors: Vec<String>, pending: Option<(&str, &str)>) -> CilError {
        let _guard = lock::libsepol();
        let text_of = |name: &str| -> Option<&str> {
            if let Some((pending_name, text)) = pending
                && pending_name == name
            {
                return Some(text);
            }
            std::str::from_utf8(self.inner.source_text(name))
                .ok()
                .filter(|text| !text.is_empty())
        };

        let diagnostics = errors
            .into_iter()
            .map(|message| {
                let located = locate(&message, |name| text_of(name).is_some())
                    .map(|(input, line)| (input.to_owned(), line));
                let Some((input, line)) = located else {
                    return CilDiagnostic {
                        message,
                        input: None,
                        line: None,
                        statement: None,
                    };
                };
                CilDiagnostic {
                    statement: text_of(&input).and_then(|text| statement_at(text, line)),
                    input: Some(input),
                    line: Some(line),
                    message,
                }
            })
            .collect();
        CilError { diagnostics }
    }

    /// Render the loaded CIL database as merged CIL source.
    pub fn to_cil(&self) -> Result<String> {
        let mut out = String::new();
        if !self.with(|p| p.to_cil(&mut out)) {
            return Err(Error::CilSerialize);
        }
        Ok(out)
    }

    /// The statements of the loaded CIL database that name `label`, rendered as
    /// CIL. A statement inside a `booleanif`, `tunableif` or `optional` is given
    /// with that whole block; a `typeattributeset` listing `label` among plain
    /// members is given as one that lists only `label`. No statement names it
    /// when the result is empty.
    pub fn extract_label(&self, label: &str) -> Result<Vec<String>> {
        let label = label.trim();
        let mut out = Vec::new();
        if label.is_empty() || !self.with(|p| p.extract_label(label, &mut out)) {
            return Err(Error::CilExtract(label.to_owned()));
        }
        Ok(out)
    }

    /// The types, attributes and type aliases the loaded sources declare, as
    /// written there. The sources are only parsed, not resolved, so one source
    /// of a split policy can be read without the rest.
    pub fn declared_types(&self) -> Result<std::collections::BTreeSet<String>> {
        let mut out = Vec::new();
        if !self.with(|p| p.declared_types(&mut out)) {
            return Err(Error::CilDeclarations);
        }
        Ok(out.into_iter().collect())
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

/// The types, attributes and type aliases CIL source text declares, as
/// written there.
///
/// The text is only parsed, not resolved, so it may name types it does not
/// declare. This is [`CilPolicy::declared_types`] for a single text, without
/// keeping a policy around.
///
/// ```
/// let declared = sepolicy::cil::declared_types(
///     "(type vendor_t)\n(typeattribute vendor_attr)\n(allow vendor_t other_t (file (read)))",
/// )?;
/// assert_eq!(declared.into_iter().collect::<Vec<_>>(), ["vendor_attr", "vendor_t"]);
/// # Ok::<(), sepolicy::Error>(())
/// ```
pub fn declared_types(text: &str) -> Result<std::collections::BTreeSet<String>> {
    CilPolicy::new().add_file(text)?.declared_types()
}

/// Render a TE policy into CIL source text.
fn render_policy(policy: &Policy) -> Result<String> {
    let rendered = policy.to_cil().ok_or(Error::CilRender)?;
    if rendered.is_empty() {
        return Err(Error::EmptyPatch);
    }
    Ok(rendered.join("\n"))
}

/// Find the input and line a libsepol message points at.
///
/// Statements are reported as `<message> at <input>:<line>`, followed by
/// ` from <file>:<line>` for each line marker around them, and syntax errors
/// as `<message> at line <line> of <input>`. Only names `is_input` accepts
/// count, so an ` at ` inside the message itself is skipped.
fn locate<'m>(message: &'m str, is_input: impl Fn(&str) -> bool) -> Option<(&'m str, u32)> {
    let found = |name: &'m str, line: &str| -> Option<(&'m str, u32)> {
        let line = line.parse().ok()?;
        is_input(name).then_some((name, line))
    };

    for (at, _) in message.match_indices(" at ") {
        let rest = &message[at + " at ".len()..];
        if let Some(rest) = rest.strip_prefix("line ")
            && let Some((line, name)) = rest.split_once(" of ")
            && let Some(found) = found(name, line)
        {
            return Some(found);
        }
        let rest = rest.split(" from ").next().unwrap_or(rest);
        if let Some((name, line)) = rest.rsplit_once(':')
            && let Some(found) = found(name, line)
        {
            return Some(found);
        }
    }
    None
}

/// The statement starting on the 1-based `line` of `text`: from the first
/// `(` on that line to its matching `)`. Falls back to the line itself when
/// the line opens no statement or the statement never closes, as with a
/// syntax error.
fn statement_at(text: &str, line: u32) -> Option<String> {
    let start = text
        .split_inclusive('\n')
        .take(usize::try_from(line).ok()?.checked_sub(1)?)
        .map(str::len)
        .sum::<usize>();
    let rest = text.get(start..)?;
    let line_text = rest.lines().next()?.trim();

    let fallback = || (!line_text.is_empty()).then(|| line_text.to_owned());
    let Some(open) = line_text.find('(') else {
        return fallback();
    };
    if line_text[..open].contains(';') {
        return fallback();
    }

    let rest = &rest[rest.find('(')?..];
    let mut depth = 0usize;
    let mut chars = rest.char_indices();
    while let Some((i, ch)) = chars.next() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[..=i].to_owned());
                }
            }
            '"' => {
                for (_, ch) in chars.by_ref() {
                    if ch == '"' {
                        break;
                    }
                }
            }
            ';' => {
                for (_, ch) in chars.by_ref() {
                    if ch == '\n' {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    fallback()
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
    fn test_to_cil_is_deterministic() {
        let source = cil_fixture_path("test_handle.cil");
        // Multi-member type sets go through a helper attribute, and permission
        // sets once came out in hash order.
        let patch = crate::parser::parse(
            "type det_a_t;\ntype det_b_t;\n\
             allow { det_a_t det_b_t } { det_b_t test_t }:test_class { test_perm open read write getattr map };",
        )
        .expect("failed to parse TE patch");

        let render = || {
            CilPolicy::from_file(&source)
                .expect("failed to load base CIL fixture")
                .add_policy(&patch)
                .expect("failed to apply TE patch to CIL")
                .to_cil()
                .expect("failed to render CIL")
        };

        let first = render();
        assert_eq!(first, render(), "rendering the same inputs twice differed");
        assert!(
            !first.contains(";;* lms"),
            "to_cil should not carry input markers:\n{first}"
        );
        assert!(
            first.contains("(getattr map open read test_perm write)"),
            "permission sets should render sorted:\n{first}"
        );
        assert!(
            first.contains("(typeattributeset base_typeattr_"),
            "the type sets should render through a helper attribute:\n{first}"
        );
    }

    #[test]
    fn test_to_cil_output_is_pinned() {
        // Exact bytes, so output that varies between processes or releases,
        // such as a hash-derived name, fails here rather than on a device.
        let patch = crate::parser::parse("allow { b_t a_t } c_t:file { write read };")
            .expect("failed to parse TE patch");
        let out = CilPolicy::new()
            .add_policy(&patch)
            .expect("failed to add patch")
            .to_cil()
            .expect("failed to render CIL");
        assert_eq!(
            out,
            "(typeattribute base_typeattr_11f50735ac8101a3)\n\
             (typeattributeset base_typeattr_11f50735ac8101a3 (a_t b_t))\n\
             (allow base_typeattr_11f50735ac8101a3 c_t (file (read write)))\n"
        );
    }

    #[test]
    fn test_to_cil_keeps_markers_from_the_sources() {
        let marked = ";;* lmx 7 vendor.te\n(type marked_t)\n;;* lme\n";
        let out = CilPolicy::new()
            .add_file(marked)
            .expect("failed to add marked source")
            .to_cil()
            .expect("failed to render CIL");
        assert_eq!(out, ";;* lmx 7 vendor.te\n(type marked_t)\n;;* lme\n");
    }

    #[test]
    fn test_compile_error_names_the_failing_statement() {
        let source = cil_fixture_path("test_handle.cil");
        let good =
            crate::parser::parse("type err_good_t;\nallow err_good_t self:test_class test_perm;")
                .expect("failed to parse TE patch");
        let bad = crate::parser::parse(
            "type err_bad_t;\nallow err_bad_t err_missing_t:test_class test_perm;",
        )
        .expect("failed to parse TE patch");

        let mut policy = CilPolicy::from_file(&source)
            .expect("failed to load base CIL fixture")
            .add_policy_named("good.te", &good)
            .expect("failed to add the good patch")
            .add_policy_named("bad.te", &bad)
            .expect("failed to add the bad patch");

        for result in [policy.compile().map(drop), policy.validate()] {
            let (Err(Error::CilCompile(error)) | Err(Error::CilValidate(error))) = result else {
                panic!("the policy should not resolve: {result:?}");
            };
            let location = error
                .location()
                .unwrap_or_else(|| panic!("no location in {error:?}"));
            assert_eq!(location.input.as_deref(), Some("bad.te"), "{error:?}");
            assert_eq!(location.line, Some(3), "{error:?}");
            assert_eq!(
                location.statement.as_deref(),
                Some("(allow err_bad_t err_missing_t (test_class (test_perm)))"),
                "{error:?}"
            );
            assert!(location.message.contains("bad.te:3"), "{error:?}");
        }
    }

    #[test]
    fn test_add_file_error_names_the_bad_line() {
        let err = CilPolicy::new()
            .add_file_named("syntax.cil", "(type ok_t)\n(type broken_t\n")
            .map(drop)
            .expect_err("an unclosed statement should not parse");
        let Error::CilAdd(error) = err else {
            panic!("unexpected error: {err:?}");
        };
        let location = error
            .location()
            .unwrap_or_else(|| panic!("no location in {error:?}"));
        assert_eq!(location.input.as_deref(), Some("syntax.cil"), "{error:?}");
    }

    #[test]
    fn test_input_names_must_be_unique() {
        let err = CilPolicy::new()
            .add_file_named("a.cil", "(type a_t)")
            .and_then(|p| p.add_file_named("a.cil", "(type b_t)"))
            .map(drop)
            .expect_err("a second input named a.cil should be refused");
        assert!(matches!(err, Error::CilInputName(name) if name == "a.cil"));
    }

    #[test]
    fn test_locate_reads_both_message_forms() {
        let known = |name: &str| matches!(name, "vendor.cil" | "dir with space/x.cil");
        assert_eq!(
            locate(
                "Failed to resolve allow statement at vendor.cil:12 from foo.te:3",
                known
            ),
            Some(("vendor.cil", 12))
        );
        assert_eq!(
            locate(
                "Open parenthesis without matching close at line 4 of dir with space/x.cil",
                known
            ),
            Some(("dir with space/x.cil", 4))
        );
        assert_eq!(locate("Name at other.cil:3 is unknown", known), None);
        assert_eq!(locate("Failed to resolve AST", known), None);
    }

    #[test]
    fn test_statement_at_spans_lines_and_skips_strings() {
        let text = "(type a_t)\n  (genfscon sysfs \"/a)b\"\n    ctx) ; trailing\n(type b_t)";
        assert_eq!(statement_at(text, 1).as_deref(), Some("(type a_t)"));
        assert_eq!(
            statement_at(text, 2).as_deref(),
            Some("(genfscon sysfs \"/a)b\"\n    ctx)")
        );
        assert_eq!(statement_at(text, 4).as_deref(), Some("(type b_t)"));
        assert_eq!(statement_at(text, 9), None);
    }

    #[test]
    fn test_clone_shares_a_base_between_variants() {
        let source = cil_fixture_path("test_handle.cil");
        let base = CilPolicy::from_file(&source).expect("failed to load base CIL fixture");
        let base_cil = base.to_cil().expect("failed to render base");

        let variant = |name: &str| {
            let patch = crate::parser::parse(&format!(
                "type {name}_t;\nallow {name}_t self:test_class test_perm;"
            ))
            .expect("failed to parse TE patch");
            base.clone()
                .add_policy_named(&format!("{name}.te"), &patch)
                .expect("failed to add the variant's patch")
        };

        let mut a = variant("clone_a");
        let mut b = variant("clone_b");
        let a_rules = a.compile().expect("variant a should compile").avtabs();
        let b_rules = b.compile().expect("variant b should compile").avtabs();

        let has = |rules: &[String], ty: &str| {
            rules
                .iter()
                .any(|rule| rule.starts_with(&format!("allow {ty} {ty} test_class")))
        };
        assert!(has(&a_rules, "clone_a_t") && !has(&a_rules, "clone_b_t"));
        assert!(has(&b_rules, "clone_b_t") && !has(&b_rules, "clone_a_t"));

        // The base is untouched, and still usable once its clones are gone.
        drop((a, b));
        assert_eq!(base.to_cil().expect("failed to render base"), base_cil);
        let mut base = base;
        base.compile().expect("the base should still compile");
    }

    #[test]
    fn test_clone_errors_name_inputs_of_the_base() {
        let base = CilPolicy::new()
            .add_file_named("base.cil", "(allow missing_t missing_t (file (read)))")
            .expect("failed to add base");
        let err = base
            .clone()
            .add_file_named("patch.cil", "(type patch_t)")
            .expect("failed to add patch")
            .validate()
            .expect_err("the base names undeclared types");
        let Error::CilValidate(error) = err else {
            panic!("unexpected error: {err:?}");
        };
        let location = error
            .location()
            .unwrap_or_else(|| panic!("no location in {error:?}"));
        assert_eq!(location.input.as_deref(), Some("base.cil"), "{error:?}");
        assert_eq!(location.line, Some(1), "{error:?}");
    }

    #[test]
    fn test_contexts_render_as_valid_cil_levelranges() {
        let source = cil_fixture_path("test_handle.cil");
        // Categories and a user whose range covers them.
        let mls = "(category c0)\n(category c1)\n(category c2)\n(categoryorder (c0 c1 c2))\n\
                   (sensitivitycategory s0 (range c0 c2))\n(user mls_u)\n(userrole mls_u object_r)\n\
                   (userlevel mls_u (s0))\n(userrange mls_u ((s0) (s0 (range c0 c2))))";
        // One multi-line patch: a category list once ran into the next line.
        let patch = crate::parser::parse(
            "genfscon sysfs /mls/single mls_u:object_r:test_t:s0\n\
             genfscon sysfs /mls/range mls_u:object_r:test_t:s0-s0:c0.c2\n\
             genfscon sysfs /mls/list mls_u:object_r:test_t:s0:c0,c1",
        )
        .expect("failed to parse TE patch");

        let mut policy = CilPolicy::from_file(&source)
            .expect("failed to load base CIL fixture")
            .add_file(mls)
            .expect("failed to add MLS declarations")
            .add_policy(&patch)
            .expect("failed to apply TE patch to CIL");

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

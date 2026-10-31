use std::borrow::Cow;
use std::path::Path;
use std::pin::Pin;

use cxx::UniquePtr;

use crate::error::{Error, Result, path_str};
use crate::ffi::{self, SePolicyImpl, XPerm};
use crate::lock;
use crate::parser::ast::*;
use crate::rules::{self, AvRule, AvtabRule, FilenameTransition, Genfs, TypeDecl, XpermRule};
use tracing::{debug, error, info, warn};

/// A binary SELinux policy database.
///
/// # Thread safety
///
/// Every call that reaches libsepol takes a crate-wide lock, so separate
/// instances can be used from different threads at the same time. A
/// `SePolicy` itself is neither `Send` nor `Sync`: create it on the thread that
/// uses it.
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<sepolicy::SePolicy>();
/// ```
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<sepolicy::SePolicy>();
/// ```
pub struct SePolicy {
    inner: UniquePtr<SePolicyImpl>,
}

impl SePolicy {
    /// Wrap a database returned by the C++ side; `None` if it is null.
    pub(crate) fn from_impl(inner: UniquePtr<SePolicyImpl>) -> Option<Self> {
        if inner.is_null() {
            None
        } else {
            Some(SePolicy { inner })
        }
    }

    /// Run `f` against the database while holding the libsepol lock.
    fn with<'s, R>(&'s self, f: impl FnOnce(&'s SePolicyImpl) -> R) -> R {
        let _guard = lock::libsepol();
        f(&self.inner)
    }

    /// The database for resolving names lazily, without the libsepol lock.
    ///
    /// Name lookups only read this policy's own name tables and run no
    /// libsepol code. Holding `&self` rules out concurrent mutation, and
    /// `SePolicy` is not `Sync`, so no other thread can reach this instance.
    fn names(&self) -> &SePolicyImpl {
        &self.inner
    }

    /// Run `f` against the mutable database while holding the libsepol lock.
    fn with_mut<R>(&mut self, f: impl FnOnce(Pin<&mut SePolicyImpl>) -> R) -> R {
        let _guard = lock::libsepol();
        f(self.inner.pin_mut())
    }

    /// Load policy from a file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let path_str = path_str(path)?;
        info!(path = %path_str, "Loading policy from file");
        let inner = {
            let _guard = lock::libsepol();
            ffi::from_file_impl(path_str)
        };
        if inner.is_null() {
            error!(path = %path_str, "Failed to load policy from file");
            Err(Error::LoadPolicy(path.to_path_buf()))
        } else {
            info!(path = %path_str, "Successfully loaded policy from file");
            Ok(SePolicy { inner })
        }
    }

    pub fn from_split() -> Result<Self> {
        info!("Loading policy from split (precompiled)");
        let inner = {
            let _guard = lock::libsepol();
            ffi::from_split_impl()
        };
        if inner.is_null() {
            error!("Failed to load policy from split");
            Err(Error::LoadSplit)
        } else {
            info!("Successfully loaded policy from split");
            Ok(SePolicy { inner })
        }
    }

    pub fn compile_split() -> Result<Self> {
        info!("Compiling policy from split CIL files");
        let inner = {
            let _guard = lock::libsepol();
            ffi::compile_split_impl()
        };
        if inner.is_null() {
            error!("Failed to compile policy from split");
            Err(Error::CompileSplit)
        } else {
            info!("Successfully compiled policy from split");
            Ok(SePolicy { inner })
        }
    }

    pub fn from_data(data: &[u8]) -> Result<Self> {
        info!(size = data.len(), "Loading policy from memory");
        let inner = {
            let _guard = lock::libsepol();
            ffi::from_data_impl(data)
        };
        if inner.is_null() {
            error!(size = data.len(), "Failed to load policy from memory");
            Err(Error::LoadPolicyData)
        } else {
            info!(size = data.len(), "Successfully loaded policy from memory");
            Ok(SePolicy { inner })
        }
    }

    /// Serialize the binary policy to a file
    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let path_str = path_str(path)?;
        if !self.with(|p| p.write(path_str)) {
            return Err(Error::WritePolicy(path.to_path_buf()));
        }
        Ok(())
    }

    pub fn allow(&mut self, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]) {
        self.with_mut(|p| p.allow(src, tgt, cls, perm));
    }

    pub fn deny(&mut self, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]) {
        self.with_mut(|p| p.deny(src, tgt, cls, perm));
    }

    pub fn auditallow(&mut self, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]) {
        self.with_mut(|p| p.auditallow(src, tgt, cls, perm));
    }

    pub fn dontaudit(&mut self, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]) {
        self.with_mut(|p| p.dontaudit(src, tgt, cls, perm));
    }

    pub fn allowxperm(&mut self, src: &[&str], tgt: &[&str], cls: &[&str], x_perm: &[XPerm]) {
        self.with_mut(|p| p.allowxperm(src, tgt, cls, x_perm));
    }

    pub fn auditallowxperm(&mut self, src: &[&str], tgt: &[&str], cls: &[&str], x_perm: &[XPerm]) {
        self.with_mut(|p| p.auditallowxperm(src, tgt, cls, x_perm));
    }

    pub fn dontauditxperm(&mut self, src: &[&str], tgt: &[&str], cls: &[&str], x_perm: &[XPerm]) {
        self.with_mut(|p| p.dontauditxperm(src, tgt, cls, x_perm));
    }

    pub fn permissive(&mut self, types: &[&str]) {
        self.with_mut(|p| p.permissive(types));
    }

    pub fn enforce(&mut self, types: &[&str]) {
        self.with_mut(|p| p.enforce(types));
    }

    pub fn typeattribute(&mut self, ty: &[&str], attrs: &[&str]) {
        self.with_mut(|p| p.typeattribute(ty, attrs));
    }

    pub fn type_(&mut self, ty: &str, attrs: &[&str]) {
        self.with_mut(|p| p.type_(ty, attrs));
    }

    pub fn attribute(&mut self, name: &str) {
        self.with_mut(|p| p.attribute(name));
    }

    pub fn type_transition(&mut self, src: &str, tgt: &str, cls: &str, dest: &str, obj: &str) {
        self.with_mut(|p| p.type_transition(src, tgt, cls, dest, obj));
    }

    pub fn type_change(&mut self, src: &str, tgt: &str, cls: &str, dest: &str) {
        self.with_mut(|p| p.type_change(src, tgt, cls, dest));
    }

    pub fn type_member(&mut self, src: &str, tgt: &str, cls: &str, dest: &str) {
        self.with_mut(|p| p.type_member(src, tgt, cls, dest));
    }

    pub fn genfscon(&mut self, fs: &str, path: &str, context: &str) {
        self.with_mut(|p| p.genfscon(fs, path, context));
    }

    /// Attribute names, in policy order.
    pub fn attribute_names(&self) -> impl Iterator<Item = Cow<'_, str>> + '_ {
        let mut values = Vec::new();
        self.with(|p| p.attribute_entries(&mut values));
        let names = self.names();
        values
            .into_iter()
            .filter_map(move |value| rules::name(names.type_name_bytes(value)))
    }

    /// Types (not attributes) with their attributes and permissive state.
    pub fn type_decls(&self) -> impl Iterator<Item = TypeDecl<'_>> + '_ {
        let (mut entries, mut attrs) = (Vec::new(), Vec::new());
        self.with(|p| p.type_entries(&mut entries, &mut attrs));
        let names = self.names();
        entries.into_iter().filter_map(move |entry| {
            let name = rules::name(names.type_name_bytes(entry.value))?;
            let start = entry.attrs_start as usize;
            let attributes = attrs[start..start + entry.attrs_len as usize]
                .iter()
                .filter_map(|&attr| rules::name(names.type_name_bytes(attr)))
                .collect();
            Some(TypeDecl {
                name,
                attributes,
                permissive: entry.permissive,
            })
        })
    }

    /// Every rule in the access vector table, in table order.
    pub fn avtab_rules(&self) -> impl Iterator<Item = AvtabRule<'_>> + '_ {
        let (mut entries, mut xperms) = (Vec::new(), Vec::new());
        self.with(|p| p.avtab_entries(&mut entries, &mut xperms));
        let names = self.names();
        entries
            .into_iter()
            .filter_map(move |entry| rules::avtab_rule(names, &entry, &xperms))
    }

    /// `allow`, `auditallow` and `dontaudit` rules.
    pub fn av_rules(&self) -> impl Iterator<Item = AvRule<'_>> + '_ {
        self.avtab_rules().filter_map(|rule| match rule {
            AvtabRule::Av(rule) => Some(rule),
            _ => None,
        })
    }

    /// `type_transition`, `type_member` and `type_change` rules.
    pub fn type_rules(&self) -> impl Iterator<Item = rules::TypeRule<'_>> + '_ {
        self.avtab_rules().filter_map(|rule| match rule {
            AvtabRule::Type(rule) => Some(rule),
            _ => None,
        })
    }

    /// `allowxperm`, `auditallowxperm` and `dontauditxperm` rules.
    pub fn xperm_rules(&self) -> impl Iterator<Item = XpermRule<'_>> + '_ {
        self.avtab_rules().filter_map(|rule| match rule {
            AvtabRule::Xperm(rule) => Some(rule),
            _ => None,
        })
    }

    /// Filename `type_transition` rules.
    pub fn filename_transitions(&self) -> impl Iterator<Item = FilenameTransition<'_>> + '_ {
        let mut entries = Vec::new();
        self.with(|p| p.filename_trans_entries(&mut entries));
        let names = self.names();
        entries.into_iter().filter_map(move |entry| {
            Some(FilenameTransition {
                source: rules::name(names.type_name_bytes(entry.source))?,
                target: rules::name(names.type_name_bytes(entry.target))?,
                class: rules::name(names.class_name_bytes(entry.class_))?,
                default: rules::name(names.type_name_bytes(entry.default_type))?,
                name: rules::name(entry.name)?,
            })
        })
    }

    /// `genfscon` statements.
    pub fn genfs(&self) -> impl Iterator<Item = Genfs<'_>> + '_ {
        let mut entries = Vec::new();
        self.with(|p| p.genfs_entries(&mut entries));
        entries.into_iter().filter_map(|entry| {
            Some(Genfs {
                fs: rules::name(entry.fs)?,
                path: rules::name(entry.path)?,
                context: entry.context,
            })
        })
    }

    pub fn attributes(&self) -> Vec<String> {
        self.attribute_names()
            .map(|name| format!("attribute {name}"))
            .collect()
    }

    pub fn types(&self) -> Vec<String> {
        let mut out = Vec::new();
        for decl in self.type_decls() {
            if !decl.attributes.is_empty() {
                out.push(format!(
                    "type {} {{ {} }}",
                    decl.name,
                    decl.attributes.join(" ")
                ));
            }
            if decl.permissive {
                out.push(format!("permissive {}", decl.name));
            }
        }
        out
    }

    pub fn avtabs(&self) -> Vec<String> {
        self.avtab_rules().map(|rule| render(&rule)).collect()
    }

    pub fn transitions(&self) -> Vec<String> {
        self.filename_transitions()
            .map(|rule| rule.to_string())
            .collect()
    }

    pub fn genfs_contexts(&self) -> Vec<String> {
        self.genfs().map(|genfs| genfs.to_string()).collect()
    }

    pub fn rules(&self) -> Vec<String> {
        let mut out = Vec::new();

        out.extend(self.attributes());
        out.extend(self.types());
        out.extend(self.avtabs());
        out.extend(self.transitions());
        out.extend(self.genfs_contexts());

        out
    }

    /// Parse a `.te` file, expanding M4 macros from `macros`, and apply it
    #[cfg(feature = "m4")]
    pub fn load_rules_from_file<P, M, I>(&mut self, path: P, macros: I) -> Result<()>
    where
        P: AsRef<Path>,
        M: AsRef<Path>,
        I: IntoIterator<Item = M>,
    {
        let policy = crate::parser::parse_file(path, macros)?;
        self.apply_policy(&policy);
        Ok(())
    }

    /// Apply a parsed policy to this sepolicy
    pub fn apply_policy(&mut self, policy: &Policy) {
        debug!(
            statement_count = policy.statements.len(),
            "Applying parsed policy"
        );
        for stmt in &policy.statements {
            self.apply_statement(stmt);
        }
    }

    fn apply_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::AVRule(rule) => self.apply_avrule(rule),
            Statement::AVXRule(rule) => self.apply_avxrule(rule),
            Statement::TypeRule(rule) => self.apply_typerule(rule),
            Statement::Type(def) => self.apply_type_def(def),
            Statement::Attribute(attr) => self.attribute(&attr.name),
            Statement::ExpandAttribute(_) => {}
            Statement::TypeAttribute(ta) => self.apply_typeattribute(ta),
            Statement::Permissive(p) => self.permissive(&[p.type_name.as_str()]),
            Statement::GenfsContext(g) => self.apply_genfscon(g),
            Statement::Conditional(_) => {
                warn!("Conditional statements are not yet supported");
            }
            // Skip unsupported statements
            _ => {
                warn!(statement = ?stmt, "Skipping unsupported statement");
            }
        }
    }

    fn apply_avrule(&mut self, rule: &AVRule) {
        let src: Vec<&str> = rule.src_types.ids.iter().map(|s| s.as_str()).collect();
        let tgt: Vec<&str> = rule.tgt_types.ids.iter().map(|s| s.as_str()).collect();
        let cls: Vec<&str> = rule.obj_classes.ids.iter().map(|s| s.as_str()).collect();
        let perm: Vec<&str> = rule.perms.ids.iter().map(|s| s.as_str()).collect();

        match rule.rule_type {
            AVRuleType::Allow => self.allow(&src, &tgt, &cls, &perm),
            AVRuleType::Dontaudit => self.dontaudit(&src, &tgt, &cls, &perm),
            AVRuleType::Auditallow => self.auditallow(&src, &tgt, &cls, &perm),
            AVRuleType::Neverallow => {}
        }
    }

    fn apply_avxrule(&mut self, rule: &AVXRule) {
        let src: Vec<&str> = rule.src_types.ids.iter().map(|s| s.as_str()).collect();
        let tgt: Vec<&str> = rule.tgt_types.ids.iter().map(|s| s.as_str()).collect();
        let cls: Vec<&str> = rule.obj_classes.ids.iter().map(|s| s.as_str()).collect();

        match rule.rule_type {
            AVRuleType::Allow => self.allowxperm(&src, &tgt, &cls, &rule.xperms),
            AVRuleType::Dontaudit => self.dontauditxperm(&src, &tgt, &cls, &rule.xperms),
            AVRuleType::Auditallow => self.auditallowxperm(&src, &tgt, &cls, &rule.xperms),
            AVRuleType::Neverallow => {}
        }
    }

    fn apply_typerule(&mut self, rule: &TypeRule) {
        // Type rules need to be expanded for each src/tgt/cls combination
        for src in &rule.src_types.ids {
            for tgt in &rule.tgt_types.ids {
                for cls in &rule.obj_classes.ids {
                    let obj = rule.file_name.as_deref().unwrap_or("");
                    match rule.rule_type {
                        TypeRuleType::TypeTransition => {
                            self.type_transition(src, tgt, cls, &rule.dest_type, obj)
                        }
                        TypeRuleType::TypeChange => {
                            self.type_change(src, tgt, cls, &rule.dest_type)
                        }
                        TypeRuleType::TypeMember => {
                            self.type_member(src, tgt, cls, &rule.dest_type)
                        }
                    }
                }
            }
        }
    }

    fn apply_type_def(&mut self, def: &TypeDef) {
        let attrs: Vec<&str> = def.attributes.ids.iter().map(|s| s.as_str()).collect();
        self.type_(&def.name, &attrs);
    }

    fn apply_typeattribute(&mut self, ta: &TypeAttribute) {
        let types = [ta.type_name.as_str()];
        let attrs: Vec<&str> = ta.attributes.ids.iter().map(|s| s.as_str()).collect();
        self.typeattribute(&types, &attrs);
    }

    fn apply_genfscon(&mut self, g: &GenfsContext) {
        let ctx = format!(
            "{}:{}:{}{}",
            g.context.user,
            g.context.role,
            g.context.type_name,
            g.context
                .level
                .as_ref()
                .map(|l| format!(":{}", l))
                .unwrap_or_default()
        );
        self.genfscon(&g.filesystem, &g.path, &ctx);
    }
}

/// Format `value` into a buffer sized for a typical rule line, avoiding the
/// repeated growth of `to_string`.
fn render(value: &impl std::fmt::Display) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(96);
    write!(out, "{value}").expect("formatting into a String cannot fail");
    out
}

impl Drop for SePolicy {
    fn drop(&mut self) {
        // policydb_destroy reaches libsepol too, so free the database under the lock.
        let _guard = lock::libsepol();
        self.inner = UniquePtr::null();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn test_sepolicy_from_file() {
        // Prefer env var so CI can inject the right path.
        let path = fixture_path("precompiled_sepolicy");
        assert!(
            path.exists(),
            "precompiled sepolicy file does not exist: {}",
            path.display()
        );

        let _ = SePolicy::from_file(path).expect("failed to load precompiled sepolicy");
    }

    #[test]
    fn test_sepolicy_get_attributes() {
        let path = fixture_path("precompiled_sepolicy");
        let sepolicy = SePolicy::from_file(path).expect("failed to load precompiled sepolicy");

        let attributes = sepolicy.attributes();
        assert!(!attributes.is_empty(), "no attributes found in sepolicy");
    }

    #[test]
    fn test_sepolicy_get_types() {
        let path = fixture_path("precompiled_sepolicy");
        let sepolicy = SePolicy::from_file(path).expect("failed to load precompiled sepolicy");

        let types = sepolicy.types();
        assert!(!types.is_empty(), "no types found in sepolicy");
    }

    #[test]
    fn test_sepolicy_get_avtabs() {
        let path = fixture_path("precompiled_sepolicy");
        let sepolicy = SePolicy::from_file(path).expect("failed to load precompiled sepolicy");

        let avtabs = sepolicy.avtabs();
        assert!(!avtabs.is_empty(), "no avtabs found in sepolicy");
    }

    #[test]
    fn test_sepolicy_get_transitions() {
        let path = fixture_path("precompiled_sepolicy");
        let sepolicy = SePolicy::from_file(path).expect("failed to load precompiled sepolicy");

        let transitions = sepolicy.transitions();
        assert!(
            !transitions.is_empty(),
            "no type transitions found in sepolicy"
        );
    }

    #[test]
    fn test_sepolicy_get_genfs_contexts() {
        let path = fixture_path("precompiled_sepolicy");
        let sepolicy = SePolicy::from_file(path).expect("failed to load precompiled sepolicy");

        let genfs_contexts = sepolicy.genfs_contexts();
        assert!(
            !genfs_contexts.is_empty(),
            "no genfs contexts found in sepolicy"
        );
    }

    fn load_policy() -> SePolicy {
        let policy_path = fixture_path("precompiled_sepolicy");
        SePolicy::from_file(policy_path).expect("failed to load precompiled sepolicy")
    }

    #[test]
    fn test_add_type() {
        let mut sepolicy = load_policy();
        let type_name = "test_new_type_xyz";
        let attr_name = "test_new_type_attr_xyz";

        // Verify type doesn't exist
        assert!(
            !sepolicy.types().iter().any(|t| t.contains(type_name)),
            "type should not exist before adding"
        );

        // Create attribute first, then type with that attribute
        // (types without attributes don't appear in types() output)
        let policy = parser::parse(&format!(
            "attribute {};\ntype {}, {};",
            attr_name, type_name, attr_name
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify type was added
        assert!(
            sepolicy.types().iter().any(|t| t.contains(type_name)),
            "type should exist after adding"
        );
    }

    #[test]
    fn test_add_attribute() {
        let mut sepolicy = load_policy();
        let attr_name = "test_new_attr_xyz";

        // Verify attribute doesn't exist
        assert!(
            !sepolicy.attributes().iter().any(|a| a.contains(attr_name)),
            "attribute should not exist before adding"
        );

        let policy =
            parser::parse(&format!("attribute {};", attr_name)).expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify attribute was added
        assert!(
            sepolicy.attributes().iter().any(|a| a.contains(attr_name)),
            "attribute should exist after adding"
        );
    }

    #[test]
    fn test_add_typeattribute() {
        let mut sepolicy = load_policy();
        let type_name = "test_ta_type_xyz";
        let attr_name = "test_ta_attr_xyz";

        // First create the type and attribute
        let policy = parser::parse(&format!(
            "type {};\nattribute {};\ntypeattribute {} {};",
            type_name, attr_name, type_name, attr_name
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify the type has the attribute
        let types = sepolicy.types();
        let type_entry = types
            .iter()
            .find(|t| t.contains(type_name))
            .expect("type should exist");

        assert!(
            type_entry.contains(attr_name),
            "type should have the attribute associated: {}",
            type_entry
        );
    }

    #[test]
    fn test_add_allow_rule() {
        let mut sepolicy = load_policy();
        let src_type = "test_allow_src_t";
        let tgt_type = "test_allow_tgt_t";

        // Create our own types first
        let policy = parser::parse(&format!(
            "type {};\ntype {};\nallow {} {}:process fork;",
            src_type, tgt_type, src_type, tgt_type
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify the allow rule was added
        let avtabs = sepolicy.avtabs();
        let has_rule = avtabs.iter().any(|rule| {
            rule.starts_with(&format!("allow {} {} process", src_type, tgt_type))
                && rule.contains("fork")
        });

        assert!(has_rule, "allow rule should exist in avtabs");
    }

    #[test]
    fn test_add_auditallow_rule() {
        let mut sepolicy = load_policy();
        let src_type = "test_auditallow_src_t";
        let tgt_type = "test_auditallow_tgt_t";

        let policy = parser::parse(&format!(
            "type {};\ntype {};\nauditallow {} {}:process fork;",
            src_type, tgt_type, src_type, tgt_type
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify the auditallow rule was added
        let avtabs = sepolicy.avtabs();
        let has_rule = avtabs.iter().any(|rule| {
            rule.starts_with(&format!("auditallow {} {} process", src_type, tgt_type))
                && rule.contains("fork")
        });

        assert!(has_rule, "auditallow rule should exist in avtabs");
    }

    #[test]
    fn test_add_dontaudit_rule() {
        let mut sepolicy = load_policy();
        let src_type = "test_dontaudit_src_t";
        let tgt_type = "test_dontaudit_tgt_t";

        let policy = parser::parse(&format!(
            "type {};\ntype {};\ndontaudit {} {}:process fork;",
            src_type, tgt_type, src_type, tgt_type
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify the dontaudit rule was added
        let avtabs = sepolicy.avtabs();
        let has_rule = avtabs.iter().any(|rule| {
            rule.starts_with(&format!("dontaudit {} {} process", src_type, tgt_type))
                && rule.contains("fork")
        });

        assert!(has_rule, "dontaudit rule should exist in avtabs");
    }

    #[test]
    fn test_add_permissive() {
        let mut sepolicy = load_policy();
        let type_name = "test_permissive_type_xyz";

        let policy = parser::parse(&format!("type {};\npermissive {};", type_name, type_name))
            .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify type is now permissive
        let types = sepolicy.types();
        let has_permissive = types
            .iter()
            .any(|t| t == &format!("permissive {}", type_name));

        assert!(has_permissive, "type should be permissive after adding");
    }

    #[test]
    fn test_add_type_transition() {
        let mut sepolicy = load_policy();
        let src_type = "test_tt_src_t";
        let tgt_type = "test_tt_tgt_t";
        let dest_type = "test_tt_dest_t";

        let policy = parser::parse(&format!(
            "type {};\ntype {};\ntype {};\ntype_transition {} {}:file {};",
            src_type, tgt_type, dest_type, src_type, tgt_type, dest_type
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify the type_transition was added
        let avtabs = sepolicy.avtabs();
        let has_transition = avtabs.iter().any(|rule| {
            rule.starts_with(&format!(
                "type_transition {} {} file {}",
                src_type, tgt_type, dest_type
            ))
        });

        assert!(
            has_transition,
            "type_transition rule should exist in avtabs"
        );
    }

    #[test]
    fn test_add_type_change() {
        let mut sepolicy = load_policy();
        let src_type = "test_tc_src_t";
        let tgt_type = "test_tc_tgt_t";
        let dest_type = "test_tc_dest_t";

        let policy = parser::parse(&format!(
            "type {};\ntype {};\ntype {};\ntype_change {} {}:file {};",
            src_type, tgt_type, dest_type, src_type, tgt_type, dest_type
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify the type_change was added
        let avtabs = sepolicy.avtabs();
        let has_change = avtabs.iter().any(|rule| {
            rule.starts_with(&format!(
                "type_change {} {} file {}",
                src_type, tgt_type, dest_type
            ))
        });

        assert!(has_change, "type_change rule should exist in avtabs");
    }

    #[test]
    fn test_add_type_member() {
        let mut sepolicy = load_policy();
        let src_type = "test_tm_src_t";
        let tgt_type = "test_tm_tgt_t";
        let dest_type = "test_tm_dest_t";

        let policy = parser::parse(&format!(
            "type {};\ntype {};\ntype {};\ntype_member {} {}:file {};",
            src_type, tgt_type, dest_type, src_type, tgt_type, dest_type
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify the type_member was added
        let avtabs = sepolicy.avtabs();
        let has_member = avtabs.iter().any(|rule| {
            rule.starts_with(&format!(
                "type_member {} {} file {}",
                src_type, tgt_type, dest_type
            ))
        });

        assert!(has_member, "type_member rule should exist in avtabs");
    }

    #[test]
    fn test_add_genfscon() {
        let mut sepolicy = load_policy();
        let test_path = "/test/genfs/xyz";
        let test_type = "test_genfscon_t";

        let policy = parser::parse(&format!(
            "type {};\ngenfscon sysfs {} u:object_r:{}:s0",
            test_type, test_path, test_type
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify the genfscon was added
        let genfs = sepolicy.genfs_contexts();
        let has_genfs = genfs
            .iter()
            .any(|ctx| ctx.contains("sysfs") && ctx.contains(test_path) && ctx.contains(test_type));

        assert!(has_genfs, "genfscon should exist in genfs_contexts");
    }

    #[test]
    fn test_add_type_with_attributes() {
        let mut sepolicy = load_policy();
        let type_name = "test_typed_attr_xyz";
        let attr_name = "test_parent_attr_xyz";

        let policy = parser::parse(&format!(
            "attribute {};\ntype {}, {};",
            attr_name, type_name, attr_name
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify type exists and has the attribute
        let types = sepolicy.types();
        let type_entry = types
            .iter()
            .find(|t| t.contains(type_name))
            .expect("type should exist");

        assert!(
            type_entry.contains(attr_name),
            "type should have attribute: {}",
            type_entry
        );
    }

    #[test]
    fn test_add_filename_transition() {
        let mut sepolicy = load_policy();
        let src_type = "test_fnt_src_xyz";
        let tgt_type = "test_fnt_tgt_xyz";
        let dest_type = "test_fnt_dest_xyz";
        let filename = "test_filename_xyz";

        let policy = parser::parse(&format!(
            "type {};\ntype {};\ntype {};\ntype_transition {} {}:file {} \"{}\";",
            src_type, tgt_type, dest_type, src_type, tgt_type, dest_type, filename
        ))
        .expect("failed to parse policy");
        sepolicy.apply_policy(&policy);

        // Verify the filename transition was added
        let transitions = sepolicy.transitions();
        let has_transition = transitions.iter().any(|rule| {
            rule.contains("type_transition")
                && rule.contains(src_type)
                && rule.contains(tgt_type)
                && rule.contains("file")
                && rule.contains(dest_type)
                && rule.contains(filename)
        });

        assert!(
            has_transition,
            "filename type_transition should exist in transitions"
        );
    }

    fn patched(rules: &str) -> SePolicy {
        let mut sepolicy = load_policy();
        sepolicy.apply_policy(&parser::parse(rules).expect("failed to parse policy"));
        sepolicy
    }

    #[test]
    fn test_av_rules_structured() {
        let sepolicy = patched(
            "type q_av_src_t;\ntype q_av_tgt_t;\nallow q_av_src_t q_av_tgt_t:process { fork sigchld };",
        );

        let rule = sepolicy
            .av_rules()
            .find(|rule| rule.source == "q_av_src_t" && rule.target == "q_av_tgt_t")
            .expect("allow rule should be listed");

        assert_eq!(rule.kind, rules::AvRuleKind::Allow);
        assert_eq!(rule.class, "process");
        let mut perms: Vec<_> = rule.perms().collect();
        perms.sort();
        assert_eq!(perms, ["fork", "sigchld"]);
    }

    #[test]
    fn test_dontaudit_rule_lists_silenced_perms() {
        let sepolicy = patched(
            "type q_da_src_t;\ntype q_da_tgt_t;\ndontaudit q_da_src_t q_da_tgt_t:process fork;",
        );

        let rule = sepolicy
            .av_rules()
            .find(|rule| rule.source == "q_da_src_t")
            .expect("dontaudit rule should be listed");

        assert_eq!(rule.kind, rules::AvRuleKind::DontAudit);
        assert_eq!(rule.perms().collect::<Vec<_>>(), ["fork"]);
    }

    #[test]
    fn test_type_rules_structured() {
        let sepolicy = patched(
            "type q_tr_src_t;\ntype q_tr_tgt_t;\ntype q_tr_dest_t;\ntype_change q_tr_src_t q_tr_tgt_t:file q_tr_dest_t;",
        );

        let rule = sepolicy
            .type_rules()
            .find(|rule| rule.source == "q_tr_src_t")
            .expect("type_change rule should be listed");

        assert_eq!(rule.kind, rules::TypeRuleKind::Change);
        assert_eq!(rule.target, "q_tr_tgt_t");
        assert_eq!(rule.class, "file");
        assert_eq!(rule.default, "q_tr_dest_t");
    }

    #[test]
    fn test_xperm_rules_structured() {
        let sepolicy = patched(
            "type q_xp_src_t;\ntype q_xp_tgt_t;\nallowxperm q_xp_src_t q_xp_tgt_t:unix_stream_socket ioctl { 0x5401 0x5413-0x5414 };",
        );

        let rule = sepolicy
            .xperm_rules()
            .find(|rule| rule.source == "q_xp_src_t")
            .expect("allowxperm rule should be listed");

        assert_eq!(rule.kind, rules::XpermRuleKind::Allow);
        assert_eq!(
            rule.ioctls.ranges().collect::<Vec<_>>(),
            [(0x5401, 0x5401), (0x5413, 0x5414)]
        );
        assert_eq!(
            rule.to_string(),
            "allowxperm q_xp_src_t q_xp_tgt_t unix_stream_socket ioctl { 0x5401 0x5413-0x5414 }"
        );
    }

    #[test]
    fn test_type_decls_and_attribute_names() {
        let sepolicy =
            patched("attribute q_decl_attr;\ntype q_decl_t, q_decl_attr;\npermissive q_decl_t;");

        let decl = sepolicy
            .type_decls()
            .find(|decl| decl.name == "q_decl_t")
            .expect("type should be listed");

        assert!(decl.attributes.iter().any(|attr| attr == "q_decl_attr"));
        assert!(decl.permissive);
        assert!(sepolicy.attribute_names().any(|name| name == "q_decl_attr"));
    }

    #[test]
    fn test_filename_transitions_structured() {
        let sepolicy = patched(
            "type q_ft_src_t;\ntype q_ft_tgt_t;\ntype q_ft_dest_t;\ntype_transition q_ft_src_t q_ft_tgt_t:file q_ft_dest_t \"q_ft_name\";",
        );

        let rule = sepolicy
            .filename_transitions()
            .find(|rule| rule.source == "q_ft_src_t")
            .expect("filename transition should be listed");

        assert_eq!(rule.target, "q_ft_tgt_t");
        assert_eq!(rule.class, "file");
        assert_eq!(rule.default, "q_ft_dest_t");
        assert_eq!(rule.name, "q_ft_name");
    }

    #[test]
    fn test_genfs_structured() {
        let sepolicy =
            patched("type q_genfs_t;\ngenfscon sysfs /q/genfs/path u:object_r:q_genfs_t:s0");

        let genfs = sepolicy
            .genfs()
            .find(|genfs| genfs.path == "/q/genfs/path")
            .expect("genfscon should be listed");

        assert_eq!(genfs.fs, "sysfs");
        assert_eq!(genfs.context, "u:object_r:q_genfs_t:s0");
    }

    #[test]
    fn test_filename_transitions_with_shared_key() {
        // Same target, class and name with different defaults: libsepol chains
        // these as datums under one key.
        let sepolicy = patched(
            "type q_fk_src1_t;\ntype q_fk_src2_t;\ntype q_fk_tgt_t;\ntype q_fk_dest1_t;\ntype q_fk_dest2_t;\n\
             type_transition q_fk_src1_t q_fk_tgt_t:file q_fk_dest1_t \"q_fk_name\";\n\
             type_transition q_fk_src2_t q_fk_tgt_t:file q_fk_dest2_t \"q_fk_name\";",
        );

        let mut found: Vec<_> = sepolicy
            .filename_transitions()
            .filter(|rule| rule.target == "q_fk_tgt_t")
            .map(|rule| (rule.source.into_owned(), rule.default.into_owned()))
            .collect();
        found.sort();

        assert_eq!(
            found,
            [
                ("q_fk_src1_t".to_string(), "q_fk_dest1_t".to_string()),
                ("q_fk_src2_t".to_string(), "q_fk_dest2_t".to_string()),
            ]
        );
    }

    #[test]
    fn test_xperm_range_across_drivers_grants_only_its_ioctls() {
        let sepolicy = patched(
            "type q_xd_src_t;\ntype q_xd_tgt_t;\nallowxperm q_xd_src_t q_xd_tgt_t:unix_stream_socket ioctl 0x5401-0x5602;",
        );

        let rules: Vec<_> = sepolicy
            .xperm_rules()
            .filter(|rule| rule.source == "q_xd_src_t")
            .collect();
        let allowed = |ioctl: u16| rules.iter().any(|rule| rule.ioctls.covers(ioctl));

        for ioctl in [0x5401, 0x54ff, 0x5500, 0x55ab, 0x55ff, 0x5600, 0x5602] {
            assert!(allowed(ioctl), "0x{ioctl:04x} should be allowed");
        }
        for ioctl in [0x5400, 0x5603, 0x56ff, 0x5300, 0x5700] {
            assert!(!allowed(ioctl), "0x{ioctl:04x} should not be allowed");
        }
    }

    #[test]
    fn test_genfscon_keeps_longest_paths_first() {
        // The kernel uses the first genfs entry whose path is a prefix of the
        // file's path, so a short path inserted first would shadow longer ones.
        let sepolicy =
            patched("type q_genfs_short_t;\ngenfscon sysfs /devices u:object_r:q_genfs_short_t:s0");

        let lengths: Vec<usize> = sepolicy
            .genfs()
            .filter(|genfs| genfs.fs == "sysfs")
            .map(|genfs| genfs.path.len())
            .collect();
        assert!(
            lengths.len() > 2,
            "fixture should have several sysfs entries"
        );
        assert!(
            lengths.windows(2).all(|pair| pair[0] >= pair[1]),
            "sysfs entries should be ordered longest path first"
        );
    }
}

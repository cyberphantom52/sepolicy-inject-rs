use std::path::Path;
use std::pin::Pin;

use cxx::UniquePtr;

use crate::error::{Error, Result, path_str};
use crate::ffi::{self, SePolicyImpl, XPerm};
use crate::lock;
use crate::parser::ast::*;
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
    fn with<R>(&self, f: impl FnOnce(&SePolicyImpl) -> R) -> R {
        let _guard = lock::libsepol();
        f(&self.inner)
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

    pub fn attributes(&self) -> Vec<String> {
        self.with(|p| p.attributes())
    }

    pub fn types(&self) -> Vec<String> {
        self.with(|p| p.types())
    }

    pub fn avtabs(&self) -> Vec<String> {
        self.with(|p| p.avtabs())
    }

    pub fn transitions(&self) -> Vec<String> {
        self.with(|p| p.transitions())
    }

    pub fn genfs_contexts(&self) -> Vec<String> {
        self.with(|p| p.genfs_contexts())
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
}

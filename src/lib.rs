use std::path::Path;

pub mod parser;

pub use self::ffi::{SePolicy, XPerm};
use parser::ast::*;

#[cxx::bridge]
mod ffi {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct XPerm {
        low: u16,
        high: u16,
        reset: bool,
    }

    struct SePolicy {
        inner: UniquePtr<SePolicyImpl>,
    }

    unsafe extern "C++" {
        include!("sepolicy-inject-rs/src/ffi/sepolicy.hpp");

        type SePolicyImpl;

        // AVRules
        fn allow(self: &mut SePolicy, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]);
        fn deny(self: &mut SePolicy, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]);
        fn auditallow(self: &mut SePolicy, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]);
        fn dontaudit(self: &mut SePolicy, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]);

        // AVXRules
        fn allowxperm(
            self: &mut SePolicy,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            x_perm: &[XPerm],
        );
        fn auditallowxperm(
            self: &mut SePolicy,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            x_perm: &[XPerm],
        );
        fn dontauditxperm(
            self: &mut SePolicy,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            x_perm: &[XPerm],
        );

        fn permissive(self: &mut SePolicy, types: &[&str]);
        fn enforce(self: &mut SePolicy, types: &[&str]);
        fn typeattribute(self: &mut SePolicy, ty: &[&str], attrs: &[&str]);
        #[cxx_name = "type"]
        fn type_(self: &mut SePolicy, ty: &str, attrs: &[&str]);
        fn attribute(self: &mut SePolicy, name: &str);

        fn type_transition(
            self: &mut SePolicy,
            src: &str,
            tgt: &str,
            cls: &str,
            dest: &str,
            obj: &str,
        );
        fn type_change(self: &mut SePolicy, src: &str, tgt: &str, cls: &str, dest: &str);
        fn type_member(self: &mut SePolicy, src: &str, tgt: &str, cls: &str, dest: &str);
        fn genfscon(self: &mut SePolicy, fs: &str, path: &str, context: &str);

        fn attributes(self: &SePolicy) -> Vec<String>;
        fn types(self: &SePolicy) -> Vec<String>;
        fn avtabs(self: &SePolicy) -> Vec<String>;
        fn transitions(self: &SePolicy) -> Vec<String>;
        fn genfs_contexts(self: &SePolicy) -> Vec<String>;

        fn from_file_impl(path: &str) -> UniquePtr<SePolicyImpl>;
        fn from_split_impl() -> UniquePtr<SePolicyImpl>;
        fn compile_split_impl() -> UniquePtr<SePolicyImpl>;
        fn from_data_impl(data: &[u8]) -> UniquePtr<SePolicyImpl>;
    }
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

    pub fn from_split() -> Option<Self> {
        let inner = ffi::from_split_impl();
        if inner.is_null() {
            None
        } else {
            Some(SePolicy { inner })
        }
    }

    pub fn compile_split() -> Option<Self> {
        let inner = ffi::compile_split_impl();
        if inner.is_null() {
            None
        } else {
            Some(SePolicy { inner })
        }
    }

    pub fn from_data(data: &[u8]) -> Option<Self> {
        let inner = ffi::from_data_impl(data);
        if inner.is_null() {
            None
        } else {
            Some(SePolicy { inner })
        }
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

    /// Load and apply rules from a .te file
    pub fn load_rules_from_file(&mut self, path: impl AsRef<Path>) -> Result<(), String> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read file: {}", e))?;
        self.load_rules(&content)
    }

    /// Parse and apply rules from a .te format string
    pub fn load_rules(&mut self, content: &str) -> Result<(), String> {
        let policy = parser::parse(content).map_err(|e| format!("Parse error: {}", e))?;
        self.apply_policy(&policy);
        Ok(())
    }

    /// Apply a parsed policy to this sepolicy
    pub fn apply_policy(&mut self, policy: &Policy) {
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
            Statement::TypeAttribute(ta) => self.apply_typeattribute(ta),
            Statement::Permissive(p) => self.permissive(&[p.type_name.as_str()]),
            Statement::GenfsContext(g) => self.apply_genfscon(g),
            Statement::Conditional(_) => {
                todo!()
            }
            // Skip unsupported statements
            _ => {
                // TODO: Warn
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
        sepolicy
            .load_rules(&format!(
                "attribute {};\ntype {}, {};",
                attr_name, type_name, attr_name
            ))
            .expect("failed to add type");

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

        sepolicy
            .load_rules(&format!("attribute {};", attr_name))
            .expect("failed to add attribute");

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
        sepolicy
            .load_rules(&format!(
                "type {};\nattribute {};",
                type_name, attr_name
            ))
            .expect("failed to create type and attribute");

        // Now associate them
        sepolicy
            .load_rules(&format!("typeattribute {} {};", type_name, attr_name))
            .expect("failed to add typeattribute");

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
        sepolicy
            .load_rules(&format!("type {};\ntype {};", src_type, tgt_type))
            .expect("failed to create types");

        // Add allow rule with our own types
        sepolicy
            .load_rules(&format!("allow {} {}:process fork;", src_type, tgt_type))
            .expect("failed to add allow rule");

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

        // Create our own types first
        sepolicy
            .load_rules(&format!("type {};\ntype {};", src_type, tgt_type))
            .expect("failed to create types");

        // Add auditallow rule
        sepolicy
            .load_rules(&format!(
                "auditallow {} {}:process fork;",
                src_type, tgt_type
            ))
            .expect("failed to add auditallow rule");

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

        // Create our own types first
        sepolicy
            .load_rules(&format!("type {};\ntype {};", src_type, tgt_type))
            .expect("failed to create types");

        // Add dontaudit rule
        sepolicy
            .load_rules(&format!(
                "dontaudit {} {}:process fork;",
                src_type, tgt_type
            ))
            .expect("failed to add dontaudit rule");

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

        // Create a new type first
        sepolicy
            .load_rules(&format!("type {};", type_name))
            .expect("failed to create type");

        // Verify type is not permissive initially
        assert!(
            !sepolicy
                .types()
                .iter()
                .any(|t| t.contains(&format!("permissive {}", type_name))),
            "type should not be permissive before adding"
        );

        // Make type permissive
        sepolicy
            .load_rules(&format!("permissive {};", type_name))
            .expect("failed to add permissive");

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

        // Create our own types first
        sepolicy
            .load_rules(&format!(
                "type {};\ntype {};\ntype {};",
                src_type, tgt_type, dest_type
            ))
            .expect("failed to create types");

        // Add type_transition rule
        sepolicy
            .load_rules(&format!(
                "type_transition {} {}:file {};",
                src_type, tgt_type, dest_type
            ))
            .expect("failed to add type_transition");

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

        // Create our own types first
        sepolicy
            .load_rules(&format!(
                "type {};\ntype {};\ntype {};",
                src_type, tgt_type, dest_type
            ))
            .expect("failed to create types");

        // Add type_change rule
        sepolicy
            .load_rules(&format!(
                "type_change {} {}:file {};",
                src_type, tgt_type, dest_type
            ))
            .expect("failed to add type_change");

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

        // Create our own types first
        sepolicy
            .load_rules(&format!(
                "type {};\ntype {};\ntype {};",
                src_type, tgt_type, dest_type
            ))
            .expect("failed to create types");

        // Add type_member rule
        sepolicy
            .load_rules(&format!(
                "type_member {} {}:file {};",
                src_type, tgt_type, dest_type
            ))
            .expect("failed to add type_member");

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

        // Create our own type first
        sepolicy
            .load_rules(&format!("type {};", test_type))
            .expect("failed to create type");

        // Add genfscon rule
        // Note: genfscon syntax doesn't use semicolons in the grammar
        sepolicy
            .load_rules(&format!(
                "genfscon sysfs {} u:object_r:{}:s0",
                test_path, test_type
            ))
            .expect("failed to add genfscon");

        // Verify the genfscon was added
        let genfs = sepolicy.genfs_contexts();
        let has_genfs = genfs.iter().any(|ctx| {
            ctx.contains("sysfs") && ctx.contains(test_path) && ctx.contains(test_type)
        });

        assert!(has_genfs, "genfscon should exist in genfs_contexts");
    }

    #[test]
    fn test_add_type_with_attributes() {
        let mut sepolicy = load_policy();
        let type_name = "test_typed_attr_xyz";
        let attr_name = "test_parent_attr_xyz";

        // Create the attribute first
        sepolicy
            .load_rules(&format!("attribute {};", attr_name))
            .expect("failed to create attribute");

        // Create type with attribute
        sepolicy
            .load_rules(&format!("type {}, {};", type_name, attr_name))
            .expect("failed to create type with attribute");

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

        // Create types first
        sepolicy
            .load_rules(&format!(
                "type {};\ntype {};\ntype {};",
                src_type, tgt_type, dest_type
            ))
            .expect("failed to create types");

        // Add filename type_transition rule
        sepolicy
            .load_rules(&format!(
                "type_transition {} {}:file {} \"{}\";",
                src_type, tgt_type, dest_type, filename
            ))
            .expect("failed to add filename transition");

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

    #[test]
    fn test_multiple_rules_combined() {
        let mut sepolicy = load_policy();

        // Test combining multiple rule types - all with our own types
        let te_content = r#"
            type test_combined_src_t;
            type test_combined_tgt_t;
            attribute test_combined_attr;
            typeattribute test_combined_src_t test_combined_attr;
            allow test_combined_src_t test_combined_tgt_t:process { fork sigchld };
            permissive test_combined_src_t;
        "#;

        sepolicy
            .load_rules(te_content)
            .expect("failed to parse and apply rules");

        // Verify type exists
        let types = sepolicy.types();
        assert!(
            types.iter().any(|t| t.contains("test_combined_src_t")),
            "type should exist"
        );

        // Verify attribute exists
        let attributes = sepolicy.attributes();
        assert!(
            attributes
                .iter()
                .any(|a| a.contains("test_combined_attr")),
            "attribute should exist"
        );

        // Verify type has attribute
        let type_entry = types
            .iter()
            .find(|t| t.contains("test_combined_src_t"))
            .expect("type should exist");
        assert!(
            type_entry.contains("test_combined_attr"),
            "type should have attribute"
        );

        // Verify allow rule exists
        let avtabs = sepolicy.avtabs();
        let has_fork = avtabs.iter().any(|rule| {
            rule.starts_with("allow test_combined_src_t test_combined_tgt_t process")
                && rule.contains("fork")
        });
        assert!(has_fork, "allow rule with fork should exist");

        // Verify permissive
        assert!(
            types
                .iter()
                .any(|t| t == "permissive test_combined_src_t"),
            "type should be permissive"
        );
    }
}

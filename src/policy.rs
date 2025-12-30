use std::path::Path;

use crate::ffi::{self, SePolicy};
use crate::parser::{self, ast::*};

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
    ///
    /// # Arguments
    /// * `path` - Path to the .te file
    /// * `macro_paths` - Paths to M4 macro definition files (can be empty)
    pub fn load_rules_from_file<P, I>(
        &mut self,
        path: impl AsRef<Path>,
        macro_paths: I,
    ) -> Result<(), String>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        use m4rs::processor::{Expander, MacroRegistry};

        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read file: {}", e))?;

        // Load macro definitions
        let mut registry = MacroRegistry::new();
        for macro_path in macro_paths {
            registry
                .load_file(
                    macro_path
                        .as_ref()
                        .to_str()
                        .ok_or("Macro path contains invalid UTF-8")?,
                )
                .map_err(|e| format!("Failed to load macro file: {}", e))?;
        }

        // Expand macros
        let mut expander = Expander::new(registry);
        let expanded = expander
            .expand(&content)
            .map_err(|e| format!("M4 expansion failed: {}", e))?;

        let policy = parser::parse(&expanded).map_err(|e| format!("Parse error: {}", e))?;
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

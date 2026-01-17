use std::path::Path;

use tracing::{debug, error, info};

use crate::ffi::{CilPolicy, cil_new_impl};
use crate::parser::{ast::*, self};

impl CilPolicy {
    /// Create a new empty CIL policy
    pub fn new() -> Self {
        let inner = cil_new_impl();
        CilPolicy { inner }
    }

    /// Load a CIL policy from a file
    pub fn from_file(path: impl AsRef<Path>) -> Option<Self> {
        let path_str = path
            .as_ref()
            .to_str()
            .expect("path contains invalid UTF-8 characters");
        info!(path = %path_str, "Loading CIL policy from file");

        let mut policy = Self::new();
        if !policy.inner.pin_mut().add_file(path_str) {
            error!(path = %path_str, "Failed to load CIL policy from file");
            return None;
        }
        info!(path = %path_str, "Successfully loaded CIL policy from file");
        Some(policy)
    }

    /// Add a CIL file to the policy
    pub fn add_file(&mut self, path: impl AsRef<Path>) -> Result<(), String> {
        let path_str = path
            .as_ref()
            .to_str()
            .expect("path contains invalid UTF-8 characters");
        if !self.inner.pin_mut().add_file(path_str) {
            return Err(format!(
                "failed to add CIL file: {}",
                path.as_ref().display()
            ));
        }
        Ok(())
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

        let path_display = path.as_ref().display().to_string();
        info!(path = %path_display, "Patching CIL with .te file");

        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            error!(path = %path_display, error = %e, "Failed to read file");
            format!("Failed to read file: {}", e)
        })?;

        // Load macro definitions
        let mut registry = MacroRegistry::new();
        for macro_path in macro_paths {
            let macro_path_str = macro_path
                .as_ref()
                .to_str()
                .ok_or("Macro path contains invalid UTF-8")?;
            debug!(macro_path = %macro_path_str, "Loading macro file");
            registry.load_file(macro_path_str).map_err(|e| {
                error!(macro_path = %macro_path_str, error = %e, "Failed to load macro file");
                format!("Failed to load macro file: {}", e)
            })?;
        }

        // Expand macros
        let mut expander = Expander::new(registry);
        let expanded = expander.expand(&content).map_err(|e| {
            error!(path = %path_display, error = %e, "M4 expansion failed");
            format!("M4 expansion failed: {}", e)
        })?;

        // Parse TE statements
        let policy = parser::parse(&expanded).map_err(|e| {
            error!(path = %path_display, error = %e, "Parse error");
            format!("Parse error: {}", e)
        })?;

        // Convert to CIL using ToCil trait
        let cil_statements = policy.to_cil().unwrap_or_default();
        let cil_content = cil_statements.join("\n");
        debug!(
            path = %path_display,
            stmt_count = cil_statements.len(),
            "Generated CIL from TE"
        );

        // Add the generated CIL to the policy
        let rule_name = format!("patch:{}", path_display);
        if !self.inner.pin_mut().add_rule(&rule_name, &cil_content) {
            error!(path = %path_display, "Failed to add generated CIL rules");
            return Err(format!("Failed to add CIL rules from: {}", path_display));
        }

        info!(path = %path_display, "Successfully patched CIL with .te file");
        Ok(())
    }

    /// Compile the CIL policy (validates and resolves references)
    pub fn compile(&mut self) -> bool {
        self.inner.pin_mut().compile()
    }
}

/// Trait for types that can be converted to CIL format.
pub trait ToCil {
    fn to_cil(&self) -> Option<Vec<String>>;
}

/// Counter for generating unique attribute names
static ATTR_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl ToCil for Policy {
    fn to_cil(&self) -> Option<Vec<String>> {
        let stmts: Vec<String> = self
            .statements
            .iter()
            .filter_map(|stmt| stmt.to_cil())
            .flatten()
            .collect();
        Some(stmts)
    }
}

impl ToCil for Statement {
    fn to_cil(&self) -> Option<Vec<String>> {
        match self {
            Statement::Type(def) => def.to_cil(),
            Statement::Attribute(attr) => attr.to_cil(),
            Statement::TypeAttribute(ta) => ta.to_cil(),
            Statement::AVRule(rule) => rule.to_cil(),
            Statement::AVXRule(rule) => rule.to_cil(),
            Statement::TypeRule(rule) => rule.to_cil(),
            Statement::Permissive(p) => p.to_cil(),
            Statement::GenfsContext(g) => g.to_cil(),
            // Unsupported statements
            _ => None,
        }
    }
}

impl ToCil for TypeDef {
    fn to_cil(&self) -> Option<Vec<String>> {
        let mut stmts = vec![format!("(type {})", self.name)];

        for attr in self.attributes.iter() {
            stmts.push(format!("(typeattributeset {} {})", attr, self.name));
        }

        Some(stmts)
    }
}

impl ToCil for Attribute {
    fn to_cil(&self) -> Option<Vec<String>> {
        Some(vec![format!("(typeattribute {})", self.name)])
    }
}

impl ToCil for TypeAttribute {
    fn to_cil(&self) -> Option<Vec<String>> {
        let stmts: Vec<String> = self
            .attributes
            .iter()
            .map(|attr| format!("(typeattributeset {} {})", attr, self.type_name))
            .collect();
        Some(stmts)
    }
}

impl ToCil for Permissive {
    fn to_cil(&self) -> Option<Vec<String>> {
        Some(vec![format!("(typepermissive {})", self.type_name)])
    }
}

impl ToCil for AVRule {
    fn to_cil(&self) -> Option<Vec<String>> {
        let keyword = match self.rule_type {
            AVRuleType::Allow => "allow",
            AVRuleType::Auditallow => "auditallow",
            AVRuleType::Dontaudit => "dontaudit",
            AVRuleType::Neverallow => "neverallow",
        };

        let mut stmts = Vec::new();

        // Check if we need intermediate attributes for set expressions
        let (src_name, src_defs) = idset_with_attr(&self.src_types, "attr_src");
        let (tgt_name, tgt_defs) = idset_with_attr(&self.tgt_types, "attr_tgt");

        // Add attribute definitions if needed
        stmts.extend(src_defs);
        stmts.extend(tgt_defs);

        for cls in self.obj_classes.iter() {
            let perms: Vec<&str> = self.perms.iter().map(|s| s.as_str()).collect();
            let perms_str = perms.join(" ");
            stmts.push(format!(
                "({} {} {} ({} ({})))",
                keyword, src_name, tgt_name, cls, perms_str
            ));
        }

        Some(stmts)
    }
}

impl ToCil for AVXRule {
    fn to_cil(&self) -> Option<Vec<String>> {
        let keyword = match self.rule_type {
            AVRuleType::Allow => "allowx",
            AVRuleType::Auditallow => "auditallowx",
            AVRuleType::Dontaudit => "dontauditx",
            AVRuleType::Neverallow => "neverallowx",
        };

        let xperms_str = self
            .xperms
            .iter()
            .map(|xp| {
                if xp.low == xp.high {
                    format!("{:#x}", xp.low)
                } else {
                    format!("({:#x} {:#x})", xp.low, xp.high)
                }
            })
            .collect::<Vec<_>>()
            .join(" ");

        let mut stmts = Vec::new();
        for src in self.src_types.iter() {
            for tgt in self.tgt_types.iter() {
                for cls in self.obj_classes.iter() {
                    stmts.push(format!(
                        "({} {} {} (permissionx ({} {} ({}))))",
                        keyword, src, tgt, cls, self.operation, xperms_str
                    ));
                }
            }
        }

        Some(stmts)
    }
}

impl ToCil for TypeRule {
    fn to_cil(&self) -> Option<Vec<String>> {
        let keyword = match self.rule_type {
            TypeRuleType::TypeTransition => "typetransition",
            TypeRuleType::TypeChange => "typechange",
            TypeRuleType::TypeMember => "typemember",
        };

        let mut stmts = Vec::new();
        for src in self.src_types.iter() {
            for tgt in self.tgt_types.iter() {
                for cls in self.obj_classes.iter() {
                    if let Some(ref name) = self.file_name {
                        // Named type transition
                        stmts.push(format!(
                            "({} {} {} {} \"{}\" {})",
                            keyword, src, tgt, cls, name, self.dest_type
                        ));
                    } else {
                        stmts.push(format!(
                            "({} {} {} {} {})",
                            keyword, src, tgt, cls, self.dest_type
                        ));
                    }
                }
            }
        }

        Some(stmts)
    }
}

impl ToCil for GenfsContext {
    fn to_cil(&self) -> Option<Vec<String>> {
        let level = self.context.level.as_deref().unwrap_or("s0");
        Some(vec![format!(
            "(genfscon {} \"{}\" ({} {} {} (({})({})))){};",
            self.filesystem,
            self.path,
            self.context.user,
            self.context.role,
            self.context.type_name,
            level,
            level,
            self.file_type
                .as_ref()
                .map(|t| format!(" {}", t))
                .unwrap_or_default()
        )])
    }
}

/// Convert an IdSet to either a simple name or an attribute with set expression.
/// Returns (name_to_use, Vec<definition_statements>)
fn idset_with_attr(idset: &IdSet, prefix: &str) -> (String, Vec<String>) {
    let mut positive: Vec<&str> = Vec::new();
    let mut excluded: Vec<&str> = Vec::new();

    for id in idset.ids.iter() {
        if let Some(stripped) = id.strip_prefix('-') {
            excluded.push(stripped);
        } else {
            positive.push(id.as_str());
        }
    }

    // Handle complement (~) flag
    if idset.complement {
        let counter = ATTR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let attr_name = format!("{}_set_{}", prefix, counter);
        let ids = positive.join(" ");
        let defs = vec![
            format!("(typeattribute {})", attr_name),
            format!("(typeattributeset {} (not ({})))", attr_name, ids),
        ];
        return (attr_name, defs);
    }

    // If no exclusions, just return the type(s) directly
    if excluded.is_empty() {
        if positive.len() == 1 {
            return (positive[0].to_string(), vec![]);
        } else {
            // For multiple positive types without exclusions, also need an attribute
            let counter = ATTR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let attr_name = format!("{}_set_{}", prefix, counter);
            let defs = vec![
                format!("(typeattribute {})", attr_name),
                format!("(typeattributeset {} ({}))", attr_name, positive.join(" ")),
            ];
            return (attr_name, defs);
        }
    }

    // Generate intermediate attribute for (and ... (not ...)) expression
    let counter = ATTR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let attr_name = format!("{}_set_{}", prefix, counter);

    let positive_expr = format!("({})", positive.join(" "));
    let excluded_expr = format!("(not ({}))", excluded.join(" "));
    let set_expr = format!("(and {} {})", positive_expr, excluded_expr);

    let defs = vec![
        format!("(typeattribute {})", attr_name),
        format!("(typeattributeset {} {})", attr_name, set_expr),
    ];

    (attr_name, defs)
}

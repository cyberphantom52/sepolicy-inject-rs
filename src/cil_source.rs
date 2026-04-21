use std::collections::{HashMap, HashSet};
use std::path::Path;

use tracing::{info, warn};

use crate::CilPolicy;
use crate::parser::ast::*;
use crate::te::parse_te_policy_from_file;

#[derive(Default)]
struct TypeNameResolver {
    exact_names: HashSet<String>,
    versioned_source_names: HashSet<String>,
    versioned_name_map: HashMap<String, String>,
}

impl TypeNameResolver {
    fn from_source(source: &str) -> Self {
        let mut resolver = Self::default();

        for line in source.lines() {
            let trimmed = line.trim_start();

            if trimmed.starts_with(';') {
                continue;
            }

            let content = trimmed
                .split_once(';')
                .map(|(before, _)| before)
                .unwrap_or(trimmed);

            for token in content.split(|ch: char| {
                !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
            }) {
                if token.is_empty() {
                    continue;
                }

                if Self::unsuffixed_android_base_name(token).is_some() {
                    resolver.versioned_source_names.insert(token.to_string());
                }
            }
        }

        resolver
    }

    fn register_policy_declarations(&mut self, policy: &Policy) {
        for stmt in &policy.statements {
            match stmt {
                Statement::Type(def) => {
                    self.register_name(&def.name);

                    for alias in CilSourcePolicy::sorted_ids(&def.aliases) {
                        if Self::is_plain_identifier(&alias) {
                            self.register_name(&alias);
                        }
                    }
                }
                Statement::TypeAlias(alias) => {
                    for alias_name in CilSourcePolicy::sorted_ids(&alias.aliases) {
                        if Self::is_plain_identifier(&alias_name) {
                            self.register_name(&alias_name);
                        }
                    }
                }
                Statement::Attribute(attr) => self.register_name(&attr.name),
                _ => {}
            }
        }
    }

    fn register_name(&mut self, name: &str) {
        if name.is_empty() {
            return;
        }

        self.exact_names.insert(name.to_string());

        if Self::unsuffixed_android_base_name(name).is_some() {
            self.versioned_source_names.insert(name.to_string());
        }
    }

    fn contains_name(&self, name: &str) -> bool {
        self.exact_names.contains(name) || self.versioned_source_names.contains(name)
    }

    fn resolve(&self, name: &str) -> String {
        if name.is_empty() {
            return String::new();
        }

        if self.exact_names.contains(name) {
            return name.to_string();
        }

        self.versioned_name_map
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }

    fn add_mapping_source(&mut self, source: &str) {
        for line in source.lines() {
            let trimmed = line.trim_start();

            if trimmed.starts_with(';') {
                continue;
            }

            let content = trimmed
                .split_once(';')
                .map(|(before, _)| before)
                .unwrap_or(trimmed)
                .trim();

            let Some((versioned_name, base_names)) = Self::parse_mapping_typeattributeset(content)
            else {
                continue;
            };

            self.versioned_source_names
                .insert(versioned_name.to_string());

            for base_name in base_names {
                self.versioned_name_map
                    .insert(base_name.to_string(), versioned_name.to_string());
            }
        }
    }

    fn helper_attr_seed(&self) -> (usize, String) {
        if let Some((counter, suffix)) = self.highest_base_typeattr() {
            return (counter + 1, suffix);
        }

        if let Some(suffix) = self.preferred_version_suffix() {
            return (1, suffix);
        }

        (1, "0_0".to_string())
    }

    fn highest_base_typeattr(&self) -> Option<(usize, String)> {
        self.versioned_source_names
            .iter()
            .filter_map(|name| Self::parse_base_typeattr_name(name))
            .max_by_key(|(counter, _)| *counter)
            .map(|(counter, suffix)| (counter, suffix.to_string()))
    }

    fn preferred_version_suffix(&self) -> Option<String> {
        let mut counts: HashMap<String, usize> = HashMap::new();

        for name in &self.versioned_source_names {
            let Some(suffix) = Self::android_version_suffix(name) else {
                continue;
            };

            *counts.entry(suffix).or_insert(0) += 1;
        }

        counts
            .into_iter()
            .max_by(|(suffix_a, count_a), (suffix_b, count_b)| {
                count_a.cmp(count_b).then_with(|| suffix_a.cmp(suffix_b))
            })
            .map(|(suffix, _)| suffix)
    }

    fn parse_base_typeattr_name(name: &str) -> Option<(usize, &str)> {
        let rest = name.strip_prefix("base_typeattr_")?;
        let (counter_str, suffix) = rest.split_once('_')?;
        let counter = counter_str.parse::<usize>().ok()?;
        let expected_suffix = Self::android_version_suffix(name)?;

        (expected_suffix == suffix && suffix.split('_').count() == 2).then_some((counter, suffix))
    }

    fn android_version_suffix(name: &str) -> Option<String> {
        let mut parts = name.rsplitn(3, '_');
        let patch = parts.next()?;
        let api = parts.next()?;
        let _base = parts.next()?;

        if api.is_empty()
            || patch.is_empty()
            || !api.chars().all(|ch| ch.is_ascii_digit())
            || !patch.chars().all(|ch| ch.is_ascii_digit())
        {
            return None;
        }

        Some(format!("{}_{}", api, patch))
    }

    fn parse_mapping_typeattributeset(content: &str) -> Option<(&str, Vec<&str>)> {
        let rest = content.strip_prefix("(typeattributeset ")?;
        let (versioned_name, expr) = rest.split_once(' ')?;

        if Self::unsuffixed_android_base_name(versioned_name).is_none() {
            return None;
        }

        let expr = expr.trim();
        let expr = expr.strip_prefix('(')?.strip_suffix("))")?.trim();

        let mut base_names = Vec::new();

        for base_name in expr.split_ascii_whitespace() {
            if !Self::is_plain_identifier(base_name) {
                return None;
            }

            base_names.push(base_name);
        }

        (!base_names.is_empty()).then_some((versioned_name, base_names))
    }

    fn unsuffixed_android_base_name(name: &str) -> Option<&str> {
        let mut parts = name.rsplitn(3, '_');
        let patch = parts.next()?;
        let api = parts.next()?;
        let base = parts.next()?;

        if base.is_empty()
            || api.is_empty()
            || patch.is_empty()
            || !api.chars().all(|ch| ch.is_ascii_digit())
            || !patch.chars().all(|ch| ch.is_ascii_digit())
        {
            return None;
        }

        Some(base)
    }

    fn is_plain_identifier(name: &str) -> bool {
        !name.is_empty() && name != "*" && !name.starts_with('-')
    }
}

/// Source-level CIL patcher.
///
/// This type keeps the original CIL text intact, renders supported parsed `.te`
/// statements back into CIL, appends those rendered patches to the source, and
/// syntax-checks the resulting file via libsepol's CIL parser.
pub struct CilSourcePolicy {
    original: String,
    generated_patches: Vec<String>,
    next_helper_attr: usize,
    helper_attr_suffix: String,
    resolver: TypeNameResolver,
}

impl CilSourcePolicy {
    /// Load an existing CIL source file and verify that it parses.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let path_display = path_ref.display().to_string();

        info!(path = %path_display, "Loading CIL source policy");

        CilPolicy::from_file(path_ref)
            .map_err(|e| format!("failed to parse CIL file {}: {}", path_display, e))?;

        let original = std::fs::read_to_string(path_ref)
            .map_err(|e| format!("failed to read CIL file {}: {}", path_display, e))?;
        let resolver = TypeNameResolver::from_source(&original);
        let (next_helper_attr, helper_attr_suffix) = resolver.helper_attr_seed();

        info!(path = %path_display, "Loaded CIL source policy");

        Ok(Self {
            original,
            generated_patches: Vec::new(),
            next_helper_attr,
            helper_attr_suffix,
            resolver,
        })
    }

    /// Load a mapping CIL file and extract simple `typeattributeset` remaps
    /// of the form:
    ///
    /// `(typeattributeset zygote_tmpfs_32_0 (zygote_tmpfs))`
    ///
    /// which means `zygote_tmpfs` should be emitted as `zygote_tmpfs_32_0`.
    pub fn load_mapping_from_file(&mut self, path: impl AsRef<Path>) -> Result<(), String> {
        let path_ref = path.as_ref();
        let path_display = path_ref.display().to_string();

        let content = std::fs::read_to_string(path_ref)
            .map_err(|e| format!("failed to read mapping CIL file {}: {}", path_display, e))?;

        self.resolver.add_mapping_source(&content);

        if self.generated_patches.is_empty() {
            let (next_helper_attr, helper_attr_suffix) = self.resolver.helper_attr_seed();
            self.next_helper_attr = next_helper_attr;
            self.helper_attr_suffix = helper_attr_suffix;
        }

        info!(path = %path_display, "Loaded CIL mapping file");
        Ok(())
    }

    /// Load multiple mapping CIL files.
    pub fn load_mapping_files<P, I>(&mut self, paths: I) -> Result<(), String>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        for path in paths {
            self.load_mapping_from_file(path)?;
        }

        Ok(())
    }

    /// Parse a `.te` file with optional M4 macro files and append a rendered CIL
    /// patch block to this source policy.
    pub fn load_rules_from_file<P, I>(
        &mut self,
        path: impl AsRef<Path>,
        macro_paths: I,
    ) -> Result<(), String>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let path_ref = path.as_ref();
        let path_display = path_ref.display().to_string();

        let policy = parse_te_policy_from_file(path_ref, macro_paths)?;
        self.resolver.register_policy_declarations(&policy);
        let patch = self.render_policy_as_patch(&policy, &path_display);

        self.generated_patches.push(patch);

        info!(
            path = %path_display,
            "Successfully rendered CIL patch from .te file"
        );

        Ok(())
    }

    /// Render the original CIL text plus every generated patch block.
    pub fn render(&self) -> String {
        let mut out = self.original.clone();

        for patch in &self.generated_patches {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
            out.push_str(patch);
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }

        out
    }

    /// Write the rendered CIL source to disk and syntax-check it by loading it
    /// through the existing `CilPolicy` parser path.
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path_ref = path.as_ref();
        let path_display = path_ref.display().to_string();
        let rendered = self.render();

        std::fs::write(path_ref, rendered)
            .map_err(|e| format!("failed to write CIL file {}: {}", path_display, e))?;

        CilPolicy::from_file(path_ref)
            .map_err(|e| format!("generated CIL failed to parse for {}: {}", path_display, e))?;

        info!(path = %path_display, "Wrote patched CIL policy to file");
        Ok(())
    }

    fn render_policy_as_patch(&mut self, policy: &Policy, source_name: &str) -> String {
        let mut lines = Vec::new();

        lines.push(format!(
            "; BEGIN generated by sepolicy-inject-rs from {}",
            source_name
        ));

        for stmt in &policy.statements {
            self.render_statement(stmt, &mut lines);
        }

        lines.push(format!(
            "; END generated by sepolicy-inject-rs from {}",
            source_name
        ));

        lines.join("\n")
    }

    fn render_statement(&mut self, stmt: &Statement, out: &mut Vec<String>) {
        match stmt {
            Statement::Type(def) => self.render_type_def(def, out),
            Statement::TypeAlias(alias) => self.render_type_alias(alias, out),
            Statement::Attribute(attr) => out.push(format!(
                "(typeattribute {})",
                self.resolver.resolve(&attr.name)
            )),
            Statement::ExpandAttribute(attr) => out.push(format!(
                "(expandtypeattribute ({}) {})",
                self.resolver.resolve(&attr.attribute),
                if attr.expand { "true" } else { "false" }
            )),
            Statement::TypeAttribute(ta) => self.render_typeattribute(ta, out),
            Statement::AVRule(rule) => self.render_avrule(rule, out),
            Statement::AVXRule(rule) => self.render_avxrule(rule, out),
            Statement::TypeRule(rule) => self.render_typerule(rule, out),
            Statement::Permissive(p) => out.push(format!("(typepermissive {})", p.type_name)),
            Statement::InitialSid(sid) => self.render_initial_sid(sid, out),
            Statement::GenfsContext(genfs) => self.render_genfscon(genfs, out),
            Statement::FsUse(fs_use) => self.render_fsuse(fs_use, out),
            Statement::PortCon(portcon) => self.render_portcon(portcon, out),
            Statement::NodeCon(nodecon) => self.render_nodecon(nodecon, out),
            Statement::NetifCon(netifcon) => self.render_netifcon(netifcon, out),
            Statement::PirqCon(pirqcon) => self.render_pirqcon(pirqcon, out),
            Statement::IomemCon(iomemcon) => self.render_iomemcon(iomemcon, out),
            Statement::IoportCon(ioportcon) => self.render_ioportcon(ioportcon, out),
            Statement::PciDeviceCon(pcidevicecon) => self.render_pcidevicecon(pcidevicecon, out),
            Statement::DevicetreeCon(devicetreecon) => {
                self.render_devicetreecon(devicetreecon, out)
            }
            unsupported => {
                warn!(
                    statement = ?unsupported,
                    "Skipping unsupported statement during CIL patch rendering"
                );
            }
        }
    }

    fn render_type_def(&mut self, def: &TypeDef, out: &mut Vec<String>) {
        let type_name = self.resolver.resolve(&def.name);

        out.push(format!("(type {})", type_name));
        out.push(format!("(roletype object_r {})", type_name));

        if def.aliases.complement {
            warn!(
                type_name = %def.name,
                aliases = ?def.aliases,
                "Skipping complemented aliases in type definition during CIL patch rendering"
            );
        }

        for alias in Self::sorted_ids(&def.aliases) {
            if !Self::is_plain_identifier(&alias) {
                warn!(
                    type_name = %def.name,
                    alias = %alias,
                    "Skipping unsupported type alias entry during CIL patch rendering"
                );
                continue;
            }

            let alias_name = self.resolver.resolve(&alias);

            out.push(format!("(typealias {})", alias_name));
            out.push(format!("(typealiasactual {} {})", alias_name, type_name));
        }

        if def.attributes.complement {
            warn!(
                type_name = %def.name,
                attributes = ?def.attributes,
                "Skipping complemented type attributes in type definition during CIL patch rendering"
            );
        }

        for attr in Self::sorted_ids(&def.attributes) {
            if !Self::is_plain_identifier(&attr) {
                warn!(
                    type_name = %def.name,
                    attribute = %attr,
                    "Skipping unsupported type attribute entry during CIL patch rendering"
                );
                continue;
            }

            let attr_name = self.resolver.resolve(&attr);

            out.push(format!("(typeattributeset {} ({}))", attr_name, type_name));
        }
    }

    fn render_type_alias(&mut self, alias: &TypeAlias, out: &mut Vec<String>) {
        let type_name = self.resolver.resolve(&alias.type_name);

        if alias.aliases.complement {
            warn!(
                type_name = %alias.type_name,
                aliases = ?alias.aliases,
                "Skipping complemented type aliases during CIL patch rendering"
            );
        }

        for alias_name in Self::sorted_ids(&alias.aliases) {
            if !Self::is_plain_identifier(&alias_name) {
                warn!(
                    type_name = %alias.type_name,
                    alias = %alias_name,
                    "Skipping unsupported type alias entry during CIL patch rendering"
                );
                continue;
            }

            let resolved_alias_name = self.resolver.resolve(&alias_name);

            out.push(format!("(typealias {})", resolved_alias_name));
            out.push(format!(
                "(typealiasactual {} {})",
                resolved_alias_name, type_name
            ));
        }
    }

    fn render_typeattribute(&mut self, ta: &TypeAttribute, out: &mut Vec<String>) {
        let type_name = self.resolver.resolve(&ta.type_name);

        if ta.attributes.complement {
            warn!(
                type_name = %ta.type_name,
                attributes = ?ta.attributes,
                "Skipping complemented typeattribute statement during CIL patch rendering"
            );
        }

        for attr in Self::sorted_ids(&ta.attributes) {
            if !Self::is_plain_identifier(&attr) {
                warn!(
                    type_name = %ta.type_name,
                    attribute = %attr,
                    "Skipping unsupported typeattribute entry during CIL patch rendering"
                );
                continue;
            }

            let attr_name = self.resolver.resolve(&attr);

            out.push(format!("(typeattributeset {} ({}))", attr_name, type_name));
        }
    }

    fn render_avrule(&mut self, rule: &AVRule, out: &mut Vec<String>) {
        let flavor = match rule.rule_type {
            AVRuleType::Allow => "allow",
            AVRuleType::Dontaudit => "dontaudit",
            AVRuleType::Auditallow => "auditallow",
            AVRuleType::Neverallow => "neverallow",
        };

        let Some(src) = self.render_type_ref(&rule.src_types, out, false) else {
            warn!(
                rule = ?rule,
                "Skipping AV rule with unsupported source type set during CIL patch rendering"
            );
            return;
        };

        let Some(tgt) = self.render_type_ref(&rule.tgt_types, out, true) else {
            warn!(
                rule = ?rule,
                "Skipping AV rule with unsupported target type set during CIL patch rendering"
            );
            return;
        };

        let Some(classes) = self.render_class_names(&rule.obj_classes) else {
            warn!(
                rule = ?rule,
                "Skipping AV rule with unsupported class set during CIL patch rendering"
            );
            return;
        };

        let Some(perms) = self.render_id_expression(&rule.perms, false) else {
            warn!(
                rule = ?rule,
                "Skipping AV rule with unsupported permission set during CIL patch rendering"
            );
            return;
        };

        for class_name in classes {
            out.push(format!(
                "({} {} {} ({} {}))",
                flavor, src, tgt, class_name, perms
            ));
        }
    }

    fn render_avxrule(&mut self, rule: &AVXRule, out: &mut Vec<String>) {
        let flavor = match rule.rule_type {
            AVRuleType::Allow => "allowx",
            AVRuleType::Dontaudit => "dontauditx",
            AVRuleType::Auditallow => "auditallowx",
            AVRuleType::Neverallow => "neverallowx",
        };

        let Some(src) = self.render_type_ref(&rule.src_types, out, false) else {
            warn!(
                rule = ?rule,
                "Skipping AVX rule with unsupported source type set during CIL patch rendering"
            );
            return;
        };

        let Some(tgt) = self.render_type_ref(&rule.tgt_types, out, true) else {
            warn!(
                rule = ?rule,
                "Skipping AVX rule with unsupported target type set during CIL patch rendering"
            );
            return;
        };

        let Some(classes) = self.render_class_names(&rule.obj_classes) else {
            warn!(
                rule = ?rule,
                "Skipping AVX rule with unsupported class set during CIL patch rendering"
            );
            return;
        };

        if rule.operation.trim().is_empty() {
            warn!(
                rule = ?rule,
                "Skipping AVX rule with empty operation during CIL patch rendering"
            );
            return;
        }

        for class_name in classes {
            for xperm in &rule.xperms {
                let xperm_expr = if xperm.low == xperm.high {
                    format!("(0x{:X})", xperm.low)
                } else {
                    format!("(range 0x{:X} 0x{:X})", xperm.low, xperm.high)
                };

                out.push(format!(
                    "({} {} {} ({} {} {}))",
                    flavor, src, tgt, rule.operation, class_name, xperm_expr
                ));
            }
        }
    }

    fn render_typerule(&mut self, rule: &TypeRule, out: &mut Vec<String>) {
        let flavor = match rule.rule_type {
            TypeRuleType::TypeTransition => "typetransition",
            TypeRuleType::TypeChange => "typechange",
            TypeRuleType::TypeMember => "typemember",
        };

        let Some(src) = self.render_type_ref(&rule.src_types, out, false) else {
            warn!(
                rule = ?rule,
                "Skipping type rule with unsupported source type set during CIL patch rendering"
            );
            return;
        };

        let Some(tgt) = self.render_type_ref(&rule.tgt_types, out, false) else {
            warn!(
                rule = ?rule,
                "Skipping type rule with unsupported target type set during CIL patch rendering"
            );
            return;
        };

        let Some(classes) = self.render_class_names(&rule.obj_classes) else {
            warn!(
                rule = ?rule,
                "Skipping type rule with unsupported class set during CIL patch rendering"
            );
            return;
        };

        let dest_type = self.resolver.resolve(&rule.dest_type);

        for class_name in classes {
            match rule.rule_type {
                TypeRuleType::TypeTransition => {
                    if let Some(file_name) = rule.file_name.as_deref().filter(|s| !s.is_empty()) {
                        out.push(format!(
                            "({} {} {} {} \"{}\" {})",
                            flavor,
                            src,
                            tgt,
                            class_name,
                            Self::escape_cil_string(file_name),
                            dest_type
                        ));
                    } else {
                        out.push(format!(
                            "({} {} {} {} {})",
                            flavor, src, tgt, class_name, dest_type
                        ));
                    }
                }
                TypeRuleType::TypeChange | TypeRuleType::TypeMember => {
                    out.push(format!(
                        "({} {} {} {} {})",
                        flavor, src, tgt, class_name, dest_type
                    ));
                }
            }
        }
    }

    fn render_initial_sid(&mut self, sid: &InitialSid, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&sid.context) else {
            warn!(
                sid = %sid.name,
                context = ?sid.context,
                "Skipping initial sid with unsupported context during CIL patch rendering"
            );
            return;
        };

        out.push(format!("(sid {})", sid.name));
        out.push(format!("(sidcontext {} {})", sid.name, context));
    }

    fn render_genfscon(&mut self, genfs: &GenfsContext, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&genfs.context) else {
            warn!(
                genfs = ?genfs,
                "Skipping genfscon with unsupported context during CIL patch rendering"
            );
            return;
        };

        match genfs.file_type.as_deref().filter(|s| !s.is_empty()) {
            Some(file_type) => out.push(format!(
                "(genfscon {} {} {} {})",
                genfs.filesystem, genfs.path, file_type, context
            )),
            None => out.push(format!(
                "(genfscon {} {} {})",
                genfs.filesystem, genfs.path, context
            )),
        }
    }

    fn render_fsuse(&mut self, fs_use: &FsUse, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&fs_use.context) else {
            warn!(
                fs_use = ?fs_use,
                "Skipping fsuse with unsupported context during CIL patch rendering"
            );
            return;
        };

        let flavor = match fs_use.use_type {
            FsUseType::Xattr => "xattr",
            FsUseType::Task => "task",
            FsUseType::Trans => "trans",
        };

        out.push(format!(
            "(fsuse {} {} {})",
            flavor, fs_use.filesystem, context
        ));
    }

    fn render_portcon(&mut self, portcon: &PortCon, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&portcon.context) else {
            warn!(
                portcon = ?portcon,
                "Skipping portcon with unsupported context during CIL patch rendering"
            );
            return;
        };

        out.push(format!(
            "(portcon {} {} {})",
            portcon.port_type, portcon.port_number, context
        ));
    }

    fn render_nodecon(&mut self, nodecon: &NodeCon, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&nodecon.context) else {
            warn!(
                nodecon = ?nodecon,
                "Skipping nodecon with unsupported context during CIL patch rendering"
            );
            return;
        };

        out.push(format!(
            "(nodecon {} {} {})",
            nodecon.start, nodecon.end, context
        ));
    }

    fn render_netifcon(&mut self, netifcon: &NetifCon, out: &mut Vec<String>) {
        let Some(interface_context) = self.render_context(&netifcon.interface_context) else {
            warn!(
                netifcon = ?netifcon,
                "Skipping netifcon with unsupported interface context during CIL patch rendering"
            );
            return;
        };

        let Some(packet_context) = self.render_context(&netifcon.packet_context) else {
            warn!(
                netifcon = ?netifcon,
                "Skipping netifcon with unsupported packet context during CIL patch rendering"
            );
            return;
        };

        out.push(format!(
            "(netifcon {} {} {})",
            netifcon.interface, interface_context, packet_context
        ));
    }

    fn render_pirqcon(&mut self, pirqcon: &PirqCon, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&pirqcon.context) else {
            warn!(
                pirqcon = ?pirqcon,
                "Skipping pirqcon with unsupported context during CIL patch rendering"
            );
            return;
        };

        out.push(format!("(pirqcon {} {})", pirqcon.pirq_number, context));
    }

    fn render_iomemcon(&mut self, iomemcon: &IomemCon, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&iomemcon.context) else {
            warn!(
                iomemcon = ?iomemcon,
                "Skipping iomemcon with unsupported context during CIL patch rendering"
            );
            return;
        };

        out.push(format!("(iomemcon {} {})", iomemcon.device_mem, context));
    }

    fn render_ioportcon(&mut self, ioportcon: &IoportCon, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&ioportcon.context) else {
            warn!(
                ioportcon = ?ioportcon,
                "Skipping ioportcon with unsupported context during CIL patch rendering"
            );
            return;
        };

        out.push(format!("(ioportcon {} {})", ioportcon.ioport, context));
    }

    fn render_pcidevicecon(&mut self, pcidevicecon: &PciDeviceCon, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&pcidevicecon.context) else {
            warn!(
                pcidevicecon = ?pcidevicecon,
                "Skipping pcidevicecon with unsupported context during CIL patch rendering"
            );
            return;
        };

        out.push(format!(
            "(pcidevicecon {} {})",
            pcidevicecon.device, context
        ));
    }

    fn render_devicetreecon(&mut self, devicetreecon: &DevicetreeCon, out: &mut Vec<String>) {
        let Some(context) = self.render_context(&devicetreecon.context) else {
            warn!(
                devicetreecon = ?devicetreecon,
                "Skipping devicetreecon with unsupported context during CIL patch rendering"
            );
            return;
        };

        out.push(format!(
            "(devicetreecon {} {})",
            devicetreecon.path, context
        ));
    }

    fn render_type_ref(
        &mut self,
        set: &IdSet,
        out: &mut Vec<String>,
        allow_special_target: bool,
    ) -> Option<String> {
        if let Some(direct) = self.direct_type_ref(set, allow_special_target) {
            return Some(direct);
        }

        let expr = self.render_id_expression(set, true)?;
        let helper = self.next_helper_attr_name();

        out.push(format!("(typeattribute {})", helper));
        out.push(format!("(typeattributeset {} {})", helper, expr));

        Some(helper)
    }

    fn direct_type_ref(&self, set: &IdSet, allow_special_target: bool) -> Option<String> {
        if set.complement {
            return None;
        }

        let ids = Self::sorted_ids(set);
        if ids.len() != 1 {
            return None;
        }

        let id = ids[0].as_str();

        if id.starts_with('-') || id == "*" {
            return None;
        }

        if Self::is_special_target_keyword(id) {
            return allow_special_target.then(|| ids[0].clone());
        }

        Some(self.resolver.resolve(id))
    }

    fn render_class_names(&self, set: &IdSet) -> Option<Vec<String>> {
        if set.complement {
            return None;
        }

        let mut classes = Vec::new();

        for id in Self::sorted_ids(set) {
            if !Self::is_plain_identifier(&id) {
                return None;
            }
            classes.push(id);
        }

        if classes.is_empty() {
            None
        } else {
            Some(classes)
        }
    }

    fn render_id_expression(&self, set: &IdSet, for_type_expression: bool) -> Option<String> {
        let mut positives = Vec::new();
        let mut negatives = Vec::new();
        let mut has_all = false;

        for id in Self::sorted_ids(set) {
            if id == "*" {
                has_all = true;
                continue;
            }

            if let Some(stripped) = id.strip_prefix('-') {
                if stripped.is_empty() {
                    return None;
                }
                if for_type_expression && Self::is_special_target_keyword(stripped) {
                    return None;
                }

                let resolved = if for_type_expression {
                    self.resolver.resolve(stripped)
                } else {
                    stripped.to_string()
                };

                negatives.push(resolved);
                continue;
            }

            if for_type_expression && Self::is_special_target_keyword(&id) {
                return None;
            }

            let resolved = if for_type_expression {
                self.resolver.resolve(&id)
            } else {
                id
            };

            positives.push(resolved);
        }

        let mut expr = if has_all {
            "(all)".to_string()
        } else if !positives.is_empty() {
            format!("({})", positives.join(" "))
        } else if !negatives.is_empty() {
            "(all)".to_string()
        } else {
            return None;
        };

        if !negatives.is_empty() {
            expr = format!("(and {} (not ({})))", expr, negatives.join(" "));
        }

        if set.complement {
            expr = format!("(not {})", expr);
        }

        Some(expr)
    }

    fn render_context(&self, context: &SecurityContext) -> Option<String> {
        if context.user.is_empty() || context.role.is_empty() || context.type_name.is_empty() {
            return None;
        }

        let type_name = self.resolver.resolve(&context.type_name);
        let mut rendered = format!("({} {} {}", context.user, context.role, type_name);

        if let Some(level) = context.level.as_deref().filter(|s| !s.trim().is_empty()) {
            rendered.push(' ');
            rendered.push_str(&Self::render_mls_range(level));
        }

        rendered.push(')');
        Some(rendered)
    }

    fn render_mls_range(range: &str) -> String {
        let trimmed = range.trim();

        if let Some((low, high)) = trimmed.split_once('-') {
            format!(
                "({} {})",
                Self::render_mls_level(low.trim()),
                Self::render_mls_level(high.trim())
            )
        } else {
            Self::render_mls_level(trimmed)
        }
    }

    fn render_mls_level(level: &str) -> String {
        let trimmed = level.trim();

        if let Some((sens, cats)) = trimmed.split_once(':') {
            let categories = cats
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
                .join(" ");

            if categories.is_empty() {
                format!("({})", sens.trim())
            } else {
                format!("({} ({}))", sens.trim(), categories)
            }
        } else {
            format!("({})", trimmed)
        }
    }

    fn next_helper_attr_name(&mut self) -> String {
        loop {
            let name = format!(
                "base_typeattr_{}_{}",
                self.next_helper_attr, self.helper_attr_suffix
            );
            self.next_helper_attr += 1;

            if !self.resolver.contains_name(&name) {
                self.resolver.register_name(&name);
                return name;
            }
        }
    }

    fn sorted_ids(set: &IdSet) -> Vec<String> {
        let mut ids = set.ids.iter().cloned().collect::<Vec<_>>();
        ids.sort();
        ids
    }

    fn is_plain_identifier(id: &str) -> bool {
        !id.is_empty() && id != "*" && !id.starts_with('-')
    }

    fn is_special_target_keyword(id: &str) -> bool {
        matches!(id, "self" | "other" | "notself")
    }

    fn escape_cil_string(value: &str) -> String {
        value.replace('\\', "\\\\").replace('"', "\\\"")
    }
}

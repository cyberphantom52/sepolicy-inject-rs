use super::ast::*;
use crate::ffi::XPerm;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::warn;

/// Trait for types that can be converted to CIL format.
pub trait ToCil {
    fn to_cil(&self) -> Option<Vec<String>>;
}

static NEXT_TYPE_HELPER_ATTR: AtomicUsize = AtomicUsize::new(1);

impl ToCil for Policy {
    fn to_cil(&self) -> Option<Vec<String>> {
        let mut lines = Vec::new();

        for stmt in &self.statements {
            lines.extend(stmt.to_cil()?);
        }

        Some(lines)
    }
}

impl ToCil for Statement {
    fn to_cil(&self) -> Option<Vec<String>> {
        match self {
            Statement::ModuleDecl(module) => module.to_cil(),
            Statement::Type(def) => def.to_cil(),
            Statement::TypeAlias(alias) => alias.to_cil(),
            Statement::Attribute(attr) => attr.to_cil(),
            Statement::ExpandAttribute(expand) => expand.to_cil(),
            Statement::TypeAttribute(ta) => ta.to_cil(),
            Statement::AVRule(rule) => rule.to_cil(),
            Statement::AVXRule(rule) => rule.to_cil(),
            Statement::TypeRule(rule) => rule.to_cil(),
            Statement::Permissive(permissive) => permissive.to_cil(),
            Statement::InitialSid(sid) => sid.to_cil(),
            Statement::GenfsContext(genfs) => genfs.to_cil(),
            Statement::FsUse(fs_use) => fs_use.to_cil(),
            Statement::PortCon(portcon) => portcon.to_cil(),
            Statement::NodeCon(nodecon) => nodecon.to_cil(),
            Statement::NetifCon(netifcon) => netifcon.to_cil(),
            Statement::PirqCon(pirqcon) => pirqcon.to_cil(),
            Statement::IomemCon(iomemcon) => iomemcon.to_cil(),
            Statement::IoportCon(ioportcon) => ioportcon.to_cil(),
            Statement::PciDeviceCon(pcidevicecon) => pcidevicecon.to_cil(),
            Statement::DevicetreeCon(devicetreecon) => devicetreecon.to_cil(),
            _ => {
                warn!(
                    statement = ?self,
                    "Skipping unsupported statement during CIL rendering"
                );
                Some(Vec::new())
            }
        }
    }
}

impl ToCil for ModuleDecl {
    fn to_cil(&self) -> Option<Vec<String>> {
        Some(vec![format!("; module {} {}", self.name, self.version)])
    }
}

impl ToCil for TypeDef {
    fn to_cil(&self) -> Option<Vec<String>> {
        let mut lines = vec![
            format!("(type {})", self.name),
            format!("(roletype object_r {})", self.name),
        ];

        if self.aliases.complement {
            warn!(
                type_name = %self.name,
                aliases = ?self.aliases,
                "Skipping complemented aliases in type definition during CIL rendering"
            );
        }

        for alias in self.aliases.iter() {
            if !is_plain_identifier(alias) {
                warn!(
                    type_name = %self.name,
                    alias = %alias,
                    "Skipping unsupported type alias entry during CIL rendering"
                );
                continue;
            }

            lines.push(format!("(typealias {})", alias));
            lines.push(format!("(typealiasactual {} {})", alias, self.name));
        }

        if self.attributes.complement {
            warn!(
                type_name = %self.name,
                attributes = ?self.attributes,
                "Skipping complemented type attributes in type definition during CIL rendering"
            );
        }

        for attr in self.attributes.iter() {
            if !is_plain_identifier(attr) {
                warn!(
                    type_name = %self.name,
                    attribute = %attr,
                    "Skipping unsupported type attribute entry during CIL rendering"
                );
                continue;
            }

            lines.push(format!("(typeattributeset {} ({}))", attr, self.name));
        }

        Some(lines)
    }
}

impl ToCil for TypeAlias {
    fn to_cil(&self) -> Option<Vec<String>> {
        let mut lines = Vec::new();

        if self.aliases.complement {
            warn!(
                type_name = %self.type_name,
                aliases = ?self.aliases,
                "Skipping complemented type aliases during CIL rendering"
            );
        }

        for alias in self.aliases.iter() {
            if !is_plain_identifier(alias) {
                warn!(
                    type_name = %self.type_name,
                    alias = %alias,
                    "Skipping unsupported type alias entry during CIL rendering"
                );
                continue;
            }

            lines.push(format!("(typealias {})", alias));
            lines.push(format!("(typealiasactual {} {})", alias, self.type_name));
        }

        Some(lines)
    }
}

impl ToCil for Attribute {
    fn to_cil(&self) -> Option<Vec<String>> {
        Some(vec![format!("(typeattribute {})", self.name)])
    }
}

impl ToCil for ExpandAttribute {
    fn to_cil(&self) -> Option<Vec<String>> {
        Some(vec![format!(
            "(expandtypeattribute ({}) {})",
            self.attribute,
            if self.expand { "true" } else { "false" }
        )])
    }
}

impl ToCil for TypeAttribute {
    fn to_cil(&self) -> Option<Vec<String>> {
        let mut lines = Vec::new();

        if self.attributes.complement {
            warn!(
                type_name = %self.type_name,
                attributes = ?self.attributes,
                "Skipping complemented typeattribute statement during CIL rendering"
            );
        }

        for attr in self.attributes.iter() {
            if !is_plain_identifier(attr) {
                warn!(
                    type_name = %self.type_name,
                    attribute = %attr,
                    "Skipping unsupported typeattribute entry during CIL rendering"
                );
                continue;
            }

            lines.push(format!("(typeattributeset {} ({}))", attr, self.type_name));
        }

        Some(lines)
    }
}

impl ToCil for AVRule {
    fn to_cil(&self) -> Option<Vec<String>> {
        let rule_type = match self.rule_type {
            AVRuleType::Allow => "allow",
            AVRuleType::Dontaudit => "dontaudit",
            AVRuleType::Auditallow => "auditallow",
            AVRuleType::Neverallow => "neverallow",
        };

        let mut lines = Vec::new();

        let Some((src, src_defs)) = render_type_ref(&self.src_types, false) else {
            warn!(
                rule = ?self,
                "Skipping AV rule with unsupported source type set during CIL rendering"
            );
            return None;
        };

        let Some((tgt, tgt_defs)) = render_type_ref(&self.tgt_types, true) else {
            warn!(
                rule = ?self,
                "Skipping AV rule with unsupported target type set during CIL rendering"
            );
            return None;
        };

        let Some(classes) = render_class_names(&self.obj_classes) else {
            warn!(
                rule = ?self,
                "Skipping AV rule with unsupported class set during CIL rendering"
            );
            return None;
        };

        let Some(perms) = render_id_expression(&self.perms, false) else {
            warn!(
                rule = ?self,
                "Skipping AV rule with unsupported permission set during CIL rendering"
            );
            return None;
        };

        lines.extend(src_defs);
        lines.extend(tgt_defs);

        for class_name in classes {
            lines.push(format!(
                "({} {} {} ({} {}))",
                rule_type, src, tgt, class_name, perms
            ));
        }

        Some(lines)
    }
}

impl ToCil for AVXRule {
    fn to_cil(&self) -> Option<Vec<String>> {
        let rule_type = match self.rule_type {
            AVRuleType::Allow => "allowx",
            AVRuleType::Dontaudit => "dontauditx",
            AVRuleType::Auditallow => "auditallowx",
            AVRuleType::Neverallow => "neverallowx",
        };

        let mut lines = Vec::new();

        let Some((src, src_defs)) = render_type_ref(&self.src_types, false) else {
            warn!(
                rule = ?self,
                "Skipping AVX rule with unsupported source type set during CIL rendering"
            );
            return None;
        };

        let Some((tgt, tgt_defs)) = render_type_ref(&self.tgt_types, true) else {
            warn!(
                rule = ?self,
                "Skipping AVX rule with unsupported target type set during CIL rendering"
            );
            return None;
        };

        let Some(classes) = render_class_names(&self.obj_classes) else {
            warn!(
                rule = ?self,
                "Skipping AVX rule with unsupported class set during CIL rendering"
            );
            return None;
        };

        if self.operation.trim().is_empty() {
            warn!(
                rule = ?self,
                "Skipping AVX rule with empty operation during CIL rendering"
            );
            return None;
        }

        lines.extend(src_defs);
        lines.extend(tgt_defs);

        for class_name in classes {
            for xperm in &self.xperms {
                lines.push(format!(
                    "({} {} {} ({} {} {}))",
                    rule_type,
                    src,
                    tgt,
                    self.operation,
                    class_name,
                    render_xperm(xperm)
                ));
            }
        }

        Some(lines)
    }
}

impl ToCil for TypeRule {
    fn to_cil(&self) -> Option<Vec<String>> {
        let rule_type = match self.rule_type {
            TypeRuleType::TypeTransition => "typetransition",
            TypeRuleType::TypeChange => "typechange",
            TypeRuleType::TypeMember => "typemember",
        };

        let mut lines = Vec::new();

        let Some((src, src_defs)) = render_type_ref(&self.src_types, false) else {
            warn!(
                rule = ?self,
                "Skipping type rule with unsupported source type set during CIL rendering"
            );
            return None;
        };

        let Some((tgt, tgt_defs)) = render_type_ref(&self.tgt_types, false) else {
            warn!(
                rule = ?self,
                "Skipping type rule with unsupported target type set during CIL rendering"
            );
            return None;
        };

        let Some(classes) = render_class_names(&self.obj_classes) else {
            warn!(
                rule = ?self,
                "Skipping type rule with unsupported class set during CIL rendering"
            );
            return None;
        };

        lines.extend(src_defs);
        lines.extend(tgt_defs);

        for class_name in classes {
            match (self.rule_type, self.file_name.as_deref()) {
                (TypeRuleType::TypeTransition, Some(file_name)) if !file_name.is_empty() => {
                    lines.push(format!(
                        "({} {} {} {} \"{}\" {})",
                        rule_type,
                        src,
                        tgt,
                        class_name,
                        escape_cil_string(file_name),
                        self.dest_type
                    ));
                }
                _ => {
                    lines.push(format!(
                        "({} {} {} {} {})",
                        rule_type, src, tgt, class_name, self.dest_type
                    ));
                }
            }
        }

        Some(lines)
    }
}

impl ToCil for Permissive {
    fn to_cil(&self) -> Option<Vec<String>> {
        Some(vec![format!("(permissive {})", self.type_name)])
    }
}

impl ToCil for InitialSid {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;
        Some(vec![
            format!("(sid {})", self.name),
            format!("(sidcontext {} {})", self.name, context),
        ])
    }
}

impl ToCil for GenfsContext {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;

        match self.file_type.as_deref().filter(|s| !s.is_empty()) {
            Some(file_type) => Some(vec![format!(
                "(genfscon {} {} {} {})",
                self.filesystem,
                render_path_atom(&self.path),
                file_type,
                context
            )]),
            None => Some(vec![format!(
                "(genfscon {} {} {})",
                self.filesystem,
                render_path_atom(&self.path),
                context
            )]),
        }
    }
}

impl ToCil for FsUse {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;
        Some(vec![format!(
            "(fsuse {} {} {})",
            match self.use_type {
                FsUseType::Xattr => "xattr",
                FsUseType::Task => "task",
                FsUseType::Trans => "trans",
            },
            self.filesystem,
            context
        )])
    }
}

impl ToCil for PortCon {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;
        Some(vec![format!(
            "(portcon {} {} {})",
            self.port_type,
            render_number_or_range(&self.port_number),
            context
        )])
    }
}

impl ToCil for NodeCon {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;
        Some(vec![format!(
            "(nodecon {} {} {})",
            render_ipaddr_atom(&self.start),
            render_ipaddr_atom(&self.end),
            context
        )])
    }
}

impl ToCil for NetifCon {
    fn to_cil(&self) -> Option<Vec<String>> {
        let interface_context = render_context(&self.interface_context)?;
        let packet_context = render_context(&self.packet_context)?;
        Some(vec![format!(
            "(netifcon {} {} {})",
            self.interface, interface_context, packet_context
        )])
    }
}

impl ToCil for PirqCon {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;
        Some(vec![format!("(pirqcon {} {})", self.pirq_number, context)])
    }
}

impl ToCil for IomemCon {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;
        Some(vec![format!(
            "(iomemcon {} {})",
            render_number_or_range(&self.device_mem),
            context
        )])
    }
}

impl ToCil for IoportCon {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;
        Some(vec![format!(
            "(ioportcon {} {})",
            render_number_or_range(&self.ioport),
            context
        )])
    }
}

impl ToCil for PciDeviceCon {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;
        Some(vec![format!("(pcidevicecon {} {})", self.device, context)])
    }
}

impl ToCil for DevicetreeCon {
    fn to_cil(&self) -> Option<Vec<String>> {
        let context = render_context(&self.context)?;
        Some(vec![format!(
            "(devicetreecon {} {})",
            render_path_atom(&self.path),
            context
        )])
    }
}

impl ToCil for IdSet {
    fn to_cil(&self) -> Option<Vec<String>> {
        render_id_expression(self, false).map(|expr| vec![expr])
    }
}

impl ToCil for SecurityContext {
    fn to_cil(&self) -> Option<Vec<String>> {
        render_context(self).map(|context| vec![context])
    }
}

impl ToCil for XPerm {
    fn to_cil(&self) -> Option<Vec<String>> {
        Some(vec![render_xperm(self)])
    }
}

fn is_plain_identifier(id: &str) -> bool {
    !id.is_empty() && id != "*" && !id.starts_with('-')
}

fn is_special_target_keyword(id: &str) -> bool {
    matches!(id, "self" | "other" | "notself")
}

fn direct_type_ref(set: &IdSet, allow_special_target: bool) -> Option<String> {
    if set.complement || set.ids.len() != 1 {
        return None;
    }

    let id = set.iter().next()?;

    if id == "*" || id.starts_with('-') {
        return None;
    }

    if is_special_target_keyword(id) {
        return allow_special_target.then(|| id.clone());
    }

    Some(id.clone())
}

fn next_type_helper_attr_name() -> String {
    let counter = NEXT_TYPE_HELPER_ATTR.fetch_add(1, Ordering::Relaxed);
    format!("base_typeattr_{}", counter)
}

fn render_type_ref(set: &IdSet, allow_special_target: bool) -> Option<(String, Vec<String>)> {
    if let Some(direct) = direct_type_ref(set, allow_special_target) {
        return Some((direct, Vec::new()));
    }

    let expr = render_id_expression(set, true)?;
    let helper = next_type_helper_attr_name();

    Some((
        helper.clone(),
        vec![
            format!("(typeattribute {})", helper),
            format!("(typeattributeset {} {})", helper, expr),
        ],
    ))
}

fn render_class_names(set: &IdSet) -> Option<Vec<String>> {
    if set.complement {
        return None;
    }

    let mut classes = Vec::new();

    for id in set.iter() {
        if !is_plain_identifier(id) {
            return None;
        }
        classes.push(id.clone());
    }

    if classes.is_empty() {
        None
    } else {
        Some(classes)
    }
}

fn render_id_expression(set: &IdSet, reject_special_target_keywords: bool) -> Option<String> {
    let mut positives = Vec::new();
    let mut negatives = Vec::new();
    let mut has_all = false;

    for id in set.iter() {
        if id == "*" {
            has_all = true;
            continue;
        }

        if let Some(stripped) = id.strip_prefix('-') {
            if stripped.is_empty() {
                return None;
            }

            if reject_special_target_keywords && is_special_target_keyword(stripped) {
                return None;
            }

            negatives.push(stripped.to_string());
            continue;
        }

        if reject_special_target_keywords && is_special_target_keyword(id) {
            return None;
        }

        positives.push(id.clone());
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

fn render_context(context: &SecurityContext) -> Option<String> {
    if context.user.is_empty() || context.role.is_empty() || context.type_name.is_empty() {
        return None;
    }

    let mut rendered = format!("({} {} {}", context.user, context.role, context.type_name);

    if let Some(level) = context.level.as_deref().filter(|s| !s.trim().is_empty()) {
        rendered.push(' ');
        rendered.push_str(&render_context_mls_range(level));
    }

    rendered.push(')');
    Some(rendered)
}

fn render_context_mls_range(range: &str) -> String {
    let trimmed = range.trim();

    if let Some((low, high)) = trimmed.split_once('-') {
        format!(
            "{} {}",
            render_level_or_name(low.trim()),
            render_level_or_name(high.trim())
        )
    } else {
        render_level_or_name(trimmed)
    }
}

fn render_level_or_name(level: &str) -> String {
    let trimmed = level.trim();

    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        return trimmed.to_string();
    }

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
    } else if looks_like_sensitivity(trimmed) {
        format!("({})", trimmed)
    } else {
        trimmed.to_string()
    }
}

fn looks_like_sensitivity(level: &str) -> bool {
    if let Some(rest) = level.strip_prefix('s') {
        !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit())
    } else {
        false
    }
}

fn render_xperm(xperm: &XPerm) -> String {
    if xperm.low == xperm.high {
        format!("(0x{:X})", xperm.low)
    } else {
        format!("(range 0x{:X} 0x{:X})", xperm.low, xperm.high)
    }
}

fn render_number_or_range(value: &str) -> String {
    let trimmed = value.trim();

    if let Some((start, end)) = trimmed.split_once('-') {
        format!("({} {})", start.trim(), end.trim())
    } else {
        trimmed.to_string()
    }
}

fn render_ipaddr_atom(value: &str) -> String {
    let trimmed = value.trim();

    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        trimmed.to_string()
    } else if trimmed.contains('.') || trimmed.contains(':') {
        format!("({})", trimmed)
    } else {
        trimmed.to_string()
    }
}

fn render_path_atom(path: &str) -> String {
    let trimmed = path.trim();

    if trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed.to_string()
    } else if trimmed.contains('/') || trimmed.contains(' ') {
        format!("\"{}\"", escape_cil_string(trimmed))
    } else {
        trimmed.to_string()
    }
}

fn escape_cil_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

//! The part of a compiled policy that concerns some of its types and
//! attributes, as `.te` statements another policy can be patched with.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::SePolicy;
use crate::rules::AvtabRule;

/// What [`SePolicy::extract`] found: the declarations and rules that concern
/// the selected names, as `.te` statements.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Extraction {
    /// `attribute`, `type` and `permissive` statements for the selected names,
    /// leaving out names the receiving policy already defines.
    pub declarations: Vec<String>,
    /// Rules that name a selected type or attribute, every other name in them
    /// being selected too or defined by the receiving policy.
    pub rules: Vec<String>,
    /// Rules that would need a name neither selected nor defined by the
    /// receiving policy, by that name. A rule needing several is under each.
    pub unresolved: BTreeMap<String, Vec<String>>,
}

impl SePolicy {
    /// Extract what concerns the types and attributes `selected` accepts.
    ///
    /// `defined` is what the policy the result is for already defines. A
    /// selected name it defines is not declared again, and a rule naming a name
    /// that is neither selected nor defined goes to
    /// [`unresolved`](Extraction::unresolved) instead of
    /// [`rules`](Extraction::rules). Without it, every selected name is
    /// declared and every rule kept.
    pub fn extract(
        &self,
        selected: impl Fn(&str) -> bool,
        defined: Option<&HashSet<String>>,
    ) -> Extraction {
        let attributes: Vec<String> = self.attribute_names().map(String::from).collect();
        let types: Vec<_> = self.type_decls().collect();
        let is_attribute: HashSet<&str> = attributes.iter().map(String::as_str).collect();
        let pair = |source: &str, target: &str| te_target(&is_attribute, source, target);
        let chosen: BTreeSet<&str> = attributes
            .iter()
            .map(String::as_str)
            .chain(types.iter().map(|t| t.name.as_ref()))
            .filter(|name| selected(name))
            .collect();

        let is_defined = |name: &str| defined.is_some_and(|d| d.contains(name));
        let resolves =
            |name: &str| chosen.contains(name) || defined.is_none_or(|d| d.contains(name));

        let mut out = Extraction::default();
        for attribute in &attributes {
            if chosen.contains(attribute.as_str()) && !is_defined(attribute) {
                out.declarations.push(format!("attribute {attribute};"));
            }
        }
        let mut permissive = Vec::new();
        for decl in &types {
            let name = decl.name.as_ref();
            if !chosen.contains(name) {
                continue;
            }
            if !is_defined(name) {
                let mut line = format!("type {name}");
                for attribute in decl.attributes.iter().filter(|a| resolves(a)) {
                    line.push_str(", ");
                    line.push_str(attribute);
                }
                line.push(';');
                out.declarations.push(line);
            }
            if decl.permissive {
                permissive.push(format!("permissive {name};"));
            }
        }
        out.declarations.extend(permissive);

        let mut place = |names: &[&str], rule: String| {
            if !names.iter().any(|name| chosen.contains(name)) {
                return;
            }
            let missing: BTreeSet<&str> = names.iter().copied().filter(|n| !resolves(n)).collect();
            if missing.is_empty() {
                out.rules.push(rule);
            } else {
                for name in missing {
                    out.unresolved
                        .entry(name.to_owned())
                        .or_default()
                        .push(rule.clone());
                }
            }
        };

        for rule in self.avtab_rules() {
            match &rule {
                AvtabRule::Av(av) => {
                    let mut line = format!(
                        "{} {}:{} {{",
                        av.kind,
                        pair(&av.source, &av.target),
                        av.class
                    );
                    for perm in av.perms() {
                        line.push(' ');
                        line.push_str(&perm);
                    }
                    line.push_str(" };");
                    place(&[&av.source, &av.target], line);
                }
                AvtabRule::Type(t) => place(
                    &[&t.source, &t.target, &t.default],
                    format!(
                        "{} {}:{} {};",
                        t.kind,
                        pair(&t.source, &t.target),
                        t.class,
                        t.default
                    ),
                ),
                AvtabRule::Xperm(x) => {
                    let mut line = format!(
                        "{} {}:{} ioctl {{",
                        x.kind,
                        pair(&x.source, &x.target),
                        x.class
                    );
                    for (low, high) in x.ioctls.ranges() {
                        line.push_str(&format!(" 0x{low:X}"));
                        if low != high {
                            line.push_str(&format!("-0x{high:X}"));
                        }
                    }
                    line.push_str(" };");
                    place(&[&x.source, &x.target], line);
                }
            }
        }
        for t in self.filename_transitions() {
            place(
                &[&t.source, &t.target, &t.default],
                format!(
                    "type_transition {}:{} {} \"{}\";",
                    pair(&t.source, &t.target),
                    t.class,
                    t.default,
                    t.name
                ),
            );
        }
        for g in self.genfs() {
            if let Some(ty) = context_type(&g.context) {
                let mut line = format!("genfscon {} {}", g.fs, g.path);
                if let Some(file_type) = g.file_type {
                    line.push_str(&format!(" -{}", file_type.as_checkpolicy()));
                }
                line.push(' ');
                line.push_str(&g.context);
                place(&[ty], line);
            }
        }

        out.rules.sort();
        out.rules.dedup();
        for rules in out.unresolved.values_mut() {
            rules.sort();
            rules.dedup();
        }
        out
    }
}

/// `source target` of a rule, the target written `self` when it is the source
/// and a type. For an attribute, `self` would narrow the rule: `allow domain
/// domain` lets any domain reach any other, `allow domain self` only itself.
fn te_target(attributes: &HashSet<&str>, source: &str, target: &str) -> String {
    if source == target && !attributes.contains(source) {
        format!("{source} self")
    } else {
        format!("{source} {target}")
    }
}

/// The type of a `user:role:type:level` security context.
fn context_type(context: &str) -> Option<&str> {
    context.split(':').nth(2)
}

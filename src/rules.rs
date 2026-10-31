//! Structured, borrowing views of the rules in a [`SePolicy`](crate::SePolicy).
//!
//! Names are borrowed from the policy's own tables instead of copied: each is
//! a [`Cow`] that is `Borrowed` whenever libsepol's bytes are valid UTF-8, as
//! they are in any real policy. Items borrow the policy, so it cannot be
//! modified while they are alive.
//!
//! Rule types implement [`Display`](fmt::Display) in the policy text format
//! used by the `SePolicy` string dumpers such as
//! [`avtabs`](crate::SePolicy::avtabs).

use std::borrow::Cow;
use std::fmt;

use crate::ffi::{AvtabEntry, AvtabKind, SePolicyImpl, XpermEntry};
use crate::parser::ast::GenfsFileType;

/// Decode a name borrowed from the policydb; `None` if it has no name.
pub(crate) fn name(bytes: &[u8]) -> Option<Cow<'_, str>> {
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes))
}

/// Write `words` separated by single spaces. Rule lines are plain
/// concatenations, and `write_str` avoids `format_args!` overhead on the
/// hundred thousand lines of a full policy.
fn write_words(f: &mut fmt::Formatter<'_>, words: &[&str]) -> fmt::Result {
    for (i, word) in words.iter().enumerate() {
        if i > 0 {
            f.write_str(" ")?;
        }
        f.write_str(word)?;
    }
    Ok(())
}

/// An access vector rule kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvRuleKind {
    Allow,
    AuditAllow,
    DontAudit,
}

impl AvRuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AvRuleKind::Allow => "allow",
            AvRuleKind::AuditAllow => "auditallow",
            AvRuleKind::DontAudit => "dontaudit",
        }
    }
}

impl fmt::Display for AvRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A type rule kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeRuleKind {
    Transition,
    Member,
    Change,
}

impl TypeRuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TypeRuleKind::Transition => "type_transition",
            TypeRuleKind::Member => "type_member",
            TypeRuleKind::Change => "type_change",
        }
    }
}

impl fmt::Display for TypeRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An extended permission rule kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XpermRuleKind {
    Allow,
    AuditAllow,
    DontAudit,
}

impl XpermRuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            XpermRuleKind::Allow => "allowxperm",
            XpermRuleKind::AuditAllow => "auditallowxperm",
            XpermRuleKind::DontAudit => "dontauditxperm",
        }
    }
}

impl fmt::Display for XpermRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The permissions of an [`AvRule`], resolved to names as they are iterated.
#[derive(Clone)]
pub struct Perms<'p> {
    policy: &'p SePolicyImpl,
    class: u32,
    mask: u32,
}

impl<'p> Iterator for Perms<'p> {
    type Item = Cow<'p, str>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.mask != 0 {
            let bit = self.mask.trailing_zeros();
            self.mask &= self.mask - 1;
            if let Some(perm) = name(self.policy.perm_name_bytes(self.class, bit)) {
                return Some(perm);
            }
        }
        None
    }
}

impl fmt::Debug for Perms<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// An `allow`, `auditallow` or `dontaudit` rule.
#[derive(Debug, Clone)]
pub struct AvRule<'p> {
    pub kind: AvRuleKind,
    pub source: Cow<'p, str>,
    pub target: Cow<'p, str>,
    pub class: Cow<'p, str>,
    perms: Perms<'p>,
}

impl<'p> AvRule<'p> {
    /// The permissions the rule grants, audits or silences.
    pub fn perms(&self) -> Perms<'p> {
        self.perms.clone()
    }
}

impl fmt::Display for AvRule<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_words(
            f,
            &[self.kind.as_str(), &self.source, &self.target, &self.class],
        )?;
        f.write_str(" {")?;
        for perm in self.perms() {
            f.write_str(" ")?;
            f.write_str(&perm)?;
        }
        f.write_str(" }")
    }
}

/// A `type_transition`, `type_member` or `type_change` rule.
#[derive(Debug, Clone)]
pub struct TypeRule<'p> {
    pub kind: TypeRuleKind,
    pub source: Cow<'p, str>,
    pub target: Cow<'p, str>,
    pub class: Cow<'p, str>,
    pub default: Cow<'p, str>,
}

impl fmt::Display for TypeRule<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_words(
            f,
            &[
                self.kind.as_str(),
                &self.source,
                &self.target,
                &self.class,
                &self.default,
            ],
        )
    }
}

/// The ioctl set of an [`XpermRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ioctls {
    function: bool,
    driver: u8,
    perms: [u32; 8],
}

impl Ioctls {
    fn contains_low_byte(&self, value: u8) -> bool {
        self.perms[usize::from(value >> 5)] & (1 << (value & 31)) != 0
    }

    fn encode(&self, value: u8) -> u16 {
        if self.function {
            u16::from(self.driver) << 8 | u16::from(value)
        } else {
            u16::from(value) << 8
        }
    }

    /// Whether the set includes `ioctl`: its driver is listed whole, or the
    /// set lists functions within that driver and includes this one.
    pub fn covers(&self, ioctl: u16) -> bool {
        let [driver, function] = ioctl.to_be_bytes();
        if self.function {
            driver == self.driver && self.contains_low_byte(function)
        } else {
            self.contains_low_byte(driver)
        }
    }

    /// Inclusive ranges of ioctl numbers. A driver-level set yields each
    /// driver as `driver << 8`.
    pub fn ranges(&self) -> impl Iterator<Item = (u16, u16)> + '_ {
        let mut value = 0u16;
        std::iter::from_fn(move || {
            while value < 256 && !self.contains_low_byte(value as u8) {
                value += 1;
            }
            if value >= 256 {
                return None;
            }
            let low = value as u8;
            while value < 256 && self.contains_low_byte(value as u8) {
                value += 1;
            }
            let high = (value - 1) as u8;
            Some((self.encode(low), self.encode(high)))
        })
    }
}

/// An `allowxperm`, `auditallowxperm` or `dontauditxperm` ioctl rule.
#[derive(Debug, Clone)]
pub struct XpermRule<'p> {
    pub kind: XpermRuleKind,
    pub source: Cow<'p, str>,
    pub target: Cow<'p, str>,
    pub class: Cow<'p, str>,
    pub ioctls: Ioctls,
}

impl fmt::Display for XpermRule<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_words(
            f,
            &[self.kind.as_str(), &self.source, &self.target, &self.class],
        )?;
        f.write_str(" ioctl {")?;
        for (low, high) in self.ioctls.ranges() {
            write!(f, " 0x{low:X}")?;
            if low != high {
                write!(f, "-0x{high:X}")?;
            }
        }
        f.write_str(" }")
    }
}

/// A rule from the policy's access vector table.
#[derive(Debug, Clone)]
pub enum AvtabRule<'p> {
    Av(AvRule<'p>),
    Type(TypeRule<'p>),
    Xperm(XpermRule<'p>),
}

impl fmt::Display for AvtabRule<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AvtabRule::Av(rule) => rule.fmt(f),
            AvtabRule::Type(rule) => rule.fmt(f),
            AvtabRule::Xperm(rule) => rule.fmt(f),
        }
    }
}

/// Resolve an avtab entry. Entries with unnamed types or classes, or with no
/// named permissions or ioctls, are skipped.
pub(crate) fn avtab_rule<'p>(
    policy: &'p SePolicyImpl,
    entry: &AvtabEntry,
    xperms: &[XpermEntry],
) -> Option<AvtabRule<'p>> {
    let source = name(policy.type_name_bytes(entry.source))?;
    let target = name(policy.type_name_bytes(entry.target))?;
    let class = name(policy.class_name_bytes(entry.class_))?;

    let av = |kind| {
        let perms = Perms {
            policy,
            class: entry.class_,
            mask: entry.data,
        };
        perms.clone().next()?;
        Some(AvtabRule::Av(AvRule {
            kind,
            source: source.clone(),
            target: target.clone(),
            class: class.clone(),
            perms,
        }))
    };
    let type_rule = |kind| {
        let default = name(policy.type_name_bytes(entry.data))?;
        Some(AvtabRule::Type(TypeRule {
            kind,
            source: source.clone(),
            target: target.clone(),
            class: class.clone(),
            default,
        }))
    };
    let xperm = |kind| {
        let x = xperms.get(usize::try_from(entry.xperm).ok()?)?;
        let ioctls = Ioctls {
            function: x.function,
            driver: x.driver,
            perms: x.perms,
        };
        ioctls.ranges().next()?;
        Some(AvtabRule::Xperm(XpermRule {
            kind,
            source: source.clone(),
            target: target.clone(),
            class: class.clone(),
            ioctls,
        }))
    };

    match entry.kind {
        AvtabKind::Allow => av(AvRuleKind::Allow),
        AvtabKind::AuditAllow => av(AvRuleKind::AuditAllow),
        AvtabKind::DontAudit => av(AvRuleKind::DontAudit),
        AvtabKind::TypeTransition => type_rule(TypeRuleKind::Transition),
        AvtabKind::TypeMember => type_rule(TypeRuleKind::Member),
        AvtabKind::TypeChange => type_rule(TypeRuleKind::Change),
        AvtabKind::AllowXperm => xperm(XpermRuleKind::Allow),
        AvtabKind::AuditAllowXperm => xperm(XpermRuleKind::AuditAllow),
        AvtabKind::DontAuditXperm => xperm(XpermRuleKind::DontAudit),
        _ => None,
    }
}

/// A type with its attributes and permissive state.
#[derive(Debug, Clone)]
pub struct TypeDecl<'p> {
    pub name: Cow<'p, str>,
    pub attributes: Vec<Cow<'p, str>>,
    pub permissive: bool,
}

/// A filename `type_transition` rule.
#[derive(Debug, Clone)]
pub struct FilenameTransition<'p> {
    pub source: Cow<'p, str>,
    pub target: Cow<'p, str>,
    pub class: Cow<'p, str>,
    pub default: Cow<'p, str>,
    pub name: Cow<'p, str>,
}

impl fmt::Display for FilenameTransition<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_words(
            f,
            &[
                "type_transition",
                &self.source,
                &self.target,
                &self.class,
                &self.default,
                &self.name,
            ],
        )
    }
}

/// A `genfscon` statement. The context is rendered by libsepol, so it is owned.
#[derive(Debug, Clone)]
pub struct Genfs<'p> {
    pub fs: Cow<'p, str>,
    pub path: Cow<'p, str>,
    /// The file type the entry is limited to; `None` applies to all.
    pub file_type: Option<GenfsFileType>,
    pub context: String,
}

impl fmt::Display for Genfs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_words(f, &["genfscon", &self.fs, &self.path])?;
        if let Some(file_type) = self.file_type {
            write!(f, " -{}", file_type.as_checkpolicy())?;
        }
        f.write_str(" ")?;
        f.write_str(&self.context)
    }
}

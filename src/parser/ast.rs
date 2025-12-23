//! AST types for SELinux type enforcement (.te) files.

use std::collections::HashSet;

/// A set of identifiers with optional complement flag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdSet {
    pub ids: HashSet<String>,
    pub complement: bool,
}

impl IdSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, id: impl Into<String>) {
        self.ids.insert(id.into());
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.ids.iter()
    }
}

impl FromIterator<String> for IdSet {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Self {
        Self {
            ids: iter.into_iter().collect(),
            complement: false,
        }
    }
}

/// Top-level policy module.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub name: Option<String>,
    pub version: Option<String>,
    pub statements: Vec<Statement>,
}

/// All statement types in a .te file.
#[derive(Debug, Clone)]
pub enum Statement {
    ModuleDecl(ModuleDecl),
    Conditional(Conditional),
    Type(TypeDef),
    TypeAlias(TypeAlias),
    Attribute(Attribute),
    AttributeRole(AttributeRole),
    TypeAttribute(TypeAttribute),
    RoleAttribute(RoleAttribute),
    TypeBound(TypeBound),
    Role(RoleDef),
    RoleAllow(RoleAllow),
    Bool(BoolDef),
    AVRule(AVRule),
    AVXRule(AVXRule),
    TypeRule(TypeRule),
    Permissive(Permissive),
    RangeTransition(RangeTransition),
    RoleTransition(RoleTransition),
    InitialSid(InitialSid),
    GenfsContext(GenfsContext),
    FsUse(FsUse),
    PortCon(PortCon),
    NodeCon(NodeCon),
    NetifCon(NetifCon),
    PirqCon(PirqCon),
    IomemCon(IomemCon),
    IoportCon(IoportCon),
    PciDeviceCon(PciDeviceCon),
    DevicetreeCon(DevicetreeCon),
}

/// Module declaration.
#[derive(Debug, Clone)]
pub struct ModuleDecl {
    pub name: String,
    pub version: String,
}

/// Conditional (if/else) block.
#[derive(Debug, Clone)]
pub struct Conditional {
    pub cond_expr: Vec<String>,
    pub true_block: Vec<Statement>,
    pub false_block: Vec<Statement>,
}

/// Type definition.
#[derive(Debug, Clone)]
pub struct TypeDef {
    pub name: String,
    pub aliases: IdSet,
    pub attributes: IdSet,
}

/// Type alias definition.
#[derive(Debug, Clone)]
pub struct TypeAlias {
    pub type_name: String,
    pub aliases: IdSet,
}

/// Attribute definition.
#[derive(Debug, Clone)]
pub struct Attribute {
    pub name: String,
}

/// Attribute role definition.
#[derive(Debug, Clone)]
pub struct AttributeRole {
    pub name: String,
}

/// Type attribute statement.
#[derive(Debug, Clone)]
pub struct TypeAttribute {
    pub type_name: String,
    pub attributes: IdSet,
}

/// Role attribute statement.
#[derive(Debug, Clone)]
pub struct RoleAttribute {
    pub role: String,
    pub roleattributes: IdSet,
}

/// Type bounds rule.
#[derive(Debug, Clone)]
pub struct TypeBound {
    pub type_name: String,
    pub tgt_types: IdSet,
}

/// Role definition.
#[derive(Debug, Clone)]
pub struct RoleDef {
    pub role: String,
    pub types: IdSet,
}

/// Role allow rule.
#[derive(Debug, Clone)]
pub struct RoleAllow {
    pub src_roles: IdSet,
    pub tgt_roles: IdSet,
}

/// Boolean definition.
#[derive(Debug, Clone)]
pub struct BoolDef {
    pub name: String,
    pub state: bool,
}

/// AV rule types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AVRuleType {
    Allow,
    Dontaudit,
    Auditallow,
    Neverallow,
}

/// Access vector rule.
#[derive(Debug, Clone)]
pub struct AVRule {
    pub rule_type: AVRuleType,
    pub src_types: IdSet,
    pub tgt_types: IdSet,
    pub obj_classes: IdSet,
    pub perms: IdSet,
}

/// Extended permission AV rule (allowxperm, etc.).
#[derive(Debug, Clone)]
pub struct AVXRule {
    pub rule_type: AVRuleType,
    pub src_types: IdSet,
    pub tgt_types: IdSet,
    pub obj_classes: IdSet,
    pub operation: String,
    pub xperms: IdSet,
}

/// Type rule types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeRuleType {
    TypeTransition,
    TypeChange,
    TypeMember,
}

/// Type rule (type_transition, type_change, type_member).
#[derive(Debug, Clone)]
pub struct TypeRule {
    pub rule_type: TypeRuleType,
    pub src_types: IdSet,
    pub tgt_types: IdSet,
    pub obj_classes: IdSet,
    pub dest_type: String,
    pub file_name: Option<String>,
}

/// Permissive statement.
#[derive(Debug, Clone)]
pub struct Permissive {
    pub type_name: String,
}

/// Range transition.
#[derive(Debug, Clone)]
pub struct RangeTransition {
    pub src_types: IdSet,
    pub tgt_types: IdSet,
    pub obj_classes: Option<IdSet>,
    pub mls_range: String,
}

/// Role transition.
#[derive(Debug, Clone)]
pub struct RoleTransition {
    pub src_roles: IdSet,
    pub types: IdSet,
    pub tgt_role: String,
}

/// Security context.
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub user: String,
    pub role: String,
    pub type_name: String,
    pub level: Option<String>,
}

/// Initial SID definition.
#[derive(Debug, Clone)]
pub struct InitialSid {
    pub name: String,
    pub context: SecurityContext,
}

/// Genfscon definition.
#[derive(Debug, Clone)]
pub struct GenfsContext {
    pub filesystem: String,
    pub path: String,
    pub file_type: Option<String>,
    pub context: SecurityContext,
}

/// Filesystem use types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsUseType {
    Xattr,
    Task,
    Trans,
}

/// Filesystem use definition.
#[derive(Debug, Clone)]
pub struct FsUse {
    pub use_type: FsUseType,
    pub filesystem: String,
    pub context: SecurityContext,
}

/// Port context definition.
#[derive(Debug, Clone)]
pub struct PortCon {
    pub port_type: String,
    pub port_number: String,
    pub context: SecurityContext,
}

/// Node context definition.
#[derive(Debug, Clone)]
pub struct NodeCon {
    pub start: String,
    pub end: String,
    pub context: SecurityContext,
}

/// Network interface context definition.
#[derive(Debug, Clone)]
pub struct NetifCon {
    pub interface: String,
    pub interface_context: SecurityContext,
    pub packet_context: SecurityContext,
}

/// PIRQ context definition.
#[derive(Debug, Clone)]
pub struct PirqCon {
    pub pirq_number: String,
    pub context: SecurityContext,
}

/// IO memory context definition.
#[derive(Debug, Clone)]
pub struct IomemCon {
    pub device_mem: String,
    pub context: SecurityContext,
}

/// IO port context definition.
#[derive(Debug, Clone)]
pub struct IoportCon {
    pub ioport: String,
    pub context: SecurityContext,
}

/// PCI device context definition.
#[derive(Debug, Clone)]
pub struct PciDeviceCon {
    pub device: String,
    pub context: SecurityContext,
}

/// Device tree context definition.
#[derive(Debug, Clone)]
pub struct DevicetreeCon {
    pub path: String,
    pub context: SecurityContext,
}

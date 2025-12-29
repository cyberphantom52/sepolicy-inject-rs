//! SELinux type enforcement (.te) file parser.

use pest::Parser;
use pest_derive::Parser;
use thiserror::Error;

use super::ast::*;
use crate::XPerm;

#[derive(Parser)]
#[grammar = "src/parser/policy.pest"]
pub struct PolicyParser;

/// Error type for policy parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Parse error: {0}")]
    Pest(#[from] pest::error::Error<Rule>),

    #[error("Unexpected rule: {0:?}")]
    UnexpectedRule(Rule),
}

/// Parse a .te policy file string into a Policy AST.
pub fn parse(input: &str) -> Result<Policy, ParseError> {
    let pairs = PolicyParser::parse(Rule::policy_file, input)?;

    let mut policy = Policy::default();

    for pair in pairs {
        if pair.as_rule() == Rule::policy_file {
            for inner in pair.into_inner() {
                if inner.as_rule() == Rule::statements {
                    policy.statements = parse_statements(inner)?;
                }
            }
        }
    }

    Ok(policy)
}

fn parse_statements(pair: pest::iterators::Pair<Rule>) -> Result<Vec<Statement>, ParseError> {
    let mut statements = Vec::new();

    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::statement {
            if let Some(stmt) = parse_statement(inner)? {
                statements.push(stmt);
            }
        }
    }

    Ok(statements)
}

fn parse_statement(pair: pest::iterators::Pair<Rule>) -> Result<Option<Statement>, ParseError> {
    let inner = match pair.into_inner().next() {
        Some(p) => p,
        None => return Ok(None),
    };

    match inner.as_rule() {
        Rule::conditional => Ok(Some(parse_conditional(inner)?)),
        Rule::avrule_def => Ok(Some(parse_avrule_def(inner)?)),
        Rule::avxrule_def => Ok(Some(parse_avxrule_def(inner)?)),
        Rule::typerule_def => Ok(Some(parse_typerule_def(inner)?)),
        Rule::type_def => Ok(Some(parse_type_def(inner)?)),
        Rule::typealias_def => Ok(Some(parse_typealias_def(inner)?)),
        Rule::attribute_def => Ok(Some(parse_attribute_def(inner)?)),
        Rule::attribute_role_def => Ok(Some(parse_attribute_role_def(inner)?)),
        Rule::typeattribute_def => Ok(Some(parse_typeattribute_def(inner)?)),
        Rule::roleattribute_def => Ok(Some(parse_roleattribute_def(inner)?)),
        Rule::typebound_def => Ok(Some(parse_typebound_def(inner)?)),
        Rule::role_def => Ok(Some(parse_role_def(inner)?)),
        Rule::role_allow => Ok(Some(parse_role_allow(inner)?)),
        Rule::bool_def => Ok(Some(parse_bool_def(inner)?)),
        Rule::permissive => Ok(Some(parse_permissive(inner)?)),
        Rule::range_transition_def => Ok(Some(parse_range_transition_def(inner)?)),
        Rule::role_transition_def => Ok(Some(parse_role_transition_def(inner)?)),
        Rule::initial_sid => Ok(Some(parse_initial_sid(inner)?)),
        Rule::genfscon => Ok(Some(parse_genfscon(inner)?)),
        Rule::fs_use => Ok(Some(parse_fs_use(inner)?)),
        Rule::portcon => Ok(Some(parse_portcon(inner)?)),
        Rule::nodecon => Ok(Some(parse_nodecon(inner)?)),
        Rule::netifcon => Ok(Some(parse_netifcon(inner)?)),
        Rule::pirqcon => Ok(Some(parse_pirqcon(inner)?)),
        Rule::iomemcon => Ok(Some(parse_iomemcon(inner)?)),
        Rule::ioportcon => Ok(Some(parse_ioportcon(inner)?)),
        Rule::pcidevicecon => Ok(Some(parse_pcidevicecon(inner)?)),
        Rule::devicetreecon => Ok(Some(parse_devicetreecon(inner)?)),
        Rule::module_stmt => Ok(Some(parse_module_stmt(inner)?)),
        _ => Ok(None),
    }
}

fn parse_conditional(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut cond_expr = Vec::new();
    let mut blocks: Vec<Vec<Statement>> = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::cond_expr => cond_expr = parse_cond_expr(inner)?,
            Rule::statements => blocks.push(parse_statements(inner)?),
            _ => {}
        }
    }

    Ok(Statement::Conditional(Conditional {
        cond_expr,
        true_block: blocks.first().cloned().unwrap_or_default(),
        false_block: blocks.get(1).cloned().unwrap_or_default(),
    }))
}

fn parse_cond_expr(pair: pest::iterators::Pair<Rule>) -> Result<Vec<String>, ParseError> {
    let mut expr = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::cond_term => expr.extend(parse_cond_term(inner)?),
            Rule::AND => expr.push("&&".to_string()),
            Rule::OR => expr.push("||".to_string()),
            Rule::EQ => expr.push("==".to_string()),
            Rule::NEQ => expr.push("!=".to_string()),
            _ => {}
        }
    }

    Ok(expr)
}

fn parse_cond_term(pair: pest::iterators::Pair<Rule>) -> Result<Vec<String>, ParseError> {
    let mut terms = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::EXPL => terms.push("!".to_string()),
            Rule::IDENTIFIER => terms.push(inner.as_str().to_string()),
            Rule::cond_expr => terms.extend(parse_cond_expr(inner)?),
            _ => {}
        }
    }

    Ok(terms)
}

fn parse_avrule_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let text = pair.as_str().to_lowercase();
    let rule_type = if text.starts_with("allow") {
        AVRuleType::Allow
    } else if text.starts_with("dontaudit") {
        AVRuleType::Dontaudit
    } else if text.starts_with("auditallow") {
        AVRuleType::Auditallow
    } else {
        AVRuleType::Neverallow
    };

    let mut names_list: Vec<IdSet> = Vec::new();
    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::names {
            names_list.push(parse_names(inner)?);
        }
    }

    Ok(Statement::AVRule(AVRule {
        rule_type,
        src_types: names_list.first().cloned().unwrap_or_default(),
        tgt_types: names_list.get(1).cloned().unwrap_or_default(),
        obj_classes: names_list.get(2).cloned().unwrap_or_default(),
        perms: names_list.get(3).cloned().unwrap_or_default(),
    }))
}

fn parse_avxrule_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let text = pair.as_str().to_lowercase();
    let rule_type = if text.starts_with("allowxperm") {
        AVRuleType::Allow
    } else if text.starts_with("dontauditxperm") {
        AVRuleType::Dontaudit
    } else if text.starts_with("auditallowxperm") {
        AVRuleType::Auditallow
    } else {
        AVRuleType::Neverallow
    };

    let mut names_list: Vec<IdSet> = Vec::new();
    let mut operation = String::new();
    let mut xperms = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::names => names_list.push(parse_names(inner)?),
            Rule::IDENTIFIER => operation = inner.as_str().to_string(),
            Rule::xperm_set => xperms = parse_xperm_set(inner)?,
            _ => {}
        }
    }

    Ok(Statement::AVXRule(AVXRule {
        rule_type,
        src_types: names_list.first().cloned().unwrap_or_default(),
        tgt_types: names_list.get(1).cloned().unwrap_or_default(),
        obj_classes: names_list.get(2).cloned().unwrap_or_default(),
        operation,
        xperms,
    }))
}

fn parse_xperm_set(pair: pest::iterators::Pair<Rule>) -> Result<Vec<XPerm>, ParseError> {
    let mut xperms = Vec::new();

    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::xperm_element {
            if let Some(xperm) = parse_xperm_element(inner)? {
                xperms.push(xperm);
            }
        }
    }

    Ok(xperms)
}

fn parse_xperm_element(pair: pest::iterators::Pair<Rule>) -> Result<Option<XPerm>, ParseError> {
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::xperm_range => {
                let mut hex_values = Vec::new();
                for hex in inner.into_inner() {
                    if hex.as_rule() == Rule::HEX_NUMBER {
                        if let Some(val) = parse_hex_value(hex.as_str()) {
                            hex_values.push(val);
                        }
                    }
                }
                if hex_values.len() == 2 {
                    return Ok(Some(XPerm {
                        low: hex_values[0],
                        high: hex_values[1],
                        reset: false,
                    }));
                }
            }
            Rule::HEX_NUMBER => {
                if let Some(val) = parse_hex_value(inner.as_str()) {
                    return Ok(Some(XPerm {
                        low: val,
                        high: val,
                        reset: false,
                    }));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

fn parse_hex_value(s: &str) -> Option<u16> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u16::from_str_radix(s, 16).ok()
}

fn parse_typerule_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let text = pair.as_str().to_lowercase();
    let rule_type = if text.starts_with("type_transition") {
        TypeRuleType::TypeTransition
    } else if text.starts_with("type_change") {
        TypeRuleType::TypeChange
    } else {
        TypeRuleType::TypeMember
    };

    let mut names_list: Vec<IdSet> = Vec::new();
    let mut identifiers: Vec<String> = Vec::new();
    let mut file_name = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::names => names_list.push(parse_names(inner)?),
            Rule::IDENTIFIER => identifiers.push(inner.as_str().to_string()),
            Rule::FILENAME => file_name = Some(inner.as_str().trim_matches('"').to_string()),
            _ => {}
        }
    }

    if file_name.is_none() && identifiers.len() > 1 {
        file_name = identifiers.get(1).cloned();
    }

    Ok(Statement::TypeRule(TypeRule {
        rule_type,
        src_types: names_list.first().cloned().unwrap_or_default(),
        tgt_types: names_list.get(1).cloned().unwrap_or_default(),
        obj_classes: names_list.get(2).cloned().unwrap_or_default(),
        dest_type: identifiers.first().cloned().unwrap_or_default(),
        file_name,
    }))
}

fn parse_type_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut name = String::new();
    let mut aliases = IdSet::new();
    let mut attributes = IdSet::new();
    let mut saw_alias = false;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => {
                if name.is_empty() {
                    name = inner.as_str().to_string();
                }
            }
            Rule::names => {
                if saw_alias {
                    aliases = parse_names(inner)?;
                }
            }
            Rule::comma_list => attributes = parse_comma_list(inner)?,
            _ => {
                if inner.as_str().to_lowercase() == "alias" {
                    saw_alias = true;
                }
            }
        }
    }

    Ok(Statement::Type(TypeDef {
        name,
        aliases,
        attributes,
    }))
}

fn parse_typealias_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut type_name = String::new();
    let mut aliases = IdSet::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => type_name = inner.as_str().to_string(),
            Rule::names => aliases = parse_names(inner)?,
            _ => {}
        }
    }

    Ok(Statement::TypeAlias(TypeAlias { type_name, aliases }))
}

fn parse_attribute_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let name = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::IDENTIFIER)
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();

    Ok(Statement::Attribute(Attribute { name }))
}

fn parse_attribute_role_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let name = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::IDENTIFIER)
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();

    Ok(Statement::AttributeRole(AttributeRole { name }))
}

fn parse_typeattribute_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut type_name = String::new();
    let mut attributes = IdSet::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => type_name = inner.as_str().to_string(),
            Rule::comma_list => attributes = parse_comma_list(inner)?,
            _ => {}
        }
    }

    Ok(Statement::TypeAttribute(TypeAttribute {
        type_name,
        attributes,
    }))
}

fn parse_roleattribute_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut role = String::new();
    let mut roleattributes = IdSet::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => role = inner.as_str().to_string(),
            Rule::comma_list => roleattributes = parse_comma_list(inner)?,
            _ => {}
        }
    }

    Ok(Statement::RoleAttribute(RoleAttribute {
        role,
        roleattributes,
    }))
}

fn parse_typebound_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut type_name = String::new();
    let mut tgt_types = IdSet::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => {
                if type_name.is_empty() {
                    type_name = inner.as_str().to_string();
                }
            }
            Rule::comma_list => tgt_types = parse_comma_list(inner)?,
            _ => {}
        }
    }

    Ok(Statement::TypeBound(TypeBound {
        type_name,
        tgt_types,
    }))
}

fn parse_role_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut role = String::new();
    let mut types = IdSet::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => role = inner.as_str().to_string(),
            Rule::comma_list => types = parse_comma_list(inner)?,
            _ => {}
        }
    }

    Ok(Statement::Role(RoleDef { role, types }))
}

fn parse_role_allow(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut names_list: Vec<IdSet> = Vec::new();

    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::names {
            names_list.push(parse_names(inner)?);
        }
    }

    Ok(Statement::RoleAllow(RoleAllow {
        src_roles: names_list.first().cloned().unwrap_or_default(),
        tgt_roles: names_list.get(1).cloned().unwrap_or_default(),
    }))
}

fn parse_bool_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut name = String::new();
    let mut state = false;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => name = inner.as_str().to_string(),
            Rule::bool_value => state = inner.as_str().to_lowercase() == "true",
            _ => {}
        }
    }

    Ok(Statement::Bool(BoolDef { name, state }))
}

fn parse_permissive(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let type_name = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::IDENTIFIER)
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();

    Ok(Statement::Permissive(Permissive { type_name }))
}

fn parse_range_transition_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut names_list: Vec<IdSet> = Vec::new();
    let mut mls_range = String::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::names => names_list.push(parse_names(inner)?),
            Rule::mls_range_def => mls_range = inner.as_str().to_string(),
            _ => {}
        }
    }

    Ok(Statement::RangeTransition(RangeTransition {
        src_types: names_list.first().cloned().unwrap_or_default(),
        tgt_types: names_list.get(1).cloned().unwrap_or_default(),
        obj_classes: names_list.get(2).cloned(),
        mls_range,
    }))
}

fn parse_role_transition_def(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut names_list: Vec<IdSet> = Vec::new();

    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::names {
            names_list.push(parse_names(inner)?);
        }
    }

    let tgt_role = names_list
        .get(2)
        .and_then(|s| s.ids.iter().next().cloned())
        .unwrap_or_default();

    Ok(Statement::RoleTransition(RoleTransition {
        src_roles: names_list.first().cloned().unwrap_or_default(),
        types: names_list.get(1).cloned().unwrap_or_default(),
        tgt_role,
    }))
}

fn parse_module_stmt(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut name = String::new();
    let mut version = String::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => name = inner.as_str().to_string(),
            Rule::NUMBER => version = inner.as_str().to_string(),
            _ => {}
        }
    }

    Ok(Statement::ModuleDecl(ModuleDecl { name, version }))
}

fn parse_initial_sid(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut name = String::new();
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => name = inner.as_str().to_string(),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    Ok(Statement::InitialSid(InitialSid { name, context }))
}

fn parse_security_context(
    pair: pest::iterators::Pair<Rule>,
) -> Result<SecurityContext, ParseError> {
    let mut identifiers: Vec<String> = Vec::new();
    let mut level = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => identifiers.push(inner.as_str().to_string()),
            Rule::mls_range_def => level = Some(inner.as_str().to_string()),
            _ => {}
        }
    }

    Ok(SecurityContext {
        user: identifiers.first().cloned().unwrap_or_default(),
        role: identifiers.get(1).cloned().unwrap_or_default(),
        type_name: identifiers.get(2).cloned().unwrap_or_default(),
        level,
    })
}

fn parse_genfscon(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut filesystem = String::new();
    let mut path = String::new();
    let mut file_type = None;
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => {
                if filesystem.is_empty() {
                    filesystem = inner.as_str().to_string();
                } else if file_type.is_none() {
                    file_type = Some(inner.as_str().to_string());
                }
            }
            Rule::PATH => path = inner.as_str().to_string(),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    Ok(Statement::GenfsContext(GenfsContext {
        filesystem,
        path,
        file_type,
        context,
    }))
}

fn parse_fs_use(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let text = pair.as_str().to_lowercase();
    let use_type = if text.starts_with("fs_use_xattr") {
        FsUseType::Xattr
    } else if text.starts_with("fs_use_task") {
        FsUseType::Task
    } else {
        FsUseType::Trans
    };

    let mut filesystem = String::new();
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => filesystem = inner.as_str().to_string(),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    Ok(Statement::FsUse(FsUse {
        use_type,
        filesystem,
        context,
    }))
}

fn parse_portcon(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut port_type = String::new();
    let mut numbers: Vec<String> = Vec::new();
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => port_type = inner.as_str().to_string(),
            Rule::NUMBER => numbers.push(inner.as_str().to_string()),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    let port_number = if numbers.len() > 1 {
        format!("{}-{}", numbers[0], numbers[1])
    } else {
        numbers.first().cloned().unwrap_or_default()
    };

    Ok(Statement::PortCon(PortCon {
        port_type,
        port_number,
        context,
    }))
}

fn parse_nodecon(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut addrs: Vec<String> = Vec::new();
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::NUMBER | Rule::IPV6_ADDR => addrs.push(inner.as_str().to_string()),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    Ok(Statement::NodeCon(NodeCon {
        start: addrs.first().cloned().unwrap_or_default(),
        end: addrs.get(1).cloned().unwrap_or_default(),
        context,
    }))
}

fn parse_netifcon(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut interface = String::new();
    let mut contexts: Vec<SecurityContext> = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::IDENTIFIER => interface = inner.as_str().to_string(),
            Rule::security_context => contexts.push(parse_security_context(inner)?),
            _ => {}
        }
    }

    let default_ctx = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    Ok(Statement::NetifCon(NetifCon {
        interface,
        interface_context: contexts.first().cloned().unwrap_or(default_ctx.clone()),
        packet_context: contexts.get(1).cloned().unwrap_or(default_ctx),
    }))
}

fn parse_pirqcon(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut pirq_number = String::new();
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::NUMBER => pirq_number = inner.as_str().to_string(),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    Ok(Statement::PirqCon(PirqCon {
        pirq_number,
        context,
    }))
}

fn parse_iomemcon(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut numbers: Vec<String> = Vec::new();
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::NUMBER => numbers.push(inner.as_str().to_string()),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    let device_mem = if numbers.len() > 1 {
        format!("{}-{}", numbers[0], numbers[1])
    } else {
        numbers.first().cloned().unwrap_or_default()
    };

    Ok(Statement::IomemCon(IomemCon {
        device_mem,
        context,
    }))
}

fn parse_ioportcon(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut numbers: Vec<String> = Vec::new();
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::NUMBER => numbers.push(inner.as_str().to_string()),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    let ioport = if numbers.len() > 1 {
        format!("{}-{}", numbers[0], numbers[1])
    } else {
        numbers.first().cloned().unwrap_or_default()
    };

    Ok(Statement::IoportCon(IoportCon { ioport, context }))
}

fn parse_pcidevicecon(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut device = String::new();
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::NUMBER => device = inner.as_str().to_string(),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    Ok(Statement::PciDeviceCon(PciDeviceCon { device, context }))
}

fn parse_devicetreecon(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let mut path = String::new();
    let mut context = SecurityContext {
        user: String::new(),
        role: String::new(),
        type_name: String::new(),
        level: None,
    };

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::NUMBER => path = inner.as_str().to_string(),
            Rule::security_context => context = parse_security_context(inner)?,
            _ => {}
        }
    }

    Ok(Statement::DevicetreeCon(DevicetreeCon { path, context }))
}

fn parse_names(pair: pest::iterators::Pair<Rule>) -> Result<IdSet, ParseError> {
    let mut ids = IdSet::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::TILDE => ids.complement = true,
            Rule::identifier => {
                if let Some(id) = inner.into_inner().next() {
                    ids.add(id.as_str());
                }
            }
            Rule::IDENTIFIER => ids.add(inner.as_str()),
            Rule::nested_id_set => {
                let nested = parse_nested_id_set(inner)?;
                ids.ids.extend(nested.ids);
            }
            Rule::asterisk => ids.add("*"),
            _ => {}
        }
    }

    Ok(ids)
}

fn parse_nested_id_set(pair: pest::iterators::Pair<Rule>) -> Result<IdSet, ParseError> {
    let mut ids = IdSet::new();

    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::nested_id_list {
            for id in parse_nested_id_list(inner)? {
                ids.add(id);
            }
        }
    }

    Ok(ids)
}

fn parse_nested_id_list(pair: pest::iterators::Pair<Rule>) -> Result<Vec<String>, ParseError> {
    let mut ids = Vec::new();

    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::nested_id_element {
            ids.extend(parse_nested_id_element(inner)?);
        }
    }

    Ok(ids)
}

fn parse_nested_id_element(pair: pest::iterators::Pair<Rule>) -> Result<Vec<String>, ParseError> {
    let mut ids = Vec::new();
    let mut has_minus = false;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::MINUS => has_minus = true,
            Rule::identifier => {
                if let Some(id) = inner.into_inner().next() {
                    let name = if has_minus {
                        format!("-{}", id.as_str())
                    } else {
                        id.as_str().to_string()
                    };
                    ids.push(name);
                    has_minus = false;
                }
            }
            Rule::IDENTIFIER => {
                let name = if has_minus {
                    format!("-{}", inner.as_str())
                } else {
                    inner.as_str().to_string()
                };
                ids.push(name);
                has_minus = false;
            }
            Rule::HEX_NUMBER => {
                let name = if has_minus {
                    format!("-{}", inner.as_str())
                } else {
                    inner.as_str().to_string()
                };
                ids.push(name);
                has_minus = false;
            }
            Rule::nested_id_set => {
                let nested = parse_nested_id_set(inner)?;
                ids.extend(nested.ids);
            }
            _ => {}
        }
    }

    Ok(ids)
}

fn parse_comma_list(pair: pest::iterators::Pair<Rule>) -> Result<IdSet, ParseError> {
    let mut ids = IdSet::new();

    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::nested_id_list {
            for id in parse_nested_id_list(inner)? {
                ids.add(id);
            }
        }
    }

    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_allow_rule() {
        let input = "allow domain_t file_t:file read;";
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let policy = result.unwrap();
        assert_eq!(policy.statements.len(), 1);

        if let Statement::AVRule(rule) = &policy.statements[0] {
            assert_eq!(rule.rule_type, AVRuleType::Allow);
            assert!(rule.src_types.ids.contains("domain_t"));
            assert!(rule.tgt_types.ids.contains("file_t"));
            assert!(rule.obj_classes.ids.contains("file"));
            assert!(rule.perms.ids.contains("read"));
        } else {
            panic!("Expected AVRule");
        }
    }

    #[test]
    fn test_parse_allow_with_sets() {
        let input = "allow { init_t kernel_t } { file_t bin_t }:{ file dir } { read write };";
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let policy = result.unwrap();
        if let Statement::AVRule(rule) = &policy.statements[0] {
            assert!(rule.src_types.ids.contains("init_t"));
            assert!(rule.src_types.ids.contains("kernel_t"));
            assert!(rule.tgt_types.ids.contains("file_t"));
            assert!(rule.tgt_types.ids.contains("bin_t"));
            assert!(rule.obj_classes.ids.contains("file"));
            assert!(rule.obj_classes.ids.contains("dir"));
            assert!(rule.perms.ids.contains("read"));
            assert!(rule.perms.ids.contains("write"));
        } else {
            panic!("Expected AVRule");
        }
    }

    #[test]
    fn test_parse_type_def() {
        let input = "type my_type_t;";
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        if let Statement::Type(t) = &result.unwrap().statements[0] {
            assert_eq!(t.name, "my_type_t");
        } else {
            panic!("Expected Type");
        }
    }

    #[test]
    fn test_parse_type_with_attributes() {
        let input = "type my_type_t, domain, file_type;";
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        if let Statement::Type(t) = &result.unwrap().statements[0] {
            assert_eq!(t.name, "my_type_t");
            assert!(t.attributes.ids.contains("domain"));
            assert!(t.attributes.ids.contains("file_type"));
        } else {
            panic!("Expected Type");
        }
    }

    #[test]
    fn test_parse_attribute() {
        let input = "attribute file_type;";
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        if let Statement::Attribute(a) = &result.unwrap().statements[0] {
            assert_eq!(a.name, "file_type");
        } else {
            panic!("Expected Attribute");
        }
    }

    #[test]
    fn test_parse_type_transition() {
        let input = "type_transition init_t bin_t:process myapp_t;";
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        if let Statement::TypeRule(rule) = &result.unwrap().statements[0] {
            assert_eq!(rule.rule_type, TypeRuleType::TypeTransition);
            assert!(rule.src_types.ids.contains("init_t"));
            assert!(rule.tgt_types.ids.contains("bin_t"));
            assert!(rule.obj_classes.ids.contains("process"));
            assert_eq!(rule.dest_type, "myapp_t");
        } else {
            panic!("Expected TypeRule");
        }
    }

    #[test]
    fn test_parse_type_transition_with_filename() {
        let input = r#"type_transition init_t bin_t:file myapp_t "script.sh";"#;
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        if let Statement::TypeRule(rule) = &result.unwrap().statements[0] {
            assert_eq!(rule.dest_type, "myapp_t");
            assert_eq!(rule.file_name, Some("script.sh".to_string()));
        } else {
            panic!("Expected TypeRule");
        }
    }

    #[test]
    fn test_parse_bool() {
        let input = "bool my_bool true;";
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        if let Statement::Bool(b) = &result.unwrap().statements[0] {
            assert_eq!(b.name, "my_bool");
            assert!(b.state);
        } else {
            panic!("Expected Bool");
        }
    }

    #[test]
    fn test_parse_conditional() {
        let input = r#"
if (my_bool) {
    allow domain_t file_t:file read;
}
"#;
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        if let Statement::Conditional(c) = &result.unwrap().statements[0] {
            assert!(c.cond_expr.contains(&"my_bool".to_string()));
            assert_eq!(c.true_block.len(), 1);
            assert!(c.false_block.is_empty());
        } else {
            panic!("Expected Conditional");
        }
    }

    #[test]
    fn test_parse_conditional_with_else() {
        let input = r#"
if (my_bool) {
    allow domain_t file_t:file read;
} else {
    allow domain_t file_t:file write;
}
"#;
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        if let Statement::Conditional(c) = &result.unwrap().statements[0] {
            assert_eq!(c.true_block.len(), 1);
            assert_eq!(c.false_block.len(), 1);
        } else {
            panic!("Expected Conditional");
        }
    }

    #[test]
    fn test_parse_permissive() {
        let input = "permissive my_domain_t;";
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        if let Statement::Permissive(p) = &result.unwrap().statements[0] {
            assert_eq!(p.type_name, "my_domain_t");
        } else {
            panic!("Expected Permissive");
        }
    }

    #[test]
    fn test_parse_multiple_statements() {
        let input = r#"
type my_type_t;
attribute my_attr;
allow my_type_t self:file read;
"#;
        let result = parse(input);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let policy = result.unwrap();
        assert_eq!(policy.statements.len(), 3);
    }
}

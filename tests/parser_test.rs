//! Integration tests for the SELinux .te file parser.

use sepolicy::parser;
use sepolicy::parser::ast::{AVRuleType, Statement, TypeRuleType};
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn load_fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("Failed to load fixture {}: {}", name, e))
}

#[test]
fn test_parse_te_file() {
    let input = load_fixture("example.te");
    let result = parser::parse(&input);
    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let policy = result.unwrap();
    assert!(!policy.statements.is_empty(), "No statements parsed");
}

#[test]
fn test_type_definitions() {
    let input = load_fixture("example.te");
    let policy = parser::parse(&input).expect("Parse failed");

    let types: Vec<_> = policy
        .statements
        .iter()
        .filter_map(|s| match s {
            Statement::Type(t) => Some(t),
            _ => None,
        })
        .collect();

    assert_eq!(types.len(), 3, "Expected 3 type definitions");

    // Check that my_exec_t has both exec_type and file_type attributes
    let exec_type = types.iter().find(|t| t.name == "my_exec_t").unwrap();
    assert!(exec_type.attributes.ids.contains("exec_type"));
    assert!(exec_type.attributes.ids.contains("file_type"));
}

#[test]
fn test_allow_rules() {
    let input = load_fixture("example.te");
    let policy = parser::parse(&input).expect("Parse failed");

    let allow_rules: Vec<_> = policy
        .statements
        .iter()
        .filter_map(|s| match s {
            Statement::AVRule(r) if r.rule_type == AVRuleType::Allow => Some(r),
            _ => None,
        })
        .collect();

    assert!(allow_rules.len() >= 4, "Expected at least 4 allow rules");

    // Find the rule with sets
    let set_rule = allow_rules
        .iter()
        .find(|r| r.src_types.ids.len() > 1)
        .expect("No rule with multiple source types");

    assert!(set_rule.src_types.ids.contains("my_domain_t"));
    assert!(set_rule.src_types.ids.contains("kernel_t"));
}

#[test]
fn test_type_transitions() {
    let input = load_fixture("example.te");
    let policy = parser::parse(&input).expect("Parse failed");

    let transitions: Vec<_> = policy
        .statements
        .iter()
        .filter_map(|s| match s {
            Statement::TypeRule(r) if r.rule_type == TypeRuleType::TypeTransition => Some(r),
            _ => None,
        })
        .collect();

    assert_eq!(transitions.len(), 2, "Expected 2 type transitions");

    // Check the one with filename
    let with_filename = transitions.iter().find(|t| t.file_name.is_some()).unwrap();
    assert_eq!(with_filename.file_name, Some("myfile.txt".to_string()));
}

#[test]
fn test_conditionals() {
    let input = load_fixture("example.te");
    let policy = parser::parse(&input).expect("Parse failed");

    let conditionals: Vec<_> = policy
        .statements
        .iter()
        .filter_map(|s| match s {
            Statement::Conditional(c) => Some(c),
            _ => None,
        })
        .collect();

    assert_eq!(conditionals.len(), 2, "Expected 2 conditionals");

    // One should have an else block
    let with_else = conditionals.iter().find(|c| !c.false_block.is_empty());
    assert!(
        with_else.is_some(),
        "Expected one conditional with else block"
    );
}

#[test]
fn test_permissive() {
    let input = load_fixture("example.te");
    let policy = parser::parse(&input).expect("Parse failed");

    let permissive = policy
        .statements
        .iter()
        .find_map(|s| match s {
            Statement::Permissive(p) => Some(p),
            _ => None,
        })
        .expect("No permissive statement found");

    assert_eq!(permissive.type_name, "my_domain_t");
}

//! Extracting what concerns some types from a compiled policy, as `.te`.

use sepolicy::{SePolicy, parser};
use std::collections::HashSet;
use std::path::PathBuf;

fn policy() -> SePolicy {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/precompiled_sepolicy");
    SePolicy::from_file(path).expect("fixture loads")
}

fn vibrator(name: &str) -> bool {
    name.starts_with("hal_vibrator_default")
}

#[test]
fn writes_te_the_parser_reads_back() {
    let extraction = policy().extract(vibrator, None);

    assert!(extraction.declarations.contains(
        &"type hal_vibrator_default, domain, halserverdomain, hal_vibrator_server;".to_owned()
    ));
    assert!(extraction.rules.contains(
        &"type_transition hal_vibrator_default crash_dump_exec:process crash_dump;".to_owned()
    ));
    assert!(
        extraction
            .rules
            .iter()
            .any(|r| r.starts_with("allow hal_vibrator_default self:"))
    );
    assert!(extraction.unresolved.is_empty());

    let te = [extraction.declarations, extraction.rules]
        .concat()
        .join("\n");
    parser::parse(&te).expect("the extraction is valid .te");
}

#[test]
fn holds_back_rules_needing_an_undefined_name() {
    let policy = policy();
    let mut defined: HashSet<String> = policy.attribute_names().map(String::from).collect();
    defined.extend(policy.type_decls().map(|t| t.name.into_owned()));
    defined.remove("crash_dump");

    let extraction = policy.extract(vibrator, Some(&defined));

    assert!(
        extraction
            .declarations
            .iter()
            .all(|d| !d.starts_with("type hal_vibrator_default,")),
        "a name the receiving policy defines is not declared again: {:#?}",
        extraction.declarations
    );
    let held = &extraction.unresolved["crash_dump"];
    assert!(held.contains(
        &"type_transition hal_vibrator_default crash_dump_exec:process crash_dump;".to_owned()
    ));
    assert!(
        extraction
            .rules
            .iter()
            .all(|r| !r.contains(" crash_dump:") && !r.ends_with(" crash_dump;"))
    );
}

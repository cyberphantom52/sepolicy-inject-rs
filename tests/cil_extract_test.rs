//! Extracting the statements that name a label from a CIL policy.

use sepolicy::CilPolicy;
use std::path::PathBuf;

fn extract(label: &str) -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/extract_label.cil");
    CilPolicy::from_file(path)
        .expect("fixture loads")
        .extract_label(label)
        .expect("extraction succeeds")
}

#[test]
fn matches_the_label_as_a_whole_token() {
    let matches = extract("hal_charger_oplus");

    assert!(matches.contains(&"(type hal_charger_oplus)".to_owned()));
    assert!(matches.contains(&"(typepermissive hal_charger_oplus)".to_owned()));
    assert!(
        matches
            .iter()
            .any(|m| m.starts_with("(typetransition init hal_charger_oplus_exec")),
        "a statement naming the label among others is extracted: {matches:#?}"
    );
    assert!(
        !matches.contains(&"(type hal_charger_oplus_exec)".to_owned()),
        "a label that only starts with it is not a match: {matches:#?}"
    );
}

#[test]
fn reduces_an_attribute_set_to_the_label() {
    let matches = extract("hal_charger_oplus_exec");

    assert!(
        matches.contains(
            &"(typeattributeset hal_charger_related (hal_charger_oplus_exec))".to_owned()
        ),
        "{matches:#?}"
    );
    assert!(
        !matches.iter().any(|m| m.contains("vendor_unused_exec")),
        "{matches:#?}"
    );
}

#[test]
fn finds_nothing_for_an_unknown_label() {
    assert!(extract("label_that_does_not_exist").is_empty());
}

#[test]
fn lists_declared_types_attributes_and_aliases() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/extract_label.cil");
    let declared = CilPolicy::from_file(path)
        .expect("fixture loads")
        .declared_types()
        .expect("declarations are read");

    for name in [
        "hal_charger_oplus",
        "hal_charger_related",
        "hal_charger_exec_alias",
    ] {
        assert!(declared.contains(name), "{name} missing from {declared:?}");
    }
    assert!(
        !declared.contains("object_r"),
        "a role is not a type: {declared:?}"
    );
}

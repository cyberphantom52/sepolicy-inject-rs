use sepolicy::CilPolicy;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

fn assert_contains_match(matches: &[String], needle: &str) {
    assert!(
        matches.iter().any(|entry| entry.contains(needle)),
        "expected to find {:?} in extracted matches.\nMatches:\n{}",
        needle,
        matches.join("\n---\n")
    );
}

fn assert_not_contains_match(matches: &[String], needle: &str) {
    assert!(
        !matches.iter().any(|entry| entry.contains(needle)),
        "did not expect to find {:?} in extracted matches.\nMatches:\n{}",
        needle,
        matches.join("\n---\n")
    );
}

#[test]
fn test_extract_exec_label_from_file_helper() {
    let matches = CilPolicy::extract_label_from_file(
        fixture_path("extract_label.cil"),
        "hal_charger_oplus_exec",
    )
    .expect("failed to extract exec label from standalone CIL fixture");

    assert!(
        !matches.is_empty(),
        "expected at least one extracted CIL statement"
    );
    assert!(
        matches
            .iter()
            .all(|entry| entry.contains("extract_label.cil:")),
        "expected extracted entries to include source file locations.\nMatches:\n{}",
        matches.join("\n---\n")
    );

    assert_contains_match(&matches, "(type hal_charger_oplus_exec)");
    assert_contains_match(&matches, "(roletype object_r hal_charger_oplus_exec)");
    assert_contains_match(
        &matches,
        "(typeattributeset exec_type (hal_charger_oplus_exec))",
    );
    assert_contains_match(
        &matches,
        "(typeattributeset file_type (hal_charger_oplus_exec))",
    );
    assert_contains_match(
        &matches,
        "(typeattributeset hal_charger_related (hal_charger_oplus hal_charger_oplus_exec))",
    );
    assert_contains_match(
        &matches,
        "(typealiasactual hal_charger_exec_alias hal_charger_oplus_exec)",
    );
    assert_contains_match(
        &matches,
        "(allow init hal_charger_oplus_exec (file (read getattr map execute open)))",
    );
    assert_contains_match(
        &matches,
        "(allow hal_charger_oplus hal_charger_oplus_exec (file (read getattr map execute open entrypoint)))",
    );
    assert_contains_match(
        &matches,
        "(typetransition init hal_charger_oplus_exec process hal_charger_oplus)",
    );

    assert_not_contains_match(&matches, "(type hal_charger_oplus)");
    assert_not_contains_match(&matches, "(typepermissive hal_charger_oplus)");
    assert_not_contains_match(&matches, "(type vendor_unused_exec)");
    assert_not_contains_match(&matches, "(allow shell vendor_unused_exec");
    assert_not_contains_match(&matches, "(typealias hal_charger_exec_alias)");
}

#[test]
fn test_extract_domain_label_uses_exact_token_matching() {
    let mut policy = CilPolicy::new();
    policy
        .add_file_mut(fixture_path("extract_label.cil"))
        .expect("failed to add standalone CIL fixture");

    let matches = policy
        .extract_label("hal_charger_oplus")
        .expect("failed to extract domain label from standalone CIL fixture");

    assert!(
        !matches.is_empty(),
        "expected at least one extracted CIL statement"
    );

    assert_contains_match(&matches, "(type hal_charger_oplus)");
    assert_contains_match(&matches, "(roletype object_r hal_charger_oplus)");
    assert_contains_match(
        &matches,
        "(typeattributeset hal_charger_related (hal_charger_oplus hal_charger_oplus_exec))",
    );
    assert_contains_match(&matches, "(typepermissive hal_charger_oplus)");
    assert_contains_match(
        &matches,
        "(allow hal_charger_oplus hal_charger_oplus_exec (file (read getattr map execute open entrypoint)))",
    );
    assert_contains_match(
        &matches,
        "(typetransition init hal_charger_oplus_exec process hal_charger_oplus)",
    );

    // Ensure token matching is exact and does not pull in exec-only statements.
    assert_not_contains_match(&matches, "(type hal_charger_oplus_exec)");
    assert_not_contains_match(&matches, "(roletype object_r hal_charger_oplus_exec)");
    assert_not_contains_match(
        &matches,
        "(typeattributeset exec_type (hal_charger_oplus_exec))",
    );
    assert_not_contains_match(
        &matches,
        "(typealiasactual hal_charger_exec_alias hal_charger_oplus_exec)",
    );
}

#[test]
fn test_extract_missing_label_returns_empty_matches() {
    let matches = CilPolicy::extract_label_from_file(
        fixture_path("extract_label.cil"),
        "label_that_does_not_exist",
    )
    .expect("missing-label extraction should not fail");

    assert!(
        matches.is_empty(),
        "expected no matches for a missing label, got:\n{}",
        matches.join("\n---\n")
    );
}

#[test]
fn test_extract_label_rejects_empty_input() {
    let mut policy = CilPolicy::from_file(fixture_path("extract_label.cil"))
        .expect("failed to load standalone CIL fixture");

    let err = policy
        .extract_label("   ")
        .expect_err("expected empty label extraction to fail");

    assert!(
        err.to_string().contains("label must not be empty"),
        "unexpected error for empty label: {err}"
    );
}

#[test]
fn test_compile_helpers_produce_equivalent_policies() {
    let path = fixture_path("extract_label.cil");

    let helper_policy = CilPolicy::compile_file(&path).unwrap_or_else(|e| {
        panic!(
            "failed to compile standalone CIL fixture with compile_file helper ({}): {}",
            path.display(),
            e
        )
    });

    let helper_attributes = sorted_strings(helper_policy.attributes());
    let helper_types = sorted_strings(helper_policy.types());
    let helper_avtabs = sorted_strings(helper_policy.avtabs());

    assert!(
        helper_attributes
            .iter()
            .any(|entry| entry == "attribute exec_type"),
        "compiled policy did not expose expected attribute set.\nAttributes:\n{}",
        helper_attributes.join("\n")
    );
    assert!(
        helper_types
            .iter()
            .any(|entry| entry.contains("hal_charger_oplus_exec")),
        "compiled policy did not include hal_charger_oplus_exec in types().\nTypes:\n{}",
        helper_types.join("\n")
    );
    assert!(
        helper_types
            .iter()
            .any(|entry| entry == "permissive hal_charger_oplus"),
        "compiled policy did not include permissive hal_charger_oplus.\nTypes:\n{}",
        helper_types.join("\n")
    );
    assert!(
        helper_avtabs.iter().any(|entry| {
            entry.starts_with("allow init hal_charger_oplus_exec file") && entry.contains("execute")
        }),
        "compiled policy did not include the expected init -> exec allow rule.\nAV rules:\n{}",
        helper_avtabs.join("\n")
    );
    assert!(
        helper_avtabs.iter().any(|entry| {
            entry.starts_with("allow hal_charger_oplus hal_charger_oplus_exec file")
                && entry.contains("entrypoint")
        }),
        "compiled policy did not include the expected domain -> exec allow rule.\nAV rules:\n{}",
        helper_avtabs.join("\n")
    );
    assert!(
        helper_avtabs.iter().any(|entry| {
            entry.starts_with(
                "type_transition init hal_charger_oplus_exec process hal_charger_oplus",
            )
        }),
        "compiled policy did not include the expected type_transition rule.\nAV rules:\n{}",
        helper_avtabs.join("\n")
    );

    let mut builder_policy = CilPolicy::from_file(&path).unwrap_or_else(|e| {
        panic!(
            "failed to load standalone CIL fixture for builder compile ({}): {}",
            path.display(),
            e
        )
    });

    let compiled_from_builder = builder_policy.compile().unwrap_or_else(|e| {
        panic!(
            "failed to compile standalone CIL fixture with builder compile ({}): {}",
            path.display(),
            e
        )
    });

    let builder_attributes = sorted_strings(compiled_from_builder.attributes());
    let builder_types = sorted_strings(compiled_from_builder.types());
    let builder_avtabs = sorted_strings(compiled_from_builder.avtabs());

    assert_eq!(
        builder_attributes, helper_attributes,
        "builder compile and helper compile produced different attribute sets"
    );
    assert_eq!(
        builder_types, helper_types,
        "builder compile and helper compile produced different type outputs"
    );
    assert_eq!(
        builder_avtabs, helper_avtabs,
        "builder compile and helper compile produced different AV rule outputs"
    );
}

//! Integration tests for the SELinux .te file parser.

use sepolicy::{SePolicy, parser};
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn test_context_statements_followed_by_more_lines_apply() {
    // A context's level used to keep the newline after it, so every
    // genfscon but the last in a file failed to apply.
    let policy = parser::parse(
        "type q_ml_a_t;\ntype q_ml_b_t;\n\
         genfscon sysfs /q/ml/a u:object_r:q_ml_a_t:s0\n\
         genfscon sysfs /q/ml/b u:object_r:q_ml_b_t:s0\n",
    )
    .expect("Parse failed");

    let mut sepolicy = SePolicy::from_file(fixture_path("precompiled_sepolicy"))
        .expect("failed to load precompiled sepolicy");
    sepolicy.apply_policy(&policy);

    let genfs = sepolicy.genfs_contexts();
    for expected in [
        "genfscon sysfs /q/ml/a u:object_r:q_ml_a_t:s0",
        "genfscon sysfs /q/ml/b u:object_r:q_ml_b_t:s0",
    ] {
        assert!(
            genfs.iter().any(|line| line == expected),
            "missing {expected}"
        );
    }
}

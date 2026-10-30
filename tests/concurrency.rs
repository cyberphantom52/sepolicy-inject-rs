//! Concurrent use of independent policy instances.
//!
//! libsepol and its CIL frontend keep process-global state (the flex lexer,
//! log handlers, the compat message handle). These tests drive several
//! instances from different threads at once and must not crash or corrupt
//! each other's output.

use sepolicy::{CilPolicy, SePolicy, parser};
use std::path::{Path, PathBuf};
use std::sync::Barrier;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const THREADS: usize = 8;

fn cil_fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("selinux")
        .join("libsemanage")
        .join("tests")
        .join(name)
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

struct TempOutput {
    path: PathBuf,
}

impl TempOutput {
    fn new(stem: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "sepolicy-inject-rs-{}-{}-{}",
            stem,
            std::process::id(),
            unique
        ));

        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempOutput {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Run `body(thread, iteration)` `iterations` times on each of [`THREADS`]
/// threads that start together.
fn run_concurrently(iterations: usize, body: impl Fn(usize, usize) + Sync) {
    let barrier = Barrier::new(THREADS);

    thread::scope(|scope| {
        for thread in 0..THREADS {
            let barrier = &barrier;
            let body = &body;
            scope.spawn(move || {
                barrier.wait();
                for iteration in 0..iterations {
                    body(thread, iteration);
                }
            });
        }
    });
}

#[test]
fn test_concurrent_cil_patch_validate_write() {
    let base = std::fs::read_to_string(cil_fixture_path("test_handle.cil"))
        .expect("failed to read base CIL fixture");

    // A CIL cycle takes about a millisecond; enough of them overlap to hit the
    // lexer race reliably when the lock is missing.
    run_concurrently(20, |thread, iteration| {
        let name = format!("cil_concurrent_{thread}_{iteration}");
        let patch = parser::parse(&format!(
            "attribute {name}_attr;\ntype {name}_t, {name}_attr;\nallow {name}_t self:test_class test_perm;"
        ))
        .expect("failed to parse TE patch");
        let output = TempOutput::new(&format!("{name}.cil"));

        let mut policy = CilPolicy::new()
            .add_file(&base)
            .expect("failed to add base CIL")
            .add_file(&format!(
                "(type {name}_extra_t)\n(roletype object_r {name}_extra_t)"
            ))
            .expect("failed to add extra CIL statements")
            .add_policy(&patch)
            .expect("failed to add TE patch");

        policy.validate().expect("failed to validate CIL policy");
        policy
            .write(output.path())
            .expect("failed to write merged CIL policy");

        let written =
            std::fs::read_to_string(output.path()).expect("failed to read merged CIL output");
        assert!(
            written.contains(&format!("(type {name}_t)"))
                && written.contains(&format!("(type {name}_extra_t)")),
            "merged CIL output is missing this thread's declarations"
        );
    });
}

#[test]
fn test_concurrent_sepolicy_patch_query_write() {
    let data = std::fs::read(fixture_path("precompiled_sepolicy"))
        .expect("failed to read precompiled sepolicy");

    // Each cycle loads, queries, writes and reloads a full Android policy, so
    // keep the count low: this drives every locked SePolicy path from several
    // threads rather than hunting for a rare interleaving.
    run_concurrently(4, |thread, iteration| {
        let name = format!("sepol_concurrent_{thread}_{iteration}");
        let patch = parser::parse(&format!(
            "type {name}_t;\nallow {name}_t {name}_t:process fork;"
        ))
        .expect("failed to parse TE patch");
        let output = TempOutput::new(&name);

        let mut policy = SePolicy::from_data(&data).expect("failed to load sepolicy");
        policy.apply_policy(&patch);
        let source = format!("{name}_t");
        assert!(
            policy
                .av_rules()
                .any(|rule| rule.source == source && rule.class == "process"),
            "patched rule missing from av_rules"
        );

        policy
            .write(output.path())
            .expect("failed to write patched policy");
        SePolicy::from_file(output.path()).expect("failed to reload written policy");
    });
}

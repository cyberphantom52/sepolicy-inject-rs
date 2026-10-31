//! M4 macro expansion for policy sources.

use std::path::Path;

use m4rs::processor::{Expander, MacroRegistry};
use tracing::debug;

use super::{ast::Policy, parse};
use crate::error::{Error, Result, read_to_string};

/// Expand M4 macros in `input` using macro definitions given as source text.
///
/// Definitions are loaded in order, so later sources can build on earlier
/// ones. A source that fails to load is reported as
/// [`Error::MacroDefinitions`] with its index in `macros`.
pub fn expand_with(input: &str, macros: &[&str]) -> Result<String> {
    let mut registry = MacroRegistry::new();
    for (index, source) in macros.iter().enumerate() {
        registry
            .load(source)
            .map_err(|source| Error::MacroDefinitions { index, source })?;
    }

    let mut expander = Expander::new(registry);
    expander.expand(input).map_err(Error::MacroExpansion)
}

/// Expand M4 macros in `input` using definitions loaded from `macros`.
///
/// Macro files are loaded in the order they are yielded, so later files can
/// build on definitions from earlier ones. A file that fails to load is
/// reported as [`Error::LoadMacros`] with its path.
pub fn expand<P, I>(input: &str, macros: I) -> Result<String>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let paths: Vec<P> = macros.into_iter().collect();
    let sources = paths
        .iter()
        .map(|path| {
            let path = path.as_ref();
            debug!(macro_path = %path.display(), "Loading macro file");
            read_to_string(path)
        })
        .collect::<Result<Vec<_>>>()?;
    let sources: Vec<&str> = sources.iter().map(String::as_str).collect();

    expand_with(input, &sources).map_err(|err| match err {
        Error::MacroDefinitions { index, source } => Error::LoadMacros {
            path: paths[index].as_ref().to_path_buf(),
            source,
        },
        err => err,
    })
}

/// Read a `.te` file, expand M4 macros from `macros`, and parse the result.
pub fn parse_file<P, M, I>(path: P, macros: I) -> Result<Policy>
where
    P: AsRef<Path>,
    M: AsRef<Path>,
    I: IntoIterator<Item = M>,
{
    let content = read_to_string(path.as_ref())?;
    let expanded = expand(&content, macros)?;
    Ok(parse(&expanded)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ast::{AVRuleType, Statement};
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn ids(names: &[&str]) -> HashSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn test_parse_file_expands_macros() {
        let policy = parse_file(fixture_path("macros.te"), [fixture_path("macros.m4")])
            .expect("failed to parse macro fixture");

        let rule = policy
            .statements
            .iter()
            .find_map(|stmt| match stmt {
                Statement::AVRule(rule) if rule.rule_type == AVRuleType::Allow => Some(rule),
                _ => None,
            })
            .expect("expanded policy should contain an allow rule");

        assert_eq!(rule.src_types.ids, ids(&["macro_src_t"]));
        assert_eq!(rule.tgt_types.ids, ids(&["macro_tgt_t"]));
        assert_eq!(rule.obj_classes.ids, ids(&["file"]));
        assert_eq!(rule.perms.ids, ids(&["getattr", "open", "read"]));
    }

    const PERMS_MACRO: &str = "define(`r_file_perms', `{ getattr open read }')";
    const ALLOW_MACRO: &str = "define(`allow_read', `allow $1 $2:file r_file_perms;')";

    #[test]
    fn test_expand_with_text_definitions() {
        // ALLOW_MACRO uses r_file_perms, defined by the earlier source.
        let expanded = expand_with("allow_read(a_t, b_t)", &[PERMS_MACRO, ALLOW_MACRO])
            .expect("failed to expand with text macros");

        assert_eq!(expanded.trim(), "allow a_t b_t:file { getattr open read };");
    }

    #[test]
    fn test_expand_with_reports_failing_source_index() {
        let err = expand_with("x", &[PERMS_MACRO, "`dangling"])
            .expect_err("unterminated quote should fail to load");

        assert!(
            matches!(err, Error::MacroDefinitions { index: 1, .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_expand_reports_failing_macro_path() {
        let bad = fixture_path("bad_macros.m4");
        let err = expand("x", [fixture_path("macros.m4"), bad.clone()])
            .expect_err("unterminated quote should fail to load");

        assert!(
            matches!(err, Error::LoadMacros { ref path, .. } if path == &bad),
            "unexpected error: {err:?}"
        );
    }
}

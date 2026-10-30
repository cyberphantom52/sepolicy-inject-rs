//! M4 macro expansion for policy sources.

use std::path::Path;

use m4rs::processor::{Expander, MacroRegistry};
use tracing::debug;

use super::{ast::Policy, parse};
use crate::error::{Error, Result, read_to_string};

/// Expand M4 macros in `input` using definitions loaded from `macros`.
///
/// Macro files are loaded in the order they are yielded, so later files can
/// build on definitions from earlier ones.
pub fn expand<P, I>(input: &str, macros: I) -> Result<String>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let mut registry = MacroRegistry::new();
    for path in macros {
        let path = path.as_ref();
        debug!(macro_path = %path.display(), "Loading macro file");
        let source = read_to_string(path)?;
        registry
            .load(&source)
            .map_err(|message| Error::LoadMacros {
                path: path.to_path_buf(),
                message,
            })?;
    }

    let mut expander = Expander::new(registry);
    expander.expand(input).map_err(Error::MacroExpansion)
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

    #[test]
    fn test_parse_file_missing_macro_file() {
        let missing = fixture_path("does_not_exist.m4");
        let err = parse_file(fixture_path("macros.te"), [&missing])
            .expect_err("missing macro file should fail");

        assert!(
            matches!(err, Error::Read { ref path, .. } if path == &missing),
            "unexpected error: {err:?}"
        );
    }
}

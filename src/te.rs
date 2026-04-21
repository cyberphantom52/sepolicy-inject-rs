#![allow(clippy::result_large_err)]

//! Shared helpers for loading, preprocessing, and parsing SELinux `.te` files.

use std::path::Path;

use m4rs::processor::{Expander, MacroRegistry};
use tracing::{debug, error, info};

use crate::parser::{self, ast::Policy};

/// Load a `.te` file, expand any provided M4 macro definitions, and parse the
/// expanded policy into the crate's AST representation.
pub(crate) fn parse_te_policy_from_file<P, I>(
    path: impl AsRef<Path>,
    macro_paths: I,
) -> Result<Policy, String>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let path_ref = path.as_ref();
    let path_display = path_ref.display().to_string();

    info!(path = %path_display, "Loading rules from .te file");

    let content = std::fs::read_to_string(path_ref).map_err(|e| {
        error!(path = %path_display, error = %e, "Failed to read file");
        format!("Failed to read file: {e}")
    })?;

    let expanded = expand_te_macros(&content, macro_paths).map_err(|e| {
        error!(path = %path_display, error = %e, "M4 expansion failed");
        format!("M4 expansion failed: {e}")
    })?;

    let policy = parser::parse(&expanded).map_err(|e| {
        error!(path = %path_display, error = %e, "Parse error");
        format!("Parse error: {e}")
    })?;

    info!(path = %path_display, "Successfully parsed .te file");
    Ok(policy)
}

fn expand_te_macros<P, I>(content: &str, macro_paths: I) -> Result<String, String>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let mut registry = MacroRegistry::new();

    for macro_path in macro_paths {
        let macro_path_ref = macro_path.as_ref();
        let macro_path_str = macro_path_ref
            .to_str()
            .ok_or_else(|| "Macro path contains invalid UTF-8".to_string())?;

        debug!(macro_path = %macro_path_str, "Loading macro file");

        registry.load_file(macro_path_str).map_err(|e| {
            error!(macro_path = %macro_path_str, error = %e, "Failed to load macro file");
            format!("Failed to load macro file: {e}")
        })?;
    }

    let mut expander = Expander::new(registry);
    expander.expand(content).map_err(|e| format!("{e}"))
}

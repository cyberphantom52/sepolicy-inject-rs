//! Error type shared by policy loading, patching, and serialization.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::parser::ParseError;

/// Errors returned by [`SePolicy`](crate::SePolicy) and [`CilPolicy`](crate::CilPolicy).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("path contains invalid UTF-8: {}", .0.display())]
    InvalidPath(PathBuf),

    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to load policy from {}", .0.display())]
    LoadPolicy(PathBuf),

    #[error("failed to load policy from memory")]
    LoadPolicyData,

    #[error("failed to load split policy")]
    LoadSplit,

    #[error("failed to compile split policy")]
    CompileSplit,

    #[error("failed to write policy to {}", .0.display())]
    WritePolicy(PathBuf),

    #[error("failed to add CIL source")]
    CilAdd,

    #[error("failed to validate CIL policy")]
    CilValidate,

    #[error("failed to compile CIL policy")]
    CilCompile,

    #[error("failed to render policy patch into CIL")]
    CilRender,

    #[error("rendered policy patch is empty")]
    EmptyPatch,

    #[error(transparent)]
    Parse(#[from] ParseError),

    #[cfg(feature = "m4")]
    #[error("failed to load macro file {}: {message}", path.display())]
    LoadMacros { path: PathBuf, message: String },

    #[cfg(feature = "m4")]
    #[error("M4 expansion failed: {0}")]
    MacroExpansion(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Read a file to a string, keeping the path in the error.
pub(crate) fn read_to_string(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// Borrow a path as UTF-8 for the C++ bridge.
pub(crate) fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::InvalidPath(path.to_path_buf()))
}

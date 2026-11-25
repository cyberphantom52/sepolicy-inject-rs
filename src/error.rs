//! Error type shared by policy loading, patching, and serialization.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::parser::ParseError;
#[cfg(feature = "m4")]
use m4rs::error::M4Error;

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

    #[error("failed to write {}: {source}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to add CIL source: {0}")]
    CilAdd(CilError),

    #[error("a CIL input named {0:?} is already loaded")]
    CilInputName(String),

    #[error("failed to validate CIL policy: {0}")]
    CilValidate(CilError),

    #[error("failed to compile CIL policy: {0}")]
    CilCompile(CilError),

    #[error("failed to serialize CIL policy")]
    CilSerialize,

    #[error("failed to extract statements for {0} from the CIL policy")]
    CilExtract(String),

    #[error("failed to read the CIL policy's declarations")]
    CilDeclarations,

    #[error("failed to remove types from the CIL policy")]
    CilRemove,

    #[error("failed to render policy patch into CIL")]
    CilRender,

    #[error("rendered policy patch is empty")]
    EmptyPatch,

    #[error(transparent)]
    Parse(#[from] ParseError),

    #[cfg(feature = "m4")]
    #[error("failed to load macro file {}: {source}", path.display())]
    LoadMacros {
        path: PathBuf,
        #[source]
        source: M4Error,
    },

    #[cfg(feature = "m4")]
    #[error("failed to load macro definitions at index {index}: {source}")]
    MacroDefinitions {
        index: usize,
        #[source]
        source: M4Error,
    },

    #[cfg(feature = "m4")]
    #[error("M4 expansion failed: {0}")]
    MacroExpansion(#[source] M4Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// What libsepol reported when it rejected a CIL policy.
///
/// libsepol usually reports the statement that failed first, then the
/// stages that failed because of it, such as `Failed to resolve AST`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CilError {
    /// Each error message, in the order libsepol logged it.
    pub diagnostics: Vec<CilDiagnostic>,
}

impl CilError {
    /// The first message that names a statement in one of the inputs:
    /// usually the cause of the failure.
    pub fn location(&self) -> Option<&CilDiagnostic> {
        self.diagnostics.iter().find(|d| d.input.is_some())
    }
}

impl std::fmt::Display for CilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.diagnostics.is_empty() {
            return f.write_str("libsepol gave no details");
        }
        for (i, diagnostic) in self.diagnostics.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            f.write_str(&diagnostic.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for CilError {}

/// One error message from libsepol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CilDiagnostic {
    /// The message as libsepol logged it, including its location.
    pub message: String,
    /// The input the message points at, by the name it was added under.
    pub input: Option<String>,
    /// The 1-based line in `input` the message points at.
    pub line: Option<u32>,
    /// The CIL statement starting on `line`, as written in `input`.
    pub statement: Option<String>,
}

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

pub mod ast;
mod cil;
#[cfg(feature = "m4")]
mod macros;
#[allow(clippy::module_inception)]
mod parser;

pub use cil::ToCil;
#[cfg(feature = "m4")]
pub use macros::{expand, expand_with, parse_file};
pub use parser::*;

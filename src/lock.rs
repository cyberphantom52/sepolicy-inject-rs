//! Process-wide lock serializing every call into libsepol.
//!
//! libsepol and its CIL frontend are not reentrant. They keep process-global
//! state that every policy instance shares:
//!
//! - the CIL flex lexer (`cil_lexer.c`), whose buffer stack and scan pointers
//!   are statics used by every `cil_add_file` parse;
//! - the CIL log handler and level (`cil_log.c`), set on each CIL database
//!   creation and read on every log call;
//! - `sepol_compat_handle` (`debug.c`), whose message fields are written by
//!   every `ERR`/`WARN`/`INFO` issued without an explicit handle;
//! - `avtab_android_m_compat` (`avtab.c`), set by `policydb_read` and read
//!   by `policydb_write`.
//!
//! [`SePolicy`](crate::SePolicy) and [`CilPolicy`](crate::CilPolicy) hold this
//! lock for every call that reaches libsepol, including dropping a binary
//! policy (`policydb_destroy`). C++ log callbacks run while it is held, so a
//! tracing subscriber must not call back into this crate.
//!
//! The one unlocked path is resolving names while iterating the
//! [`rules`](crate::rules) views: those calls only read the policy's own name
//! tables and run no libsepol code.

use std::sync::{Mutex, MutexGuard, PoisonError};

static LIBSEPOL: Mutex<()> = Mutex::new(());

pub(crate) fn libsepol() -> MutexGuard<'static, ()> {
    // The guarded state lives in C++, not in the mutex. A panic cannot unwind
    // out of the noexcept C++ entry points, so poisoning protects nothing.
    LIBSEPOL.lock().unwrap_or_else(PoisonError::into_inner)
}

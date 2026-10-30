//! FFI bridge that forwards libsepol and C++ log messages into Rust's tracing system.
//!
//! The library only emits `tracing` events; installing a subscriber is left to
//! the application.

// FFI bridge functions for C++ to call into Rust's tracing system.
// These are exported via the cxx bridge in lib.rs.
//
// Note: tracing's target must be a compile-time constant, so we use a fixed
// target for FFI logging and prepend the caller-provided target to the message.

const FFI_TARGET: &str = "sepolicy::ffi";

/// Log a trace-level message from C++.
pub fn log_trace(target: &str, message: &str) {
    tracing::trace!(target: FFI_TARGET, "{}: {}", target, message);
}

/// Log a debug-level message from C++.
pub fn log_debug(target: &str, message: &str) {
    tracing::debug!(target: FFI_TARGET, "{}: {}", target, message);
}

/// Log an info-level message from C++.
pub fn log_info(target: &str, message: &str) {
    tracing::info!(target: FFI_TARGET, "{}: {}", target, message);
}

/// Log a warn-level message from C++.
pub fn log_warn(target: &str, message: &str) {
    tracing::warn!(target: FFI_TARGET, "{}: {}", target, message);
}

/// Log an error-level message from C++.
pub fn log_error(target: &str, message: &str) {
    tracing::error!(target: FFI_TARGET, "{}: {}", target, message);
}


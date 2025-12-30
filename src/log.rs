//! Logging module with tracing integration and FFI bridge for C++.
//!
//! This module provides:
//! - Platform-specific subscriber initialization (tracing-subscriber for desktop, tracing-android for Android)
//! - FFI bridge functions for C++ to call into Rust's tracing system

/// Initialize the tracing subscriber based on the target platform.
///
/// On Android (when compiled with `--features android`), this uses `tracing-android`
/// to output logs to logcat.
///
/// On other platforms, this uses `tracing-subscriber` with an environment filter
/// (controllable via the `RUST_LOG` environment variable).
pub fn init_subscriber() {
    use tracing_subscriber::{prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    #[cfg(feature = "android")]
    {
        let android_layer = tracing_android::layer("sepolicy-inject-rs")
            .expect("Failed to create Android tracing layer");

        tracing_subscriber::registry()
            .with(filter)
            .with(android_layer)
            .init();
    }

    #[cfg(not(feature = "android"))]
    {
        use tracing_subscriber::fmt;

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true))
            .init();
    }
}

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


mod cil;
mod error;
mod lock;
pub mod log;
pub mod parser;
mod policy;

pub use cil::CilPolicy;
pub use error::{Error, Result};
pub use ffi::XPerm;
pub use policy::SePolicy;

// Re-export log functions for FFI bridge
pub use log::{log_debug, log_error, log_info, log_trace, log_warn};

#[cxx::bridge]
mod ffi {
    // Logging FFI - Rust functions callable from C++
    extern "Rust" {
        fn log_trace(target: &str, message: &str);
        fn log_debug(target: &str, message: &str);
        fn log_info(target: &str, message: &str);
        fn log_warn(target: &str, message: &str);
        fn log_error(target: &str, message: &str);
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct XPerm {
        low: u16,
        high: u16,
        reset: bool,
    }

    unsafe extern "C++" {
        include!("sepolicy-inject-rs/src/ffi/sepolicy.hpp");

        type SePolicyImpl;

        // AVRules
        fn allow(
            self: Pin<&mut SePolicyImpl>,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            perm: &[&str],
        );
        fn deny(
            self: Pin<&mut SePolicyImpl>,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            perm: &[&str],
        );
        fn auditallow(
            self: Pin<&mut SePolicyImpl>,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            perm: &[&str],
        );
        fn dontaudit(
            self: Pin<&mut SePolicyImpl>,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            perm: &[&str],
        );

        // AVXRules
        fn allowxperm(
            self: Pin<&mut SePolicyImpl>,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            x_perm: &[XPerm],
        );
        fn auditallowxperm(
            self: Pin<&mut SePolicyImpl>,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            x_perm: &[XPerm],
        );
        fn dontauditxperm(
            self: Pin<&mut SePolicyImpl>,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            x_perm: &[XPerm],
        );

        fn permissive(self: Pin<&mut SePolicyImpl>, types: &[&str]);
        fn enforce(self: Pin<&mut SePolicyImpl>, types: &[&str]);
        fn typeattribute(self: Pin<&mut SePolicyImpl>, ty: &[&str], attrs: &[&str]);
        #[cxx_name = "type"]
        fn type_(self: Pin<&mut SePolicyImpl>, ty: &str, attrs: &[&str]);
        fn attribute(self: Pin<&mut SePolicyImpl>, name: &str);

        fn type_transition(
            self: Pin<&mut SePolicyImpl>,
            src: &str,
            tgt: &str,
            cls: &str,
            dest: &str,
            obj: &str,
        );
        fn type_change(self: Pin<&mut SePolicyImpl>, src: &str, tgt: &str, cls: &str, dest: &str);
        fn type_member(self: Pin<&mut SePolicyImpl>, src: &str, tgt: &str, cls: &str, dest: &str);
        fn genfscon(self: Pin<&mut SePolicyImpl>, fs: &str, path: &str, context: &str);

        fn attributes(self: &SePolicyImpl) -> Vec<String>;
        fn types(self: &SePolicyImpl) -> Vec<String>;
        fn avtabs(self: &SePolicyImpl) -> Vec<String>;
        fn transitions(self: &SePolicyImpl) -> Vec<String>;
        fn genfs_contexts(self: &SePolicyImpl) -> Vec<String>;

        fn write(self: &SePolicyImpl, path: &str) -> bool;

        fn from_file_impl(path: &str) -> UniquePtr<SePolicyImpl>;
        fn from_split_impl() -> UniquePtr<SePolicyImpl>;
        fn compile_split_impl() -> UniquePtr<SePolicyImpl>;
        fn from_data_impl(data: &[u8]) -> UniquePtr<SePolicyImpl>;
    }

    // CIL Policy FFI
    unsafe extern "C++" {
        include!("sepolicy-inject-rs/src/ffi/cil.hpp");

        type CilPolicyImpl;

        fn add_file(self: Pin<&mut CilPolicyImpl>, source: &str) -> bool;
        fn write(self: Pin<&mut CilPolicyImpl>, path: &str) -> bool;
        fn validate(self: Pin<&mut CilPolicyImpl>) -> bool;
        fn compile(self: Pin<&mut CilPolicyImpl>) -> UniquePtr<SePolicyImpl>;

        fn cil_new_impl() -> UniquePtr<CilPolicyImpl>;
    }
}

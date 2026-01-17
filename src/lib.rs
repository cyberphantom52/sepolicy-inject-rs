mod cil;
pub mod log;
pub mod parser;
mod policy;

pub use ffi::{CilPolicy, SePolicy};

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

    struct SePolicy {
        inner: UniquePtr<SePolicyImpl>,
    }

    unsafe extern "C++" {
        include!("sepolicy-inject-rs/src/ffi/sepolicy.hpp");

        type SePolicyImpl;

        // AVRules
        fn allow(self: &mut SePolicy, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]);
        fn deny(self: &mut SePolicy, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]);
        fn auditallow(self: &mut SePolicy, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]);
        fn dontaudit(self: &mut SePolicy, src: &[&str], tgt: &[&str], cls: &[&str], perm: &[&str]);

        // AVXRules
        fn allowxperm(
            self: &mut SePolicy,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            x_perm: &[XPerm],
        );
        fn auditallowxperm(
            self: &mut SePolicy,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            x_perm: &[XPerm],
        );
        fn dontauditxperm(
            self: &mut SePolicy,
            src: &[&str],
            tgt: &[&str],
            cls: &[&str],
            x_perm: &[XPerm],
        );

        fn permissive(self: &mut SePolicy, types: &[&str]);
        fn enforce(self: &mut SePolicy, types: &[&str]);
        fn typeattribute(self: &mut SePolicy, ty: &[&str], attrs: &[&str]);
        #[cxx_name = "type"]
        fn type_(self: &mut SePolicy, ty: &str, attrs: &[&str]);
        fn attribute(self: &mut SePolicy, name: &str);

        fn type_transition(
            self: &mut SePolicy,
            src: &str,
            tgt: &str,
            cls: &str,
            dest: &str,
            obj: &str,
        );
        fn type_change(self: &mut SePolicy, src: &str, tgt: &str, cls: &str, dest: &str);
        fn type_member(self: &mut SePolicy, src: &str, tgt: &str, cls: &str, dest: &str);
        fn genfscon(self: &mut SePolicy, fs: &str, path: &str, context: &str);

        fn attributes(self: &SePolicy) -> Vec<String>;
        fn types(self: &SePolicy) -> Vec<String>;
        fn avtabs(self: &SePolicy) -> Vec<String>;
        fn transitions(self: &SePolicy) -> Vec<String>;
        fn genfs_contexts(self: &SePolicy) -> Vec<String>;

        fn write(self: &SePolicy, path: &str) -> bool;

        fn from_file_impl(path: &str) -> UniquePtr<SePolicyImpl>;
        fn from_split_impl() -> UniquePtr<SePolicyImpl>;
        fn compile_split_impl() -> UniquePtr<SePolicyImpl>;
        fn from_data_impl(data: &[u8]) -> UniquePtr<SePolicyImpl>;
    }

    // CIL Policy FFI
    struct CilPolicy {
        inner: UniquePtr<CilPolicyImpl>,
    }

    unsafe extern "C++" {
        include!("sepolicy-inject-rs/src/ffi/cil.hpp");

        type CilPolicyImpl;

        fn add_file(self: Pin<&mut CilPolicyImpl>, path: &str) -> bool;
        fn add_rule(self: Pin<&mut CilPolicyImpl>, name: &str, data: &str) -> bool;
        fn compile(self: Pin<&mut CilPolicyImpl>) -> bool;
        fn write(self: &CilPolicy, path: &str) -> bool;

        fn cil_new_impl() -> UniquePtr<CilPolicyImpl>;
    }
}

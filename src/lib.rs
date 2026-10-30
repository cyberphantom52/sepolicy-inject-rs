mod cil;
mod error;
mod lock;
pub mod log;
pub mod parser;
mod policy;
pub mod rules;

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

    /// Kind of an avtab entry, from its exact `specified` value.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    enum AvtabKind {
        Allow,
        AuditAllow,
        DontAudit,
        TypeTransition,
        TypeMember,
        TypeChange,
        AllowXperm,
        AuditAllowXperm,
        DontAuditXperm,
    }

    /// An avtab entry. `data` is the permission mask for access vector
    /// rules (already complemented for dontaudit) and the default type for
    /// type rules. `xperm` indexes the extended-permission list, or is
    /// `u32::MAX`.
    struct AvtabEntry {
        kind: AvtabKind,
        source: u32,
        target: u32,
        class_: u32,
        data: u32,
        xperm: u32,
    }

    /// Extended permissions of an avtab entry: a 256-bit set of ioctl
    /// functions within `driver`, or of drivers when `function` is false.
    struct XpermEntry {
        function: bool,
        driver: u8,
        perms: [u32; 8],
    }

    /// A type and the range of its attributes in the accompanying list.
    struct TypeEntry {
        value: u32,
        permissive: bool,
        attrs_start: u32,
        attrs_len: u32,
    }

    struct FilenameTransEntry<'a> {
        source: u32,
        target: u32,
        class_: u32,
        default_type: u32,
        name: &'a [u8],
    }

    struct GenfsEntry<'a> {
        fs: &'a [u8],
        path: &'a [u8],
        context: String,
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

        // Names borrowed from the policydb; empty if the value has no name.
        fn type_name_bytes(self: &SePolicyImpl, value: u32) -> &[u8];
        fn class_name_bytes(self: &SePolicyImpl, value: u32) -> &[u8];
        fn perm_name_bytes(self: &SePolicyImpl, class_value: u32, bit: u32) -> &[u8];

        // Bulk extraction of rule records, with names left as values.
        fn attribute_entries(self: &SePolicyImpl, out: &mut Vec<u32>);
        fn type_entries(self: &SePolicyImpl, out: &mut Vec<TypeEntry>, attrs: &mut Vec<u32>);
        fn avtab_entries(
            self: &SePolicyImpl,
            out: &mut Vec<AvtabEntry>,
            xperms: &mut Vec<XpermEntry>,
        );
        fn filename_trans_entries<'a>(
            self: &'a SePolicyImpl,
            out: &mut Vec<FilenameTransEntry<'a>>,
        );
        fn genfs_entries<'a>(self: &'a SePolicyImpl, out: &mut Vec<GenfsEntry<'a>>);

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
        fn to_cil(self: &CilPolicyImpl, out: &mut String) -> bool;
        fn validate(self: Pin<&mut CilPolicyImpl>) -> bool;
        fn compile(self: Pin<&mut CilPolicyImpl>) -> UniquePtr<SePolicyImpl>;

        fn cil_new_impl() -> UniquePtr<CilPolicyImpl>;
    }
}

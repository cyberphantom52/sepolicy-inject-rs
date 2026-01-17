use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/ffi/file.hpp");
    println!("cargo:rerun-if-changed=src/ffi/sepolicy.cpp");
    println!("cargo:rerun-if-changed=src/ffi/sepolicy.hpp");
    println!("cargo:rerun-if-changed=src/ffi/mmap.hpp");
    println!("cargo:rerun-if-changed=src/ffi/mmap.cpp");
    println!("cargo:rerun-if-changed=src/ffi/cil.hpp");
    println!("cargo:rerun-if-changed=src/ffi/cil.cpp");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let libsepol_dir = manifest_dir.join("selinux").join("libsepol");

    // Build libsepol
    build_libsepol();

    // Build the FFI Bridge
    cxx_build::bridge("src/lib.rs")
        .std("c++20")
        .include(&libsepol_dir.join("include"))
        .include(&libsepol_dir.join("cil").join("include"))
        .include("src/ffi")
        .file("src/ffi/mmap.cpp")
        .file("src/ffi/sepolicy.cpp")
        .file("src/ffi/cil.cpp")
        .flag("-Wno-unused-parameter")
        .compile("sepolicy_ffi");

    // Link libraries
    println!("cargo:rustc-link-lib=static=libsepol");
    println!("cargo:rustc-link-lib=static=sepolicy_ffi");

    // Link C++ standard library:
    // - Android NDK uses libc++ (c++_static)
    // - macOS uses libc++ (c++)
    // - Linux uses libstdc++ (stdc++)
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("android") {
        println!("cargo:rustc-link-lib=c++_static");
    } else if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}

fn build_libsepol() {
    let mut libsepol_build = cc::Build::new();
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let libsepol_dir = manifest_dir.join("selinux").join("libsepol");

    libsepol_build
        .cpp(false)
        .include(&libsepol_dir.join("include"))
        .include(&libsepol_dir.join("cil").join("include"))
        .include(&libsepol_dir.join("src"))
        .include(&libsepol_dir.join("cil").join("src"))
        .flag("-Wno-unused-but-set-variable")
        .flag("-Wno-deprecated-declarations");

    // Determine if we should define HAVE_REALLOCARRAY
    // - macOS: does NOT have reallocarray, use libsepol's fallback
    // - Linux (glibc): has reallocarray
    // - Android API 29+: Bionic provides reallocarray
    // - Android API < 29: Bionic does NOT have reallocarray, use libsepol's fallback
    let target = std::env::var("TARGET").unwrap_or_default();
    let android_api = std::env::var("ANDROID_PLATFORM")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    let has_reallocarray = if target.contains("apple") {
        false
    } else if target.contains("android") {
        android_api.unwrap_or(0) >= 29
    } else {
        true
    };

    if has_reallocarray {
        libsepol_build.define("HAVE_REALLOCARRAY", None);
    }

    let srcs = [
        "src/assertion.c",
        "src/avrule_block.c",
        "src/avtab.c",
        "src/boolean_record.c",
        "src/booleans.c",
        "src/conditional.c",
        "src/constraint.c",
        "src/context.c",
        "src/context_record.c",
        "src/debug.c",
        "src/ebitmap.c",
        "src/expand.c",
        "src/handle.c",
        "src/hashtab.c",
        "src/hierarchy.c",
        "src/ibendport_record.c",
        "src/ibendports.c",
        "src/ibpkey_record.c",
        "src/ibpkeys.c",
        "src/iface_record.c",
        "src/interfaces.c",
        "src/kernel_to_cil.c",
        "src/kernel_to_common.c",
        "src/kernel_to_conf.c",
        "src/link.c",
        "src/mls.c",
        "src/module.c",
        "src/module_to_cil.c",
        "src/node_record.c",
        "src/nodes.c",
        "src/optimize.c",
        "src/polcaps.c",
        "src/policydb.c",
        "src/policydb_convert.c",
        "src/policydb_public.c",
        "src/policydb_validate.c",
        "src/port_record.c",
        "src/ports.c",
        "src/services.c",
        "src/sidtab.c",
        "src/symtab.c",
        "src/user_record.c",
        "src/users.c",
        "src/util.c",
        "src/write.c",
        "cil/src/cil.c",
        "cil/src/cil_binary.c",
        "cil/src/cil_build_ast.c",
        "cil/src/cil_copy_ast.c",
        "cil/src/cil_deny.c",
        "cil/src/cil_find.c",
        "cil/src/cil_fqn.c",
        "cil/src/cil_lexer.c",
        "cil/src/cil_list.c",
        "cil/src/cil_log.c",
        "cil/src/cil_mem.c",
        "cil/src/cil_parser.c",
        "cil/src/cil_policy.c",
        "cil/src/cil_post.c",
        "cil/src/cil_reset_ast.c",
        "cil/src/cil_resolve_ast.c",
        "cil/src/cil_stack.c",
        "cil/src/cil_strpool.c",
        "cil/src/cil_symtab.c",
        "cil/src/cil_tree.c",
        "cil/src/cil_verify.c",
        "cil/src/cil_write_ast.c",
    ];

    for s in &srcs {
        libsepol_build.file(libsepol_dir.join(s));
    }

    libsepol_build.compile("libsepol");
}

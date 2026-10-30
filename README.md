# sepolicy-inject-rs

A Rust library and CLI tool for injecting SELinux policy rules into compiled policy binaries. This tool allows you to modify existing SELinux policies by applying rules from `.te` (Type Enforcement) files without needing to recompile the entire policy.

## Features

- **Load compiled policies**: Support for monolithic policy files and Android split policies
- **CIL**: Patch, validate and compile CIL sources, in memory or on disk
- **Parse and apply `.te` files**: Parse Type Enforcement files and inject rules into loaded policies
- **Query rules**: Structured rule views that borrow names from the policy instead of formatting text
- **M4 macro expansion**: Built-in support for M4 macro preprocessing (required for many SELinux policy files)
- **Live patching**: Load patched policies directly into the running kernel (Android)
- **CLI and library**: Use as a command-line tool or embed in your Rust projects
- **Android support**: Special support for Android's split policy system

## Installation

### Building from Source

```bash
git clone --recurse-submodules https://github.com/cyberphantom52/sepolicy-inject-rs.git
cd sepolicy-inject-rs
cargo build --release --features cli
```

The binary will be at `target/release/sepolicy-inject-rs`.

### Building for Android

To build for Android, you'll need:

1. **Android NDK**: Download and install the Android NDK (r29 or later recommended)
2. **cargo-ndk**: Install the cargo-ndk tool:
   ```bash
   cargo install cargo-ndk
   ```
3. **Rust Android targets**: Install the target for your desired architecture:
   ```bash
   rustup target add aarch64-linux-android  # For arm64-v8a
   rustup target add armv7-linux-androideabi  # For armeabi-v7a
   rustup target add x86_64-linux-android  # For x86_64
   rustup target add i686-linux-android  # For x86
   ```

Then build with:

```bash
# Set Android NDK path to your NDK installation directory
# Replace the path below with your actual NDK path
export ANDROID_NDK_HOME=/path/to/your/android-ndk

# Build for arm64-v8a (most common)
# Use -P to specify Android platform version
cargo ndk -t arm64-v8a -P 30 build --release --features cli

# Build for other architectures
cargo ndk -t armeabi-v7a -P 30 build --release --features cli
cargo ndk -t x86_64 -P 30 build --release --features cli
cargo ndk -t x86 -P 30 build --release --features cli

# Build for all architectures
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 -P 30 build --release --features cli
```

The binaries will be at `target/aarch64-linux-android/release/sepolicy-inject-rs` (or corresponding path for other architectures).

### Dependencies

- Rust 1.70+ (2024 edition)
- C++ compiler (for building libsepol bindings)
- libsepol (included as submodule in `selinux/`)
- **For Android builds**: Android NDK r29+ and `cargo-ndk`

## Usage

### Command Line Interface

Every command starts from a policy source: `precompiled` (a binary policy),
`cil` (one CIL file) or `split-cil` (an ordered list of CIL files). Without a
further command, the CLI prints a summary of the loaded policy.

#### Print Policy Rules

```bash
# Print all rules
sepolicy-inject-rs precompiled --policy /path/to/policy print

# Print one kind: attributes, types, avtabs, transitions or genfs
sepolicy-inject-rs precompiled --policy /path/to/policy print avtabs
```

#### Patch a Binary Policy with .te Files

```bash
# Apply .te files (repeat -p for several), expanding M4 macros (repeat -m)
sepolicy-inject-rs precompiled --policy /path/to/policy \
  patch -p rules.te -m global_macros.m4 -m te_macros.m4 \
  --output /path/to/patched_policy
```

#### Work with CIL

```bash
# Patch a CIL file and write the merged CIL (without --output it only checks
# that the patched policy resolves). --resolve-with loads extra CIL files
# first, for references the patched file does not define itself.
sepolicy-inject-rs cil vendor_sepolicy.cil \
  patch -p rules.te --resolve-with plat_sepolicy.cil --output patched.cil

# Compile CIL to a binary policy, then optionally print or patch it
sepolicy-inject-rs cil policy.cil compile --output policy.bin print types

# Compile an ordered list of CIL files, in the order given
sepolicy-inject-rs split-cil \
  --source plat_sepolicy.cil --source mapping.cil --source vendor_sepolicy.cil \
  compile --output policy.bin
```

#### Android-Specific Usage

Android builds add two sources and live patching:

```bash
# The running kernel policy (/sys/fs/selinux/policy)
sepolicy-inject-rs live-load print

# The device's split policy: the precompiled policy when it matches the
# installed CIL, otherwise compiled from the CIL files
sepolicy-inject-rs load-split print

# Patch and save to a file
sepolicy-inject-rs live-load patch -p rules.te -m te_macros.m4 --output /data/local/tmp/patched

# Patch and load the result into the kernel
sepolicy-inject-rs live-load patch -p rules.te --live-patch
```

> **Note**: `--live-patch` writes the patched policy to `/sys/fs/selinux/load`, which requires root.

### Library Usage

Add the crate as a git dependency; it is imported as `sepolicy`. The CLI-only
dependencies (`clap`, `tracing-subscriber`) sit behind the `cli` feature, so
the library pulls in only what it needs.

```toml
[dependencies]
sepolicy-inject-rs = { git = "https://github.com/cyberphantom52/sepolicy-inject-rs.git" }
```

| Feature   | Default | Description                                                      |
|-----------|---------|------------------------------------------------------------------|
| `m4`      | yes     | M4 macro expansion (`parser::parse_file`, `load_rules_from_file`) |
| `cli`     | no      | Builds the `sepolicy-inject-rs` binary                            |
| `android` | no      | `cli` plus logcat logging via `tracing-android`                   |

The library emits `tracing` events but does not install a subscriber.

```rust
use sepolicy::SePolicy;

// Load a policy from file
let mut policy = SePolicy::from_file("policy.bin")
    .expect("Failed to load policy");

// Apply rules from a .te file
policy.load_rules_from_file(
    "rules.te",
    ["global_macros.m4", "te_macros.m4"]
).expect("Failed to apply rules");

// Query the policy as text
let avtabs = policy.avtabs();
let types = policy.types();
let attributes = policy.attributes();

// Or as structured rules that borrow names from the policy instead of
// formatting every line
let can_fork = policy
    .av_rules()
    .any(|rule| rule.source == "my_domain_t" && rule.perms().any(|p| p == "fork"));

// Apply rules programmatically
policy.allow(
    &["my_domain_t"],
    &["my_file_t"],
    &["file"],
    &["read", "write"]
);

// Make a domain permissive
policy.permissive(&["my_domain_t"]);
```

### Example .te File

```te
# Define types
type my_domain_t;
type my_file_t, file_type;

# Define attribute
attribute my_attr;

# Associate type with attribute
typeattribute my_domain_t my_attr;

# Add allow rules
allow my_domain_t my_file_t:file { read write open };

# Type transition
type_transition my_domain_t my_file_t:file my_file_t;

# Make domain permissive
permissive my_domain_t;
```

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_add_allow_rule

# Run with output
cargo test -- --nocapture
```

### Project Structure

```
sepolicy-inject-rs/
├── src/
│   ├── lib.rs          # Library entry point and C++ bridge declarations
│   ├── main.rs         # CLI (behind the `cli` feature)
│   ├── policy.rs       # SePolicy: binary policies
│   ├── cil.rs          # CilPolicy: CIL sources
│   ├── rules.rs        # Structured, borrowing rule views
│   ├── error.rs        # Error type
│   ├── lock.rs         # Lock serializing libsepol access
│   ├── log.rs          # Forwards C++ log messages to tracing
│   ├── parser/         # .te parser
│   │   ├── policy.pest # Grammar
│   │   ├── parser.rs   # Grammar to AST
│   │   ├── ast.rs      # Abstract syntax tree
│   │   ├── cil.rs      # AST to CIL rendering
│   │   └── macros.rs   # M4 expansion (behind the `m4` feature)
│   └── ffi/            # C++ side of the bridge
│       ├── sepolicy.cpp/.hpp
│       ├── cil.cpp/.hpp
│       └── mmap.cpp/.hpp, utils.hpp
├── tests/
│   ├── fixtures/       # Test policies, .te and .m4 files
│   ├── concurrency.rs  # Concurrent use from several threads
│   └── parser_test.rs  # Parser tests
└── selinux/            # libsepol submodule
```

## License

See `LICENSE` file for details.

## Contributing

Contributions are welcome! Please ensure:

- Code follows Rust style guidelines
- Tests pass (`cargo test`)
- New features include tests

## Credits

A significant portion of the code in this project was ported or adapted from [Magisk](https://github.com/topjohnwu/Magisk), particularly the SELinux policy manipulation and Android-specific functionality. Magisk is licensed under GPL-3.0.

This project also includes code from the SELinux project (libsepol) which is licensed under LGPL.

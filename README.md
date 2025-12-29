# sepolicy-inject-rs

A Rust library and CLI tool for injecting SELinux policy rules into compiled policy binaries. This tool allows you to modify existing SELinux policies by applying rules from `.te` (Type Enforcement) files without needing to recompile the entire policy.

## Features

- **Load compiled policies**: Support for monolithic policy files and Android split policies
- **Parse and apply `.te` files**: Parse Type Enforcement files and inject rules into loaded policies
- **M4 macro expansion**: Built-in support for M4 macro preprocessing (required for many SELinux policy files)
- **CLI and library**: Use as a command-line tool or embed in your Rust projects
- **Android support**: Special support for Android's split policy system

## Installation

### Building from Source

```bash
git clone --recurse-submodules https://github.com/cyberphantom52/sepolicy-inject-rs.git
cd sepolicy-inject-rs
cargo build --release
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
cargo ndk -t arm64-v8a -P 30 build --release

# Build for other architectures
cargo ndk -t armeabi-v7a -P 30 build --release
cargo ndk -t x86_64 -P 30 build --release
cargo ndk -t x86 -P 30 build --release

# Build for all architectures
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 -P 30 build --release
```

The binaries will be at `target/aarch64-linux-android/release/sepolicy-inject-rs` (or corresponding path for other architectures).

### Dependencies

- Rust 1.70+ (2024 edition)
- C++ compiler (for building libsepol bindings)
- libsepol (included as submodule in `selinux/`)
- **For Android builds**: Android NDK r29+ and `cargo-ndk`

## Usage

### Command Line Interface

#### Load and Print Policy Rules

```bash
# Load a policy and print all rules
sepolicy-inject-rs --load /path/to/policy print

# Print specific rule types
sepolicy-inject-rs --load /path/to/policy print avtabs
sepolicy-inject-rs --load /path/to/policy print types
sepolicy-inject-rs --load /path/to/policy print attributes
sepolicy-inject-rs --load /path/to/policy print transitions
sepolicy-inject-rs --load /path/to/policy print genfs
```

#### Patch Policy with .te Files

```bash
# Apply a single .te file
sepolicy-inject-rs --load /path/to/policy patch rules.te

# Apply multiple .te files
sepolicy-inject-rs --load /path/to/policy patch rules1.te rules2.te

# Apply with M4 macro definitions
sepolicy-inject-rs --load /path/to/policy patch rules.te -m global_macros.m4 -m te_macros.m4

# Apply multiple files with macros
sepolicy-inject-rs --load /path/to/policy patch *.te -m macros.m4
```

#### Android-Specific Usage

On Android devices or when building for Android, the tool automatically loads from the live policy (`/sys/fs/selinux/policy`) if no source option is specified:

```bash
# Load from live policy (default - no options needed)
sepolicy-inject-rs print
sepolicy-inject-rs patch rules.te -m te_macros.m4

# Load from precompiled split policy
sepolicy-inject-rs --load-split print

# Compile split CIL policies
sepolicy-inject-rs --compile-split print

# Explicitly load from a file (overrides default)
sepolicy-inject-rs --load /path/to/policy.bin print
```

### Library Usage

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

// Query the policy
let avtabs = policy.avtabs();
let types = policy.types();
let attributes = policy.attributes();

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
│   ├── lib.rs          # Main library API
│   ├── main.rs         # CLI implementation
│   ├── parser/         # .te file parser
│   │   ├── parser.rs   # Pest grammar implementation
│   │   ├── ast.rs      # Abstract Syntax Tree
│   │   └── policy.pest # Grammar definition
│   └── ffi/            # C++ FFI bindings
│       ├── sepolicy.cpp
│       └── sepolicy.hpp
├── tests/
│   ├── fixtures/       # Test policy files
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


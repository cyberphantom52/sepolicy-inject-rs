# Linux releases

The release workflow tests and builds Linux x86-64 executables on Ubuntu 22.04
with Rust 1.93.1 and the committed Cargo.lock. Run it manually to check a branch,
or push a tag matching the Cargo package version (initially `v0.1.0`) to publish.

Assets contain the executable, license, source/submodule revisions, compiler
version, lockfile checksum, and dynamic-library requirements. The adjacent
`.sha256` file covers the complete archive. Linux hosts need glibc 2.35 or later
and the standard libraries listed in BUILD-INFO.txt; end users do not need Rust.

Evelyn pins the published archive URL and SHA-256. Publish a new version rather
than replacing an existing asset.

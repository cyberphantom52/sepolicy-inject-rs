#pragma once

#include "sepolicy-inject-rs/src/ffi/sepolicy.hpp"
#include <memory>
#include <optional>
#include <rust/cxx.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cil/cil.h>
#include <sepol/policydb.h>

struct cil_db_deleter {
  void operator()(cil_db_t *db) const noexcept { cil_db_destroy(&db); }
};

using unique_cil_db = std::unique_ptr<cil_db_t, cil_db_deleter>;

// One input: its name, its text, and a database holding only its parse tree.
// The parse tree is never built, so it stays as cil_parser left it, and is
// shared by every policy cloned from the one it was added to.
struct CilSource {
  std::string name;
  std::string text;
  unique_cil_db parsed;
};

// libsepol consumes a cil_db_t's parse tree when it builds the AST, so a
// database supports a single validate, write or compile. CilPolicyImpl parses
// each input once and copies the parse trees into a fresh database for each
// operation, which skips lexing the text again.
//
// Destroying a CilSource frees libsepol memory, so copies and destruction of
// a CilPolicyImpl need the libsepol lock, as every other call does.
class CilPolicyImpl {
  std::vector<std::shared_ptr<const CilSource>> sources;
  std::optional<int> policy_version;

  unique_cil_db new_db() const noexcept;
  unique_cil_db build_db() const noexcept;
  std::string next_input_name() const;
  bool has_source(std::string_view name) const noexcept;
  bool add_file(std::string name, const char *source, size_t size) noexcept;

public:
  CilPolicyImpl();
  CilPolicyImpl(const CilPolicyImpl &) = default;

  // A policy holding the same inputs, which shares their parse trees.
  std::unique_ptr<CilPolicyImpl> clone() const noexcept;

  // The bridge's entry points collect the error messages libsepol logs.
  bool add_file(rust::Str name, rust::Str source,
                rust::Vec<rust::String> &errors) noexcept;
  bool validate(rust::Vec<rust::String> &errors) noexcept;
  std::unique_ptr<SePolicyImpl> compile(rust::Vec<rust::String> &errors) noexcept;
  rust::Slice<const uint8_t> source_text(rust::Str name) const noexcept;
  rust::String next_name() const noexcept;

  bool add_file(const char *source, size_t size) noexcept;
  bool validate() noexcept;
  bool to_cil(rust::String &out) const noexcept;
  void set_policy_version(int version) noexcept;
  std::unique_ptr<SePolicyImpl> compile() noexcept;
  bool extract_label(rust::Str label, rust::Vec<rust::String> &out) const noexcept;
  bool declared_types(rust::Vec<rust::String> &out) const noexcept;
  bool remove_types(rust::Slice<const rust::String> names) noexcept;
};

std::unique_ptr<CilPolicyImpl> cil_new_impl() noexcept;

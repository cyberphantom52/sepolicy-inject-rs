#pragma once

#include "sepolicy-inject-rs/src/ffi/sepolicy.hpp"
#include <memory>
#include <optional>
#include <rust/cxx.h>
#include <string>
#include <utility>
#include <vector>

#include <cil/cil.h>
#include <sepol/policydb.h>

struct cil_db_deleter {
  void operator()(cil_db_t *db) const noexcept { cil_db_destroy(&db); }
};

using unique_cil_db = std::unique_ptr<cil_db_t, cil_db_deleter>;

// libsepol consumes a cil_db_t's parse tree when it builds the AST, so a
// database supports a single validate, write or compile. CilPolicyImpl keeps
// the (name, source) pairs it was given and replays them into a fresh
// database for each operation.
class CilPolicyImpl {
  std::vector<std::pair<std::string, std::string>> sources;
  std::optional<int> policy_version;

  unique_cil_db new_db() const noexcept;
  unique_cil_db build_db() const noexcept;

public:
  CilPolicyImpl();

  bool add_file(rust::Str source) noexcept;
  bool add_file(const char *source, size_t size) noexcept;
  bool validate() noexcept;
  bool write(rust::Str path) noexcept;
  bool write(const char *path) noexcept;
  void set_policy_version(int version) noexcept;
  std::unique_ptr<SePolicyImpl> compile() noexcept;
};

std::unique_ptr<CilPolicyImpl> cil_new_impl() noexcept;

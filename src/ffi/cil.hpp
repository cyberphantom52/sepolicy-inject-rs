#pragma once

#include "sepolicy-inject-rs/src/ffi/sepolicy.hpp"
#include <memory>
#include <rust/cxx.h>

#include <cil/cil.h>
#include <sepol/policydb.h>

class CilPolicyImpl {
  cil_db_t *db;
  friend struct CilPolicy;

public:
  CilPolicyImpl();
  ~CilPolicyImpl();

  bool add_file(rust::Str path) noexcept;
  bool add_rule(rust::Str name, rust::Str data) noexcept;
  bool compile() noexcept;
  void set_policy_version(int version) noexcept;

  bool write(rust::Str path);

  std::unique_ptr<SePolicyImpl> build() noexcept;
};

std::unique_ptr<CilPolicyImpl> cil_new_impl() noexcept;

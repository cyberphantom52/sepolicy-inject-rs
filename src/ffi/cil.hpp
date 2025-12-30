#pragma once

#include "sepolicy-inject-rs/src/ffi/sepolicy.hpp"
#include <memory>
#include <rust/cxx.h>

#include <cil/cil.h>
#include <sepol/policydb.h>

// CIL files
static const char *CIL_FILES[] = {
    PLAT_POLICY_DIR "mapping/%s.cil",
    PLAT_POLICY_DIR "mapping/%s.compat.cil",
    SYSEXT_POLICY_DIR "mapping/%s.cil",
    SYSEXT_POLICY_DIR "mapping/%s.compat.cil",
    SYSEXT_POLICY_DIR "system_ext_sepolicy.cil",
    PROD_POLICY_DIR "mapping/%s.cil",
    PROD_POLICY_DIR "product_sepolicy.cil",
    VEND_POLICY_DIR "nonplat_sepolicy.cil",
    VEND_POLICY_DIR "plat_pub_versioned.cil",
    VEND_POLICY_DIR "vendor_sepolicy.cil",
    ODM_POLICY_DIR "odm_sepolicy.cil",
};

class CilPolicyImpl {
  cil_db_t *db;
  friend struct CilPolicy;

public:
  CilPolicyImpl();
  ~CilPolicyImpl();

  bool add_file(rust::Str path) noexcept;
  bool add_file(const char *path) noexcept;
  void set_policy_version(int version) noexcept;
  std::unique_ptr<SePolicyImpl> compile() noexcept;
};

std::unique_ptr<CilPolicyImpl> cil_new_impl() noexcept;

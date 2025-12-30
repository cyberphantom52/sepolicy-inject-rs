#include "sepolicy-inject-rs/src/lib.rs.h"
#include "mmap.hpp"

#include <cil/cil.h>
#include <memory>

CilPolicyImpl::CilPolicyImpl() : db(nullptr) {
  cil_db_init(&db);
  cil_set_mls(db, 1);
  cil_set_multiple_decls(db, 1);
  cil_set_disable_neverallow(db, 1);
  cil_set_target_platform(db, SEPOL_TARGET_SELINUX);
  cil_set_attrs_expand_generated(db, 1);
}

std::unique_ptr<CilPolicyImpl> cil_new_impl() noexcept {
  return std::make_unique<CilPolicyImpl>();
}

CilPolicyImpl::~CilPolicyImpl() {
  cil_db_destroy(&db);
  free(db);
}

bool CilPolicyImpl::add_file(rust::Str path) noexcept {
  std::string path_str(path.data(), path.size());
  return add_file(path_str.c_str());
}

bool CilPolicyImpl::add_file(const char *path) noexcept {
  mmap_data data(path);
  if (!data.data() || data.size() == 0) {
    return false;
  }

  if (cil_add_file(db, path, (const char *)data.data(), data.size()) !=
      SEPOL_OK) {
    return false;
  }

  return true;
}

void CilPolicyImpl::set_policy_version(int version) noexcept {
  cil_set_policy_version(db, version);
}

std::unique_ptr<SePolicyImpl> CilPolicyImpl::compile() noexcept {
  sepol_policydb_t *pdb = nullptr;
  if (cil_compile(db) != SEPOL_OK) {
    return nullptr;
  }
  if (cil_build_policydb(db, &pdb) != SEPOL_OK) {
    return nullptr;
  }
  return std::make_unique<SePolicyImpl>(&pdb->p);
}

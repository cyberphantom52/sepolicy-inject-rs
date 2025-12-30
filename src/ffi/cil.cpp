#include "sepolicy-inject-rs/src/lib.rs.h"
#include "mmap.hpp"

#include <cil/cil.h>
#include <memory>

// Logging target for CIL operations
static constexpr const char *CIL_LOG_TARGET = "sepolicy::cil";

// Setup CIL log handler to route messages through Rust's tracing
static void setup_cil_logging() {
  cil_set_log_handler(+[](int lvl, const char *msg) {
    // Remove trailing newline if present
    std::string message(msg);
    if (!message.empty() && message.back() == '\n') {
      message.pop_back();
    }

    if (lvl == CIL_ERR) {
      log_error(CIL_LOG_TARGET, message);
    } else if (lvl == CIL_WARN) {
      log_warn(CIL_LOG_TARGET, message);
    } else if (lvl == CIL_INFO) {
      log_info(CIL_LOG_TARGET, message);
    } else {
      log_debug(CIL_LOG_TARGET, message);
    }
  });
}

CilPolicyImpl::CilPolicyImpl() : db(nullptr) {
  setup_cil_logging();
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
  log_trace(CIL_LOG_TARGET, std::string("Loading CIL file: ") + path);

  mmap_data data(path);
  if (!data.data() || data.size() == 0) {
    log_error(CIL_LOG_TARGET,
              std::string("Failed to mmap CIL file: ") + path);
    return false;
  }

  if (cil_add_file(db, path, (const char *)data.data(), data.size()) !=
      SEPOL_OK) {
    log_error(CIL_LOG_TARGET,
              std::string("Failed to parse CIL file: ") + path);
    return false;
  }

  log_debug(CIL_LOG_TARGET, std::string("Successfully loaded CIL file: ") +
                                path + " (" + std::to_string(data.size()) +
                                " bytes)");
  return true;
}

void CilPolicyImpl::set_policy_version(int version) noexcept {
  cil_set_policy_version(db, version);
}

std::unique_ptr<SePolicyImpl> CilPolicyImpl::compile() noexcept {
  log_info(CIL_LOG_TARGET, "Compiling CIL database...");

  sepol_policydb_t *pdb = nullptr;
  if (cil_compile(db) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "CIL compilation failed");
    return nullptr;
  }
  log_debug(CIL_LOG_TARGET, "CIL compilation successful, building policydb...");

  if (cil_build_policydb(db, &pdb) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "Failed to build policydb from CIL");
    return nullptr;
  }

  log_info(CIL_LOG_TARGET, "Successfully built policydb from CIL");
  return std::make_unique<SePolicyImpl>(&pdb->p);
}

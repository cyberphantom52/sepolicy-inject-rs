#include "mmap.hpp"
#include "sepolicy-inject-rs/src/lib.rs.h"

#include <cil/cil.h>
#include <cstdio>
#include <memory>
#include <string>

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
  log_trace(CIL_LOG_TARGET, std::string("Loading CIL file: ") + path_str);

  mmap_data data(path_str.c_str());
  if (!data.data() || data.size() == 0) {
    log_error(CIL_LOG_TARGET, std::string("Failed to mmap CIL file: ") + path_str);
    return false;
  }

  if (cil_add_file(db, path_str.c_str(), (const char *)data.data(), data.size()) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, std::string("Failed to parse CIL file: ") + path_str);
    return false;
  }

  log_debug(CIL_LOG_TARGET, std::string("Successfully loaded CIL file: ") +
                                path_str + " (" + std::to_string(data.size()) + " bytes)");
  return true;
}

bool CilPolicyImpl::add_rule(rust::Str name, rust::Str data) noexcept {
  std::string name_str(name.data(), name.size());
  std::string data_str(data.data(), data.size());

  log_trace(CIL_LOG_TARGET, std::string("Adding CIL rule: ") + name_str);

  if (cil_add_file(db, name_str.c_str(), data_str.c_str(), data_str.size()) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, std::string("Failed to add CIL rule: ") + name_str);
    return false;
  }

  log_debug(CIL_LOG_TARGET, std::string("Successfully added CIL rule: ") +
                                name_str + " (" + std::to_string(data_str.size()) + " bytes)");
  return true;
}

bool CilPolicyImpl::compile() noexcept {
  log_info(CIL_LOG_TARGET, "Compiling CIL database...");

  if (cil_compile(db) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "CIL compilation failed");
    return false;
  }

  log_info(CIL_LOG_TARGET, "CIL compilation successful");
  return true;
}

void CilPolicyImpl::set_policy_version(int version) noexcept {
  cil_set_policy_version(db, version);
}

std::unique_ptr<SePolicyImpl> CilPolicyImpl::build() noexcept {
  log_debug(CIL_LOG_TARGET, "Building policydb from CIL...");

  if (!this->compile()) {
    return nullptr;
  }

  sepol_policydb_t *pdb = nullptr;
  if (cil_build_policydb(db, &pdb) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "Failed to build policydb from CIL");
    return nullptr;
  }

  log_info(CIL_LOG_TARGET, "Successfully built policydb from CIL");
  return std::make_unique<SePolicyImpl>(&pdb->p);
}

bool CilPolicyImpl::write(rust::Str path) {
  std::string path_str(path.data(), path.size());
  log_info(CIL_LOG_TARGET, std::string("Writing CIL to: ") + path_str);

  FILE *out = fopen(path_str.c_str(), "w");
  if (!out) {
    log_error(CIL_LOG_TARGET, std::string("Failed to open file for writing: ") + path_str);
    return false;
  }

  int rc = cil_write_post_ast(out, const_cast<cil_db_t *>(db));
  fclose(out);

  if (rc != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, std::string("Failed to write CIL: ") + path_str);
    return false;
  }

  log_info(CIL_LOG_TARGET, std::string("Successfully wrote CIL to: ") + path_str);
  return true;
}

bool CilPolicy::write(::rust::Str path) const noexcept {
  return inner->write(path);
}

#include "sepolicy-inject-rs/src/lib.rs.h"
#include "utils.hpp"

#include <atomic>
#include <cil/cil.h>
#include <memory>

// Logging target for CIL operations
static constexpr const char *CIL_LOG_TARGET = "sepolicy::cil";
static std::atomic_size_t NEXT_CIL_SOURCE_ID{1};

static std::string next_generated_cil_name() {
  auto id = NEXT_CIL_SOURCE_ID.fetch_add(1, std::memory_order_relaxed);
  return std::string("generated_input_") + std::to_string(id) + ".cil";
}


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
}

bool CilPolicyImpl::add_file(rust::Str source) noexcept {
  return add_file(source.data(), source.size());
}

bool CilPolicyImpl::add_file(const char *source, size_t size) noexcept {
  auto name = next_generated_cil_name();
  log_trace(CIL_LOG_TARGET,
            std::string("Loading in-memory CIL source: ") + name);

  if (source == nullptr || size == 0) {
    log_error(CIL_LOG_TARGET,
              std::string("Refusing to load empty CIL source: ") + name);
    return false;
  }

  if (cil_add_file(db, name.c_str(), source, size) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET,
              std::string("Failed to parse CIL source: ") + name);
    return false;
  }

  log_debug(CIL_LOG_TARGET,
            std::string("Successfully loaded in-memory CIL source: ") + name +
                " (" + std::to_string(size) + " bytes)");
  return true;
}

bool CilPolicyImpl::validate() noexcept {
  log_info(CIL_LOG_TARGET, "Validating CIL AST with libsepol resolution...");

  unique_file sink(std::tmpfile());
  if (!sink) {
    log_error(CIL_LOG_TARGET,
              "Failed to create temporary file for CIL AST validation");
    return false;
  }

  if (cil_write_resolve_ast(sink.get(), db) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "CIL AST validation failed during resolution");
    return false;
  }

  log_info(CIL_LOG_TARGET, "CIL AST validation completed successfully");
  return true;
}

bool CilPolicyImpl::write(rust::Str path) noexcept {
  std::string path_str(path.data(), path.size());
  return write(path_str.c_str());
}

bool CilPolicyImpl::write(const char *path) noexcept {
  log_info(CIL_LOG_TARGET, std::string("Writing merged CIL AST to: ") + path);

  auto out = open_file(path, "w");
  if (!out) {
    log_error(CIL_LOG_TARGET,
              std::string("Failed to open output file for writing: ") + path);
    return false;
  }

  if (cil_write_build_ast(out->get(), db) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET,
              std::string("Failed to write merged CIL AST: ") + path);
    return false;
  }

  log_info(CIL_LOG_TARGET,
           std::string("Successfully wrote merged CIL AST: ") + path);
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

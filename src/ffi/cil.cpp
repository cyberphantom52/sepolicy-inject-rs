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

CilPolicyImpl::CilPolicyImpl() { setup_cil_logging(); }

unique_cil_db CilPolicyImpl::new_db() const noexcept {
  cil_db_t *raw = nullptr;
  cil_db_init(&raw);
  unique_cil_db db(raw);

  cil_set_mls(db.get(), 1);
  cil_set_multiple_decls(db.get(), 1);
  cil_set_disable_neverallow(db.get(), 1);
  cil_set_target_platform(db.get(), SEPOL_TARGET_SELINUX);
  cil_set_attrs_expand_generated(db.get(), 1);
  if (policy_version) {
    cil_set_policy_version(db.get(), *policy_version);
  }
  return db;
}

// Fresh database with every source added so far, or null if one fails to parse.
unique_cil_db CilPolicyImpl::build_db() const noexcept {
  auto db = new_db();
  for (const auto &[name, source] : sources) {
    if (cil_add_file(db.get(), name.c_str(), source.data(), source.size()) !=
        SEPOL_OK) {
      log_error(CIL_LOG_TARGET,
                std::string("Failed to parse CIL source: ") + name);
      return nullptr;
    }
  }
  return db;
}

std::unique_ptr<CilPolicyImpl> cil_new_impl() noexcept {
  return std::make_unique<CilPolicyImpl>();
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

  // Parse into a scratch database so syntax errors surface here rather than
  // at the next validate, write or compile.
  auto db = new_db();
  if (cil_add_file(db.get(), name.c_str(), source, size) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET,
              std::string("Failed to parse CIL source: ") + name);
    return false;
  }
  log_debug(CIL_LOG_TARGET,
            std::string("Successfully loaded in-memory CIL source: ") + name +
                " (" + std::to_string(size) + " bytes)");
  sources.emplace_back(std::move(name), std::string(source, size));
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

  auto db = build_db();
  if (!db || cil_write_resolve_ast(sink.get(), db.get()) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "CIL AST validation failed during resolution");
    return false;
  }

  log_info(CIL_LOG_TARGET, "CIL AST validation completed successfully");
  return true;
}

bool CilPolicyImpl::to_cil(rust::String &out) const noexcept {
  log_debug(CIL_LOG_TARGET, "Rendering merged CIL AST");

  char *buf = nullptr;
  size_t size = 0;
  std::FILE *fp = open_memstream(&buf, &size);
  if (!fp) {
    log_error(CIL_LOG_TARGET, "Failed to create memory buffer for CIL output");
    return false;
  }

  auto db = build_db();
  bool ok = db && cil_write_build_ast(fp, db.get()) == SEPOL_OK;
  // buf and size are only valid once the stream is closed.
  std::fclose(fp);

  if (ok) {
    out = rust::String::lossy(buf, size);
    log_debug(CIL_LOG_TARGET, "Rendered merged CIL AST (" +
                                  std::to_string(size) + " bytes)");
  } else {
    log_error(CIL_LOG_TARGET, "Failed to render merged CIL AST");
  }
  std::free(buf);
  return ok;
}

void CilPolicyImpl::set_policy_version(int version) noexcept {
  policy_version = version;
}

std::unique_ptr<SePolicyImpl> CilPolicyImpl::compile() noexcept {
  log_info(CIL_LOG_TARGET, "Compiling CIL database...");

  sepol_policydb_t *pdb = nullptr;
  auto db = build_db();
  if (!db || cil_compile(db.get()) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "CIL compilation failed");
    return nullptr;
  }
  log_debug(CIL_LOG_TARGET, "CIL compilation successful, building policydb...");

  // The built policydb is independent of the CIL database freed on return.
  if (cil_build_policydb(db.get(), &pdb) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "Failed to build policydb from CIL");
    return nullptr;
  }

  log_info(CIL_LOG_TARGET, "Successfully built policydb from CIL");
  return std::make_unique<SePolicyImpl>(&pdb->p);
}

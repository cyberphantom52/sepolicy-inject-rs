#include "sepolicy-inject-rs/src/lib.rs.h"
#include "utils.hpp"

#include <atomic>
#include <cil/cil.h>
#include <memory>

// libsepol's internal CIL headers, for walking a database's AST.
extern "C" {
#define class class_
#include "cil_build_ast.h"
#include "cil_tree.h"
#include "cil_write_ast.h"
#undef class
}

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <unordered_set>

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

static void trim_trailing_newlines(std::string &text) noexcept {
  while (!text.empty() &&
         (text.back() == '\n' || text.back() == '\r')) {
    text.pop_back();
  }
}

static std::string close_memstream(FILE *fp, char *&buf, size_t &size) noexcept {
  if (fp != nullptr) {
    std::fclose(fp);
  }

  std::string out;
  if (buf != nullptr) {
    out.assign(buf, size);
    std::free(buf);
  }

  trim_trailing_newlines(out);
  return out;
}

static std::string render_cil_node_text(struct cil_tree_node *node) {
  if (node == nullptr || node->data == nullptr) {
    return {};
  }

  char *buf = nullptr;
  size_t size = 0;
  FILE *fp = open_memstream(&buf, &size);
  if (fp == nullptr) {
    log_error(CIL_LOG_TARGET, "Failed to allocate memory stream while rendering a CIL AST node");
    return {};
  }

  cil_write_ast_node(fp, node);
  return close_memstream(fp, buf, size);
}

static std::string render_cil_subtree(struct cil_tree_node *node) {
  if (node == nullptr || node->data == nullptr) {
    return {};
  }

  char *buf = nullptr;
  size_t size = 0;
  FILE *fp = open_memstream(&buf, &size);
  if (fp == nullptr) {
    log_error(CIL_LOG_TARGET, "Failed to allocate memory stream while rendering a CIL AST subtree");
    return {};
  }

  cil_write_ast_node(fp, node);

  if (node->cl_head != nullptr &&
      cil_write_ast(fp, CIL_WRITE_AST_PHASE_BUILD, node) != SEPOL_OK) {
    std::fclose(fp);
    std::free(buf);
    log_error(CIL_LOG_TARGET, "Failed to render CIL AST subtree");
    return {};
  }

  return close_memstream(fp, buf, size);
}

static bool is_label_char(unsigned char ch) noexcept {
  return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.' || ch == ':';
}

static bool contains_label_token(std::string_view text,
                                 std::string_view label) noexcept {
  if (text.empty() || label.empty()) {
    return false;
  }

  size_t pos = 0;
  while ((pos = text.find(label, pos)) != std::string_view::npos) {
    const size_t end = pos + label.size();
    const bool left_ok =
        (pos == 0) || !is_label_char(static_cast<unsigned char>(text[pos - 1]));
    const bool right_ok =
        (end >= text.size()) ||
        !is_label_char(static_cast<unsigned char>(text[end]));

    if (left_ok && right_ok) {
      return true;
    }

    ++pos;
  }

  return false;
}

static std::string_view cstr_view(const char *value) noexcept {
  return value != nullptr ? std::string_view(value) : std::string_view();
}

static const char *datum_name(const struct cil_symtab_datum *datum) noexcept {
  if (datum == nullptr) {
    return nullptr;
  }

  if (datum->fqn != nullptr && *datum->fqn != '\0') {
    return datum->fqn;
  }

  if (datum->name != nullptr && *datum->name != '\0') {
    return datum->name;
  }

  return nullptr;
}

static const char *
typeattributeset_name(const struct cil_typeattributeset *attrset) noexcept {
  if (attrset == nullptr) {
    return nullptr;
  }

  if (attrset->attr != nullptr) {
    const char *name = datum_name(DATUM(attrset->attr));
    if (name != nullptr) {
      return name;
    }
  }

  return attrset->attr_str;
}

static const char *typeattributeset_member_name(
    const struct cil_list_item *item) noexcept {
  if (item == nullptr || item->data == nullptr) {
    return nullptr;
  }

  switch (item->flavor) {
  case CIL_STRING:
    return static_cast<const char *>(item->data);
  case CIL_DATUM:
  case CIL_TYPE:
  case CIL_TYPEATTRIBUTE:
  case CIL_TYPEALIAS:
    return datum_name(DATUM(item->data));
  default:
    return nullptr;
  }
}

struct TypeAttributeSetMembershipInfo {
  const char *attribute_name;
  bool matches_attribute_name;
  bool contains_label_member;
  bool simple_member_list;
};

static TypeAttributeSetMembershipInfo inspect_typeattributeset_membership(
    const struct cil_typeattributeset *attrset,
    std::string_view label) noexcept {
  TypeAttributeSetMembershipInfo info{typeattributeset_name(attrset), false,
                                      false, true};

  info.matches_attribute_name = cstr_view(info.attribute_name) == label;

  if (attrset == nullptr) {
    return info;
  }

  const struct cil_list *expr =
      attrset->str_expr != nullptr ? attrset->str_expr : attrset->datum_expr;
  if (expr == nullptr) {
    return info;
  }

  for (struct cil_list_item *item = expr->head; item != nullptr;
       item = item->next) {
    const char *member_name = typeattributeset_member_name(item);
    if (member_name == nullptr) {
      info.simple_member_list = false;
      return info;
    }


    if (cstr_view(member_name) == label) {
      info.contains_label_member = true;
    }
  }

  return info;
}

static std::string summarize_typeattributeset_membership(
    const struct cil_typeattributeset *attrset, std::string_view label) {
  const char *attribute_name = typeattributeset_name(attrset);
  if (attribute_name == nullptr || *attribute_name == '\0') {
    attribute_name = "<?ATTR>";
  }

  return "(typeattributeset " + std::string(attribute_name) + " (" +
         std::string(label) + "))";
}

static rust::String make_cil_match_entry(struct cil_tree_node *node,
                                         std::string_view text) {
  (void)node;
  return rust::String(std::string(text));
}

static bool should_render_as_subtree(const struct cil_tree_node *node) noexcept {
  if (node == nullptr || node->cl_head == nullptr) {
    return false;
  }

  switch (node->flavor) {
  case CIL_BOOLEANIF:
  case CIL_TUNABLEIF:
  case CIL_OPTIONAL:
    return true;
  default:
    return false;
  }
}

static struct cil_tree_node *
contextual_render_root(struct cil_tree_node *node) noexcept {
  if (node == nullptr) {
    return nullptr;
  }

  for (struct cil_tree_node *cur = node; cur != nullptr; cur = cur->parent) {
    switch (cur->flavor) {
    case CIL_BOOLEANIF:
    case CIL_TUNABLEIF:
    case CIL_OPTIONAL:
      return cur;
    default:
      break;
    }
  }

  return node;
}

struct ExtractLabelArgs {
  std::string label;
  rust::Vec<rust::String> *out;
  std::unordered_set<const struct cil_tree_node *> emitted_roots;
};

static int collect_label_matches(struct cil_tree_node *node,
                                 uint32_t *finished,
                                 void *extra_args) {
  (void)finished;

  if (node == nullptr || extra_args == nullptr) {
    return SEPOL_OK;
  }

  auto *args = static_cast<ExtractLabelArgs *>(extra_args);

  if (node->data == nullptr || node->flavor == CIL_ROOT ||
      node->flavor == CIL_SRC_INFO) {
    return SEPOL_OK;
  }

  if (node->flavor == CIL_TYPEATTRIBUTESET) {
    auto *attrset = static_cast<struct cil_typeattributeset *>(node->data);
    auto membership = inspect_typeattributeset_membership(attrset, args->label);

    if (membership.contains_label_member && !membership.matches_attribute_name &&
        membership.simple_member_list) {
      if (args->emitted_roots.insert(node).second) {
        args->out->push_back(make_cil_match_entry(
            node, summarize_typeattributeset_membership(attrset, args->label)));
      }
      return SEPOL_OK;
    }
  }

  std::string rendered_node = render_cil_node_text(node);
  if (rendered_node.empty() ||
      !contains_label_token(rendered_node, args->label)) {
    return SEPOL_OK;
  }

  struct cil_tree_node *render_root = contextual_render_root(node);
  if (render_root == nullptr) {
    return SEPOL_OK;
  }

  if (!args->emitted_roots.insert(render_root).second) {
    return SEPOL_OK;
  }

  std::string rendered_root;
  if (should_render_as_subtree(render_root)) {
    rendered_root = render_cil_subtree(render_root);
  } else {
    rendered_root = render_cil_node_text(render_root);
  }

  if (rendered_root.empty()) {
    return SEPOL_OK;
  }

  args->out->push_back(make_cil_match_entry(render_root, rendered_root));
  return SEPOL_OK;
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

bool CilPolicyImpl::extract_label(rust::Str label,
                                  rust::Vec<rust::String> &out) const noexcept {
  std::string label_str(label.data(), label.size());
  log_info(CIL_LOG_TARGET, "Extracting CIL statements for label: " + label_str);

  auto db = build_db();
  if (!db) {
    return false;
  }
  if (cil_build_ast(db.get(), db->parse->root, db->ast->root) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "Failed to build CIL AST");
    return false;
  }

  ExtractLabelArgs args{label_str, &out, {}};
  if (cil_tree_walk(db->ast->root, collect_label_matches, nullptr, nullptr,
                    &args) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET,
              "Failed while walking the CIL AST for label extraction");
    return false;
  }

  log_info(CIL_LOG_TARGET, "Found " + std::to_string(args.emitted_roots.size()) +
                               " matching CIL statement(s) for label: " +
                               label_str);
  return true;
}

#include "sepolicy-inject-rs/src/lib.rs.h"
#include "mmap.hpp"

#include <cil/cil.h>

extern "C" {
#define class class_
#include "cil_build_ast.h"
#include "cil_fqn.h"
#include "cil_post.h"
#include "cil_resolve_ast.h"
#include "cil_tree.h"
#include "cil_write_ast.h"
#undef class
}

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>

// Logging target for CIL operations
static constexpr const char *CIL_LOG_TARGET = "sepolicy::cil";

// Logging helpers that route messages through Rust's tracing system
static void cil_log_trace_msg(const std::string &msg) {
  log_trace(CIL_LOG_TARGET, msg);
}

static void cil_log_debug_msg(const std::string &msg) {
  log_debug(CIL_LOG_TARGET, msg);
}

static void cil_log_info_msg(const std::string &msg) {
  log_info(CIL_LOG_TARGET, msg);
}

static void cil_log_warn_msg(const std::string &msg) {
  log_warn(CIL_LOG_TARGET, msg);
}

static void cil_log_error_msg(const std::string &msg) {
  log_error(CIL_LOG_TARGET, msg);
}

// Setup CIL log handler to route messages through Rust's tracing
static void setup_cil_logging() {
  cil_set_log_handler(+[](int lvl, const char *msg) {
    std::string message(msg ? msg : "");
    if (!message.empty() && message.back() == '\n') {
      message.pop_back();
    }

    if (lvl == CIL_ERR) {
      cil_log_error_msg(message);
    } else if (lvl == CIL_WARN) {
      cil_log_warn_msg(message);
    } else if (lvl == CIL_INFO) {
      cil_log_info_msg(message);
    } else {
      cil_log_debug_msg(message);
    }
  });
}

static bool ast_is_built(const cil_db_t *db) noexcept {
  return db != nullptr && db->ast != nullptr && db->ast->root != nullptr &&
         db->ast->root->cl_head != nullptr;
}

static bool ensure_ast_built(cil_db_t *db) noexcept {
  if (db == nullptr) {
    cil_log_error_msg("Cannot build AST for a null CIL database");
    return false;
  }

  if (ast_is_built(db)) {
    return true;
  }

  if (db->parse == nullptr || db->parse->root == nullptr || db->ast == nullptr ||
      db->ast->root == nullptr) {
    cil_log_error_msg("CIL database is missing parse or AST state");
    return false;
  }

  cil_log_info_msg("Building CIL AST for label extraction...");
  if (cil_build_ast(db, db->parse->root, db->ast->root) != SEPOL_OK) {
    cil_log_error_msg("Failed to build CIL AST");
    return false;
  }

  cil_log_debug_msg("Successfully built CIL AST");
  return true;
}

static bool finish_compile_from_existing_ast(cil_db_t *db) noexcept {
  if (db == nullptr || db->ast == nullptr || db->ast->root == nullptr) {
    cil_log_error_msg("Cannot finish compilation with an invalid CIL database");
    return false;
  }

  if (db->parse != nullptr) {
    cil_log_debug_msg("Destroying parse tree before resolving existing AST");
    cil_tree_destroy(&db->parse);
  }

  cil_log_info_msg("Resolving existing CIL AST...");
  if (cil_resolve_ast(db, db->ast->root) != SEPOL_OK) {
    cil_log_error_msg("Failed to resolve existing CIL AST");
    return false;
  }

  cil_log_info_msg("Qualifying CIL names...");
  if (cil_fqn_qualify(db->ast->root) != SEPOL_OK) {
    cil_log_error_msg("Failed to qualify CIL names");
    return false;
  }

  cil_log_info_msg("Running CIL post processing...");
  if (cil_post_process(db) != SEPOL_OK) {
    cil_log_error_msg("CIL post processing failed");
    return false;
  }

  return true;
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
    cil_log_error_msg("Failed to allocate memory stream while rendering a CIL AST node");
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
    cil_log_error_msg("Failed to allocate memory stream while rendering a CIL AST subtree");
    return {};
  }

  cil_write_ast_node(fp, node);

  if (node->cl_head != nullptr &&
      cil_write_ast(fp, CIL_WRITE_AST_PHASE_BUILD, node) != SEPOL_OK) {
    std::fclose(fp);
    std::free(buf);
    cil_log_error_msg("Failed to render CIL AST subtree");
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

  return "(typeattributeset " + std::string(attribute_name) + " contains " +
         std::string(label) + ")";
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

bool CilPolicyImpl::add_file(rust::Str path) noexcept {
  std::string path_str(path.data(), path.size());
  return add_file(path_str.c_str());
}

bool CilPolicyImpl::add_file(const char *path) noexcept {
  cil_log_trace_msg(std::string("Loading CIL file: ") + path);

  mmap_data data(path);
  if (!data.data() || data.size() == 0) {
    cil_log_error_msg(std::string("Failed to mmap CIL file: ") + path);
    return false;
  }

  if (cil_add_file(db, path, reinterpret_cast<const char *>(data.data()),
                   data.size()) != SEPOL_OK) {
    cil_log_error_msg(std::string("Failed to parse CIL file: ") + path);
    return false;
  }

  cil_log_debug_msg(std::string("Successfully loaded CIL file: ") + path +
                    " (" + std::to_string(data.size()) + " bytes)");
  return true;
}

void CilPolicyImpl::set_policy_version(int version) noexcept {
  cil_set_policy_version(db, version);
}

std::unique_ptr<SePolicyImpl> CilPolicyImpl::compile() noexcept {
  cil_log_info_msg("Compiling CIL database...");

  sepol_policydb_t *pdb = nullptr;

  if (!ast_is_built(db)) {
    if (cil_compile(db) != SEPOL_OK) {
      cil_log_error_msg("CIL compilation failed");
      return nullptr;
    }
    cil_log_debug_msg("CIL compilation successful, building policydb...");
  } else if (db != nullptr && db->parse != nullptr) {
    if (!finish_compile_from_existing_ast(db)) {
      cil_log_error_msg("Failed to finish compilation from existing AST");
      return nullptr;
    }
    cil_log_debug_msg("Existing CIL AST prepared successfully, building policydb...");
  } else {
    cil_log_debug_msg("Using previously prepared CIL AST state, building policydb...");
  }

  if (cil_build_policydb(db, &pdb) != SEPOL_OK) {
    cil_log_error_msg("Failed to build policydb from CIL");
    return nullptr;
  }

  cil_log_info_msg("Successfully built policydb from CIL");
  return std::make_unique<SePolicyImpl>(pdb);
}

rust::Vec<rust::String> CilPolicyImpl::extract_label(rust::Str label) noexcept {
  rust::Vec<rust::String> out;
  std::string label_str(label.data(), label.size());

  if (label_str.empty()) {
    cil_log_warn_msg("Requested label extraction with an empty label");
    return out;
  }

  if (db == nullptr) {
    cil_log_error_msg("Cannot extract from a null CIL database");
    return out;
  }

  cil_log_info_msg("Extracting CIL statements for label: " + label_str);

  if (!ensure_ast_built(db)) {
    return out;
  }

  ExtractLabelArgs args{label_str, &out, {}};
  if (cil_tree_walk(db->ast->root, collect_label_matches, nullptr, nullptr,
                    &args) != SEPOL_OK) {
    cil_log_error_msg("Failed while walking the CIL AST for label extraction");
    return rust::Vec<rust::String>();
  }

  cil_log_info_msg("Found " + std::to_string(args.emitted_roots.size()) +
                   " matching CIL statement(s) for label: " + label_str);
  return out;
}
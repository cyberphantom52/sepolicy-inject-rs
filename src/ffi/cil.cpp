#include "sepolicy-inject-rs/src/lib.rs.h"
#include "utils.hpp"

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
#include <vector>

// Logging target for CIL operations
static constexpr const char *CIL_LOG_TARGET = "sepolicy::cil";

// libsepol logs one message across several calls: cil_tree_log sends the
// text, then " at <input>:<line>", then any " from <file>:<line>", then "\n".
// Pieces are joined here until the newline, so each message is logged, and
// captured, as one line.
struct CilLogState {
  std::string pending;
  int level = CIL_ERR;
  // Where the current operation collects its error messages, if anywhere.
  rust::Vec<rust::String> *errors = nullptr;
};

// Only the thread holding the libsepol lock reaches libsepol.
static thread_local CilLogState cil_log_state;

static void emit_cil_log(int lvl, std::string message) {
  while (!message.empty() &&
         (message.back() == '\n' || message.back() == '\r')) {
    message.pop_back();
  }
  if (message.empty()) {
    return;
  }

  if (lvl == CIL_ERR) {
    log_error(CIL_LOG_TARGET, message);
    if (cil_log_state.errors != nullptr) {
      cil_log_state.errors->push_back(rust::String(message));
    }
  } else if (lvl == CIL_WARN) {
    log_warn(CIL_LOG_TARGET, message);
  } else if (lvl == CIL_INFO) {
    log_info(CIL_LOG_TARGET, message);
  } else {
    log_debug(CIL_LOG_TARGET, message);
  }
}

static void flush_cil_log() {
  if (!cil_log_state.pending.empty()) {
    emit_cil_log(cil_log_state.level, std::move(cil_log_state.pending));
    cil_log_state.pending.clear();
  }
}

// Route CIL log messages through Rust's tracing.
static void setup_cil_logging() {
  cil_set_log_handler(+[](int lvl, const char *msg) {
    if (msg == nullptr) {
      return;
    }
    if (cil_log_state.pending.empty()) {
      cil_log_state.level = lvl;
    }
    cil_log_state.pending += msg;
    if (!cil_log_state.pending.empty() && cil_log_state.pending.back() == '\n') {
      flush_cil_log();
    }
  });
}

// Collects the error messages libsepol logs while it is alive into `out`.
class CilErrorCapture {
public:
  explicit CilErrorCapture(rust::Vec<rust::String> &out) {
    flush_cil_log();
    cil_log_state.errors = &out;
  }
  ~CilErrorCapture() {
    flush_cil_log();
    cil_log_state.errors = nullptr;
  }
  CilErrorCapture(const CilErrorCapture &) = delete;
  CilErrorCapture &operator=(const CilErrorCapture &) = delete;
};

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

// Append a copy of the children of the parse node `from` to `to`. Parse nodes
// hold only strings from libsepol's string pool, which lives as long as any
// database does, so the copy can point at the same strings.
static void copy_parse_children(const struct cil_tree_node *from,
                                struct cil_tree_node *to) {
  for (const struct cil_tree_node *child = from->cl_head; child != nullptr;
       child = child->next) {
    struct cil_tree_node *node = nullptr;
    cil_tree_node_init(&node);
    node->parent = to;
    node->flavor = child->flavor;
    node->line = child->line;
    node->hll_offset = child->hll_offset;
    node->data = child->data;

    if (to->cl_head == nullptr) {
      to->cl_head = node;
    } else {
      to->cl_tail->next = node;
    }
    to->cl_tail = node;

    copy_parse_children(child, node);
  }
}

// Fresh database with every source added so far, as if each had been parsed
// into it in order.
unique_cil_db CilPolicyImpl::build_db() const noexcept {
  auto db = new_db();
  for (const auto &source : sources) {
    copy_parse_children(source->parsed->parse->root, db->parse->root);
  }
  return db;
}

std::unique_ptr<CilPolicyImpl> CilPolicyImpl::clone() const noexcept {
  return std::make_unique<CilPolicyImpl>(*this);
}

std::unique_ptr<CilPolicyImpl> cil_new_impl() noexcept {
  return std::make_unique<CilPolicyImpl>();
}

bool CilPolicyImpl::has_source(std::string_view name) const noexcept {
  for (const auto &source : sources) {
    if (source->name == name) {
      return true;
    }
  }
  return false;
}

// Inputs are numbered within their policy, so a name depends only on the
// sources the policy already holds.
std::string CilPolicyImpl::next_input_name() const {
  for (size_t n = sources.size() + 1;; ++n) {
    auto name = "input_" + std::to_string(n) + ".cil";
    if (!has_source(name)) {
      return name;
    }
  }
}

rust::Slice<const uint8_t>
CilPolicyImpl::source_text(rust::Str name) const noexcept {
  std::string_view wanted(name.data(), name.size());
  for (const auto &source : sources) {
    if (source->name == wanted) {
      return {reinterpret_cast<const uint8_t *>(source->text.data()),
              source->text.size()};
    }
  }
  return {};
}

rust::String CilPolicyImpl::next_name() const noexcept {
  return rust::String(next_input_name());
}

bool CilPolicyImpl::add_file(rust::Str name, rust::Str source,
                             rust::Vec<rust::String> &errors) noexcept {
  CilErrorCapture capture(errors);
  return add_file(std::string(name.data(), name.size()), source.data(),
                  source.size());
}

bool CilPolicyImpl::add_file(const char *source, size_t size) noexcept {
  return add_file(next_input_name(), source, size);
}

bool CilPolicyImpl::add_file(std::string name, const char *source,
                             size_t size) noexcept {
  log_trace(CIL_LOG_TARGET,
            std::string("Loading in-memory CIL source: ") + name);

  if (source == nullptr || size == 0) {
    log_error(CIL_LOG_TARGET,
              std::string("Refusing to load empty CIL source: ") + name);
    return false;
  }
  if (name.empty() || has_source(name)) {
    log_error(CIL_LOG_TARGET,
              std::string("Refusing to load a second CIL source named: ") + name);
    return false;
  }

  // Parse once, here, so syntax errors surface now rather than at the next
  // validate, write or compile. Later operations copy this parse tree.
  auto db = new_db();
  if (cil_add_file(db.get(), name.c_str(), source, size) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET,
              std::string("Failed to parse CIL source: ") + name);
    return false;
  }
  log_debug(CIL_LOG_TARGET,
            std::string("Successfully loaded in-memory CIL source: ") + name +
                " (" + std::to_string(size) + " bytes)");
  sources.push_back(std::make_shared<const CilSource>(
      CilSource{std::move(name), std::string(source, size), std::move(db)}));
  return true;
}

bool CilPolicyImpl::validate(rust::Vec<rust::String> &errors) noexcept {
  CilErrorCapture capture(errors);
  return validate();
}

std::unique_ptr<SePolicyImpl>
CilPolicyImpl::compile(rust::Vec<rust::String> &errors) noexcept {
  CilErrorCapture capture(errors);
  return compile();
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

// cil_write_build_ast wraps each input in a `;;* lms 1 <name>` ... `;;* lme`
// pair. Input names are internal to this policy, so drop those pairs and keep
// only the line markers the sources themselves carry. libsepol writes every
// marker at the start of its own line, and comments are not kept in the AST,
// so a line starting with `;;*` is always a marker.
static std::string strip_input_markers(std::string_view text,
                                       const std::unordered_set<std::string_view> &inputs) {
  std::string out;
  out.reserve(text.size());
  // One entry per open marker: whether it wraps one of the inputs.
  std::vector<bool> open;

  while (!text.empty()) {
    size_t end = text.find('\n');
    std::string_view line =
        end == std::string_view::npos ? text : text.substr(0, end + 1);
    text.remove_prefix(line.size());

    std::string_view body = line;
    if (!body.empty() && body.back() == '\n') {
      body.remove_suffix(1);
    }

    bool keep = true;
    if (body == ";;* lme") {
      if (!open.empty()) {
        keep = !open.back();
        open.pop_back();
      }
    } else if (body.starts_with(";;* ")) {
      // `;;* <kind> <line> <path>`
      bool input = false;
      if (open.empty() && body.starts_with(";;* lms 1 ")) {
        input = inputs.contains(body.substr(std::string_view(";;* lms 1 ").size()));
      }
      open.push_back(input);
      keep = !input;
    }

    if (keep) {
      out.append(line);
    }
  }
  return out;
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
    std::unordered_set<std::string_view> inputs;
    for (const auto &source : sources) {
      inputs.insert(source->name);
    }
    out = rust::String::lossy(
        strip_input_markers(std::string_view(buf, size), inputs));
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

static int collect_declared_types(struct cil_tree_node *node, uint32_t *finished,
                                  void *extra_args) {
  (void)finished;
  switch (node->flavor) {
  case CIL_TYPE:
  case CIL_TYPEATTRIBUTE:
  case CIL_TYPEALIAS: {
    const char *name = DATUM(node->data)->name;
    if (name != nullptr) {
      static_cast<rust::Vec<rust::String> *>(extra_args)->push_back(
          rust::String(name));
    }
    break;
  }
  default:
    break;
  }
  return SEPOL_OK;
}

bool CilPolicyImpl::declared_types(rust::Vec<rust::String> &out) const noexcept {
  auto db = build_db();
  if (!db) {
    return false;
  }
  if (cil_build_ast(db.get(), db->parse->root, db->ast->root) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "Failed to build CIL AST");
    return false;
  }
  if (cil_tree_walk(db->ast->root, collect_declared_types, nullptr, nullptr,
                    &out) != SEPOL_OK) {
    log_error(CIL_LOG_TARGET, "Failed while walking the CIL AST for declarations");
    return false;
  }
  return true;
}

// Removing types from parse trees. A parse tree is cil_parser's s-expressions:
// each node is a list (no data) or an atom (a string from libsepol's string
// pool, which the CIL_KEY_* keywords are too).

static bool is_atom(const struct cil_tree_node *node) noexcept {
  return node->data != nullptr;
}

// The keyword a statement starts with, if it is an atom.
static const char *keyword(const struct cil_tree_node *node) noexcept {
  if (is_atom(node) || node->cl_head == nullptr || !is_atom(node->cl_head)) {
    return nullptr;
  }
  return static_cast<const char *>(node->cl_head->data);
}

using Names = std::unordered_set<std::string_view>;

static bool names_any(const struct cil_tree_node *node, const Names &names) {
  if (is_atom(node)) {
    return names.contains(static_cast<const char *>(node->data));
  }
  for (auto *child = node->cl_head; child != nullptr; child = child->next) {
    if (names_any(child, names)) {
      return true;
    }
  }
  return false;
}

// Unlink `node` from its parent and free it with everything under it.
static void destroy_child(struct cil_tree_node *node) {
  struct cil_tree_node *parent = node->parent;
  struct cil_tree_node *prev = nullptr;
  for (auto *cur = parent->cl_head; cur != node; cur = cur->next) {
    prev = cur;
  }
  if (prev == nullptr) {
    parent->cl_head = node->next;
  } else {
    prev->next = node->next;
  }
  if (parent->cl_tail == node) {
    parent->cl_tail = prev;
  }
  node->next = nullptr;
  cil_tree_subtree_destroy(node);
}

// Make the list `list` stand for `operand`, one of its descendants: the list
// `operand` is, or the set of the one name it is.
static void replace_with(struct cil_tree_node *list, struct cil_tree_node *operand) {
  // Detach `operand` so freeing the rest of `list` keeps it.
  struct cil_tree_node *parent = operand->parent;
  struct cil_tree_node *prev = nullptr;
  for (auto *cur = parent->cl_head; cur != operand; cur = cur->next) {
    prev = cur;
  }
  if (prev == nullptr) {
    parent->cl_head = operand->next;
  } else {
    prev->next = operand->next;
  }
  if (parent->cl_tail == operand) {
    parent->cl_tail = prev;
  }
  operand->next = nullptr;
  cil_tree_children_destroy(list);

  if (is_atom(operand)) {
    operand->parent = list;
    list->cl_head = list->cl_tail = operand;
    return;
  }
  list->cl_head = operand->cl_head;
  list->cl_tail = operand->cl_tail;
  for (auto *child = list->cl_head; child != nullptr; child = child->next) {
    child->parent = list;
  }
  operand->cl_head = operand->cl_tail = nullptr;
  cil_tree_node_destroy(&operand);
}

enum class Set { Empty, All, Some };

// Simplify the type expression `node` with every name in `names` taken as the
// empty set. An empty or full result is left for the caller to drop or replace.
static Set simplify(struct cil_tree_node *node, const Names &names) {
  if (is_atom(node)) {
    return names.contains(static_cast<const char *>(node->data)) ? Set::Empty
                                                                 : Set::Some;
  }
  const char *op = keyword(node);
  if (op == CIL_KEY_ALL) {
    return Set::All;
  }
  if (op == CIL_KEY_NOT) {
    switch (simplify(node->cl_head->next, names)) {
    case Set::Empty:
      return Set::All;
    case Set::All:
      return Set::Empty;
    case Set::Some:
      return Set::Some;
    }
  }
  if (op == CIL_KEY_AND || op == CIL_KEY_OR || op == CIL_KEY_XOR) {
    struct cil_tree_node *a = node->cl_head->next;
    struct cil_tree_node *b = a->next;
    Set sa = simplify(a, names);
    Set sb = simplify(b, names);
    // The operand the whole is, if it is one of them.
    struct cil_tree_node *result = nullptr;
    if (op == CIL_KEY_AND) {
      if (sa == Set::Empty || sb == Set::Empty) {
        return Set::Empty;
      }
      if (sa == Set::All && sb == Set::All) {
        return Set::All;
      }
      result = sa == Set::All ? b : sb == Set::All ? a : nullptr;
    } else {
      if (sa == Set::Empty && sb == Set::Empty) {
        return Set::Empty;
      }
      if (op == CIL_KEY_OR && (sa == Set::All || sb == Set::All)) {
        return Set::All;
      }
      result = sa == Set::Empty ? b : sb == Set::Empty ? a : nullptr;
    }
    if (result != nullptr) {
      replace_with(node, result);
    }
    return Set::Some;
  }
  // A set of names and expressions.
  for (auto *child = node->cl_head; child != nullptr;) {
    auto *next = child->next;
    switch (simplify(child, names)) {
    case Set::Empty:
      destroy_child(child);
      break;
    case Set::All:
      return Set::All;
    case Set::Some:
      break;
    }
    child = next;
  }
  return node->cl_head == nullptr ? Set::Empty : Set::Some;
}

static bool has_statement(const struct cil_tree_node *node) noexcept {
  for (auto *child = node->cl_head; child != nullptr; child = child->next) {
    if (!is_atom(child)) {
      return true;
    }
  }
  return false;
}

// Remove from the statements under `parent` the ones that name a type or
// attribute in `names`, and those names from the attribute sets of others.
// A line mark (`;;* lmx`) is a statement holding the ones it marks.
static void remove_names(struct cil_tree_node *parent, const Names &names) {
  for (auto *node = parent->cl_head; node != nullptr;) {
    auto *next = node->next;
    if (is_atom(node)) {
      node = next;
      continue;
    }
    const char *kw = keyword(node);
    if (kw == CIL_KEY_SRC_INFO || kw == CIL_KEY_BLOCK || kw == CIL_KEY_IN ||
        kw == CIL_KEY_OPTIONAL || kw == CIL_KEY_BOOLEANIF ||
        kw == CIL_KEY_TUNABLEIF || kw == CIL_KEY_CONDTRUE ||
        kw == CIL_KEY_CONDFALSE || kw == CIL_KEY_MACRO) {
      remove_names(node, names);
      // A line mark left marking no statement goes too.
      if (kw == CIL_KEY_SRC_INFO && !has_statement(node)) {
        destroy_child(node);
      }
    } else if (kw == CIL_KEY_TYPEATTRIBUTESET &&
               !names_any(node->cl_head->next, names)) {
      // `(typeattributeset <attribute> <expression>)`
      struct cil_tree_node *expr = node->cl_head->next->next;
      switch (simplify(expr, names)) {
      case Set::Empty:
        destroy_child(node);
        break;
      case Set::All: {
        cil_tree_children_destroy(expr);
        struct cil_tree_node *all = nullptr;
        cil_tree_node_init(&all);
        all->parent = expr;
        all->flavor = CIL_NODE;
        all->line = expr->line;
        all->hll_offset = expr->hll_offset;
        all->data = CIL_KEY_ALL;
        expr->cl_head = expr->cl_tail = all;
        break;
      }
      case Set::Some:
        break;
      }
    } else if (names_any(node, names)) {
      destroy_child(node);
    }
    node = next;
  }
}

bool CilPolicyImpl::remove_types(rust::Slice<const rust::String> names) noexcept {
  std::vector<std::string> owned;
  for (const auto &name : names) {
    owned.emplace_back(name.data(), name.size());
  }
  Names set(owned.begin(), owned.end());
  for (auto &source : sources) {
    auto db = new_db();
    if (!db) {
      return false;
    }
    copy_parse_children(source->parsed->parse->root, db->parse->root);
    remove_names(db->parse->root, set);
    source = std::make_shared<const CilSource>(
        CilSource{source->name, source->text, std::move(db)});
  }
  log_info(CIL_LOG_TARGET, "Removed " + std::to_string(owned.size()) +
                               " type(s) from the CIL policy");
  return true;
}

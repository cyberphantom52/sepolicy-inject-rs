#include "sepolicy.hpp"
#include "utils.hpp"
#include "sepolicy-inject-rs/src/lib.rs.h"
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/policydb.h>
#include <sstream>

static std::string to_string(rust::Str str) {
  return std::string(str.data(), str.size());
}

// Logging helpers that call into Rust's tracing system
static constexpr const char *LOG_TARGET = "sepolicy::ffi";

static void ffi_log_info(const std::string &msg) {
  log_info(LOG_TARGET, msg);
}

static void ffi_log_error(const std::string &msg) {
  log_error(LOG_TARGET, msg);
}

static void ffi_log_debug(const std::string &msg) {
  log_debug(LOG_TARGET, msg);
}

SePolicyImpl::~SePolicyImpl() {
  policydb_destroy(db);
  free(db);
}

std::optional<std::string> SePolicyImpl::type_name(uint32_t v) const {
  // v is a 1-based SELinux type value (0 is invalid).
  // libsepol stores names in a 0-based array indexed by (v - 1),
  // and valid values are in the range [1, p_types.nprim].
  if (v < 1 || v > db->p_types.nprim)
    return std::nullopt;
  const char *name = db->p_type_val_to_name[v - 1];
  return name ? std::optional(name) : std::nullopt;
}

std::optional<std::string> SePolicyImpl::class_name(uint32_t v) const {
  // v is a 1-based SELinux class value (0 is invalid).
  // class names are stored in a 0-based array indexed by (v - 1),
  // with valid values in the range [1, p_classes.nprim].
  if (v < 1 || v > db->p_classes.nprim)
    return std::nullopt;
  const char *name = db->p_class_val_to_name[v - 1];
  return name ? std::optional(name) : std::nullopt;
}

type_datum_t *SePolicyImpl::type_datum(uint32_t v) const {
  // v is a 1-based SELinux type value.
  // type_val_to_struct is a 0-based array indexed by (v - 1);
  // values outside [1, p_types.nprim] would be out-of-bounds.
  if (v < 1 || v > db->p_types.nprim)
    return nullptr;
  return db->type_val_to_struct[v - 1];
}

class_datum_t *SePolicyImpl::class_datum(uint32_t v) const {
  // v is a 1-based SELinux class value.
  // class_val_to_struct is a 0-based array indexed by (v - 1);
  // values outside [1, p_classes.nprim] would be out-of-bounds.
  if (v < 1 || v > db->p_classes.nprim)
    return nullptr;
  return db->class_val_to_struct[v - 1];
}

std::unique_ptr<SePolicyImpl> from_file_impl(rust::Str file) noexcept {
  std::string path = to_string(file);

  ffi_log_debug("Opening policy file: " + path);

  policy_file policy_file;
  policy_file_init(&policy_file);
  auto file_opt = open_file(path.c_str(), "r");
  if (!file_opt) {
    ffi_log_error("Failed to open policy file: " + path);
    return nullptr;
  }

  policy_file.fp = file_opt->get();
  policy_file.type = PF_USE_STDIO;

  policydb *db = static_cast<policydb *>(malloc(sizeof(policydb_t)));
  if (policydb_init(db) || policydb_read(db, &policy_file, 0)) {
    ffi_log_error("Failed to read policy database from file: " + path);
    free(db);
    return nullptr;
  }

  ffi_log_info("Successfully loaded policy from file: " + path);
  return std::make_unique<SePolicyImpl>(db);
}

std::unique_ptr<SePolicyImpl>
from_data_impl(rust::Slice<const uint8_t> data) noexcept {
  ffi_log_debug("Loading policy from memory buffer, size: " +
                std::to_string(data.size()));

  policy_file policy_file;
  policy_file_init(&policy_file);
  policy_file.data = (char *)data.data();
  policy_file.len = data.size();
  policy_file.type = PF_USE_MEMORY;

  policydb *db = static_cast<policydb *>(malloc(sizeof(policydb_t)));
  if (policydb_init(db) || policydb_read(db, &policy_file, 0)) {
    ffi_log_error("Failed to read policy database from memory");
    free(db);
    return nullptr;
  }

  ffi_log_info("Successfully loaded policy from memory");
  return std::make_unique<SePolicyImpl>(db);
}

std::unique_ptr<SePolicyImpl> from_split_impl() noexcept {
  const char *odm_pre = ODM_POLICY_DIR "precompiled_sepolicy";
  const char *vend_pre = VEND_POLICY_DIR "precompiled_sepolicy";

  ffi_log_debug("Checking for precompiled policy");

  if (access(odm_pre, R_OK) == 0 && check_precompiled(odm_pre)) {
    ffi_log_info(std::string("Using precompiled policy from: ") + odm_pre);
    return from_file_impl(odm_pre);
  } else if (access(vend_pre, R_OK) == 0 && check_precompiled(vend_pre)) {
    ffi_log_info(std::string("Using precompiled policy from: ") + vend_pre);
    return from_file_impl(vend_pre);
  } else {
    ffi_log_info("No valid precompiled policy found, compiling from CIL");
    return compile_split_impl();
  }
}

std::unique_ptr<SePolicyImpl> compile_split_impl() noexcept {
  char path[128], plat_ver[10];
  FILE *f;
  int policy_ver;

  ffi_log_info("Compiling split CIL policies");

  CilPolicyImpl cil;

  f = fopen(SELINUX_VERSION, "re");
  if (!f) {
    ffi_log_error("Failed to open SELinux version file: " SELINUX_VERSION);
    return nullptr;
  }
  fscanf(f, "%d", &policy_ver);
  fclose(f);
  cil.set_policy_version(policy_ver);
  ffi_log_debug("Policy version: " + std::to_string(policy_ver));

  // Get mapping version
  f = fopen(VEND_POLICY_DIR "plat_sepolicy_vers.txt", "re");
  if (!f) {
    ffi_log_error("Failed to open platform sepolicy version file");
    return nullptr;
  }
  fscanf(f, "%s", plat_ver);
  fclose(f);
  ffi_log_debug("Platform version: " + std::string(plat_ver));

  ffi_log_debug("Adding base CIL file: " SPLIT_PLAT_CIL);
  cil.add_file(SPLIT_PLAT_CIL);

  for (const char *file : CIL_FILES) {
    const char *actual_file = file;
    if (strchr(file, '%')) {
      sprintf(path, file, plat_ver);
      actual_file = path;
    }
    if (access(actual_file, R_OK) == 0) {
      ffi_log_debug(std::string("Adding CIL file: ") + actual_file);
      cil.add_file(actual_file);
    }
  }

  ffi_log_debug("Compiling CIL database");
  auto result = cil.compile();
  if (result) {
    ffi_log_info("Successfully compiled split CIL policies");
  } else {
    ffi_log_error("Failed to compile CIL policies");
  }
  return result;
}

rust::Vec<rust::String> SePolicy::attributes() const noexcept {
  rust::Vec<rust::String> out;

  for_each_hashtab(inner->db->p_types.table, [&](hashtab_ptr_t node) {
    auto type = static_cast<type_datum_t *>(node->datum);
    if (type->flavor != TYPE_ATTRIB)
      return;

    if (auto name = inner->type_name(type->s.value)) {
      out.push_back(rust::String(std::string("attribute ") + *name));
    }
  });

  return out;
}

rust::Vec<rust::String> SePolicy::types() const noexcept {
  rust::Vec<rust::String> out;

  for_each_hashtab(inner->db->p_types.table, [&](hashtab_ptr_t node) {
    auto type = static_cast<type_datum_t *>(node->datum);
    if (!type || type->flavor != TYPE_TYPE)
      return;

    auto name = inner->type_name(type->s.value);
    if (!name)
      return;

    ebitmap_t *bitmap = &inner->db->type_attr_map[type->s.value - 1];

    bool first = true;
    std::ostringstream stream;

    ebitmap_node_t *n;
    uint32_t bit;
    ebitmap_for_each_positive_bit(bitmap, n, bit) {
      uint32_t type_val = bit + 1;

      auto attr_type = inner->type_datum(type_val);
      if (!attr_type || attr_type->flavor != TYPE_ATTRIB)
        continue;

      if (auto attr = inner->type_name(type_val)) {
        if (first) {
          stream << "type " << name.value() << " {";
          first = false;
        }
        stream << " " << attr.value();
      }
    }

    if (!first) {
      stream << " }";
      out.push_back(rust::String(stream.str()));
    }

    // permissive
    if (ebitmap_get_bit(&inner->db->permissive_map, type->s.value)) {
      out.push_back(rust::String(std::string("permissive ") + name.value()));
    }
  });

  return out;
}

static size_t class_perm_vec_size(const class_datum_t *clz) {
  size_t n = clz->permissions.nprim;
  if (clz->comdatum)
    n = std::max(n, size_t(clz->comdatum->permissions.nprim));
  return n;
}

void SePolicyImpl::emit_av_rule(const avtab_ptr_t node,
                                rust::Vec<rust::String> &out) const {
  auto source = this->type_name(node->key.source_type);
  auto target = this->type_name(node->key.target_type);
  auto class_ = this->class_name(node->key.target_class);
  uint16_t class_val = node->key.target_class;
  if (!source || !target || !class_)
    return;

  auto rule = specified_to_name(node->key.specified);
  if (!rule)
    return;

  uint32_t data = node->key.specified == AVTAB_AUDITDENY ? ~(node->datum.data)
                                                         : node->datum.data;

  auto clz = this->class_datum(class_val);
  if (clz == nullptr)
    return;

  auto [it, inserted] = this->class_perm_cache.try_emplace(class_val);
  if (inserted) {
    size_t size = class_perm_vec_size(clz);
    auto &vec = it->second;
    vec.assign(size, nullptr);

    auto collect = [&](hashtab_t tab) {
      for_each_hashtab(tab, [&](hashtab_ptr_t pnode) {
        auto perm = static_cast<perm_datum *>(pnode->datum);
        if (!perm)
          return;

        size_t idx = perm->s.value - 1;
        if (idx < vec.size())
          vec[idx] = pnode->key;
      });
    };

    collect(clz->permissions.table);
    if (clz->comdatum)
      collect(clz->comdatum->permissions.table);
  }

  std::ostringstream ss;
  bool first = true;
  while (data) {
    uint32_t bit = __builtin_ctz(data);
    data &= data - 1;

    if (bit >= it->second.size())
      continue;

    const char *perm = it->second[bit];
    if (!perm)
      continue;

    if (first) {
      ss << rule.value() << " " << source.value() << " " << target.value()
         << " " << class_.value() << " {";
      first = false;
    }
    ss << " " << perm;
  }

  if (!first) {
    ss << " }";
    out.push_back(rust::String(ss.str()));
  }
}

void SePolicyImpl::emit_type_rule(const avtab_ptr_t node,
                                  rust::Vec<rust::String> &out) const {
  auto source = this->type_name(node->key.source_type);
  auto target = this->type_name(node->key.target_type);
  auto class_ = this->class_name(node->key.target_class);
  if (!source || !target || !class_)
    return;

  auto rule = specified_to_name(node->key.specified);
  if (!rule)
    return;

  auto def = this->type_name(node->datum.data);
  if (!def)
    return;

  std::ostringstream ss;
  ss << rule.value() << " " << source.value() << " " << target.value() << " "
     << class_.value() << " " << def.value();

  out.push_back(rust::String(ss.str()));
}

void SePolicyImpl::emit_xperm_rule(const avtab_ptr_t node,
                                   rust::Vec<rust::String> &out) const {
  auto source = this->type_name(node->key.source_type);
  auto target = this->type_name(node->key.target_type);
  auto class_ = this->class_name(node->key.target_class);
  if (!source || !target || !class_)
    return;

  auto rule = specified_to_name(node->key.specified);
  if (!rule)
    return;

  avtab_extended_perms_t *xperms = node->datum.xperms;
  if (!xperms)
    return;

  std::vector<std::pair<uint8_t, uint8_t>> ranges;
  int low = -1;

  for (int i = 0; i < 256; ++i) {
    if (xperm_test(i, xperms->perms)) {
      if (low < 0)
        low = i;
      if (i == 255)
        ranges.emplace_back(low, 255);
    } else if (low >= 0) {
      ranges.emplace_back(low, i - 1);
      low = -1;
    }
  }

  if (ranges.empty())
    return;

  auto encode = [&](uint8_t v) -> uint16_t {
    return xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION
               ? (uint16_t(xperms->driver) << 8) | v
               : uint16_t(v) << 8;
  };

  std::ostringstream ss;
  ss << rule.value() << " " << source.value() << " " << target.value() << " "
     << class_.value() << " ioctl {";

  for (auto &[lo8, hi8] : ranges) {
    uint16_t lo = encode(lo8);
    uint16_t hi = encode(hi8);

    ss << " 0x" << std::hex << std::uppercase << lo;
    if (lo != hi)
      ss << "-0x" << hi;
  }

  ss << " }";
  out.push_back(rust::String(ss.str()));
}

rust::Vec<rust::String> SePolicy::avtabs() const noexcept {
  rust::Vec<rust::String> out;

  for_each_avtab(&inner->db->te_avtab, [&](avtab_ptr_t node) {
    if (node->key.specified & AVTAB_AV) {
      inner->emit_av_rule(node, out);
    } else if (node->key.specified & AVTAB_TYPE) {
      inner->emit_type_rule(node, out);
    } else if (node->key.specified & AVTAB_XPERMS) {
      inner->emit_xperm_rule(node, out);
    }
  });

  return out;
}

rust::Vec<rust::String> SePolicy::transitions() const noexcept {
  rust::Vec<rust::String> out;

  for_each_hashtab(inner->db->filename_trans, [&](hashtab_ptr_t node) {
    auto key = reinterpret_cast<filename_trans_key_t *>(node->key);
    auto trans = static_cast<filename_trans_datum *>(node->datum);

    auto target = inner->type_name(key->ttype);
    auto class_ = inner->class_name(key->tclass);
    auto def = inner->type_name(trans->otype);
    if (!target || !class_ || !def || key->name == nullptr)
      return;

    ebitmap_node_t *n;
    uint32_t bit;
    ebitmap_for_each_positive_bit(&trans->stypes, n, bit) {
      uint32_t src_val = bit + 1;

      if (auto src = inner->type_name(src_val)) {
        std::ostringstream stream;
        stream << "type_transition " << src.value() << " " << target.value()
               << " " << class_.value() << " " << def.value() << " "
               << key->name;
        out.push_back(rust::String(stream.str()));
      }
    }
  });

  return out;
}

rust::Vec<rust::String> SePolicy::genfs_contexts() const noexcept {
  rust::Vec<rust::String> out;

  for_each_list(inner->db->genfs, [&](genfs_t *genfs) {
    for_each_list(genfs->head, [&](ocontext *context) {
      char *raw_ptr = nullptr;
      size_t len = 0;
      if (context_to_string(nullptr, inner->db, &context->context[0], &raw_ptr,
                            &len) == 0) {
        std::unique_ptr<char, decltype(&free)> ctx(raw_ptr, &free);
        std::ostringstream stream;
        stream << "genfscon " << genfs->fstype << " " << context->u.name << " "
               << ctx.get();
        out.push_back(rust::String(stream.str()));
      }
    });
  });

  return out;
}

bool SePolicyImpl::add_rule(rust::Str s, rust::Str t, rust::Str c, rust::Str p,
                            int effect, bool remove) {
  auto src = hashtab_find<type_datum_t>(db->p_types.table, s);
  auto tgt = hashtab_find<type_datum_t>(db->p_types.table, t);
  auto cls = hashtab_find<class_datum_t>(db->p_classes.table, c);
  if (!src || !tgt || !cls)
    return false;

  auto perm = hashtab_find<perm_datum_t>(cls->permissions.table, p);
  if (!perm && cls->comdatum)
    perm = hashtab_find<perm_datum_t>(cls->comdatum->permissions.table, p);
  if (!perm)
    return false;

  avtab_key_t key{};
  key.source_type = src->s.value;
  key.target_type = tgt->s.value;
  key.target_class = cls->s.value;
  key.specified = effect;

  avtab_ptr_t node = avtab_search_node(&db->te_avtab, &key);
  if (!node) {
    if (remove)
      return true; // Nothing to remove
    avtab_datum_t avdatum{};
    // AUDITDENY (dontaudit) uses inverted logic - initialize to all bits set
    avdatum.data = key.specified == AVTAB_AUDITDENY ? ~0U : 0U;
    node = avtab_insert_nonunique(&db->te_avtab, &key, &avdatum);
  }

  uint32_t bit = 1U << (perm->s.value - 1);
  if (remove || effect == AVTAB_AUDITDENY) {
    node->datum.data &= ~bit;
  } else {
    node->datum.data |= bit;
  }
  return true;
}

void SePolicy::allow(rust::Slice<rust::Str const> src,
                     rust::Slice<rust::Str const> tgt,
                     rust::Slice<rust::Str const> cls,
                     rust::Slice<rust::Str const> perm) noexcept {
  for_each_rule(src, tgt, cls, perm, [this](auto s, auto t, auto c, auto p) {
    inner->add_rule(s, t, c, p, AVTAB_ALLOWED);
  });
}

void SePolicy::deny(rust::Slice<rust::Str const> src,
                    rust::Slice<rust::Str const> tgt,
                    rust::Slice<rust::Str const> cls,
                    rust::Slice<rust::Str const> perm) noexcept {
  for_each_rule(src, tgt, cls, perm, [this](auto s, auto t, auto c, auto p) {
    inner->add_rule(s, t, c, p, AVTAB_ALLOWED, true);
  });
}

void SePolicy::auditallow(rust::Slice<rust::Str const> src,
                          rust::Slice<rust::Str const> tgt,
                          rust::Slice<rust::Str const> cls,
                          rust::Slice<rust::Str const> perm) noexcept {
  for_each_rule(src, tgt, cls, perm, [this](auto s, auto t, auto c, auto p) {
    inner->add_rule(s, t, c, p, AVTAB_AUDITALLOW);
  });
}

void SePolicy::dontaudit(rust::Slice<rust::Str const> src,
                         rust::Slice<rust::Str const> tgt,
                         rust::Slice<rust::Str const> cls,
                         rust::Slice<rust::Str const> perm) noexcept {
  for_each_rule(src, tgt, cls, perm, [this](auto s, auto t, auto c, auto p) {
    inner->add_rule(s, t, c, p, AVTAB_AUDITDENY);
  });
}

// Extended permissions (ioctl) rule
bool SePolicyImpl::add_xperm_rule(rust::Str s, rust::Str t, rust::Str c,
                                  const XPerm &xp, int effect) {
  auto src = hashtab_find<type_datum_t>(db->p_types.table, s);
  auto tgt = hashtab_find<type_datum_t>(db->p_types.table, t);
  auto cls = hashtab_find<class_datum_t>(db->p_classes.table, c);
  if (!src || !tgt || !cls)
    return false;

  avtab_key_t key{};
  key.source_type = src->s.value;
  key.target_type = tgt->s.value;
  key.target_class = cls->s.value;
  key.specified = effect;

  // Find existing xperm nodes
  avtab_ptr_t node_list[257] = {nullptr};
#define driver_node (node_list[256])

  for (avtab_ptr_t node = avtab_search_node(&db->te_avtab, &key); node;
       node = avtab_search_node_next(node, key.specified)) {
    if (node->datum.xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
      driver_node = node;
    } else if (node->datum.xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION) {
      node_list[node->datum.xperms->driver] = node;
    }
  }

  auto new_node = [&](uint8_t specified, uint8_t driver) -> avtab_ptr_t {
    avtab_datum_t avdatum{};
    auto node = avtab_insert_nonunique(&db->te_avtab, &key, &avdatum);
    node->datum.xperms =
        static_cast<avtab_extended_perms_t *>(calloc(1, sizeof(avtab_extended_perms_t)));
    node->datum.xperms->specified = specified;
    node->datum.xperms->driver = driver;
    return node;
  };

  if (ioctl_driver(xp.low) != ioctl_driver(xp.high)) {
    // Range spans multiple drivers - use driver node
    if (!driver_node)
      driver_node = new_node(AVTAB_XPERMS_IOCTLDRIVER, 0);
    for (int i = ioctl_driver(xp.low); i <= ioctl_driver(xp.high); ++i)
      xperm_set(i, driver_node->datum.xperms->perms);
  } else {
    // Single driver - use function node
    uint8_t driver = ioctl_driver(xp.low);
    auto node = node_list[driver];
    if (!node) {
      node = new_node(AVTAB_XPERMS_IOCTLFUNCTION, driver);
      node_list[driver] = node;
    }
    for (int i = ioctl_func(xp.low); i <= ioctl_func(xp.high); ++i)
      xperm_set(i, node->datum.xperms->perms);
  }

#undef driver_node
  return true;
}

void SePolicy::allowxperm(rust::Slice<rust::Str const> src,
                          rust::Slice<rust::Str const> tgt,
                          rust::Slice<rust::Str const> cls,
                          rust::Slice<XPerm const> xperm) noexcept {
  for_each_rule(src, tgt, cls, xperm, [this](auto s, auto t, auto c, auto &x) {
    inner->add_xperm_rule(s, t, c, x, AVTAB_XPERMS_ALLOWED);
  });
}

void SePolicy::auditallowxperm(rust::Slice<rust::Str const> src,
                               rust::Slice<rust::Str const> tgt,
                               rust::Slice<rust::Str const> cls,
                               rust::Slice<XPerm const> xperm) noexcept {
  for_each_rule(src, tgt, cls, xperm, [this](auto s, auto t, auto c, auto &x) {
    inner->add_xperm_rule(s, t, c, x, AVTAB_XPERMS_AUDITALLOW);
  });
}

void SePolicy::dontauditxperm(rust::Slice<rust::Str const> src,
                              rust::Slice<rust::Str const> tgt,
                              rust::Slice<rust::Str const> cls,
                              rust::Slice<XPerm const> xperm) noexcept {
  for_each_rule(src, tgt, cls, xperm, [this](auto s, auto t, auto c, auto &x) {
    inner->add_xperm_rule(s, t, c, x, AVTAB_XPERMS_DONTAUDIT);
  });
}

// Permissive/enforce
bool SePolicyImpl::set_type_state(rust::Str type_name, bool permissive) {
  auto type = hashtab_find<type_datum_t>(db->p_types.table, type_name);
  if (!type)
    return false;

  return ebitmap_set_bit(&db->permissive_map, type->s.value, permissive) == 0;
}

void SePolicy::permissive(rust::Slice<rust::Str const> types) noexcept {
  for (auto t : types) {
    inner->set_type_state(t, true);
  }
}

void SePolicy::enforce(rust::Slice<rust::Str const> types) noexcept {
  for (auto t : types) {
    inner->set_type_state(t, false);
  }
}

// Type attribute association
bool SePolicyImpl::add_typeattribute(rust::Str type, rust::Str attr) {
  auto type_d = hashtab_find<type_datum_t>(db->p_types.table, type);
  auto attr_d = hashtab_find<type_datum_t>(db->p_types.table, attr);
  if ((!type_d || type_d->flavor == TYPE_ATTRIB) ||
      (!attr_d || attr_d->flavor != TYPE_ATTRIB))
  {
    return false;
  }


  ebitmap_set_bit(&db->type_attr_map[type_d->s.value - 1], attr_d->s.value - 1,1);
  ebitmap_set_bit(&db->attr_type_map[attr_d->s.value - 1], type_d->s.value - 1,1);

  // Update constraint expressions that reference this attribute
  for_each_hashtab(db->p_classes.table, [&](hashtab_ptr_t node) {
    auto cls = static_cast<class_datum_t *>(node->datum);
    for_each_list(cls->constraints, [&](constraint_node_t *n) {
      for_each_list(n->expr, [&](constraint_expr_t *e) {
        if (e->expr_type == CEXPR_NAMES &&
            ebitmap_get_bit(&e->type_names->types, attr_d->s.value - 1)) {
          ebitmap_set_bit(&e->names, type_d->s.value - 1, 1);
        }
      });
    });
  });

  return true;
}

void SePolicy::typeattribute(rust::Slice<rust::Str const> ty,
                             rust::Slice<rust::Str const> attrs) noexcept {
  for (auto t : ty) {
    for (auto a : attrs) {
      inner->add_typeattribute(t, a);
    }
  }
}

// Create new type or attribute
bool SePolicyImpl::add_type(rust::Str type_name, uint32_t flavor) {
  if (hashtab_find<type_datum_t>(db->p_types.table, type_name))
    return true; // Already exists

  auto type = static_cast<type_datum_t *>(malloc(sizeof(type_datum_t)));
  type_datum_init(type);
  type->primary = 1;
  type->flavor = flavor;

  uint32_t value = 0;
  char *name = dup_str(type_name);
  if (symtab_insert(db, SYM_TYPES, name, type, SCOPE_DECL, 1, &value)) {
    free(name);
    free(type);
    return false;
  }
  type->s.value = value;
  ebitmap_set_bit(&db->global->branch_list->declared.p_types_scope, value - 1,
                  1);

  auto new_size = sizeof(ebitmap_t) * db->p_types.nprim;
  db->type_attr_map = static_cast<ebitmap_t *>(realloc(db->type_attr_map, new_size));
  db->attr_type_map = static_cast<ebitmap_t *>(realloc(db->attr_type_map, new_size));
  ebitmap_init(&db->type_attr_map[value - 1]);
  ebitmap_init(&db->attr_type_map[value - 1]);
  ebitmap_set_bit(&db->type_attr_map[value - 1], value - 1, 1);

  // Re-index
  if (policydb_index_decls(nullptr, db) ||
      policydb_index_classes(db) ||
      policydb_index_others(nullptr, db, 0))
  {
    return false;
  }

  // Add type to all roles
  for (uint32_t i = 0; i < db->p_roles.nprim; ++i) {
    ebitmap_set_bit(&db->role_val_to_struct[i]->types.negset, value - 1, 0);
    ebitmap_set_bit(&db->role_val_to_struct[i]->types.types, value - 1, 1);
    type_set_expand(&db->role_val_to_struct[i]->types,
                    &db->role_val_to_struct[i]->cache, db, 0);
  }

  return true;
}

void SePolicy::type(rust::Str ty, rust::Slice<rust::Str const> attrs) noexcept {
  if (!inner->add_type(ty, TYPE_TYPE))
    return;

  for (auto a : attrs) {
    inner->add_typeattribute(ty, a);
  }
}

void SePolicy::attribute(rust::Str name) noexcept {
  inner->add_type(name, TYPE_ATTRIB);
}

// Type rules (type_transition, type_change, type_member)
bool SePolicyImpl::add_type_rule(rust::Str s, rust::Str t, rust::Str c,
                                 rust::Str d, int effect) {
  auto src = hashtab_find<type_datum_t>(db->p_types.table, s);
  auto tgt = hashtab_find<type_datum_t>(db->p_types.table, t);
  auto cls = hashtab_find<class_datum_t>(db->p_classes.table, c);
  auto def = hashtab_find<type_datum_t>(db->p_types.table, d);
  if (!src || !tgt || !cls || !def)
    return false;

  avtab_key_t key{};
  key.source_type = src->s.value;
  key.target_type = tgt->s.value;
  key.target_class = cls->s.value;
  key.specified = effect;

  avtab_ptr_t node = avtab_search_node(&db->te_avtab, &key);
  if (!node) {
    avtab_datum_t avdatum{};
    node = avtab_insert_nonunique(&db->te_avtab, &key, &avdatum);
  }
  node->datum.data = def->s.value;

  return true;
}

bool SePolicyImpl::add_filename_trans(rust::Str s, rust::Str t, rust::Str c,
                                      rust::Str d, rust::Str o) {
  auto src = hashtab_find<type_datum_t>(db->p_types.table, s);
  auto tgt = hashtab_find<type_datum_t>(db->p_types.table, t);
  auto cls = hashtab_find<class_datum_t>(db->p_classes.table, c);
  auto def = hashtab_find<type_datum_t>(db->p_types.table, d);
  if (!src || !tgt || !cls || !def)
    return false;

  std::string obj_name(o.data(), o.size());

  filename_trans_key_t key{};
  key.ttype = tgt->s.value;
  key.tclass = cls->s.value;
  // We use const_cast because filename_trans_key_t::name is char* not const char*, but we're only using it for the lookup.
  key.name = const_cast<char *>(obj_name.c_str());

  auto trans = static_cast<filename_trans_datum_t *>(
      hashtab_search(db->filename_trans, reinterpret_cast<hashtab_key_t>(&key)));
  filename_trans_datum_t *last = nullptr;

  while (trans) {
    if (ebitmap_get_bit(&trans->stypes, src->s.value - 1)) {
      trans->otype = def->s.value;
      return true;
    }
    if (trans->otype == def->s.value)
      break;
    last = trans;
    trans = trans->next;
  }

  if (!trans) {
    trans = static_cast<filename_trans_datum_t *>(calloc(1, sizeof(*trans)));
    ebitmap_init(&trans->stypes);
    trans->otype = def->s.value;
  }

  if (last) {
    last->next = trans;
  } else {
    auto new_key = static_cast<filename_trans_key_t *>(malloc(sizeof(filename_trans_key_t)));
    new_key->ttype = key.ttype;
    new_key->tclass = key.tclass;
    new_key->name = strdup(key.name);
    hashtab_insert(db->filename_trans, reinterpret_cast<hashtab_key_t>(new_key), trans);
  }

  db->filename_trans_count++;
  return ebitmap_set_bit(&trans->stypes, src->s.value - 1, 1) == 0;
}

void SePolicy::type_transition(rust::Str src, rust::Str tgt, rust::Str cls,
                               rust::Str dest, rust::Str obj) noexcept {
  if (obj.empty()) {
    inner->add_type_rule(src, tgt, cls, dest, AVTAB_TRANSITION);
  } else {
    inner->add_filename_trans(src, tgt, cls, dest, obj);
  }
}

void SePolicy::type_change(rust::Str src, rust::Str tgt, rust::Str cls,
                           rust::Str dest) noexcept {
  inner->add_type_rule(src, tgt, cls, dest, AVTAB_CHANGE);
}

void SePolicy::type_member(rust::Str src, rust::Str tgt, rust::Str cls,
                           rust::Str dest) noexcept {
  inner->add_type_rule(src, tgt, cls, dest, AVTAB_MEMBER);
}

// Genfscon
bool SePolicyImpl::add_genfscon(rust::Str fs_name, rust::Str path,
                                rust::Str context) {
  context_struct_t *ctx;
  if (context_from_string(nullptr, db, &ctx, context.data(), context.size()))
    return false;

  auto fs = list_find(db->genfs, [&](genfs_t *n) {
    return str_eq(n->fstype, fs_name);
  });
  if (!fs) {
    fs = static_cast<genfs_t *>(calloc(1, sizeof(genfs_t)));
    fs->fstype = dup_str(fs_name);
    fs->next = db->genfs;
    db->genfs = fs;
  }

  auto o_ctx = list_find(fs->head, [&](ocontext_t *n) {
    return str_eq(n->u.name, path);
  });
  if (!o_ctx) {
    o_ctx = static_cast<ocontext_t *>(calloc(1, sizeof(ocontext_t)));
    o_ctx->u.name = dup_str(path);
    o_ctx->next = fs->head;
    fs->head = o_ctx;
  }

  memset(o_ctx->context, 0, sizeof(o_ctx->context));
  memcpy(&o_ctx->context[0], ctx, sizeof(*ctx));
  free(ctx);

  return true;
}

void SePolicy::genfscon(rust::Str fs, rust::Str path,
                        rust::Str context) noexcept {
  inner->add_genfscon(fs, path, context);
}

#include "utils.hpp"
#include "sepolicy-inject-rs/src/lib.rs.h"
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/policydb.h>
#include <algorithm>
#include <vector>

static std::string to_string(rust::Str str) {
  return std::string(str.data(), str.size());
}

const char *CIL_FILES[] = {
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

// Logging helpers that call into Rust's tracing system
static constexpr const char *LOG_TARGET = "sepolicy::ffi";

static void ffi_log_trace(const std::string &msg) {
  log_trace(LOG_TARGET, msg);
}

static void ffi_log_debug(const std::string &msg) {
  log_debug(LOG_TARGET, msg);
}

static void ffi_log_info(const std::string &msg) {
  log_info(LOG_TARGET, msg);
}

static void ffi_log_warn(const std::string &msg) {
  log_warn(LOG_TARGET, msg);
}

static void ffi_log_error(const std::string &msg) {
  log_error(LOG_TARGET, msg);
}

static size_t class_perm_vec_size(const class_datum_t *clz) {
  size_t n = clz->permissions.nprim;
  if (clz->comdatum)
    n = std::max(n, size_t(clz->comdatum->permissions.nprim));
  return n;
}

SePolicyImpl::SePolicyImpl(policydb *db, bool android_m_compat)
    : db(db), android_m_compat(android_m_compat) {
  perm_names.resize(db->p_classes.nprim);
  for (uint32_t value = 1; value <= db->p_classes.nprim; ++value) {
    auto clz = db->class_val_to_struct[value - 1];
    if (!clz)
      continue;

    auto &names = perm_names[value - 1];
    names.assign(class_perm_vec_size(clz), nullptr);
    auto collect = [&](hashtab_t tab) {
      for_each_hashtab(tab, [&](hashtab_ptr_t node) {
        auto perm = static_cast<perm_datum *>(node->datum);
        if (!perm)
          return;
        size_t idx = perm->s.value - 1;
        if (idx < names.size())
          names[idx] = node->key;
      });
    };
    collect(clz->permissions.table);
    if (clz->comdatum)
      collect(clz->comdatum->permissions.table);
  }
}

SePolicyImpl::~SePolicyImpl() {
  policydb_destroy(db);
  free(db);
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

// Read a binary policy, keeping its Android M format flag with the policy
// rather than in libsepol's process global.
static std::unique_ptr<SePolicyImpl> read_policydb(policy_file &file) {
  avtab_android_m_compat = 0;
  policydb *db = static_cast<policydb *>(malloc(sizeof(policydb_t)));
  bool ok = policydb_init(db) == 0 && policydb_read(db, &file, 0) == 0;
  bool android_m_compat = avtab_android_m_compat != 0;
  avtab_android_m_compat = 0;

  if (!ok) {
    free(db);
    return nullptr;
  }
  return std::make_unique<SePolicyImpl>(db, android_m_compat);
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

  auto impl = read_policydb(policy_file);
  if (!impl) {
    ffi_log_error("Failed to read policy database from file: " + path);
    return nullptr;
  }

  ffi_log_info("Successfully loaded policy from file: " + path);
  return impl;
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

  auto impl = read_policydb(policy_file);
  if (!impl) {
    ffi_log_error("Failed to read policy database from memory");
    return nullptr;
  }

  ffi_log_info("Successfully loaded policy from memory");
  return impl;
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
  int scanned = fscanf(f, "%d", &policy_ver);
  fclose(f);
  if (scanned != 1) {
    ffi_log_error("Failed to read SELinux version from " SELINUX_VERSION);
    return nullptr;
  }
  cil.set_policy_version(policy_ver);
  ffi_log_debug("Policy version: " + std::to_string(policy_ver));

  // Get mapping version
  f = fopen(VEND_POLICY_DIR "plat_sepolicy_vers.txt", "re");
  if (!f) {
    ffi_log_error("Failed to open platform sepolicy version file");
    return nullptr;
  }
  scanned = fscanf(f, "%9s", plat_ver);
  fclose(f);
  if (scanned != 1) {
    ffi_log_error("Failed to read platform sepolicy version");
    return nullptr;
  }
  ffi_log_debug("Platform version: " + std::string(plat_ver));

  // add_file takes CIL source text, so load each file's contents.
  auto add_cil_file = [&](const char *file) {
    ffi_log_debug(std::string("Adding CIL file: ") + file);
    auto content = read_file(file);
    if (!content) {
      ffi_log_error(std::string("Failed to read CIL file: ") + file);
      return false;
    }
    return cil.add_file(content->data(), content->size());
  };

  if (!add_cil_file(SPLIT_PLAT_CIL))
    return nullptr;

  for (const char *file : CIL_FILES) {
    const char *actual_file = file;
    if (strchr(file, '%')) {
      snprintf(path, sizeof(path), file, plat_ver);
      actual_file = path;
    }
    // Compiling without a present file would load an incomplete policy.
    if (access(actual_file, R_OK) == 0 && !add_cil_file(actual_file))
      return nullptr;
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

static rust::Slice<const uint8_t> name_bytes(const char *name) {
  if (name == nullptr)
    return {};
  return {reinterpret_cast<const uint8_t *>(name), std::strlen(name)};
}

rust::Slice<const uint8_t>
SePolicyImpl::type_name_bytes(uint32_t value) const noexcept {
  if (value < 1 || value > db->p_types.nprim)
    return {};
  return name_bytes(db->p_type_val_to_name[value - 1]);
}

rust::Slice<const uint8_t>
SePolicyImpl::class_name_bytes(uint32_t value) const noexcept {
  if (value < 1 || value > db->p_classes.nprim)
    return {};
  return name_bytes(db->p_class_val_to_name[value - 1]);
}

rust::Slice<const uint8_t>
SePolicyImpl::perm_name_bytes(uint32_t class_value,
                              uint32_t bit) const noexcept {
  if (class_value < 1 || class_value > perm_names.size())
    return {};
  auto &names = perm_names[class_value - 1];
  if (bit >= names.size())
    return {};
  return name_bytes(names[bit]);
}

void SePolicyImpl::attribute_entries(rust::Vec<uint32_t> &out) const noexcept {
  for_each_hashtab(db->p_types.table, [&](hashtab_ptr_t node) {
    auto type = static_cast<type_datum_t *>(node->datum);
    if (type && type->flavor == TYPE_ATTRIB)
      out.push_back(type->s.value);
  });
}

void SePolicyImpl::type_entries(rust::Vec<TypeEntry> &out,
                                rust::Vec<uint32_t> &attrs) const noexcept {
  for_each_hashtab(db->p_types.table, [&](hashtab_ptr_t node) {
    auto type = static_cast<type_datum_t *>(node->datum);
    if (!type || type->flavor != TYPE_TYPE)
      return;

    TypeEntry entry;
    entry.value = type->s.value;
    entry.permissive = ebitmap_get_bit(&db->permissive_map, type->s.value);
    entry.attrs_start = attrs.size();

    ebitmap_node_t *n;
    uint32_t bit;
    ebitmap_for_each_positive_bit(&db->type_attr_map[type->s.value - 1], n,
                                  bit) {
      uint32_t attr_val = bit + 1;
      auto attr = type_datum(attr_val);
      if (attr && attr->flavor == TYPE_ATTRIB)
        attrs.push_back(attr_val);
    }

    entry.attrs_len = attrs.size() - entry.attrs_start;
    out.push_back(entry);
  });
}

// Exact `specified` values only, as libsepol never sets AVTAB_ENABLED in
// te_avtab.
static std::optional<AvtabKind> avtab_kind(uint16_t specified) {
  switch (specified) {
  case AVTAB_ALLOWED:
    return AvtabKind::Allow;
  case AVTAB_AUDITALLOW:
    return AvtabKind::AuditAllow;
  case AVTAB_AUDITDENY:
    return AvtabKind::DontAudit;
  case AVTAB_TRANSITION:
    return AvtabKind::TypeTransition;
  case AVTAB_MEMBER:
    return AvtabKind::TypeMember;
  case AVTAB_CHANGE:
    return AvtabKind::TypeChange;
  case AVTAB_XPERMS_ALLOWED:
    return AvtabKind::AllowXperm;
  case AVTAB_XPERMS_AUDITALLOW:
    return AvtabKind::AuditAllowXperm;
  case AVTAB_XPERMS_DONTAUDIT:
    return AvtabKind::DontAuditXperm;
  default:
    return std::nullopt;
  }
}

void SePolicyImpl::avtab_entries(rust::Vec<AvtabEntry> &out,
                                 rust::Vec<XpermEntry> &xperms) const noexcept {
  out.reserve(db->te_avtab.nel);

  for_each_avtab(&db->te_avtab, [&](avtab_ptr_t node) {
    auto kind = avtab_kind(node->key.specified);
    if (!kind)
      return;

    AvtabEntry entry;
    entry.kind = *kind;
    entry.source = node->key.source_type;
    entry.target = node->key.target_type;
    entry.class_ = node->key.target_class;
    entry.data = node->datum.data;
    entry.xperm = UINT32_MAX;

    // An auditdeny datum stores the permissions that are audited; dontaudit
    // lists the complement.
    if (*kind == AvtabKind::DontAudit)
      entry.data = ~entry.data;

    if (node->key.specified & AVTAB_XPERMS) {
      auto xp = node->datum.xperms;
      if (!xp)
        return;

      XpermEntry x;
      x.function = xp->specified == AVTAB_XPERMS_IOCTLFUNCTION;
      x.driver = xp->driver;
      std::copy(std::begin(xp->perms), std::end(xp->perms), x.perms.begin());
      entry.xperm = xperms.size();
      xperms.push_back(x);
    }

    out.push_back(entry);
  });
}

void SePolicyImpl::filename_trans_entries(
    rust::Vec<FilenameTransEntry> &out) const noexcept {
  for_each_hashtab(db->filename_trans, [&](hashtab_ptr_t node) {
    auto key = reinterpret_cast<filename_trans_key_t *>(node->key);
    if (key->name == nullptr)
      return;

    // A key maps to a chain of datums, one per default type.
    for (auto trans = static_cast<filename_trans_datum *>(node->datum); trans;
         trans = trans->next) {
      ebitmap_node_t *n;
      uint32_t bit;
      ebitmap_for_each_positive_bit(&trans->stypes, n, bit) {
        FilenameTransEntry entry;
        entry.source = bit + 1;
        entry.target = key->ttype;
        entry.class_ = key->tclass;
        entry.default_type = trans->otype;
        entry.name = name_bytes(key->name);
        out.push_back(entry);
      }
    }
  });
}

void SePolicyImpl::genfs_entries(rust::Vec<GenfsEntry> &out) const noexcept {
  for_each_list(db->genfs, [&](genfs_t *genfs) {
    for_each_list(genfs->head, [&](ocontext *context) {
      char *raw_ptr = nullptr;
      size_t len = 0;
      if (context_to_string(nullptr, db, &context->context[0], &raw_ptr,
                            &len) != 0)
        return;

      std::unique_ptr<char, decltype(&free)> ctx(raw_ptr, &free);
      GenfsEntry entry;
      entry.fs = name_bytes(genfs->fstype);
      entry.path = name_bytes(context->u.name);
      entry.class_ = context->v.sclass;
      entry.context = rust::String::lossy(ctx.get());
      out.push_back(std::move(entry));
    });
  });
}

bool SePolicyImpl::add_rule(rust::Str s, rust::Str t, rust::Str c, rust::Str p,
                            int effect, bool remove) {
  std::string src_str(s.data(), s.size());
  std::string tgt_str(t.data(), t.size());
  std::string cls_str(c.data(), c.size());
  std::string perm_str(p.data(), p.size());

  auto src = hashtab_find<type_datum_t>(db->p_types.table, s);
  auto tgt = hashtab_find<type_datum_t>(db->p_types.table, t);
  auto cls = hashtab_find<class_datum_t>(db->p_classes.table, c);
  if (!src || !tgt || !cls) {
    ffi_log_warn("add_rule: type/class not found - src=" + src_str +
                 " tgt=" + tgt_str + " cls=" + cls_str);
    return false;
  }

  auto perm = hashtab_find<perm_datum_t>(cls->permissions.table, p);
  if (!perm && cls->comdatum)
    perm = hashtab_find<perm_datum_t>(cls->comdatum->permissions.table, p);
  if (!perm) {
    ffi_log_warn("add_rule: permission not found - " + perm_str + " in class " +
                 cls_str);
    return false;
  }

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

  ffi_log_trace("add_rule: " + src_str + " " + tgt_str + ":" + cls_str + " " +
                perm_str + (remove ? " (remove)" : ""));
  return true;
}

void SePolicyImpl::allow(rust::Slice<rust::Str const> src,
                     rust::Slice<rust::Str const> tgt,
                     rust::Slice<rust::Str const> cls,
                     rust::Slice<rust::Str const> perm) noexcept {
  for_each_rule(src, tgt, cls, perm, [this](auto s, auto t, auto c, auto p) {
    add_rule(s, t, c, p, AVTAB_ALLOWED);
  });
}

void SePolicyImpl::deny(rust::Slice<rust::Str const> src,
                    rust::Slice<rust::Str const> tgt,
                    rust::Slice<rust::Str const> cls,
                    rust::Slice<rust::Str const> perm) noexcept {
  for_each_rule(src, tgt, cls, perm, [this](auto s, auto t, auto c, auto p) {
    add_rule(s, t, c, p, AVTAB_ALLOWED, true);
  });
}

void SePolicyImpl::auditallow(rust::Slice<rust::Str const> src,
                          rust::Slice<rust::Str const> tgt,
                          rust::Slice<rust::Str const> cls,
                          rust::Slice<rust::Str const> perm) noexcept {
  for_each_rule(src, tgt, cls, perm, [this](auto s, auto t, auto c, auto p) {
    add_rule(s, t, c, p, AVTAB_AUDITALLOW);
  });
}

void SePolicyImpl::dontaudit(rust::Slice<rust::Str const> src,
                         rust::Slice<rust::Str const> tgt,
                         rust::Slice<rust::Str const> cls,
                         rust::Slice<rust::Str const> perm) noexcept {
  for_each_rule(src, tgt, cls, perm, [this](auto s, auto t, auto c, auto p) {
    add_rule(s, t, c, p, AVTAB_AUDITDENY);
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

  auto set_functions = [&](uint8_t driver, int low, int high) {
    auto node = node_list[driver];
    if (!node) {
      node = new_node(AVTAB_XPERMS_IOCTLFUNCTION, driver);
      node_list[driver] = node;
    }
    for (int i = low; i <= high; ++i)
      xperm_set(i, node->datum.xperms->perms);
  };

  int low_driver = ioctl_driver(xp.low);
  int high_driver = ioctl_driver(xp.high);
  if (low_driver == high_driver) {
    set_functions(low_driver, ioctl_func(xp.low), ioctl_func(xp.high));
  } else {
    // Drivers the range covers completely go in the driver node. A driver it
    // covers only partly, at either end, gets just those functions; setting
    // the whole driver would allow ioctls the rule never listed.
    for (int driver = low_driver; driver <= high_driver; ++driver) {
      int first = driver == low_driver ? ioctl_func(xp.low) : 0x00;
      int last = driver == high_driver ? ioctl_func(xp.high) : 0xff;
      if (first == 0x00 && last == 0xff) {
        if (!driver_node)
          driver_node = new_node(AVTAB_XPERMS_IOCTLDRIVER, 0);
        xperm_set(driver, driver_node->datum.xperms->perms);
      } else {
        set_functions(driver, first, last);
      }
    }
  }

#undef driver_node
  return true;
}

void SePolicyImpl::allowxperm(rust::Slice<rust::Str const> src,
                          rust::Slice<rust::Str const> tgt,
                          rust::Slice<rust::Str const> cls,
                          rust::Slice<XPerm const> xperm) noexcept {
  for_each_rule(src, tgt, cls, xperm, [this](auto s, auto t, auto c, auto &x) {
    add_xperm_rule(s, t, c, x, AVTAB_XPERMS_ALLOWED);
  });
}

void SePolicyImpl::auditallowxperm(rust::Slice<rust::Str const> src,
                               rust::Slice<rust::Str const> tgt,
                               rust::Slice<rust::Str const> cls,
                               rust::Slice<XPerm const> xperm) noexcept {
  for_each_rule(src, tgt, cls, xperm, [this](auto s, auto t, auto c, auto &x) {
    add_xperm_rule(s, t, c, x, AVTAB_XPERMS_AUDITALLOW);
  });
}

void SePolicyImpl::dontauditxperm(rust::Slice<rust::Str const> src,
                              rust::Slice<rust::Str const> tgt,
                              rust::Slice<rust::Str const> cls,
                              rust::Slice<XPerm const> xperm) noexcept {
  for_each_rule(src, tgt, cls, xperm, [this](auto s, auto t, auto c, auto &x) {
    add_xperm_rule(s, t, c, x, AVTAB_XPERMS_DONTAUDIT);
  });
}

// Permissive/enforce
bool SePolicyImpl::set_type_state(rust::Str type_name, bool permissive) {
  auto type = hashtab_find<type_datum_t>(db->p_types.table, type_name);
  if (!type)
    return false;

  return ebitmap_set_bit(&db->permissive_map, type->s.value, permissive) == 0;
}

void SePolicyImpl::permissive(rust::Slice<rust::Str const> types) noexcept {
  for (auto t : types) {
    set_type_state(t, true);
  }
}

void SePolicyImpl::enforce(rust::Slice<rust::Str const> types) noexcept {
  for (auto t : types) {
    set_type_state(t, false);
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

void SePolicyImpl::typeattribute(rust::Slice<rust::Str const> ty,
                             rust::Slice<rust::Str const> attrs) noexcept {
  for (auto t : ty) {
    for (auto a : attrs) {
      add_typeattribute(t, a);
    }
  }
}

// Create new type or attribute
bool SePolicyImpl::add_type(rust::Str type_name, uint32_t flavor) {
  std::string name_str(type_name.data(), type_name.size());
  const char *flavor_str = (flavor == TYPE_TYPE) ? "type" : "attribute";

  if (hashtab_find<type_datum_t>(db->p_types.table, type_name)) {
    ffi_log_trace(std::string("add_type: ") + flavor_str + " already exists: " +
                  name_str);
    return true; // Already exists
  }

  ffi_log_debug(std::string("add_type: creating ") + flavor_str + ": " +
                name_str);

  auto type = static_cast<type_datum_t *>(malloc(sizeof(type_datum_t)));
  type_datum_init(type);
  type->primary = 1;
  type->flavor = flavor;

  uint32_t value = 0;
  char *name = dup_str(type_name);
  if (symtab_insert(db, SYM_TYPES, name, type, SCOPE_DECL, 1, &value)) {
    ffi_log_error(std::string("add_type: failed to insert ") + flavor_str +
                  ": " + name_str);
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

void SePolicyImpl::type(rust::Str ty, rust::Slice<rust::Str const> attrs) noexcept {
  if (!add_type(ty, TYPE_TYPE))
    return;

  for (auto a : attrs) {
    add_typeattribute(ty, a);
  }
}

void SePolicyImpl::attribute(rust::Str name) noexcept {
  add_type(name, TYPE_ATTRIB);
}

// Type rules (type_transition, type_change, type_member)
bool SePolicyImpl::add_type_rule(rust::Str s, rust::Str t, rust::Str c,
                                 rust::Str d, int effect) {
  std::string src_str(s.data(), s.size());
  std::string tgt_str(t.data(), t.size());
  std::string cls_str(c.data(), c.size());
  std::string def_str(d.data(), d.size());

  auto src = hashtab_find<type_datum_t>(db->p_types.table, s);
  auto tgt = hashtab_find<type_datum_t>(db->p_types.table, t);
  auto cls = hashtab_find<class_datum_t>(db->p_classes.table, c);
  auto def = hashtab_find<type_datum_t>(db->p_types.table, d);
  if (!src || !tgt || !cls || !def) {
    ffi_log_warn("add_type_rule: type/class not found - src=" + src_str +
                 " tgt=" + tgt_str + " cls=" + cls_str + " def=" + def_str);
    return false;
  }

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

  ffi_log_trace("add_type_rule: " + src_str + " " + tgt_str + ":" + cls_str +
                " -> " + def_str);
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
  // We use const_cast because filename_trans_key_t::name is char* not const
  // char*, but we're only using it for the lookup.
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

void SePolicyImpl::type_transition(rust::Str src, rust::Str tgt, rust::Str cls,
                               rust::Str dest, rust::Str obj) noexcept {
  if (obj.empty()) {
    add_type_rule(src, tgt, cls, dest, AVTAB_TRANSITION);
  } else {
    add_filename_trans(src, tgt, cls, dest, obj);
  }
}

void SePolicyImpl::type_change(rust::Str src, rust::Str tgt, rust::Str cls,
                           rust::Str dest) noexcept {
  add_type_rule(src, tgt, cls, dest, AVTAB_CHANGE);
}

void SePolicyImpl::type_member(rust::Str src, rust::Str tgt, rust::Str cls,
                           rust::Str dest) noexcept {
  add_type_rule(src, tgt, cls, dest, AVTAB_MEMBER);
}

// Genfscon
bool SePolicyImpl::add_genfscon(rust::Str fs_name, rust::Str path,
                                rust::Str class_name, rust::Str context) {
  // An empty class applies the entry to every file type.
  uint32_t sclass = 0;
  if (!class_name.empty()) {
    auto cls = hashtab_find<class_datum_t>(db->p_classes.table, class_name);
    if (!cls)
      return false;
    sclass = cls->s.value;
  }

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

  // The kernel labels a file with the first entry whose path is a prefix of
  // the file's path, so keep entries ordered longest path first, inserting
  // before the first shorter one as checkpolicy does.
  ocontext_t *o_ctx = nullptr;
  ocontext_t **link = &fs->head;
  for (; *link; link = &(*link)->next) {
    bool same_path = str_eq((*link)->u.name, path);
    if (same_path && (*link)->v.sclass == sclass) {
      o_ctx = *link;
      break;
    }
    // A class-specific entry goes before the generic entry for its path,
    // which would otherwise always match first.
    if (same_path && sclass && !(*link)->v.sclass)
      break;
    if (path.size() > strlen((*link)->u.name))
      break;
  }

  if (!o_ctx) {
    o_ctx = static_cast<ocontext_t *>(calloc(1, sizeof(ocontext_t)));
    o_ctx->u.name = dup_str(path);
    o_ctx->v.sclass = sclass;
    o_ctx->next = *link;
    *link = o_ctx;
  }

  memset(o_ctx->context, 0, sizeof(o_ctx->context));
  memcpy(&o_ctx->context[0], ctx, sizeof(*ctx));
  free(ctx);

  return true;
}

void SePolicyImpl::genfscon(rust::Str fs, rust::Str path, rust::Str class_name,
                            rust::Str context) noexcept {
  add_genfscon(fs, path, class_name, context);
}

bool SePolicyImpl::write(rust::Str path) const noexcept {
  std::string path_str(path.data(), path.size());

  // Write policy to memory buffer first
  // This is required because /sys/fs/selinux/load doesn't allow partial writes
  char *buf = nullptr;
  size_t buf_size = 0;

  FILE *fp = open_memstream(&buf, &buf_size);
  if (!fp) {
    ffi_log_error("write: failed to create memory buffer");
    return false;
  }

  policy_file_t pf;
  policy_file_init(&pf);
  pf.type = PF_USE_STDIO;
  pf.fp = fp;

  avtab_android_m_compat = android_m_compat;
  int write_result = policydb_write(this->db, &pf);
  avtab_android_m_compat = 0;
  fclose(fp);

  if (write_result != 0) {
    ffi_log_error("write: failed to serialize policy");
    free(buf);
    return false;
  }

  ffi_log_debug("write: serialized policy (" + std::to_string(buf_size) + " bytes)");

  // Open file with O_TRUNC to handle existing content
  int fd = open(path_str.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) {
    ffi_log_error("write: failed to open " + path_str + ": " + strerror(errno));
    free(buf);
    return false;
  }

  // Write in one operation (required for /sys/fs/selinux/load)
  ssize_t written = ::write(fd, buf, buf_size);
  close(fd);
  free(buf);

  if (written < 0 || static_cast<size_t>(written) != buf_size) {
    ffi_log_error("write: failed to write policy to " + path_str);
    return false;
  }

  ffi_log_info("write: successfully wrote policy to " + path_str);
  return true;
}


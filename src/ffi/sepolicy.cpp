#include "sepolicy.hpp"
#include "utils.hpp"
#include "mmap.hpp"
#include "sepolicy-inject-rs/src/lib.rs.h"
#include <fcntl.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/policydb.h>
#include <sstream>
#include <unistd.h>

#include <cil/cil.h>

static std::string to_string(rust::Str str) {
  return std::string(str.data(), str.size());
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

  policy_file policy_file;
  policy_file_init(&policy_file);
  auto file_opt = open_file(path.c_str(), "r");
  if (!file_opt)
    return nullptr;

  policy_file.fp = file_opt->get();
  policy_file.type = PF_USE_STDIO;

  policydb *db = static_cast<policydb *>(malloc(sizeof(policydb_t)));
  if (policydb_init(db) || policydb_read(db, &policy_file, 0)) {
    free(db);
    return nullptr;
  }

  return std::make_unique<SePolicyImpl>(db);
}

std::unique_ptr<SePolicyImpl>
from_data_impl(rust::Slice<const uint8_t> data) noexcept {
  policy_file policy_file;
  policy_file_init(&policy_file);
  policy_file.data = (char *)data.data();
  policy_file.len = data.size();
  policy_file.type = PF_USE_MEMORY;

  policydb *db = static_cast<policydb *>(malloc(sizeof(policydb_t)));
  if (policydb_init(db) || policydb_read(db, &policy_file, 0)) {
    free(db);
    return nullptr;
  }

  return std::make_unique<SePolicyImpl>(db);
}

#define SHALEN 64
static bool read_exact(const char *path, char *buf, size_t len) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return false;

  ssize_t total = 0;
  while (total < (ssize_t)len) {
    ssize_t r = read(fd, buf + total, len - total);
    if (r <= 0) {
      close(fd);
      return false;
    }
    total += r;
  }

  close(fd);
  return true;
}

static bool cmp_sha256(const char *a, const char *b) {
  char id_a[SHALEN] = {0};
  char id_b[SHALEN] = {0};

  if (!read_exact(a, id_a, SHALEN))
    return false;

  if (!read_exact(b, id_b, SHALEN))
    return false;

  return memcmp(id_a, id_b, SHALEN) == 0;
}

static bool check_precompiled(const char *precompiled) {
  bool ok = false;
  const char *actual_sha;
  char compiled_sha[128];

  actual_sha = PLAT_POLICY_DIR "plat_and_mapping_sepolicy.cil.sha256";
  if (access(actual_sha, R_OK) == 0) {
    ok = true;
    sprintf(compiled_sha, "%s.plat_and_mapping.sha256", precompiled);
    if (!cmp_sha256(actual_sha, compiled_sha))
      return false;
  }

  actual_sha = PLAT_POLICY_DIR "plat_sepolicy_and_mapping.sha256";
  if (access(actual_sha, R_OK) == 0) {
    ok = true;
    sprintf(compiled_sha, "%s.plat_sepolicy_and_mapping.sha256", precompiled);
    if (!cmp_sha256(actual_sha, compiled_sha))
      return false;
  }

  actual_sha = PROD_POLICY_DIR "product_sepolicy_and_mapping.sha256";
  if (access(actual_sha, R_OK) == 0) {
    ok = true;
    sprintf(compiled_sha, "%s.product_sepolicy_and_mapping.sha256",
            precompiled);
    if (!cmp_sha256(actual_sha, compiled_sha))
      return false;
  }

  actual_sha = SYSEXT_POLICY_DIR "system_ext_sepolicy_and_mapping.sha256";
  if (access(actual_sha, R_OK) == 0) {
    ok = true;
    sprintf(compiled_sha, "%s.system_ext_sepolicy_and_mapping.sha256",
            precompiled);
    if (!cmp_sha256(actual_sha, compiled_sha))
      return false;
  }

  return ok;
}

std::unique_ptr<SePolicyImpl> from_split_impl() noexcept {
  const char *odm_pre = ODM_POLICY_DIR "precompiled_sepolicy";
  const char *vend_pre = VEND_POLICY_DIR "precompiled_sepolicy";
  if (access(odm_pre, R_OK) == 0 && check_precompiled(odm_pre))
    return from_file_impl(odm_pre);
  else if (access(vend_pre, R_OK) == 0 && check_precompiled(vend_pre))
    return from_file_impl(vend_pre);
  else
    return compile_split_impl();
}

static void load_cil(struct cil_db *db, const char *file) {
  mmap_data d(file);
  cil_add_file(db, file, (const char *)d.data(), d.size());
}

std::unique_ptr<SePolicyImpl> compile_split_impl() noexcept {
  char path[128], plat_ver[10];
  cil_db_t *db = nullptr;
  sepol_policydb_t *pdb = nullptr;
  FILE *f;
  int policy_ver;
  const char *cil_file;

  cil_db_init(&db);
  run_finally fin([db_ptr = &db] { cil_db_destroy(db_ptr); });
  cil_set_mls(db, 1);
  cil_set_multiple_decls(db, 1);
  cil_set_disable_neverallow(db, 1);
  cil_set_target_platform(db, SEPOL_TARGET_SELINUX);
  cil_set_attrs_expand_generated(db, 1);

  f = fopen(SELINUX_VERSION, "re");
  if (!f)
    return nullptr;
  fscanf(f, "%d", &policy_ver);
  fclose(f);
  cil_set_policy_version(db, policy_ver);

  // Get mapping version
  f = fopen(VEND_POLICY_DIR "plat_sepolicy_vers.txt", "re");
  if (!f)
    return nullptr;
  fscanf(f, "%s", plat_ver);
  fclose(f);

  // plat
  load_cil(db, SPLIT_PLAT_CIL);

  sprintf(path, PLAT_POLICY_DIR "mapping/%s.cil", plat_ver);
  load_cil(db, path);

  sprintf(path, PLAT_POLICY_DIR "mapping/%s.compat.cil", plat_ver);
  if (access(path, R_OK) == 0)
    load_cil(db, path);

  // system_ext
  sprintf(path, SYSEXT_POLICY_DIR "mapping/%s.cil", plat_ver);
  if (access(path, R_OK) == 0)
    load_cil(db, path);

  sprintf(path, SYSEXT_POLICY_DIR "mapping/%s.compat.cil", plat_ver);
  if (access(path, R_OK) == 0)
    load_cil(db, path);

  cil_file = SYSEXT_POLICY_DIR "system_ext_sepolicy.cil";
  if (access(cil_file, R_OK) == 0)
    load_cil(db, cil_file);

  // product
  sprintf(path, PROD_POLICY_DIR "mapping/%s.cil", plat_ver);
  if (access(path, R_OK) == 0)
    load_cil(db, path);

  cil_file = PROD_POLICY_DIR "product_sepolicy.cil";
  if (access(cil_file, R_OK) == 0)
    load_cil(db, cil_file);

  // vendor
  cil_file = VEND_POLICY_DIR "nonplat_sepolicy.cil";
  if (access(cil_file, R_OK) == 0)
    load_cil(db, cil_file);

  cil_file = VEND_POLICY_DIR "plat_pub_versioned.cil";
  if (access(cil_file, R_OK) == 0)
    load_cil(db, cil_file);

  cil_file = VEND_POLICY_DIR "vendor_sepolicy.cil";
  if (access(cil_file, R_OK) == 0)
    load_cil(db, cil_file);

  // odm
  cil_file = ODM_POLICY_DIR "odm_sepolicy.cil";
  if (access(cil_file, R_OK) == 0)
    load_cil(db, cil_file);

  if (cil_compile(db))
    return {};
  if (cil_build_policydb(db, &pdb))
    return {};
  return std::make_unique<SePolicyImpl>(&pdb->p);
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
  auto class_ = this->type_name(node->key.target_class);
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
  auto class_ = this->type_name(node->key.target_class);
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
  auto class_ = this->type_name(node->key.target_class);
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

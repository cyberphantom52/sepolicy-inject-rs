#pragma once

#include <memory>
#include <optional>
#include <rust/cxx.h>

#include <sepol/policydb/policydb.h>
#include <string>
#include <unordered_map>

// libsepol internal APIs
__BEGIN_DECLS
int context_from_string(sepol_handle_t *handle, const policydb_t *policydb,
                        context_struct_t **cptr, const char *con_str,
                        size_t con_str_len);
int context_to_string(sepol_handle_t *handle, const policydb_t *policydb,
                      const context_struct_t *context, char **result,
                      size_t *result_len);
int policydb_index_decls(sepol_handle_t *handle, policydb_t *p);
int type_set_expand(type_set_t *set, ebitmap_t *t, policydb_t *p,
                    unsigned char alwaysexpand);
__END_DECLS

#define ioctl_driver(x) ((x >> 8) & 0xFF)
#define ioctl_func(x) (x & 0xFF)

// sepolicy paths
#define PLAT_POLICY_DIR "/system/etc/selinux/"
#define VEND_POLICY_DIR "/vendor/etc/selinux/"
#define PROD_POLICY_DIR "/product/etc/selinux/"
#define ODM_POLICY_DIR "/odm/etc/selinux/"
#define SYSEXT_POLICY_DIR "/system_ext/etc/selinux/"
#define SPLIT_PLAT_CIL PLAT_POLICY_DIR "plat_sepolicy.cil"

// selinuxfs paths
#define SELINUX_MNT "/sys/fs/selinux"
#define SELINUX_VERSION SELINUX_MNT "/policyvers"

struct XPerm;

class SePolicyImpl {
  policydb *db;
  mutable std::unordered_map<uint32_t, std::vector<const char *>>
      class_perm_cache;
  friend struct SePolicy;

  std::optional<std::string> type_name(uint32_t v) const;
  std::optional<std::string> class_name(uint32_t v) const;
  type_datum_t *type_datum(uint32_t v) const;
  class_datum_t *class_datum(uint32_t v) const;

  void emit_av_rule(const avtab_ptr_t node, rust::Vec<rust::String> &out) const;
  void emit_type_rule(const avtab_ptr_t node,
                      rust::Vec<rust::String> &out) const;
  void emit_xperm_rule(const avtab_ptr_t node,
                       rust::Vec<rust::String> &out) const;

  // Rule modification methods
  bool add_rule(rust::Str s, rust::Str t, rust::Str c, rust::Str p, int effect,
                bool remove = false);
  bool add_xperm_rule(rust::Str s, rust::Str t, rust::Str c, const XPerm &xp,
                      int effect);
  bool add_type_rule(rust::Str s, rust::Str t, rust::Str c, rust::Str d,
                     int effect);
  bool add_filename_trans(rust::Str s, rust::Str t, rust::Str c, rust::Str d,
                          rust::Str o);
  bool add_genfscon(rust::Str fs_name, rust::Str path, rust::Str context);
  bool add_type(rust::Str type_name, uint32_t flavor);
  bool set_type_state(rust::Str type_name, bool permissive);
  bool add_typeattribute(rust::Str type, rust::Str attr);

  bool write(rust::Str path);

public:
  explicit SePolicyImpl(policydb *db) : db(db) {}
  ~SePolicyImpl();
};

std::unique_ptr<SePolicyImpl> from_file_impl(rust::Str path) noexcept;
std::unique_ptr<SePolicyImpl> from_split_impl() noexcept;
std::unique_ptr<SePolicyImpl> compile_split_impl() noexcept;
std::unique_ptr<SePolicyImpl>
from_data_impl(rust::Slice<const uint8_t> data) noexcept;

static auto specified_to_name =
    [](uint32_t spec) -> std::optional<std::string> {
  switch (spec) {
  case AVTAB_ALLOWED:
    return "allow";
  case AVTAB_AUDITALLOW:
    return "auditallow";
  case AVTAB_AUDITDENY:
    return "dontaudit";
  case AVTAB_TRANSITION:
    return "type_transition";
  case AVTAB_MEMBER:
    return "type_member";
  case AVTAB_CHANGE:
    return "type_change";
  case AVTAB_XPERMS_ALLOWED:
    return "allowxperm";
  case AVTAB_XPERMS_AUDITALLOW:
    return "auditallowxperm";
  case AVTAB_XPERMS_DONTAUDIT:
    return "dontauditxperm";
  default:
    return std::nullopt;
  }
};

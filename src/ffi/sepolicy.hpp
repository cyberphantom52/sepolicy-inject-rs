#pragma once

#include <memory>
#include <optional>
#include <rust/cxx.h>

#include <sepol/policydb/policydb.h>
#include <string>

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
struct AvtabEntry;
struct XpermEntry;
struct TypeEntry;
struct FilenameTransEntry;
struct GenfsEntry;

class SePolicyImpl {
  policydb *db;
  // Permission names per class, indexed [class value - 1][bit]. Built once at
  // construction: classes and permissions never change after loading.
  std::vector<std::vector<const char *>> perm_names;

  type_datum_t *type_datum(uint32_t v) const;
  class_datum_t *class_datum(uint32_t v) const;

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

public:
  explicit SePolicyImpl(policydb *db);
  ~SePolicyImpl();

  // AVRules
  void allow(rust::Slice<rust::Str const> src, rust::Slice<rust::Str const> tgt,
             rust::Slice<rust::Str const> cls,
             rust::Slice<rust::Str const> perm) noexcept;
  void deny(rust::Slice<rust::Str const> src, rust::Slice<rust::Str const> tgt,
            rust::Slice<rust::Str const> cls,
            rust::Slice<rust::Str const> perm) noexcept;
  void auditallow(rust::Slice<rust::Str const> src,
                  rust::Slice<rust::Str const> tgt,
                  rust::Slice<rust::Str const> cls,
                  rust::Slice<rust::Str const> perm) noexcept;
  void dontaudit(rust::Slice<rust::Str const> src,
                 rust::Slice<rust::Str const> tgt,
                 rust::Slice<rust::Str const> cls,
                 rust::Slice<rust::Str const> perm) noexcept;

  // AVXRules
  void allowxperm(rust::Slice<rust::Str const> src,
                  rust::Slice<rust::Str const> tgt,
                  rust::Slice<rust::Str const> cls,
                  rust::Slice<XPerm const> xperm) noexcept;
  void auditallowxperm(rust::Slice<rust::Str const> src,
                       rust::Slice<rust::Str const> tgt,
                       rust::Slice<rust::Str const> cls,
                       rust::Slice<XPerm const> xperm) noexcept;
  void dontauditxperm(rust::Slice<rust::Str const> src,
                      rust::Slice<rust::Str const> tgt,
                      rust::Slice<rust::Str const> cls,
                      rust::Slice<XPerm const> xperm) noexcept;

  void permissive(rust::Slice<rust::Str const> types) noexcept;
  void enforce(rust::Slice<rust::Str const> types) noexcept;
  void typeattribute(rust::Slice<rust::Str const> ty,
                     rust::Slice<rust::Str const> attrs) noexcept;
  void type(rust::Str ty, rust::Slice<rust::Str const> attrs) noexcept;
  void attribute(rust::Str name) noexcept;

  void type_transition(rust::Str src, rust::Str tgt, rust::Str cls,
                       rust::Str dest, rust::Str obj) noexcept;
  void type_change(rust::Str src, rust::Str tgt, rust::Str cls,
                   rust::Str dest) noexcept;
  void type_member(rust::Str src, rust::Str tgt, rust::Str cls,
                   rust::Str dest) noexcept;
  void genfscon(rust::Str fs, rust::Str path, rust::Str context) noexcept;

  // Names borrowed from the policydb; empty if the value has no name.
  rust::Slice<const uint8_t> type_name_bytes(uint32_t value) const noexcept;
  rust::Slice<const uint8_t> class_name_bytes(uint32_t value) const noexcept;
  rust::Slice<const uint8_t> perm_name_bytes(uint32_t class_value,
                                             uint32_t bit) const noexcept;

  // Bulk extraction of rule records, with names left as values.
  void attribute_entries(rust::Vec<uint32_t> &out) const noexcept;
  void type_entries(rust::Vec<TypeEntry> &out,
                    rust::Vec<uint32_t> &attrs) const noexcept;
  void avtab_entries(rust::Vec<AvtabEntry> &out,
                     rust::Vec<XpermEntry> &xperms) const noexcept;
  void filename_trans_entries(rust::Vec<FilenameTransEntry> &out) const noexcept;
  void genfs_entries(rust::Vec<GenfsEntry> &out) const noexcept;

  bool write(rust::Str path) const noexcept;
};

std::unique_ptr<SePolicyImpl> from_file_impl(rust::Str path) noexcept;
std::unique_ptr<SePolicyImpl> from_split_impl() noexcept;
std::unique_ptr<SePolicyImpl> compile_split_impl() noexcept;
std::unique_ptr<SePolicyImpl>
from_data_impl(rust::Slice<const uint8_t> data) noexcept;


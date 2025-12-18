#pragma once

#include <optional>
#include <rust/cxx.h>
#include <memory>

#include <sepol/policydb/policydb.h>
#include <string>
#include <unordered_map>

// libsepol internal APIs
__BEGIN_DECLS
int context_from_string(
        sepol_handle_t * handle,
        const policydb_t * policydb,
        context_struct_t ** cptr,
        const char *con_str, size_t con_str_len);
int context_to_string(
        sepol_handle_t * handle,
        const policydb_t * policydb,
        const context_struct_t * context,
        char **result, size_t * result_len);
__END_DECLS

class SePolicyImpl {
    policydb *db;
    mutable std::unordered_map<uint32_t, std::vector<const char *>> class_perm_cache;

    std::optional<std::string> type_name(uint32_t v) const;
    std::optional<std::string> class_name(uint32_t v) const;
    type_datum_t * type_datum(uint32_t v) const;
    class_datum_t * class_datum(uint32_t v) const;

    void emit_av_rule(const avtab_ptr_t node, rust::Vec<rust::String> &out) const;
    void emit_type_rule(const avtab_ptr_t node, rust::Vec<rust::String> &out) const;
    void emit_xperm_rule(const avtab_ptr_t node, rust::Vec<rust::String> &out) const;

public:
    explicit SePolicyImpl(policydb *db) : db(db) {}
    ~SePolicyImpl();

    rust::Vec<rust::String> attributes() const;
    rust::Vec<rust::String> types() const;
    rust::Vec<rust::String> avtabs() const;
    rust::Vec<rust::String> type_transitions() const;
    rust::Vec<rust::String> genfs_ctx() const;
};

std::unique_ptr<SePolicyImpl> from_file_impl(rust::Str path) noexcept;
rust::Vec<rust::String> attributes_impl(const SePolicyImpl &impl) noexcept;
rust::Vec<rust::String> types_impl(const SePolicyImpl &impl) noexcept;
rust::Vec<rust::String> avtabs_impl(const SePolicyImpl &impl) noexcept;
rust::Vec<rust::String> type_transitions_impl(const SePolicyImpl &impl) noexcept;
rust::Vec<rust::String> genfs_ctx_impl(const SePolicyImpl &impl) noexcept;


static auto specified_to_name = [](uint32_t spec) -> std::optional<std::string> {
    switch (spec) {
        case AVTAB_ALLOWED:              return "allow";
        case AVTAB_AUDITALLOW:           return "auditallow";
        case AVTAB_AUDITDENY:            return "dontaudit";
        case AVTAB_TRANSITION:           return "type_transition";
        case AVTAB_MEMBER:               return "type_member";
        case AVTAB_CHANGE:               return "type_change";
        case AVTAB_XPERMS_ALLOWED:       return "allowxperm";
        case AVTAB_XPERMS_AUDITALLOW:    return "auditallowxperm";
        case AVTAB_XPERMS_DONTAUDIT:     return "dontauditxperm";
        default:                         return std::nullopt;
    }
};

// Helper templates to iterate over lists and hashtables
template <typename Node, typename F>
static void for_each_list(Node *node_ptr, const F &fn) {
    for (; node_ptr; node_ptr = node_ptr->next) {
        fn(node_ptr);
    }
}

template <typename Node, typename F>
static void for_each_hash(Node **node_ptr, int n_slot, const F &fn) {
    for (int i = 0; i < n_slot; ++i) {
        for_each_list(node_ptr[i], fn);
    }
}

template <typename F>
static void for_each_hashtab(hashtab_t htab, const F &fn) {
    for_each_hash(htab->htable, htab->size, fn);
}

template <typename F>
static void for_each_avtab(avtab_t *avtab, const F &fn) {
    for_each_hash(avtab->htable, avtab->nslot, fn);
}

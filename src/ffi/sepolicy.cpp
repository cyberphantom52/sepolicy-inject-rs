#include "file.hpp"
#include "sepolicy.hpp"
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/ebitmap.h>
#include <sstream>
#include "rust/cxx.h"
#include "sepolicy-inject-rs/src/ffi/mod.rs.h"

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
    if (v < 1 || v > db->p_types.nprim) return std::nullopt;
    const char *name = db->p_type_val_to_name[v - 1];
    return name ? std::optional(name) : std::nullopt;
}

std::optional<std::string> SePolicyImpl::class_name(uint32_t v) const {
    // v is a 1-based SELinux class value (0 is invalid).
    // class names are stored in a 0-based array indexed by (v - 1),
    // with valid values in the range [1, p_classes.nprim].
    if (v < 1 || v > db->p_classes.nprim) return std::nullopt;
    const char *name = db->p_class_val_to_name[v - 1];
    return name ? std::optional(name) : std::nullopt;
}

type_datum_t * SePolicyImpl::type_datum(uint32_t v) const {
    // v is a 1-based SELinux type value.
    // type_val_to_struct is a 0-based array indexed by (v - 1);
    // values outside [1, p_types.nprim] would be out-of-bounds.
    if (v < 1 || v > db->p_types.nprim) return nullptr;
    return db->type_val_to_struct[v - 1];
}

class_datum_t * SePolicyImpl::class_datum(uint32_t v) const {
    // v is a 1-based SELinux class value.
    // class_val_to_struct is a 0-based array indexed by (v - 1);
    // values outside [1, p_classes.nprim] would be out-of-bounds.
    if (v < 1 || v > db->p_classes.nprim) return nullptr;
    return db->class_val_to_struct[v - 1];
}

std::unique_ptr<SePolicyImpl> from_file_impl(rust::Str file) noexcept {
    std::string path = to_string(file);

    policy_file policy_file;
    policy_file_init(&policy_file);
    auto file_opt = open_file(path.c_str(), "r");
    if (!file_opt)  return nullptr;

    policy_file.fp = file_opt->get();
    policy_file.type = PF_USE_STDIO;

    policydb *db = static_cast<policydb *>(malloc(sizeof(policydb_t)));
    if (policydb_init(db) || policydb_read(db, &policy_file, 0)) {
        free(db);
        return nullptr;
    }

    return std::make_unique<SePolicyImpl>(db);
}

rust::Vec<rust::String> SePolicyImpl::attributes() const {
    rust::Vec<rust::String> out;

    for_each_hashtab(db->p_types.table, [&](hashtab_ptr_t node) {
        auto type = static_cast<type_datum_t *>(node->datum);
        if (type->flavor != TYPE_ATTRIB) return;

        if (auto name = this->type_name(type->s.value)) {
            out.push_back(rust::String(std::string("attribute ") + *name));
        }
    });

    return out;
}

rust::Vec<rust::String> SePolicyImpl::types() const {
    rust::Vec<rust::String> out;

    for_each_hashtab(db->p_types.table, [&](hashtab_ptr_t node) {
        auto type = static_cast<type_datum_t *>(node->datum);
        if (!type || type->flavor != TYPE_TYPE) return;

        auto name = this->type_name(type->s.value);
        if (!name) return;

        ebitmap_t *bitmap = &db->type_attr_map[type->s.value - 1];

        bool first = true;
        std::ostringstream stream;

        ebitmap_node_t *n; uint32_t bit;
        ebitmap_for_each_positive_bit(bitmap, n, bit) {
            uint32_t type_val = bit + 1;

            auto attr_type = this->type_datum(type_val);
            if (!attr_type || attr_type->flavor != TYPE_ATTRIB) continue;

            if (auto attr = type_name(type_val)) {
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
        if (ebitmap_get_bit(&db->permissive_map, type->s.value)) {
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
    if (!source || !target || !class_) return;

    auto rule = specified_to_name(node->key.specified);
    if (!rule) return;

    uint32_t data = node->key.specified == AVTAB_AUDITDENY ? ~(node->datum.data)
                                                            : node->datum.data;

    auto clz = this->class_datum(class_val);
    if (clz == nullptr) return;

    auto [it, inserted] = this->class_perm_cache.try_emplace(class_val);
    if (inserted) {
        size_t size = class_perm_vec_size(clz);
        auto &vec = it->second;
        vec.assign(size, nullptr);

        auto collect = [&](hashtab_t tab) {
            for_each_hashtab(tab, [&](hashtab_ptr_t pnode) {
                auto perm = static_cast<perm_datum *>(pnode->datum);
                if (!perm) return;

                size_t idx = perm->s.value - 1;
                if (idx < vec.size()) vec[idx] = pnode->key;
            });
        };

        collect(clz->permissions.table);
        if (clz->comdatum) collect(clz->comdatum->permissions.table);
    }

    std::ostringstream ss;
    bool first = true;
    while (data) {
        uint32_t bit = __builtin_ctz(data);
        data &= data - 1;

        if (bit >= it->second.size()) continue;

        const char *perm = it->second[bit];
        if (!perm) continue;

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
    if (!source || !target || !class_) return;

    auto rule = specified_to_name(node->key.specified);
    if (!rule) return;

    auto def = this->type_name(node->datum.data);
    if (!def) return;

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
    if (!source || !target || !class_) return;

    auto rule = specified_to_name(node->key.specified);
    if (!rule) return;

    avtab_extended_perms_t *xperms = node->datum.xperms;
    if (!xperms) return;

    std::vector<std::pair<uint8_t, uint8_t>> ranges;
    int low = -1;

    for (int i = 0; i < 256; ++i) {
        if (xperm_test(i, xperms->perms)) {
            if (low < 0) low = i;
            if (i == 255) ranges.emplace_back(low, 255);
        } else if (low >= 0) {
            ranges.emplace_back(low, i - 1);
            low = -1;
        }
    }

    if (ranges.empty()) return;

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
        if (lo != hi) ss << "-0x" << hi;
    }

    ss << " }";
    out.push_back(rust::String(ss.str()));
}

rust::Vec<rust::String> SePolicyImpl::avtabs() const {
    rust::Vec<rust::String> out;

    for_each_avtab(&db->te_avtab, [&](avtab_ptr_t node) {
        if (node->key.specified & AVTAB_AV) {
            this->emit_av_rule(node, out);
        } else if (node->key.specified & AVTAB_TYPE) {
            this->emit_type_rule(node, out);
        } else if (node->key.specified & AVTAB_XPERMS) {
            this->emit_xperm_rule(node, out);
        }
    });

    return out;
}

rust::Vec<rust::String> SePolicyImpl::type_transitions() const {
    rust::Vec<rust::String> out;

    for_each_hashtab(db->filename_trans, [&](hashtab_ptr_t node) {
        auto key = reinterpret_cast<filename_trans_key_t *>(node->key);
        auto trans = static_cast<filename_trans_datum *>(node->datum);

        auto target = this->type_name(key->ttype);
        auto class_ = this->class_name(key->tclass);
        auto def = this->type_name(trans->otype);
        if (!target || !class_ || !def || key->name == nullptr) return;

        ebitmap_node_t *n; uint32_t bit;
        ebitmap_for_each_positive_bit(&trans->stypes, n, bit) {
            uint32_t src_val = bit + 1;

            if (auto src = this->type_name(src_val)) {
                std::ostringstream stream;
                stream << "type_transition " << src.value() << " " << target.value() << " " << class_.value() << " " << def.value() << " " << key->name;
                out.push_back(rust::String(stream.str()));
            }
        }
    });

    return out;
}

rust::Vec<rust::String> SePolicyImpl::genfs_ctx() const {
    rust::Vec<rust::String> out;

    for_each_list(db->genfs, [&](genfs_t *genfs) {
        for_each_list(genfs->head, [&](ocontext *context) {
            char *raw_ptr = nullptr;
            size_t len = 0;
            if (context_to_string(nullptr, db, &context->context[0], &raw_ptr, &len) == 0) {
                std::unique_ptr<char, decltype(&free)> ctx(raw_ptr, &free);
                std::ostringstream stream;
                stream << "genfscon " << genfs->fstype << " " << context->u.name << " " << ctx.get();
                out.push_back(rust::String(stream.str()));
            }
        });
    });

    return out;
}

rust::Vec<rust::String> attributes_impl(const SePolicyImpl &impl) noexcept {
    return impl.attributes();
}

rust::Vec<rust::String> types_impl(const SePolicyImpl &impl) noexcept {
    return impl.types();
}

rust::Vec<rust::String> avtabs_impl(const SePolicyImpl &impl) noexcept {
    return impl.avtabs();
}

rust::Vec<rust::String> type_transitions_impl(const SePolicyImpl &impl) noexcept {
    return impl.type_transitions();
}

rust::Vec<rust::String> genfs_ctx_impl(const SePolicyImpl &impl) noexcept {
    return impl.genfs_ctx();
}

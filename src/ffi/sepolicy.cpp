#include "file.hpp"
#include "sepolicy.hpp"
#include <sepol/policydb/policydb.h>
#include <sstream>
#include <unordered_map>
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
    if (!v) return std::nullopt;
    const char *name = db->p_type_val_to_name[v - 1];
    return name ? std::optional(name) : std::nullopt;
}

std::optional<std::string> SePolicyImpl::class_name(uint32_t v) const {
    if (!v) return std::nullopt;
    const char *name = db->p_class_val_to_name[v - 1];
    return name ? std::optional(name) : std::nullopt;
}

std::unique_ptr<SePolicyImpl> from_file_impl(rust::Str file) noexcept {
    std::string path = to_string(file);

    policy_file policy_file;
    policy_file_init(&policy_file);
    auto file_opt = open_file(path.c_str(), "r");
    if (!file_opt) {
        return nullptr;
    }

    unique_file file_ptr = std::move(*file_opt);
    policy_file.fp = file_ptr.get();
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
        auto type = static_cast<type_datum *>(node->datum);
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
        auto type = static_cast<type_datum *>(node->datum);
        if (type->flavor != TYPE_TYPE) return;

        auto name = this->type_name(type->s.value);
        if (!name) return;

        bool first = true;
        std::ostringstream stream;
        ebitmap_t *bitmap = &db->type_attr_map[type->s.value - 1];

        for (uint32_t i = 0; i <= bitmap->highbit; ++i) {
            if (!ebitmap_get_bit(bitmap, i)) continue;

            auto attr_type = db->type_val_to_struct[i];
            if (!attr_type || attr_type->flavor != TYPE_ATTRIB) continue;

            if (auto attr = this->type_name(i + 1)) {
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

rust::Vec<rust::String> SePolicyImpl::avtabs() const {
    rust::Vec<rust::String> out;

    std::unordered_map<std::string, std::vector<const char*>> class_perm_names;


    auto specified_to_name = [](uint32_t spec) -> std::optional<std::string> {
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

    for_each_avtab(&db->te_avtab, [&](avtab_ptr_t node) {
        auto source = this->type_name(node->key.source_type);
        auto target = this->type_name(node->key.target_type);
        auto class_ = this->type_name(node->key.target_class);
        if (!source || !target  || !class_) return;
        const std::string &class_name = class_.value();

        source = std::move(*source);

        auto name = specified_to_name(node->key.specified);
        if (!name) return;

        std::ostringstream ss;

        if (node->key.specified & AVTAB_AV) {
            uint32_t data = node->key.specified == AVTAB_AUDITDENY
                                ? ~(node->datum.data)
                                : node->datum.data;

            class_datum_t *clz = db->class_val_to_struct[node->key.target_class - 1];
            if (clz == nullptr) return;

            auto [it, inserted] = class_perm_names.try_emplace(class_name);

            if (inserted) {
                auto &vec = it->second;
                vec.assign(32, nullptr);

                auto collect = [&](hashtab_t tab) {
                    for_each_hashtab(tab, [&](hashtab_ptr_t pnode) {
                        auto perm = static_cast<perm_datum *>(pnode->datum);
                        if (!perm) return;
                        size_t idx = perm->s.value - 1;
                        if (idx < vec.size()) vec[idx] = pnode->key;
                    });
                };

                collect(clz->permissions.table);
                if (clz->comdatum)
                    collect(clz->comdatum->permissions.table);
            }

            bool first = true;
            for (int i = 0; i < 32; ++i) {
                if (!(data & (1u << i))) continue;

                const char *perm = it->second[i];
                if (!perm) continue;

                if (first) {
                    ss << name.value() << " " << source.value() << " " << target.value() << " " << class_name << " {";
                    first = false;
                }
                ss << " " << perm;
            }

            if (!first) {
                ss << " }";
                out.push_back(rust::String(ss.str()));
            }

            return;
        }

        if (node->key.specified & AVTAB_TYPE) {
            if (auto def = type_name(node->datum.data)) {
                ss << name.value() << " " << source.value() << " " << target.value() << " " << class_name << " " << def.value();
                out.push_back(rust::String(ss.str()));
            }
            return;
        }

        if (node->key.specified & AVTAB_XPERMS) {
            avtab_extended_perms_t *xperms = node->datum.xperms;
            if (xperms == nullptr) return;

            // build ranges
            std::vector<std::pair<uint8_t,uint8_t>> ranges;
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

            ss << name.value() << " " << source.value() << " " << target.value() << " " << class_name << " ioctl {";
            for (auto &p : ranges) {
                uint16_t lo = encode(p.first);
                uint16_t hi = encode(p.second);

                ss << " 0x" << std::hex << std::uppercase << lo;
                if (lo != hi) ss << "-0x" << hi;
            }

            ss << " }";
            out.push_back(rust::String(ss.str()));
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

        for (uint32_t i = 0; i <= trans->stypes.highbit; ++i) {
            if (!ebitmap_get_bit(&trans->stypes, i))  continue;

            if (auto src = this->type_name(i + 1)) {
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
            char *ctx = nullptr;
            size_t len = 0;
            if (context_to_string(nullptr, db, &context->context[0], &ctx, &len) == 0) {
                std::ostringstream stream;
                stream << "genfscon " << genfs->fstype << " " << context->u.name << " " << ctx;
                out.push_back(rust::String(stream.str()));
                free(ctx);
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

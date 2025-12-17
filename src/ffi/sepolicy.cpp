#include "file.hpp"
#include "sepolicy.hpp"
#include <sepol/policydb/policydb.h>
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
        type_datum *type = static_cast<type_datum *>(node->datum);
        if (type->flavor == TYPE_ATTRIB) {
            const char *name = db->p_type_val_to_name[type->s.value - 1];
            if (name) {
                out.push_back(rust::String(std::string("attribute ") + name));
            }
        }
    });

    return out;
}

rust::Vec<rust::String> SePolicyImpl::types() const {
    rust::Vec<rust::String> out;
    for_each_hashtab(db->p_types.table, [&](hashtab_ptr_t node) {
        type_datum *type = static_cast<type_datum *>(node->datum);
        if (type->flavor == TYPE_TYPE) {
            const char *name = db->p_type_val_to_name[type->s.value - 1];
            if (name == nullptr) return;

            bool first = true;
            ebitmap_t *bitmap = &db->type_attr_map[type->s.value - 1];
            std::ostringstream stream;
            for (uint32_t i = 0; i <= bitmap->highbit; ++i) {
                if (ebitmap_get_bit(bitmap, i)) {
                    auto attr_type = db->type_val_to_struct[i];
                    if (attr_type && attr_type->flavor == TYPE_ATTRIB) {
                        if (const char *attr = db->p_type_val_to_name[i]) {
                            if (first) {
                                stream << "type " << name << " {";
                                first = false;
                            }
                            stream << " " << attr;
                        }
                    }
                }
            }
            if (!first) {
                stream << " }";
                out.push_back(rust::String(stream.str()));
            }

            // permissive
            if (ebitmap_get_bit(&db->permissive_map, type->s.value)) {
                out.push_back(rust::String(std::string("permissive ") + name));
            }
        }
    });

    return out;
}

rust::Vec<rust::String> SePolicyImpl::type_transitions() const {
    rust::Vec<rust::String> out;

    for_each_hashtab(db->filename_trans, [&](hashtab_ptr_t node) {
        auto key = reinterpret_cast<filename_trans_key_t *>(node->key);
        filename_trans_datum *trans = static_cast<filename_trans_datum *>(node->datum);

        const char *target = db->p_type_val_to_name[key->ttype - 1];
        const char *class_ = db->p_class_val_to_name[key->tclass - 1];
        const char *def = db->p_type_val_to_name[trans->otype - 1];
        if (target == nullptr || class_ == nullptr || def == nullptr || key->name == nullptr)
            return;

        for (uint32_t i = 0; i <= trans->stypes.highbit; ++i) {
            if (ebitmap_get_bit(&trans->stypes, i)) {
                if (const char *src = db->p_type_val_to_name[i]) {
                    std::ostringstream stream;
                    stream << "type_transition " << src << " " << target << " " << class_ << " " << def << " " << key->name;
                    out.push_back(rust::String(stream.str()));
                }
            }
        }
    });

    return out;
}

rust::Vec<rust::String> SePolicyImpl::genfs_ctx() const {
    rust::Vec<rust::String> out;
    auto push = [&](const std::string &s) {
        out.push_back(rust::String(s));
    };

    for_each_list(db->genfs, [this,&push](genfs_t *genfs) {
        for_each_list(genfs->head, [&](ocontext *context) {
            char *ctx = nullptr;
            size_t len = 0;
            if (context_to_string(nullptr, db, &context->context[0], &ctx, &len) == 0) {
                std::ostringstream stream;
                stream << "genfscon " << genfs->fstype << " " << context->u.name << " " << ctx;
                push(stream.str());
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

rust::Vec<rust::String> type_transitions_impl(const SePolicyImpl &impl) noexcept {
    return impl.type_transitions();
}

rust::Vec<rust::String> genfs_ctx_impl(const SePolicyImpl &impl) noexcept {
    return impl.genfs_ctx();
}

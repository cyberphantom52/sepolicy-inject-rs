#include "file.hpp"
#include "sepolicy.hpp"
#include <sepol/policydb/policydb.h>
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

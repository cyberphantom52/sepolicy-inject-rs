#pragma once

#include <rust/cxx.h>
#include <memory>

#include <sepol/policydb/policydb.h>

class SePolicyImpl {
    policydb *db;

public:
    explicit SePolicyImpl(policydb *db) : db(db) {}
    ~SePolicyImpl();
};

std::unique_ptr<SePolicyImpl> from_file_impl(rust::Str path) noexcept;

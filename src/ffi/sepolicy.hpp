#pragma once

#include <rust/cxx.h>
#include <memory>

class SePolicyImpl {};

std::unique_ptr<SePolicyImpl> from_file_impl(rust::Str path) noexcept;

#pragma once

#include <cstdio>
#include <memory>
#include <optional>

struct file_deleter {
    void operator()(std::FILE *fp) const noexcept {
        if (fp) std::fclose(fp);
    }
};

using unique_file = std::unique_ptr<std::FILE, file_deleter>;

inline std::optional<unique_file> open_file(const char *path, const char *mode) {
    if (std::FILE *fp = std::fopen(path, mode)) {
        return unique_file(fp);
    }
    return std::nullopt;
}

#pragma once

#include <sepol/policydb/avtab.h>
#include <sepol/policydb/hashtab.h>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <fcntl.h>
#include <unistd.h>
#include "sepolicy.hpp"

#define ALLOW_MOVE_ONLY(clazz)                                                 \
  clazz(const clazz &) = delete;                                               \
  clazz(clazz &&o) : clazz() { swap(o); }                                      \
  clazz &operator=(clazz &&o) {                                                \
    swap(o);                                                                   \
    return *this;                                                              \
  }

#define SHALEN 64
static bool read_exact(const char *path, char *buf, size_t len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;

    ssize_t total = 0;
    while (total < (ssize_t)len) {
        ssize_t r = read(fd, buf + total, len - total);
        if (r <= 0) {
        close(fd);
        return false;
        }
        total += r;
    }

    close(fd);
    return true;
}

static bool cmp_sha256(const char *a, const char *b) {
    char id_a[SHALEN] = {0};
    char id_b[SHALEN] = {0};

    if (!read_exact(a, id_a, SHALEN))
        return false;

    if (!read_exact(b, id_b, SHALEN))
        return false;

    return memcmp(id_a, id_b, SHALEN) == 0;
}

inline bool check_precompiled(const char *precompiled) {
    bool ok = false;
    const char *actual_sha;
    char compiled_sha[128];

    actual_sha = PLAT_POLICY_DIR "plat_and_mapping_sepolicy.cil.sha256";
    if (access(actual_sha, R_OK) == 0) {
        ok = true;
        sprintf(compiled_sha, "%s.plat_and_mapping.sha256", precompiled);
        if (!cmp_sha256(actual_sha, compiled_sha))
        return false;
    }

    actual_sha = PLAT_POLICY_DIR "plat_sepolicy_and_mapping.sha256";
    if (access(actual_sha, R_OK) == 0) {
        ok = true;
        sprintf(compiled_sha, "%s.plat_sepolicy_and_mapping.sha256", precompiled);
        if (!cmp_sha256(actual_sha, compiled_sha))
        return false;
    }

    actual_sha = PROD_POLICY_DIR "product_sepolicy_and_mapping.sha256";
    if (access(actual_sha, R_OK) == 0) {
        ok = true;
        sprintf(compiled_sha, "%s.product_sepolicy_and_mapping.sha256", precompiled);
        if (!cmp_sha256(actual_sha, compiled_sha))
        return false;
    }

    actual_sha = SYSEXT_POLICY_DIR "system_ext_sepolicy_and_mapping.sha256";
    if (access(actual_sha, R_OK) == 0) {
        ok = true;
        sprintf(compiled_sha, "%s.system_ext_sepolicy_and_mapping.sha256", precompiled);
        if (!cmp_sha256(actual_sha, compiled_sha))
        return false;
    }

    return ok;
}

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

template <typename F> static void for_each_avtab(avtab_t *avtab, const F &fn) {
  for_each_hash(avtab->htable, avtab->nslot, fn);
}

template <typename T>
static T *hashtab_find(hashtab_t h, rust::Str key) {
  std::string s(key.data(), key.size());
  return static_cast<T *>(hashtab_search(h, s.c_str()));
}

inline char *dup_str(rust::Str src) {
  size_t len = src.size();
  char *s = static_cast<char *>(malloc(len + 1));
  memcpy(s, src.data(), len);
  s[len] = '\0';
  return s;
}

inline bool str_eq(std::string_view a, rust::Str b) {
  return a.size() == b.size() && memcmp(a.data(), b.data(), a.size()) == 0;
}

template <class Node, class Func>
static Node *list_find(Node *node_ptr, const Func &fn) {
  for (auto cur = node_ptr; cur; cur = cur->next) {
    if (fn(cur))
      return cur;
  }
  return nullptr;
}

template <typename T, typename F>
static void for_each_rule(rust::Slice<rust::Str const> src,
                          rust::Slice<rust::Str const> tgt,
                          rust::Slice<rust::Str const> cls,
                          rust::Slice<T const> last, const F &fn) {
  for (auto s : src)
    for (auto t : tgt)
      for (auto c : cls)
        for (auto &x : last)
          fn(s, t, c, x);
}

//
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

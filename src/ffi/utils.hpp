#pragma once

#include <sepol/policydb/avtab.h>
#include <sepol/policydb/hashtab.h>
#include <cstdio>
#include <memory>
#include <optional>

#define ALLOW_MOVE_ONLY(clazz)                                                 \
  clazz(const clazz &) = delete;                                               \
  clazz(clazz &&o) : clazz() { swap(o); }                                      \
  clazz &operator=(clazz &&o) {                                                \
    swap(o);                                                                   \
    return *this;                                                              \
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

//
template <class Func> class run_finally {
  run_finally(const run_finally &) = delete;
  run_finally &operator=(const run_finally &) = delete;

public:
  explicit run_finally(Func &&fn) : fn(std::move(fn)) {}
  ~run_finally() { fn(); }

private:
  Func fn;
};

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

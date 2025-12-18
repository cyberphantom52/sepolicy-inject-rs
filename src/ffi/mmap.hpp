#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <rust/cxx.h>

#define ALLOW_MOVE_ONLY(clazz) \
clazz(const clazz&) = delete;  \
clazz(clazz &&o) : clazz() { swap(o); }  \
clazz& operator=(clazz &&o) { swap(o); return *this; }

using ByteSlice = rust::Slice<const uint8_t>;
using MutByteSlice = rust::Slice<uint8_t>;

// Interchangeable as `&[u8]` in Rust
struct byte_view {
    byte_view() : _buf(nullptr), _sz(0) {}
    byte_view(const void *buf, size_t sz) : _buf((uint8_t *) buf), _sz(sz) {}

    // byte_view, or any of its subclasses, can be copied as byte_view
    byte_view(const byte_view &o) : _buf(o._buf), _sz(o._sz) {}

    // Transparent conversion to Rust slice
    byte_view(const ByteSlice o) : byte_view(o.data(), o.size()) {}
    operator ByteSlice() const { return {_buf, _sz}; }

    // String as bytes, including null terminator
    byte_view(const char *s) : byte_view(s, strlen(s) + 1) {}

    const uint8_t *data() const { return _buf; }
    size_t size() const { return _sz; }
    bool contains(byte_view pattern) const;
    bool operator==(byte_view rhs) const;

protected:
    uint8_t *_buf;
    size_t _sz;
};

// Interchangeable as `&mut [u8]` in Rust
struct byte_data : public byte_view {
    byte_data() = default;
    byte_data(void *buf, size_t sz) : byte_view(buf, sz) {}

    // byte_data, or any of its subclasses, can be copied as byte_data
    byte_data(const byte_data &o) : byte_data(o._buf, o._sz) {}

    // Transparent conversion to Rust slice
    byte_data(const MutByteSlice o) : byte_data(o.data(), o.size()) {}
    operator MutByteSlice() const { return {_buf, _sz}; }

    using byte_view::data;
    uint8_t *data() const { return _buf; }

    void swap(byte_data &o);
    rust::Vec<size_t> patch(byte_view from, byte_view to) const;
};

struct mmap_data : public byte_data {
    ALLOW_MOVE_ONLY(mmap_data)

    mmap_data() = default;
    explicit mmap_data(const char *name, bool rw = false);
    mmap_data(int dirfd, const char *name, bool rw = false);
    mmap_data(int fd, size_t sz, bool rw = false);
    ~mmap_data();

private:
    void map(int fd, size_t sz, int prot);
};

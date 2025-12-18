#include "mmap.hpp"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>


void mmap_data::map(int fd, size_t sz, int prot){
    void *p = mmap(nullptr, sz, prot, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED)
        throw std::runtime_error("mmap failed");

    _buf = static_cast<uint8_t *>(p);
    _sz  = sz;
}

mmap_data::mmap_data(const char *name, bool rw) {
        int flags = rw ? O_RDWR : O_RDONLY;
        int prot  = rw ? (PROT_READ | PROT_WRITE) : PROT_READ;

        int fd = open(name, flags | O_CLOEXEC);
        if (fd < 0)
            throw std::runtime_error(std::string("open failed: ") + strerror(errno));

        struct stat st {};
        if (fstat(fd, &st) < 0) {
            close(fd);
            throw std::runtime_error("fstat failed");
        }

        map(fd, st.st_size, prot);
        close(fd);
    }

mmap_data::mmap_data(int dirfd, const char *name, bool rw) {
        int flags = rw ? O_RDWR : O_RDONLY;
        int prot  = rw ? (PROT_READ | PROT_WRITE) : PROT_READ;

        int fd = openat(dirfd, name, flags | O_CLOEXEC);
        if (fd < 0)
            throw std::runtime_error("openat failed");

        struct stat st {};
        if (fstat(fd, &st) < 0) {
            close(fd);
            throw std::runtime_error("fstat failed");
        }

        map(fd, st.st_size, prot);
        close(fd);
    }

mmap_data::mmap_data(int fd, size_t sz, bool rw) {
    int prot = rw ? (PROT_READ | PROT_WRITE) : PROT_READ;
    map(fd, sz, prot);
}

mmap_data::~mmap_data() {
    if (_buf)
        munmap(_buf, _sz);
}

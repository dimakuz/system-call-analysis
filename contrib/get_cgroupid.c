#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>

struct handle{
    unsigned int handle_bytes;
    int handle_type;
    uint64_t cgid;
};

uint64_t resolve_cgroupid(const char *path) {
    struct handle handle;
    int mount_id;
    int err = name_to_handle_at(AT_FDCWD, path, &handle, &mount_id, 0);
    return handle.cgid;
}

int main(int argc, char **argv) {
    uint64_t res = resolve_cgroupid(argv[1]);
    printf("%lld\n", res);
    return 0;
}

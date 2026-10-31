/* Gunyah VM probe 3 — close stdin first to get fd=0 as vcpu, check fd count,
   and probe alternative vcpu run methods */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <dirent.h>

#define GH_IOCTL_TYPE 'G'
#define GH_CREATE_VM  _IO(GH_IOCTL_TYPE, 0x0)

struct gh_userspace_memory_region {
    uint32_t label; uint32_t flags;
    uint64_t guest_phys_addr; uint64_t memory_size; uint64_t userspace_addr;
};
struct gh_fn_vcpu_init { uint32_t vcpu_id; };
struct gh_fn_desc { uint32_t type; uint32_t arg_size; uint64_t arg; };
#define GH_VM_SET_USER_MEM_REGION  _IOW(GH_IOCTL_TYPE, 0x1, struct gh_userspace_memory_region)
#define GH_VM_ADD_FUNCTION         _IOW(GH_IOCTL_TYPE, 0x2, struct gh_fn_desc)
#define GH_VCPU_RUN                _IO(GH_IOCTL_TYPE, 0x5)
#define GH_VCPU_MMAP_SIZE          _IO(GH_IOCTL_TYPE, 0x6)
#define GH_FN_VCPU 1

/* Qualcomm might use different vcpu run ioctl numbers - probe all */
#define GH_VCPU_RUN_A   _IO(GH_IOCTL_TYPE, 0x4)
#define GH_VCPU_RUN_B   _IO(GH_IOCTL_TYPE, 0x5)
#define GH_VCPU_RUN_C   _IO(GH_IOCTL_TYPE, 0x6)
#define GH_VCPU_RUN_D   _IO(GH_IOCTL_TYPE, 0x7)

static void list_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return;
    struct dirent *e;
    printf("Open fds: ");
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char lpath[64], target[256];
        snprintf(lpath, sizeof(lpath), "/proc/self/fd/%s", e->d_name);
        ssize_t n = readlink(lpath, target, sizeof(target)-1);
        if (n > 0) { target[n] = 0; printf("%s->%s ", e->d_name, target); }
    }
    printf("\n");
    closedir(d);
}

int main(void) {
    int dev_fd, vm_fd, vcpu_fd;

    /* Close stdin so next allocation gets fd=0 */
    close(0);
    printf("=== Gunyah VM probe 3 ===\n");
    list_fds();

    dev_fd = open("/dev/gunyah", O_RDWR);
    printf("dev_fd=%d\n", dev_fd);

    errno = 0;
    vm_fd = ioctl(dev_fd, GH_CREATE_VM, 0);
    printf("vm_fd=%d errno=%d\n", vm_fd, errno);
    if (vm_fd < 0) return 1;

    /* Map 4 MB at guest PA 0x80000000 */
    void *mem = mmap(NULL, 0x400000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem != MAP_FAILED) {
        struct gh_userspace_memory_region r = {
            .label=1, .flags=0,
            .guest_phys_addr=0x80000000ULL,
            .memory_size=0x400000,
            .userspace_addr=(uint64_t)mem
        };
        errno = 0;
        int ret = ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &r);
        printf("SET_MEM_REGION: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
    }

    list_fds();

    /* Add vcpu - note what fds exist before and after */
    struct gh_fn_vcpu_init vi = { .vcpu_id=0 };
    struct gh_fn_desc fn = { .type=GH_FN_VCPU, .arg_size=sizeof(vi), .arg=(uint64_t)&vi };
    errno = 0;
    vcpu_fd = ioctl(vm_fd, GH_VM_ADD_FUNCTION, &fn);
    printf("ADD_FUNCTION VCPU: ret=%d errno=%d (%s)\n", vcpu_fd, errno, strerror(errno));
    list_fds();

    /* The vcpu might have been created as fd=0 since we closed stdin */
    printf("\nTesting fd=0 for vcpu ops:\n");
    for (int n = 4; n <= 10; n++) {
        unsigned long ioc = _IO(GH_IOCTL_TYPE, n);
        errno = 0;
        int r = ioctl(0, ioc, 0);
        printf("  fd=0 _IO('G',%d): ret=%d errno=%d (%s)\n", n, r, errno,
               errno==ENOTTY?"ENOTTY":strerror(errno));
    }

    /* Also test vm_fd directly for vcpu-like operations */
    printf("\nTesting vm_fd for vcpu-like ops:\n");
    for (int n = 4; n <= 10; n++) {
        unsigned long ioc = _IO(GH_IOCTL_TYPE, n);
        errno = 0;
        int r = ioctl(vm_fd, ioc, 0);
        printf("  vm_fd _IO('G',%d): ret=%d errno=%d (%s)\n", n, r, errno,
               errno==ENOTTY?"ENOTTY":strerror(errno));
    }

    /* Check dmesg for kernel messages */
    printf("\n=== dmesg tail ===\n");
    system("dmesg | tail -15");

    close(vm_fd);
    close(dev_fd);
    return 0;
}

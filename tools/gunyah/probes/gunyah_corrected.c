/*
 * Corrected Gunyah probe using Android 16 UAPI numbering:
 *   GUNYAH_CREATE_VM        = _IO('G', 0x0)   -- returns vm_fd
 *   GH_VM_SET_USER_MEM_REGION= _IOW('G',0x1,...)
 *   GUNYAH_VM_SET_DTB_CONFIG = _IOW('G',0x2,...)  [WAS MISUSED AS ADD_FUNCTION]
 *   GUNYAH_VM_START          = _IO('G', 0x3)
 *   GUNYAH_VM_ADD_FUNCTION   = _IOW('G',0x4,...)  [CORRECT ioctl for vCPUs]
 *   GUNYAH_VCPU_RUN          = _IO('G', 0x5)   -- on vCPU fd
 *   GUNYAH_VCPU_MMAP_SIZE    = _IO('G', 0x6)   -- on vCPU fd
 *   GUNYAH_VM_REMOVE_FUNCTION= _IOW('G',0x7,...)
 *   GUNYAH_VM_SET_BOOT_CONTEXT=_IOW('G',0xa,...)
 *   GH_VM_ANDROID_LEND_USER_MEM=_IOW('A',0x11,...) -- for protected VMs
 *   GH_VM_ANDROID_SET_FW_CONFIG=_IOW('A',0x12,...) -- firmware config
 *   GH_VM_ANDROID_SET_AUTH_TYPE=_IOW('A',0x16,...) -- QTVM auth
 *
 * Previous probes INCORRECTLY used _IOW('G', 0x2, ...) for ADD_FUNCTION.
 * 0x2 is actually GUNYAH_VM_SET_DTB_CONFIG. ADD_FUNCTION is 0x4.
 */
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

/* Gunyah UAPI (Android 16 / kernel 6.12 numbering) */
#define GUNYAH_IOCTL_TYPE   'G'
#define GH_ANDROID_IOCTL_TYPE 'A'

#define GUNYAH_CREATE_VM         _IO(GUNYAH_IOCTL_TYPE, 0x0)
#define GH_VM_SET_USER_MEM_REGION _IOW(GUNYAH_IOCTL_TYPE, 0x1, struct gunyah_userspace_memory_region)
#define GUNYAH_VM_SET_DTB_CONFIG  _IOW(GUNYAH_IOCTL_TYPE, 0x2, struct gunyah_vm_dtb_config)
#define GUNYAH_VM_START           _IO(GUNYAH_IOCTL_TYPE, 0x3)
#define GUNYAH_VM_ADD_FUNCTION    _IOW(GUNYAH_IOCTL_TYPE, 0x4, struct gunyah_fn_desc)
#define GUNYAH_VCPU_RUN           _IO(GUNYAH_IOCTL_TYPE, 0x5)
#define GUNYAH_VCPU_MMAP_SIZE     _IO(GUNYAH_IOCTL_TYPE, 0x6)
#define GUNYAH_VM_REMOVE_FUNCTION _IOW(GUNYAH_IOCTL_TYPE, 0x7, struct gunyah_fn_desc)
#define GUNYAH_VM_SET_BOOT_CONTEXT _IOW(GUNYAH_IOCTL_TYPE, 0xa, struct gunyah_vm_boot_context)

/* Android-specific ('A') ioctls for protected VMs */
#define GH_VM_ANDROID_LEND_USER_MEM _IOW(GH_ANDROID_IOCTL_TYPE, 0x11, struct gunyah_userspace_memory_region)
#define GH_VM_ANDROID_SET_FW_CONFIG  _IOW(GH_ANDROID_IOCTL_TYPE, 0x12, struct gunyah_vm_firmware_config)
#define GH_ANDROID_CREATE_CMA_MEM_FD _IO(GH_ANDROID_IOCTL_TYPE, 0x14)
#define GH_VM_ANDROID_SET_AUTH_TYPE  _IOW(GH_ANDROID_IOCTL_TYPE, 0x16, struct gunyah_auth_desc)

#define GUNYAH_FN_VCPU 1

struct gunyah_userspace_memory_region {
    uint32_t label;
    uint32_t flags;
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
};

struct gunyah_vm_dtb_config {
    uint64_t guest_phys_addr;
    uint64_t size;
};

struct gunyah_fn_vcpu_arg {
    uint32_t id;
    uint32_t padding;
};

struct gunyah_fn_desc {
    uint32_t type;
    uint32_t arg_size;
    uint64_t arg;  /* pointer to arg struct */
};

struct gunyah_vm_boot_context {
    uint32_t reg;
    uint32_t reserved;
    uint64_t value;
};

struct gunyah_vm_firmware_config {
    uint64_t guest_phys_addr;
    uint64_t size;
};

#define GUNYAH_VM_BOOT_CONTEXT_REG_SHIFT 8
#define GUNYAH_VM_BOOT_CONTEXT_REG(r, idx) (((r) << GUNYAH_VM_BOOT_CONTEXT_REG_SHIFT) | (idx))
#define REG_SET_X  0
#define REG_SET_PC 1

static void list_fds(const char *label) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return;
    struct dirent *e;
    printf("FDs[%s]:", label);
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char lpath[64], target[256] = {0};
        snprintf(lpath, sizeof(lpath), "/proc/self/fd/%s", e->d_name);
        readlink(lpath, target, sizeof(target)-1);
        if (strstr(target, "gunyah") || strstr(target, "anon"))
            printf(" fd%s->%s", e->d_name, target);
    }
    printf("\n");
    closedir(d);
}

int main(void) {
    printf("=== Corrected Gunyah probe (Android 16 UAPI) ===\n");
    printf("GUNYAH_VM_ADD_FUNCTION ioctl nr: 0x%lx\n",
           (unsigned long)GUNYAH_VM_ADD_FUNCTION);
    printf("GH_VM_ANDROID_LEND_USER_MEM ioctl nr: 0x%lx\n",
           (unsigned long)GH_VM_ANDROID_LEND_USER_MEM);

    system("dmesg -c > /dev/null 2>&1");

    int dev_fd = open("/dev/gunyah", O_RDWR);
    if (dev_fd < 0) { perror("open /dev/gunyah"); return 1; }
    printf("dev_fd=%d\n", dev_fd);

    /* Step 1: Create VM */
    errno = 0;
    int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
    printf("GUNYAH_CREATE_VM: vm_fd=%d errno=%d\n", vm_fd, errno);
    if (vm_fd < 0) { return 1; }
    list_fds("after_create");

    /* Step 2a: Try GH_VM_ANDROID_LEND_USER_MEM (protected path) */
    size_t mem_size = 64 * 1024 * 1024;
    void *mem = mmap(NULL, mem_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    printf("mmap: %p\n", mem);

    struct gunyah_userspace_memory_region mr = {
        .label = 1,
        .flags = 0x7,  /* ALLOW_READ|ALLOW_WRITE|ALLOW_EXEC */
        .guest_phys_addr = 0x80000000ULL,
        .memory_size = mem_size,
        .userspace_addr = (uint64_t)mem
    };

    errno = 0;
    int ret = ioctl(vm_fd, GH_VM_ANDROID_LEND_USER_MEM, &mr);
    printf("GH_VM_ANDROID_LEND_USER_MEM: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret != 0) {
        printf("  Lend failed — trying GH_VM_SET_USER_MEM_REGION instead\n");
        errno = 0;
        ret = ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);
        printf("  GH_VM_SET_USER_MEM_REGION: ret=%d errno=%d (%s)\n",
               ret, errno, strerror(errno));
    }

    /* Print dmesg after memory mapping */
    printf("\n-- dmesg after memory map --\n");
    system("dmesg");
    system("dmesg -c > /dev/null 2>&1");

    /* Step 3: Add vCPUs with CORRECT ioctl (0x4) */
    printf("\n-- Adding vCPUs with GUNYAH_VM_ADD_FUNCTION (_IOW('G',0x4,...)) --\n");
    for (int i = 0; i < 4; i++) {
        struct gunyah_fn_vcpu_arg va = { .id = i, .padding = 0 };
        struct gunyah_fn_desc fd_desc = {
            .type = GUNYAH_FN_VCPU,
            .arg_size = sizeof(va),
            .arg = (uint64_t)&va
        };
        errno = 0;
        int r = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fd_desc);
        printf("  GUNYAH_VM_ADD_FUNCTION VCPU[%d]: ret=%d errno=%d (%s)\n",
               i, r, errno, strerror(errno));
    }
    list_fds("after_add_vcpu");

    /* Print dmesg */
    usleep(500000);
    printf("\n-- dmesg after ADD_FUNCTION --\n");
    system("dmesg");
    system("dmesg -c > /dev/null 2>&1");

    /* Step 4: Try GUNYAH_VM_START */
    printf("\n-- GUNYAH_VM_START --\n");
    errno = 0;
    ret = ioctl(vm_fd, GUNYAH_VM_START, 0);
    printf("GUNYAH_VM_START: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
    list_fds("after_start");

    usleep(500000);
    printf("\n-- dmesg after START --\n");
    system("dmesg");

    /* Try GUNYAH_VCPU_RUN on each fd that might be a vCPU */
    printf("\n-- Probing vCPU fds (GUNYAH_VCPU_MMAP_SIZE on fd 4-20) --\n");
    for (int f = 4; f <= 20; f++) {
        errno = 0;
        int sz = ioctl(f, GUNYAH_VCPU_MMAP_SIZE, 0);
        if (errno != EBADF && errno != ENOTTY) {
            printf("  fd%d GUNYAH_VCPU_MMAP_SIZE: ret=%d errno=%d (%s)\n",
                   f, sz, errno, strerror(errno));
        }
    }

    printf("\n=== Done ===\n");

    close(vm_fd);
    close(dev_fd);
    munmap(mem, mem_size);
    return 0;
}

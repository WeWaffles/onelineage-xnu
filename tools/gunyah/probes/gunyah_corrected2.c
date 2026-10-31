/*
 * Corrected Gunyah probe v2 — fixed vcpu_arg size (4 bytes, not 8)
 * and tries both lend and set_mem approaches.
 *
 * Android 16 UAPI (6.12):
 *   GUNYAH_VM_ADD_FUNCTION   = _IOW('G', 0x4, struct gunyah_fn_desc)
 *   gunyah_fn_vcpu_arg       = { __u32 id }  (4 bytes ONLY, no padding)
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

#define GUNYAH_IOCTL_TYPE    'G'
#define GH_ANDROID_IOCTL_TYPE 'A'

struct gunyah_userspace_memory_region {
    uint32_t label;
    uint32_t flags;
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
};

struct gunyah_vm_dtb_config { uint64_t guest_phys_addr; uint64_t size; };
struct gunyah_fn_vcpu_arg { uint32_t id; }; /* EXACTLY 4 bytes */
struct gunyah_fn_desc { uint32_t type; uint32_t arg_size; uint64_t arg; };
struct gunyah_vm_boot_context { uint32_t reg; uint32_t reserved; uint64_t value; };
struct gunyah_vm_firmware_config { uint64_t guest_phys_addr; uint64_t size; };

#define GUNYAH_CREATE_VM          _IO(GUNYAH_IOCTL_TYPE, 0x0)
#define GH_VM_SET_USER_MEM_REGION  _IOW(GUNYAH_IOCTL_TYPE, 0x1, struct gunyah_userspace_memory_region)
#define GUNYAH_VM_SET_DTB_CONFIG   _IOW(GUNYAH_IOCTL_TYPE, 0x2, struct gunyah_vm_dtb_config)
#define GUNYAH_VM_START            _IO(GUNYAH_IOCTL_TYPE, 0x3)
#define GUNYAH_VM_ADD_FUNCTION     _IOW(GUNYAH_IOCTL_TYPE, 0x4, struct gunyah_fn_desc)
#define GUNYAH_VCPU_RUN            _IO(GUNYAH_IOCTL_TYPE, 0x5)
#define GUNYAH_VCPU_MMAP_SIZE      _IO(GUNYAH_IOCTL_TYPE, 0x6)
#define GUNYAH_VM_SET_BOOT_CONTEXT _IOW(GUNYAH_IOCTL_TYPE, 0xa, struct gunyah_vm_boot_context)

#define GH_VM_ANDROID_LEND_USER_MEM _IOW(GH_ANDROID_IOCTL_TYPE, 0x11, struct gunyah_userspace_memory_region)
#define GH_VM_ANDROID_SET_FW_CONFIG  _IOW(GH_ANDROID_IOCTL_TYPE, 0x12, struct gunyah_vm_firmware_config)
#define GH_ANDROID_CREATE_CMA_MEM_FD _IO(GH_ANDROID_IOCTL_TYPE, 0x14)
#define GH_VM_CHECK_EXTENSION        _IO(GH_ANDROID_IOCTL_TYPE, 0x17)

#define GUNYAH_FN_VCPU 1

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

static void print_dmesg(void) {
    system("dmesg | grep -E 'gunyah|gh_rm|vcpu|vm' | tail -10");
    system("dmesg -c > /dev/null 2>&1");
}

static void try_vcpu_add(int vm_fd, int use_lend, size_t mem_size, void *mem) {
    struct gunyah_userspace_memory_region mr = {
        .label = 1,
        .flags = 0x7,  /* ALLOW_READ|ALLOW_WRITE|ALLOW_EXEC */
        .guest_phys_addr = 0x80000000ULL,
        .memory_size = mem_size,
        .userspace_addr = (uint64_t)mem
    };

    int ret;
    errno = 0;
    if (use_lend) {
        ret = ioctl(vm_fd, GH_VM_ANDROID_LEND_USER_MEM, &mr);
        printf("  GH_VM_ANDROID_LEND_USER_MEM: ret=%d errno=%d\n", ret, errno);
    } else {
        ret = ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);
        printf("  GH_VM_SET_USER_MEM_REGION: ret=%d errno=%d\n", ret, errno);
    }
    if (ret < 0) return;

    printf("  GUNYAH_VM_ADD_FUNCTION VCPU (arg_size=%zu):\n", sizeof(struct gunyah_fn_vcpu_arg));
    for (int i = 0; i < 4; i++) {
        struct gunyah_fn_vcpu_arg va = { .id = (uint32_t)i };
        struct gunyah_fn_desc fd_desc = {
            .type = GUNYAH_FN_VCPU,
            .arg_size = (uint32_t)sizeof(struct gunyah_fn_vcpu_arg),  /* 4 bytes */
            .arg = (uint64_t)&va
        };
        errno = 0;
        int r = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fd_desc);
        printf("    VCPU[%d]: ret=%d errno=%d (%s)\n", i, r, errno, strerror(errno));
    }
    list_fds("after_vcpu_add");

    /* Try GUNYAH_VM_START */
    errno = 0;
    ret = ioctl(vm_fd, GUNYAH_VM_START, 0);
    printf("  GUNYAH_VM_START: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));

    print_dmesg();
}

int main(void) {
    printf("=== Gunyah corrected probe v2 ===\n");
    printf("sizeof(gunyah_fn_vcpu_arg)=%zu\n", sizeof(struct gunyah_fn_vcpu_arg));
    printf("sizeof(gunyah_fn_desc)=%zu\n", sizeof(struct gunyah_fn_desc));
    printf("GUNYAH_VM_ADD_FUNCTION=0x%lx\n", (unsigned long)GUNYAH_VM_ADD_FUNCTION);

    system("dmesg -c > /dev/null 2>&1");

    /* Check device extensions */
    int dev_fd = open("/dev/gunyah", O_RDWR);
    if (dev_fd < 0) { perror("open /dev/gunyah"); return 1; }
    printf("dev_fd=%d\n", dev_fd);

    /* Check GH_VM_CHECK_EXTENSION */
    printf("GH_VM_CHECK_EXTENSION=0x%lx\n", (unsigned long)GH_VM_CHECK_EXTENSION);
    for (int i = 0; i <= 10; i++) {
        errno = 0;
        int r = ioctl(dev_fd, _IO(GH_ANDROID_IOCTL_TYPE, 0x17), i);
        if (errno != ENOTTY)
            printf("  CHECK_EXTENSION(%d): ret=%d errno=%d (%s)\n", i, r, errno, strerror(errno));
    }

    size_t mem_size = 64 * 1024 * 1024;
    void *mem = mmap(NULL, mem_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); return 1; }

    /* Test 1: SET_USER_MEM_REGION + ADD_FUNCTION (non-protected) */
    printf("\n=== Test 1: non-protected (SET_USER_MEM_REGION) ===\n");
    {
        errno = 0;
        int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        printf("GUNYAH_CREATE_VM: vm_fd=%d errno=%d\n", vm_fd, errno);
        if (vm_fd >= 0) {
            try_vcpu_add(vm_fd, 0, mem_size, mem);
            close(vm_fd);
        }
    }

    printf("\n=== Test 2: protected-without-firmware (LEND_USER_MEM) ===\n");
    {
        errno = 0;
        int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        printf("GUNYAH_CREATE_VM: vm_fd=%d errno=%d\n", vm_fd, errno);
        if (vm_fd >= 0) {
            try_vcpu_add(vm_fd, 1, mem_size, mem);
            close(vm_fd);
        }
    }

    printf("\n=== Test 3: Set DTB config then add vCPUs ===\n");
    {
        errno = 0;
        int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        printf("GUNYAH_CREATE_VM: vm_fd=%d errno=%d\n", vm_fd, errno);
        if (vm_fd >= 0) {
            /* Map memory */
            struct gunyah_userspace_memory_region mr = {
                .label=1, .flags=0x7,
                .guest_phys_addr=0x80000000ULL,
                .memory_size=mem_size,
                .userspace_addr=(uint64_t)mem
            };
            ioctl(vm_fd, GH_VM_ANDROID_LEND_USER_MEM, &mr);

            /* Set DTB config at 0x81000000 */
            struct gunyah_vm_dtb_config dtb = { .guest_phys_addr=0x81000000ULL, .size=0x100000 };
            errno = 0;
            int r = ioctl(vm_fd, GUNYAH_VM_SET_DTB_CONFIG, &dtb);
            printf("GUNYAH_VM_SET_DTB_CONFIG: ret=%d errno=%d\n", r, errno);

            /* Set boot context PC */
            struct gunyah_vm_boot_context bc = { .reg=1, .reserved=0, .value=0x80000000ULL };
            errno = 0;
            r = ioctl(vm_fd, GUNYAH_VM_SET_BOOT_CONTEXT, &bc);
            printf("GUNYAH_VM_SET_BOOT_CONTEXT(PC): ret=%d errno=%d\n", r, errno);

            /* Add vCPUs with correct arg size */
            for (int i = 0; i < 2; i++) {
                struct gunyah_fn_vcpu_arg va = { .id = (uint32_t)i };
                struct gunyah_fn_desc fd_desc = {
                    .type = GUNYAH_FN_VCPU,
                    .arg_size = sizeof(struct gunyah_fn_vcpu_arg),
                    .arg = (uint64_t)&va
                };
                errno = 0;
                int vcpu_ret = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fd_desc);
                printf("  VCPU[%d]: ret=%d errno=%d (%s)\n", i, vcpu_ret, errno, strerror(errno));
                list_fds("after_vcpu");
            }

            print_dmesg();
            close(vm_fd);
        }
    }

    close(dev_fd);
    munmap(mem, mem_size);
    printf("\n=== Done ===\n");
    return 0;
}

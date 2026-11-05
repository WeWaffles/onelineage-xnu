/*
 * Test: VM_START with only DTB config set (no SET_USER_MEM_REGION).
 * Checks if the DTB config parcel allocation itself triggers RM rejection on vendor.
 * Also tries without SET_DTB_CONFIG to isolate what causes the SHARE_MEMORY error.
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

#define GUNYAH_IOCTL_TYPE 'G'

struct gunyah_fn_vcpu_arg { uint32_t id; };
struct gunyah_fn_desc { uint32_t type, arg_size; uint64_t arg; };
struct gunyah_vm_dtb_config { uint64_t guest_phys_addr, size; };
struct gunyah_vm_boot_context { uint32_t reg, reserved; uint64_t value; };
struct gunyah_userspace_memory_region {
    uint32_t label, flags;
    uint64_t guest_phys_addr, memory_size, userspace_addr;
};

#define GUNYAH_CREATE_VM           _IO(GUNYAH_IOCTL_TYPE, 0x0)
#define GH_VM_SET_USER_MEM_REGION   _IOW(GUNYAH_IOCTL_TYPE, 0x1, struct gunyah_userspace_memory_region)
#define GUNYAH_VM_SET_DTB_CONFIG    _IOW(GUNYAH_IOCTL_TYPE, 0x2, struct gunyah_vm_dtb_config)
#define GUNYAH_VM_START             _IO(GUNYAH_IOCTL_TYPE, 0x3)
#define GUNYAH_VM_ADD_FUNCTION      _IOW(GUNYAH_IOCTL_TYPE, 0x4, struct gunyah_fn_desc)
#define GUNYAH_VM_SET_BOOT_CONTEXT  _IOW(GUNYAH_IOCTL_TYPE, 0xa, struct gunyah_vm_boot_context)

#define GUNYAH_FN_VCPU 1
#define REG_SET_PC 1
#define GUNYAH_VM_BOOT_CONTEXT_REG(r,i) (((r)<<8)|(i))

static int run_test(const char *label, int use_dtb, int use_mem) {
    int r;

    printf("\n--- Test: %s ---\n", label);
    fflush(stdout);

    int dev_fd = open("/dev/gunyah", O_RDWR);
    if (dev_fd < 0) { perror("open /dev/gunyah"); return -1; }

    errno = 0;
    int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
    if (vm_fd < 0) { printf("CREATE_VM failed: %s\n", strerror(errno)); close(dev_fd); return -1; }
    printf("CREATE_VM: fd=%d\n", vm_fd); fflush(stdout);

    /* Add one vCPU */
    struct gunyah_fn_vcpu_arg va = {.id=0};
    struct gunyah_fn_desc fn = {.type=GUNYAH_FN_VCPU,.arg_size=4,.arg=(uint64_t)&va};
    errno = 0;
    int vcpu_fd = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fn);
    printf("ADD_FUNCTION VCPU[0]: fd=%d errno=%d\n", vcpu_fd, errno); fflush(stdout);

    void *mem = NULL;
    if (use_mem || use_dtb) {
        size_t mem_size = 4*1024*1024;  /* 4 MB minimum */
        mem = mmap(NULL, mem_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) { printf("mmap failed\n"); goto out; }
        printf("mmap OK: %p (%zu bytes)\n", mem, mem_size); fflush(stdout);

        if (use_dtb) {
            /* Set DTB config pointing into our mapped memory */
            struct gunyah_vm_dtb_config dtb = {
                .guest_phys_addr = 0x80000000ULL,
                .size = 0x1000
            };
            errno = 0;
            r = ioctl(vm_fd, GUNYAH_VM_SET_DTB_CONFIG, &dtb);
            printf("SET_DTB_CONFIG: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
            fflush(stdout);
        }

        if (use_mem) {
            /* Set user memory region */
            struct gunyah_userspace_memory_region mr = {
                .label=1, .flags=7,
                .guest_phys_addr=0x80000000ULL,
                .memory_size=4*1024*1024,
                .userspace_addr=(uint64_t)mem
            };
            errno = 0;
            r = ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);
            printf("SET_USER_MEM_REGION: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
            fflush(stdout);
        }
    }

    /* Try VM_START */
    errno = 0;
    r = ioctl(vm_fd, GUNYAH_VM_START, 0);
    printf("GUNYAH_VM_START: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    if (r == 0) printf("  *** SUCCESS ***\n");
    fflush(stdout);

out:
    if (vcpu_fd > 0) close(vcpu_fd);
    close(vm_fd);
    close(dev_fd);
    if (mem) munmap(mem, 4*1024*1024);
    return r;
}

int main(void) {
    printf("=== Gunyah VM_START isolation tests ===\n");
    fflush(stdout);

    /* Test 1: DTB config only (no user memory region) */
    run_test("DTB_CONFIG only (no SET_USER_MEM_REGION)", 1, 0);

    /* Test 2: User memory region but NO DTB config */
    run_test("SET_USER_MEM_REGION only (no SET_DTB_CONFIG)", 0, 1);

    /* Test 3: Both DTB config and memory region */
    run_test("Both SET_DTB_CONFIG + SET_USER_MEM_REGION", 1, 1);

    printf("\n=== Done ===\n");
    fflush(stdout);
    return 0;
}

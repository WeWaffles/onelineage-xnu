/*
 * Debug why GUNYAH_VM_START returns EINVAL.
 * Tests different sequences and captures dmesg messages.
 * No kernel parameter modifications.
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

struct gunyah_userspace_memory_region { uint32_t label,flags; uint64_t guest_phys_addr,memory_size,userspace_addr; };
struct gunyah_vm_dtb_config { uint64_t guest_phys_addr, size; };
struct gunyah_fn_vcpu_arg { uint32_t id; };
struct gunyah_fn_desc { uint32_t type, arg_size; uint64_t arg; };
struct gunyah_vm_boot_context { uint32_t reg, reserved; uint64_t value; };

#define GUNYAH_CREATE_VM           _IO(GUNYAH_IOCTL_TYPE, 0x0)
#define GH_VM_SET_USER_MEM_REGION   _IOW(GUNYAH_IOCTL_TYPE, 0x1, struct gunyah_userspace_memory_region)
#define GUNYAH_VM_SET_DTB_CONFIG    _IOW(GUNYAH_IOCTL_TYPE, 0x2, struct gunyah_vm_dtb_config)
#define GUNYAH_VM_START             _IO(GUNYAH_IOCTL_TYPE, 0x3)
#define GUNYAH_VM_ADD_FUNCTION      _IOW(GUNYAH_IOCTL_TYPE, 0x4, struct gunyah_fn_desc)
#define GUNYAH_VCPU_RUN             _IO(GUNYAH_IOCTL_TYPE, 0x5)
#define GUNYAH_VCPU_MMAP_SIZE       _IO(GUNYAH_IOCTL_TYPE, 0x6)
#define GUNYAH_VM_SET_BOOT_CONTEXT  _IOW(GUNYAH_IOCTL_TYPE, 0xa, struct gunyah_vm_boot_context)
#define GH_ANDROID_CREATE_CMA_MEM_FD _IO(GH_ANDROID_IOCTL_TYPE, 0x14)

#define GUNYAH_FN_VCPU 1
#define REG_SET_PC 1
#define GUNYAH_VM_BOOT_CONTEXT_REG(r,i) (((r)<<8)|(i))

static void dmesg_gunyah(const char *tag) {
    printf("[dmesg %s]:\n", tag);
    system("dmesg 2>/dev/null | grep -iE 'gunyah|gh_rm|vcpu|alloc_vmid|vm_mgr' | tail -20");
    system("dmesg -c > /dev/null 2>&1");
}

int main(void) {
    printf("=== Gunyah VM_START debug ===\n");
    system("dmesg -c > /dev/null 2>&1");

    int dev_fd = open("/dev/gunyah", O_RDWR);
    if (dev_fd < 0) { perror("open /dev/gunyah"); return 1; }

    size_t mem_size = 64*1024*1024;
    void *mem = mmap(NULL, mem_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); return 1; }

    /* Test 1: VCPU_MMAP_SIZE before START */
    printf("\n=== Test 1: VCPU_MMAP_SIZE before START ===\n");
    {
        int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        printf("vm_fd=%d\n", vm_fd);

        struct gunyah_userspace_memory_region mr = {
            .label=1,.flags=7,.guest_phys_addr=0x80000000ULL,.memory_size=mem_size,.userspace_addr=(uint64_t)mem
        };
        ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);

        struct gunyah_fn_vcpu_arg va = {0};
        struct gunyah_fn_desc fn = {.type=GUNYAH_FN_VCPU,.arg_size=sizeof(va),.arg=(uint64_t)&va};
        int vcpu_fd = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fn);
        printf("vcpu_fd=%d\n", vcpu_fd);

        errno = 0;
        long sz = ioctl(vcpu_fd, GUNYAH_VCPU_MMAP_SIZE, 0);
        printf("VCPU_MMAP_SIZE (before start): %ld errno=%d (%s)\n", sz, errno, strerror(errno));

        errno = 0;
        int r = ioctl(vcpu_fd, GUNYAH_VCPU_RUN, 0);
        printf("VCPU_RUN (before start): ret=%d errno=%d (%s)\n", r, errno, strerror(errno));

        dmesg_gunyah("after_vcpu_run_attempt");
        close(vcpu_fd);
        close(vm_fd);
    }

    /* Test 2: CMA FD */
    printf("\n=== Test 2: CMA FD creation ===\n");
    {
        errno = 0;
        int cma_fd = ioctl(dev_fd, GH_ANDROID_CREATE_CMA_MEM_FD, 0);
        printf("CREATE_CMA_MEM_FD on /dev/gunyah: ret=%d errno=%d (%s)\n",
               cma_fd, errno, strerror(errno));

        int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        errno = 0;
        cma_fd = ioctl(vm_fd, GH_ANDROID_CREATE_CMA_MEM_FD, 0);
        printf("CREATE_CMA_MEM_FD on vm_fd: ret=%d errno=%d (%s)\n",
               cma_fd, errno, strerror(errno));

        int tvm_fd = open("/dev/trustedvm_cma", O_RDWR);
        printf("open /dev/trustedvm_cma: fd=%d errno=%d\n", tvm_fd, errno);
        if (tvm_fd >= 0) close(tvm_fd);

        close(vm_fd);
    }

    /* Test 3: Different orderings before VM_START */
    /* Try: vcpu FIRST, then mem, then boot_ctx, then DTB, then start */
    printf("\n=== Test 3: vcpu-first ordering ===\n");
    {
        int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        printf("vm_fd=%d\n", vm_fd);

        /* Add vCPU FIRST */
        struct gunyah_fn_vcpu_arg va = {0};
        struct gunyah_fn_desc fn = {.type=GUNYAH_FN_VCPU,.arg_size=sizeof(va),.arg=(uint64_t)&va};
        int vcpu_fd = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fn);
        printf("vcpu_fd (first)=%d\n", vcpu_fd);

        /* Then map memory */
        struct gunyah_userspace_memory_region mr = {
            .label=1,.flags=7,.guest_phys_addr=0x80000000ULL,.memory_size=mem_size,.userspace_addr=(uint64_t)mem
        };
        int r = ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);
        printf("SET_USER_MEM_REGION: %d\n", r);

        /* Set boot context */
        struct gunyah_vm_boot_context bc = {
            .reg = GUNYAH_VM_BOOT_CONTEXT_REG(REG_SET_PC, 0),
            .value = 0x80000000ULL
        };
        ioctl(vm_fd, GUNYAH_VM_SET_BOOT_CONTEXT, &bc);

        /* Set DTB */
        struct gunyah_vm_dtb_config dtb = {.guest_phys_addr=0x80000000ULL,.size=0x10000};
        ioctl(vm_fd, GUNYAH_VM_SET_DTB_CONFIG, &dtb);

        dmesg_gunyah("before_start_test3");

        errno = 0;
        r = ioctl(vm_fd, GUNYAH_VM_START, 0);
        printf("GUNYAH_VM_START: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));

        usleep(300000);
        dmesg_gunyah("after_start_test3");

        close(vcpu_fd);
        close(vm_fd);
    }

    /* Test 4: try calling VM_START directly after CREATE_VM (no mem, no vcpu) */
    printf("\n=== Test 4: START with no mem/vcpu ===\n");
    {
        int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        errno = 0;
        int r = ioctl(vm_fd, GUNYAH_VM_START, 0);
        printf("GUNYAH_VM_START (bare): ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
        dmesg_gunyah("bare_start");
        close(vm_fd);
    }

    /* Test 5: just mem, no vcpu, then start */
    printf("\n=== Test 5: mem-only then START ===\n");
    {
        int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        struct gunyah_userspace_memory_region mr = {
            .label=1,.flags=7,.guest_phys_addr=0x80000000ULL,.memory_size=mem_size,.userspace_addr=(uint64_t)mem
        };
        ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);
        struct gunyah_vm_boot_context bc = {.reg=GUNYAH_VM_BOOT_CONTEXT_REG(REG_SET_PC,0),.value=0x80000000ULL};
        ioctl(vm_fd, GUNYAH_VM_SET_BOOT_CONTEXT, &bc);
        errno = 0;
        int r = ioctl(vm_fd, GUNYAH_VM_START, 0);
        printf("GUNYAH_VM_START (no vcpu): ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
        dmesg_gunyah("no_vcpu_start");
        close(vm_fd);
    }

    /* Test 6: start with 2 vCPUs */
    printf("\n=== Test 6: 2 vCPUs then START ===\n");
    {
        int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        struct gunyah_userspace_memory_region mr = {
            .label=1,.flags=7,.guest_phys_addr=0x80000000ULL,.memory_size=mem_size,.userspace_addr=(uint64_t)mem
        };
        ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);

        struct gunyah_vm_boot_context bc = {.reg=GUNYAH_VM_BOOT_CONTEXT_REG(REG_SET_PC,0),.value=0x80000000ULL};
        ioctl(vm_fd, GUNYAH_VM_SET_BOOT_CONTEXT, &bc);

        struct gunyah_vm_dtb_config dtb = {.guest_phys_addr=0x80000000ULL,.size=0x10000};
        ioctl(vm_fd, GUNYAH_VM_SET_DTB_CONFIG, &dtb);

        struct gunyah_fn_vcpu_arg va0 = {0}, va1 = {.id=1};
        struct gunyah_fn_desc fn0 = {.type=GUNYAH_FN_VCPU,.arg_size=sizeof(va0),.arg=(uint64_t)&va0};
        struct gunyah_fn_desc fn1 = {.type=GUNYAH_FN_VCPU,.arg_size=sizeof(va1),.arg=(uint64_t)&va1};
        int vcpu0 = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fn0);
        int vcpu1 = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fn1);
        printf("vcpu0=%d vcpu1=%d\n", vcpu0, vcpu1);

        dmesg_gunyah("before_start_test6");

        errno = 0;
        int r = ioctl(vm_fd, GUNYAH_VM_START, 0);
        printf("GUNYAH_VM_START (2 vcpus): ret=%d errno=%d (%s)\n", r, errno, strerror(errno));

        usleep(500000);
        dmesg_gunyah("after_start_test6");

        /* If start succeeded, try VCPU_MMAP_SIZE and VCPU_RUN */
        if (r == 0) {
            printf("VM_START SUCCEEDED!\n");
            errno = 0;
            long sz = ioctl(vcpu0, GUNYAH_VCPU_MMAP_SIZE, 0);
            printf("VCPU_MMAP_SIZE: %ld errno=%d\n", sz, errno);
        }

        close(vcpu0); close(vcpu1);
        close(vm_fd);
    }

    close(dev_fd);
    munmap(mem, mem_size);
    printf("\n=== Done ===\n");
    return 0;
}

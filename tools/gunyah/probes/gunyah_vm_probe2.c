/* Clean Gunyah VM fd probe — always clear errno before each ioctl */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

#define GH_IOCTL_TYPE 'G'
#define GH_CREATE_VM  _IO(GH_IOCTL_TYPE, 0x0)

struct gh_userspace_memory_region {
    uint32_t label;
    uint32_t flags;
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
};

struct gh_fn_vcpu_init { uint32_t vcpu_id; };

struct gh_fn_desc {
    uint32_t type;
    uint32_t arg_size;
    uint64_t arg;
};

#define GH_VM_SET_USER_MEM_REGION  _IOW(GH_IOCTL_TYPE, 0x1, struct gh_userspace_memory_region)
#define GH_VM_ADD_FUNCTION         _IOW(GH_IOCTL_TYPE, 0x2, struct gh_fn_desc)
#define GH_VM_REMOVE_FUNCTION      _IOW(GH_IOCTL_TYPE, 0x3, struct gh_fn_desc)
#define GH_VCPU_RUN                _IO(GH_IOCTL_TYPE, 0x5)
#define GH_VCPU_MMAP_SIZE          _IO(GH_IOCTL_TYPE, 0x6)
#define GH_FN_VCPU 1

#define PROBE(fd, ioc, arg) do { \
    errno = 0; \
    int _r = ioctl((fd), (ioc), (arg)); \
    printf("  ioctl(0x%08lx) ret=%d errno=%d (%s)\n", (unsigned long)(ioc), _r, errno, strerror(errno)); \
} while(0)

int main(void) {
    int dev_fd, vm_fd, vcpu_fd;

    dev_fd = open("/dev/gunyah", O_RDWR);
    if (dev_fd < 0) { perror("open"); return 1; }

    errno = 0;
    vm_fd = ioctl(dev_fd, GH_CREATE_VM, 0);
    printf("GH_CREATE_VM: vm_fd=%d errno=%d (%s)\n\n", vm_fd, errno, strerror(errno));
    if (vm_fd < 0) return 1;

    /* Brute-force probe: _IO('G', 0..20) with NULL arg, report non-ENOTTY */
    printf("=== _IO('G', n) NULL probe on VM fd ===\n");
    for (int n = 0; n <= 20; n++) {
        unsigned long ioc = _IO(GH_IOCTL_TYPE, n);
        errno = 0;
        int r = ioctl(vm_fd, ioc, 0);
        printf("  n=%2d ioc=0x%08lx ret=%d errno=%d (%s)\n", n, ioc, r, errno,
               errno==ENOTTY?"ENOTTY":strerror(errno));
    }

    /* Test GH_VM_SET_USER_MEM_REGION */
    printf("\n=== GH_VM_SET_USER_MEM_REGION (0x%08lx) ===\n", (unsigned long)GH_VM_SET_USER_MEM_REGION);
    void *mem = mmap(NULL, 0x200000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem != MAP_FAILED) {
        struct gh_userspace_memory_region r = {
            .label=1, .flags=0,
            .guest_phys_addr=0x80000000ULL,
            .memory_size=0x200000,
            .userspace_addr=(uint64_t)mem
        };
        PROBE(vm_fd, GH_VM_SET_USER_MEM_REGION, &r);
    }

    /* Test GH_VM_ADD_FUNCTION VCPU */
    printf("\n=== GH_VM_ADD_FUNCTION VCPU (0x%08lx) ===\n", (unsigned long)GH_VM_ADD_FUNCTION);
    struct gh_fn_vcpu_init vi = { .vcpu_id=0 };
    struct gh_fn_desc fn = { .type=GH_FN_VCPU, .arg_size=sizeof(vi), .arg=(uint64_t)&vi };
    errno = 0;
    vcpu_fd = ioctl(vm_fd, GH_VM_ADD_FUNCTION, &fn);
    printf("  ret=%d errno=%d (%s)\n", vcpu_fd, errno, strerror(errno));
    if (vcpu_fd > 0) {
        printf("  vcpu_fd=%d\n", vcpu_fd);
        /* Probe vCPU fd */
        printf("  GH_VCPU_MMAP_SIZE: "); PROBE(vcpu_fd, GH_VCPU_MMAP_SIZE, 0);
        printf("  GH_VCPU_RUN: ");       PROBE(vcpu_fd, GH_VCPU_RUN, 0);
        close(vcpu_fd);
    }

    /* Show dmesg tail to capture any kernel messages */
    close(vm_fd);
    close(dev_fd);
    printf("\n=== Recent dmesg (gunyah/vm) ===\n");
    system("dmesg | grep -iE 'gunyah|gh_vm|gh_rm|vcpu|vm_id' | tail -20");
    return 0;
}

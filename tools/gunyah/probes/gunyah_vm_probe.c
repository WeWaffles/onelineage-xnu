/* Probe Gunyah VM fd ioctl interface (after GH_CREATE_VM succeeds) */
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

/* VM fd ioctls — from upstream Linux 6.12 include/uapi/linux/gunyah.h */
struct gh_userspace_memory_region {
    uint32_t label;
    uint32_t flags;
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
};

struct gh_fn_vcpu_init {
    uint32_t vcpu_id;
};

struct gh_fn_irqfd_config {
    uint32_t resamplefd;
    uint32_t fd;
    uint32_t label;
    uint32_t flags;
};

struct gh_fn_ioeventfd_config {
    uint64_t datamatch;
    uint64_t addr;
    uint32_t len;
    int32_t  fd;
    uint32_t flags;
    uint32_t label;
};

struct gh_fn_desc {
    uint32_t type;
    uint32_t arg_size;
    uint64_t arg;  /* pointer to arg struct */
};

#define GH_VM_SET_USER_MEM_REGION  _IOW(GH_IOCTL_TYPE, 0x1, struct gh_userspace_memory_region)
#define GH_VM_ADD_FUNCTION         _IOW(GH_IOCTL_TYPE, 0x2, struct gh_fn_desc)
#define GH_VM_REMOVE_FUNCTION      _IOW(GH_IOCTL_TYPE, 0x3, struct gh_fn_desc)

/* vCPU fd ioctls */
#define GH_VCPU_RUN                _IO(GH_IOCTL_TYPE, 0x5)
#define GH_VCPU_MMAP_SIZE          _IO(GH_IOCTL_TYPE, 0x6)

/* gh_fn type values */
#define GH_FN_VCPU    1
#define GH_FN_IRQFD   2
#define GH_FN_IOEVENTFD 3

static const char *err2str(int e) {
    switch (e) {
    case EBADF:      return "EBADF";
    case EINVAL:     return "EINVAL";
    case ENOTTY:     return "ENOTTY";
    case EPERM:      return "EPERM";
    case EACCES:     return "EACCES";
    case ENOMEM:     return "ENOMEM";
    case ENODEV:     return "ENODEV";
    case ENOENT:     return "ENOENT";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case EBUSY:      return "EBUSY";
    case EFAULT:     return "EFAULT";
    case ENXIO:      return "ENXIO";
    case 0:          return "OK";
    default:         return strerror(e);
    }
}

int main(void) {
    int dev_fd, vm_fd, ret;

    printf("=== Gunyah VM fd probe ===\n");

    dev_fd = open("/dev/gunyah", O_RDWR);
    if (dev_fd < 0) { perror("open /dev/gunyah"); return 1; }

    vm_fd = ioctl(dev_fd, GH_CREATE_VM, 0);
    if (vm_fd < 0) { perror("GH_CREATE_VM"); return 1; }
    printf("Created VM fd=%d\n\n", vm_fd);

    /* 1. Probe all _IO('G', n) on VM fd */
    printf("Probing _IO('G', 0..15) on VM fd:\n");
    for (int n = 0; n <= 15; n++) {
        unsigned long ioc = _IO(GH_IOCTL_TYPE, n);
        errno = 0;
        ret = ioctl(vm_fd, ioc, 0);
        if (errno != ENOTTY)
            printf("  _IO('G',%2d)=0x%08lx: ret=%d errno=%d (%s)\n",
                   n, ioc, ret, errno, err2str(errno));
    }

    /* 2. Probe _IOW variants */
    printf("\nProbing _IOW('G', 1..4) on VM fd:\n");
    for (int n = 1; n <= 4; n++) {
        unsigned long ioc = _IOW(GH_IOCTL_TYPE, n, uint64_t);
        errno = 0;
        ret = ioctl(vm_fd, ioc, 0);
        if (errno != ENOTTY)
            printf("  _IOW('G',%2d): ret=%d errno=%d (%s)\n", n, ret, errno, err2str(errno));
    }

    /* 3. Try GH_VM_SET_USER_MEM_REGION with a real mapping */
    printf("\nTrying GH_VM_SET_USER_MEM_REGION (ioc=0x%08lx):\n", (unsigned long)GH_VM_SET_USER_MEM_REGION);
    void *mem = mmap(NULL, 0x100000, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { printf("  mmap failed\n"); }
    else {
        struct gh_userspace_memory_region region = {
            .label          = 1,
            .flags          = 0,
            .guest_phys_addr = 0x80000000ULL,
            .memory_size    = 0x100000,
            .userspace_addr = (uint64_t)mem,
        };
        ret = ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &region);
        printf("  ret=%d errno=%d (%s)\n", ret, errno, err2str(errno));
        munmap(mem, 0x100000);
    }

    /* 4. Try GH_VM_ADD_FUNCTION with VCPU */
    printf("\nTrying GH_VM_ADD_FUNCTION VCPU (ioc=0x%08lx):\n", (unsigned long)GH_VM_ADD_FUNCTION);
    struct gh_fn_vcpu_init vcpu_init = { .vcpu_id = 0 };
    struct gh_fn_desc fn = {
        .type     = GH_FN_VCPU,
        .arg_size = sizeof(vcpu_init),
        .arg      = (uint64_t)&vcpu_init,
    };
    ret = ioctl(vm_fd, GH_VM_ADD_FUNCTION, &fn);
    printf("  ret=%d errno=%d (%s)\n", ret, errno, err2str(errno));
    if (ret >= 0) {
        int vcpu_fd = ret;
        printf("  Got vcpu_fd=%d!\n", vcpu_fd);

        /* Check vCPU mmap size */
        ret = ioctl(vcpu_fd, GH_VCPU_MMAP_SIZE, 0);
        printf("  GH_VCPU_MMAP_SIZE: ret=%d errno=%d (%s)\n", ret, errno, err2str(errno));

        /* Try vCPU run */
        ret = ioctl(vcpu_fd, GH_VCPU_RUN, 0);
        printf("  GH_VCPU_RUN: ret=%d errno=%d (%s)\n", ret, errno, err2str(errno));

        close(vcpu_fd);
    }

    close(vm_fd);
    close(dev_fd);
    printf("\nDone.\n");
    return 0;
}

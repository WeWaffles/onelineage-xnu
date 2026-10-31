/* Probe /dev/gunyah ioctl interface */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

/* Try both known Gunyah ioctl type values */
#define GH_IOCTL_TYPE_UPSTREAM  0xA5
#define GH_IOCTL_TYPE_ALT       'G'   /* 0x47 */

/* GH_CREATE_VM = _IO(type, 0x0) */
#define GH_CREATE_VM_A5    _IO(GH_IOCTL_TYPE_UPSTREAM, 0x0)
#define GH_CREATE_VM_G     _IO(GH_IOCTL_TYPE_ALT, 0x0)

/* Also try with arg struct: _IOW type */
struct gh_create_vm_args {
    unsigned long flags;
    int vmid;
};
#define GH_CREATE_VM_IOW_A5 _IOW(GH_IOCTL_TYPE_UPSTREAM, 0x0, struct gh_create_vm_args)
#define GH_CREATE_VM_IOW_G  _IOW(GH_IOCTL_TYPE_ALT, 0x0, struct gh_create_vm_args)

static const char *err2str(int e) {
    switch (e) {
    case EBADF:    return "EBADF (bad fd)";
    case EINVAL:   return "EINVAL (invalid arg)";
    case ENOTTY:   return "ENOTTY (wrong ioctl)";
    case EPERM:    return "EPERM (permission)";
    case EACCES:   return "EACCES (access)";
    case ENOMEM:   return "ENOMEM (no memory)";
    case ENODEV:   return "ENODEV (no device)";
    case ENOENT:   return "ENOENT (not found)";
    case EOPNOTSUPP: return "EOPNOTSUPP (not supported)";
    case EBUSY:    return "EBUSY (device busy)";
    default:       return strerror(e);
    }
}

int main(void) {
    int fd, ret, vm_fd;
    struct gh_create_vm_args args = {0, 0};

    printf("=== Gunyah /dev/gunyah probe ===\n");

    fd = open("/dev/gunyah", O_RDWR);
    if (fd < 0) {
        printf("open(/dev/gunyah) FAILED: %s (errno=%d)\n", err2str(errno), errno);
        return 1;
    }
    printf("open(/dev/gunyah) OK, fd=%d\n", fd);

    /* Try upstream Linux: _IO(0xA5, 0x0) = 0x0000A500 */
    printf("\nTrying GH_CREATE_VM _IO(0xA5, 0x0) = 0x%08lx\n", (unsigned long)GH_CREATE_VM_A5);
    ret = ioctl(fd, GH_CREATE_VM_A5, 0);
    if (ret >= 0) {
        vm_fd = ret;
        printf("  SUCCESS: returned vm_fd=%d\n", vm_fd);
        close(vm_fd);
    } else {
        printf("  FAILED: %s (errno=%d)\n", err2str(errno), errno);
    }

    /* Try alt: _IO('G', 0x0) = 0x00004700 */
    printf("\nTrying GH_CREATE_VM _IO('G', 0x0) = 0x%08lx\n", (unsigned long)GH_CREATE_VM_G);
    ret = ioctl(fd, GH_CREATE_VM_G, 0);
    if (ret >= 0) {
        vm_fd = ret;
        printf("  SUCCESS: returned vm_fd=%d\n", vm_fd);
        close(vm_fd);
    } else {
        printf("  FAILED: %s (errno=%d)\n", err2str(errno), errno);
    }

    /* Try IOW variants */
    printf("\nTrying GH_CREATE_VM _IOW(0xA5, 0x0, args) = 0x%08lx\n", (unsigned long)GH_CREATE_VM_IOW_A5);
    ret = ioctl(fd, GH_CREATE_VM_IOW_A5, &args);
    if (ret >= 0) {
        printf("  SUCCESS: ret=%d args.vmid=%d\n", ret, args.vmid);
    } else {
        printf("  FAILED: %s (errno=%d)\n", err2str(errno), errno);
    }

    printf("\nTrying GH_CREATE_VM _IOW('G', 0x0, args) = 0x%08lx\n", (unsigned long)GH_CREATE_VM_IOW_G);
    ret = ioctl(fd, GH_CREATE_VM_IOW_G, &args);
    if (ret >= 0) {
        printf("  SUCCESS: ret=%d args.vmid=%d\n", ret, args.vmid);
    } else {
        printf("  FAILED: %s (errno=%d)\n", err2str(errno), errno);
    }

    /* Probe all ioctl numbers 0-15 with type 0xA5 */
    printf("\nProbing all _IO(0xA5, 0..15):\n");
    for (int n = 0; n <= 15; n++) {
        unsigned long ioc = _IO(0xA5, n);
        errno = 0;
        ret = ioctl(fd, ioc, 0);
        if (errno != ENOTTY && errno != EINVAL) {
            printf("  _IO(0xA5, %d)=0x%08lx: ret=%d errno=%d (%s)\n",
                   n, ioc, ret, errno, err2str(errno));
        }
    }

    /* Probe ioctl numbers 0-15 with type 'G' */
    printf("\nProbing all _IO('G', 0..15):\n");
    for (int n = 0; n <= 15; n++) {
        unsigned long ioc = _IO('G', n);
        errno = 0;
        ret = ioctl(fd, ioc, 0);
        if (errno != ENOTTY && errno != EINVAL) {
            printf("  _IO('G', %d)=0x%08lx: ret=%d errno=%d (%s)\n",
                   n, ioc, ret, errno, err2str(errno));
        }
    }

    close(fd);
    printf("\nDone.\n");
    return 0;
}

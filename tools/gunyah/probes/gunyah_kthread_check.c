/* Check for kernel threads created by gh_vcpu_mgr after VM creation */
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
#include <sys/types.h>

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
#define GH_FN_VCPU 1

static void find_gh_threads(void) {
    printf("=== kernel threads with 'vcpu' or 'vm' in name ===\n");
    system("cat /proc/*/status 2>/dev/null | awk '/Name.*vcpu|Name.*vm[0-9]/{print}' | head -20");
    printf("=== ps for vm threads ===\n");
    system("ps -A 2>/dev/null | grep -E 'vcpu|vm[0-9]' | head -20");
}

int main(void) {
    printf("=== Gunyah kthread check ===\n");
    system("dmesg -c > /dev/null 2>&1");

    printf("Before VM creation:\n");
    find_gh_threads();

    int dev_fd = open("/dev/gunyah", O_RDWR);
    int vm_fd = ioctl(dev_fd, GH_CREATE_VM, 0);
    printf("VM created: vm_fd=%d\n", vm_fd);

    size_t mem_size = 64 * 1024 * 1024;
    void *mem = mmap(NULL, mem_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    struct gh_userspace_memory_region r = {
        .label=1, .flags=0,
        .guest_phys_addr=0x80000000ULL,
        .memory_size=mem_size,
        .userspace_addr=(uint64_t)mem
    };
    int ret = ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &r);
    printf("Memory mapped: ret=%d\n", ret);

    /* Add 4 vCPUs */
    for (int i = 0; i < 4; i++) {
        struct gh_fn_vcpu_init vi = { .vcpu_id=i };
        struct gh_fn_desc fn = { .type=GH_FN_VCPU, .arg_size=sizeof(vi), .arg=(uint64_t)&vi };
        ret = ioctl(vm_fd, GH_VM_ADD_FUNCTION, &fn);
        printf("ADD_VCPU[%d]: ret=%d\n", i, ret);
    }

    usleep(1000000);  /* wait 1 second for async initialization */
    printf("\nAfter VM creation + 1s wait:\n");
    find_gh_threads();

    printf("\n=== dmesg after VM creation ===\n");
    system("dmesg");
    system("dmesg -c > /dev/null 2>&1");

    /* Keep VM alive for 3 more seconds and check again */
    sleep(3);
    printf("\nAfter 3 more seconds:\n");
    find_gh_threads();
    printf("\n=== dmesg after 3s ===\n");
    system("dmesg");

    close(vm_fd);
    close(dev_fd);
    return 0;
}

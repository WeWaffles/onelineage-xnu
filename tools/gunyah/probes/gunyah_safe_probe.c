/*
 * Safe Gunyah probe — no VM_START (to avoid kernel panic)
 * Tests: create VM, map mem, add vCPU, check VCPU_MMAP_SIZE, VCPU_RUN
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

#define GUNYAH_IOCTL_TYPE    'G'
#define GH_ANDROID_IOCTL_TYPE 'A'

struct gunyah_userspace_memory_region { uint32_t label,flags; uint64_t guest_phys_addr,memory_size,userspace_addr; };
struct gunyah_vm_dtb_config { uint64_t guest_phys_addr, size; };
struct gunyah_fn_vcpu_arg { uint32_t id; };
struct gunyah_fn_desc { uint32_t type, arg_size; uint64_t arg; };
struct gunyah_vm_boot_context { uint32_t reg, reserved; uint64_t value; };

struct gunyah_vcpu_run {
    uint8_t  immediate_exit; uint8_t padding[7];
    uint32_t exit_reason, exit_reason_size;
    uint8_t  raw[64];
};

#define GUNYAH_CREATE_VM           _IO(GUNYAH_IOCTL_TYPE, 0x0)
#define GH_VM_SET_USER_MEM_REGION   _IOW(GUNYAH_IOCTL_TYPE, 0x1, struct gunyah_userspace_memory_region)
#define GUNYAH_VM_SET_DTB_CONFIG    _IOW(GUNYAH_IOCTL_TYPE, 0x2, struct gunyah_vm_dtb_config)
#define GUNYAH_VM_START             _IO(GUNYAH_IOCTL_TYPE, 0x3)
#define GUNYAH_VM_ADD_FUNCTION      _IOW(GUNYAH_IOCTL_TYPE, 0x4, struct gunyah_fn_desc)
#define GUNYAH_VCPU_RUN             _IO(GUNYAH_IOCTL_TYPE, 0x5)
#define GUNYAH_VCPU_MMAP_SIZE       _IO(GUNYAH_IOCTL_TYPE, 0x6)
#define GUNYAH_VM_SET_BOOT_CONTEXT  _IOW(GUNYAH_IOCTL_TYPE, 0xa, struct gunyah_vm_boot_context)

#define GUNYAH_FN_VCPU 1
#define REG_SET_PC 1
#define GUNYAH_VM_BOOT_CONTEXT_REG(r,i) (((r)<<8)|(i))

int main(void) {
    printf("=== Safe Gunyah vCPU probe (no VM_START) ===\n");
    fflush(stdout);

    int dev_fd = open("/dev/gunyah", O_RDWR);
    if (dev_fd < 0) { perror("open /dev/gunyah"); return 1; }
    printf("dev_fd=%d\n", dev_fd);
    fflush(stdout);

    int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
    printf("vm_fd=%d\n", vm_fd);
    fflush(stdout);
    if (vm_fd < 0) return 1;

    size_t mem_size = 16*1024*1024;
    void *mem = mmap(NULL, mem_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == (void*)-1) { perror("mmap"); return 1; }
    printf("mem=%p\n", mem); fflush(stdout);

    /* Write ARM64 NOP sled + WFI */
    uint32_t *code = (uint32_t *)mem;
    for (int i = 0; i < 16; i++) code[i] = 0xd503201f; /* nop */
    code[16] = 0xd503207f;  /* wfi */
    code[17] = 0x14000000;  /* b . */

    struct gunyah_userspace_memory_region mr = {
        .label=1,.flags=7,.guest_phys_addr=0x80000000ULL,
        .memory_size=mem_size,.userspace_addr=(uint64_t)mem
    };
    int r = ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);
    printf("SET_MEM: %d errno=%d\n", r, errno); fflush(stdout);

    struct gunyah_vm_dtb_config dtb = {.guest_phys_addr=0x80000000ULL,.size=0x1000};
    r = ioctl(vm_fd, GUNYAH_VM_SET_DTB_CONFIG, &dtb);
    printf("SET_DTB: %d errno=%d\n", r, errno); fflush(stdout);

    struct gunyah_vm_boot_context bc = {
        .reg = GUNYAH_VM_BOOT_CONTEXT_REG(REG_SET_PC, 0),
        .value = 0x80000000ULL
    };
    r = ioctl(vm_fd, GUNYAH_VM_SET_BOOT_CONTEXT, &bc);
    printf("SET_BOOT_CTX(PC): %d errno=%d\n", r, errno); fflush(stdout);

    struct gunyah_fn_vcpu_arg va = {.id=0};
    struct gunyah_fn_desc fn = {.type=GUNYAH_FN_VCPU,.arg_size=sizeof(va),.arg=(uint64_t)&va};
    errno = 0;
    int vcpu_fd = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fn);
    printf("ADD_FUNCTION VCPU: vcpu_fd=%d errno=%d\n", vcpu_fd, errno); fflush(stdout);

    if (vcpu_fd < 0) {
        printf("No vCPU fd\n");
        return 1;
    }

    /* Check VCPU_MMAP_SIZE without VM_START */
    errno = 0;
    long mmap_sz = ioctl(vcpu_fd, GUNYAH_VCPU_MMAP_SIZE, 0);
    printf("VCPU_MMAP_SIZE (pre-start): %ld errno=%d (%s)\n",
           mmap_sz, errno, strerror(errno));
    fflush(stdout);

    /* Try VCPU_RUN without VM_START — should fail safely */
    errno = 0;
    r = ioctl(vcpu_fd, GUNYAH_VCPU_RUN, 0);
    printf("VCPU_RUN (pre-start): ret=%d errno=%d (%s)\n",
           r, errno, strerror(errno));
    fflush(stdout);

    /* If VCPU_MMAP_SIZE returned a size, try to mmap the vcpu_run area */
    if (mmap_sz > 0) {
        void *vcpu_run_map = mmap(NULL, (size_t)mmap_sz,
                                   PROT_READ|PROT_WRITE, MAP_SHARED,
                                   vcpu_fd, 0);
        printf("mmap vcpu_run (%ld bytes): %s\n", mmap_sz,
               (vcpu_run_map == MAP_FAILED) ? "FAILED" : "OK");
        fflush(stdout);
        if (vcpu_run_map != MAP_FAILED) munmap(vcpu_run_map, (size_t)mmap_sz);
    }

    /* Now try VM_START and immediately check dmesg */
    printf("\nAttempting VM_START...\n"); fflush(stdout);
    errno = 0;
    r = ioctl(vm_fd, GUNYAH_VM_START, 0);
    printf("GUNYAH_VM_START: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));
    fflush(stdout);

    if (r == 0) {
        printf("VM_START SUCCEEDED!\n"); fflush(stdout);
        /* Try VCPU ops after start */
        mmap_sz = ioctl(vcpu_fd, GUNYAH_VCPU_MMAP_SIZE, 0);
        printf("VCPU_MMAP_SIZE (post-start): %ld errno=%d\n", mmap_sz, errno);
        fflush(stdout);
    }

    close(vcpu_fd);
    close(vm_fd);
    close(dev_fd);
    munmap(mem, mem_size);
    printf("=== Done ===\n");
    fflush(stdout);
    return 0;
}

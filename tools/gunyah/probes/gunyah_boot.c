/*
 * Gunyah minimal ARM64 guest boot test
 *
 * Sequence:
 *  1. Create VM
 *  2. Allocate 128MB guest memory (0x80000000)
 *  3. Write minimal ARM64 payload: WFI loop (guest code)
 *  4. Write minimal FDT at 0x81000000 (required by Gunyah DTB config)
 *  5. Set DTB config -> guest PA 0x81000000
 *  6. Set boot context: PC=0x80000000, x0=0x81000000 (DTB ptr)
 *  7. Add 1 vCPU -> returns vCPU fd
 *  8. GUNYAH_VM_START
 *  9. mmap vCPU run area (GUNYAH_VCPU_MMAP_SIZE)
 * 10. GUNYAH_VCPU_RUN -> observe exit reason
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

/* ---- Gunyah UAPI ---- */
#define GUNYAH_IOCTL_TYPE    'G'
#define GH_ANDROID_IOCTL_TYPE 'A'

struct gunyah_userspace_memory_region {
    uint32_t label; uint32_t flags;
    uint64_t guest_phys_addr; uint64_t memory_size; uint64_t userspace_addr;
};
struct gunyah_vm_dtb_config { uint64_t guest_phys_addr; uint64_t size; };
struct gunyah_fn_vcpu_arg { uint32_t id; };          /* 4 bytes exactly */
struct gunyah_fn_desc { uint32_t type; uint32_t arg_size; uint64_t arg; };
struct gunyah_vm_boot_context { uint32_t reg; uint32_t reserved; uint64_t value; };

/* vcpu_run struct (from UAPI) */
struct gunyah_vcpu_run {
    uint8_t  immediate_exit;
    uint8_t  padding[7];
    uint32_t exit_reason;
    uint32_t exit_reason_size;
    union {
        struct { uint64_t phys_addr; uint8_t data[8]; uint32_t len; uint8_t is_write; } mmio;
        struct { uint32_t type; } status;
        struct { uint64_t phys_addr; } page_fault;
        uint8_t raw[64];
    };
};

#define GUNYAH_VCPU_EXIT_UNKNOWN    0
#define GUNYAH_VCPU_EXIT_MMIO       1
#define GUNYAH_VCPU_EXIT_STATUS     2
#define GUNYAH_VCPU_EXIT_PAGE_FAULT 3

#define GUNYAH_VM_STATUS_LOAD_FAILED 1
#define GUNYAH_VM_STATUS_EXITED      2
#define GUNYAH_VM_STATUS_CRASHED     3

#define GUNYAH_CREATE_VM           _IO(GUNYAH_IOCTL_TYPE, 0x0)
#define GH_VM_SET_USER_MEM_REGION   _IOW(GUNYAH_IOCTL_TYPE, 0x1, struct gunyah_userspace_memory_region)
#define GUNYAH_VM_SET_DTB_CONFIG    _IOW(GUNYAH_IOCTL_TYPE, 0x2, struct gunyah_vm_dtb_config)
#define GUNYAH_VM_START             _IO(GUNYAH_IOCTL_TYPE, 0x3)
#define GUNYAH_VM_ADD_FUNCTION      _IOW(GUNYAH_IOCTL_TYPE, 0x4, struct gunyah_fn_desc)
#define GUNYAH_VCPU_RUN             _IO(GUNYAH_IOCTL_TYPE, 0x5)
#define GUNYAH_VCPU_MMAP_SIZE       _IO(GUNYAH_IOCTL_TYPE, 0x6)
#define GUNYAH_VM_SET_BOOT_CONTEXT  _IOW(GUNYAH_IOCTL_TYPE, 0xa, struct gunyah_vm_boot_context)
#define GH_VM_ANDROID_LEND_USER_MEM _IOW(GH_ANDROID_IOCTL_TYPE, 0x11, struct gunyah_userspace_memory_region)

#define GUNYAH_FN_VCPU 1
#define REG_SET_PC     1
#define REG_SET_X      0
#define GUNYAH_VM_BOOT_CONTEXT_REG(reg, idx) (((reg) << 8) | (idx))

/* ---- Minimal FDT builder ---- */
#define FDT_BEGIN_NODE    0x00000001
#define FDT_END_NODE      0x00000002
#define FDT_PROP          0x00000003
#define FDT_END           0x00000009

static uint32_t be32(uint32_t v) {
    return ((v>>24)&0xff)|((v>>8)&0xff00)|((v<<8)&0xff0000)|((v<<24)&0xff000000);
}

/* Build a minimal FDT that Gunyah will accept:
 * / { #address-cells = <1>; #size-cells = <1>; }
 * Returns size of built FDT */
static size_t build_fdt(uint8_t *buf, size_t bufsz) {
    memset(buf, 0, bufsz);

    /* FDT header */
    uint32_t *h = (uint32_t *)buf;
    /* We'll fill offsets after building the structure */

    uint8_t *p = buf + 48;  /* start of structure after header (48 bytes) */
    uint8_t *struct_start = p;

#define PUT32(v) do { *(uint32_t *)p = be32(v); p += 4; } while(0)
#define PUTSTR(s) do { size_t l = strlen(s)+1; memcpy(p,s,l); p += (l+3)&~3; } while(0)

    PUT32(FDT_BEGIN_NODE);  /* root node */
    PUTSTR("");              /* root name = "" */

    /* #address-cells property */
    PUT32(FDT_PROP);
    PUT32(4);              /* prop data size = 4 */
    PUT32(1);              /* name offset (placeholder) */
    PUT32(be32(1));        /* value = 1 */

    /* #size-cells property */
    PUT32(FDT_PROP);
    PUT32(4);
    PUT32(16);             /* name offset (placeholder) */
    PUT32(be32(1));

    /* compatible property */
    PUT32(FDT_PROP);
    PUT32(8);
    PUT32(30);
    memcpy(p, "linux,dum", 9); p += 12;

    PUT32(FDT_END_NODE);   /* end root */
    PUT32(FDT_END);        /* end structure */

    uint32_t struct_size = (uint32_t)(p - struct_start);

    /* Strings block */
    uint8_t *strings = p;
    const char *s1 = "#address-cells";
    const char *s2 = "#size-cells";
    const char *s3 = "compatible";
    memcpy(p, s1, strlen(s1)+1); p += strlen(s1)+1;
    memcpy(p, s2, strlen(s2)+1); p += strlen(s2)+1;
    memcpy(p, s3, strlen(s3)+1); p += strlen(s3)+1;
    uint32_t strings_size = (uint32_t)(p - strings);

    uint32_t total = (uint32_t)(p - buf);

    /* Fill in header */
    h[0] = be32(0xd00dfeed);  /* magic */
    h[1] = be32(total);
    h[2] = be32(48);          /* off_dt_struct */
    h[3] = be32(48 + struct_size);  /* off_dt_strings */
    h[4] = be32(0);           /* off_mem_rsvmap — right after header, but we skip it */
    h[5] = be32(17);          /* version */
    h[6] = be32(16);          /* last_comp_version */
    h[7] = be32(0);           /* boot_cpuid_phys */
    h[8] = be32(strings_size);
    h[9] = be32(struct_size);

    (void)bufsz;
    return total;
}

/* ---- ARM64 minimal payload ---- */
/* wfi; b . — loops at first instruction */
static const uint32_t arm64_wfi_loop[] = {
    0xd503207f,  /* wfi */
    0x14000000,  /* b . (infinite loop) */
};

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
        if (strstr(target, "gunyah") || strstr(target, "anon") || strstr(target, "mem"))
            printf(" fd%s->%s", e->d_name, target);
    }
    printf("\n");
    closedir(d);
}

int main(void) {
    printf("=== Gunyah minimal boot test ===\n");
    system("dmesg -c > /dev/null 2>&1");

    int dev_fd = open("/dev/gunyah", O_RDWR);
    if (dev_fd < 0) { perror("open /dev/gunyah"); return 1; }
    printf("dev_fd=%d\n", dev_fd);

    /* 1. Create VM */
    errno = 0;
    int vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
    printf("GUNYAH_CREATE_VM: vm_fd=%d errno=%d\n", vm_fd, errno);
    if (vm_fd < 0) return 1;

    /* 2. Allocate 128MB host memory */
    size_t mem_size = 128 * 1024 * 1024;
    void *mem = mmap(NULL, mem_size, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); return 1; }
    printf("host mem: %p (128MB)\n", mem);

    /* 3. Write ARM64 payload at guest offset 0 (guest PA 0x80000000) */
    memcpy(mem, arm64_wfi_loop, sizeof(arm64_wfi_loop));
    printf("Payload: WFI loop (%zu bytes) at guest PA 0x80000000\n",
           sizeof(arm64_wfi_loop));

    /* 4. Write FDT at guest offset 1MB (guest PA 0x80100000) */
    uint8_t *fdt_buf = (uint8_t *)mem + 0x100000;
    size_t fdt_size = build_fdt(fdt_buf, 4096);
    printf("FDT: %zu bytes at guest PA 0x80100000\n", fdt_size);

    /* 5. Map memory to VM */
    struct gunyah_userspace_memory_region mr = {
        .label = 1,
        .flags = 0x7,  /* R|W|X */
        .guest_phys_addr = 0x80000000ULL,
        .memory_size = mem_size,
        .userspace_addr = (uint64_t)mem
    };
    errno = 0;
    int ret = ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);
    printf("SET_USER_MEM_REGION: ret=%d errno=%d\n", ret, errno);

    /* 6. Set DTB config */
    struct gunyah_vm_dtb_config dtb = {
        .guest_phys_addr = 0x80100000ULL,
        .size = fdt_size
    };
    errno = 0;
    ret = ioctl(vm_fd, GUNYAH_VM_SET_DTB_CONFIG, &dtb);
    printf("GUNYAH_VM_SET_DTB_CONFIG: ret=%d errno=%d\n", ret, errno);

    /* 7. Set boot context: PC = 0x80000000 */
    struct gunyah_vm_boot_context bc_pc = {
        .reg = GUNYAH_VM_BOOT_CONTEXT_REG(REG_SET_PC, 0),
        .reserved = 0,
        .value = 0x80000000ULL
    };
    errno = 0;
    ret = ioctl(vm_fd, GUNYAH_VM_SET_BOOT_CONTEXT, &bc_pc);
    printf("GUNYAH_VM_SET_BOOT_CONTEXT(PC=0x80000000): ret=%d errno=%d\n", ret, errno);

    /* Set x0 = DTB pointer (AArch64 Linux calling convention) */
    struct gunyah_vm_boot_context bc_x0 = {
        .reg = GUNYAH_VM_BOOT_CONTEXT_REG(REG_SET_X, 0),
        .reserved = 0,
        .value = 0x80100000ULL
    };
    errno = 0;
    ret = ioctl(vm_fd, GUNYAH_VM_SET_BOOT_CONTEXT, &bc_x0);
    printf("GUNYAH_VM_SET_BOOT_CONTEXT(x0=0x80100000): ret=%d errno=%d\n", ret, errno);

    /* 8. Add 1 vCPU */
    struct gunyah_fn_vcpu_arg va = { .id = 0 };
    struct gunyah_fn_desc fn = {
        .type = GUNYAH_FN_VCPU,
        .arg_size = sizeof(struct gunyah_fn_vcpu_arg),
        .arg = (uint64_t)&va
    };
    errno = 0;
    int vcpu_fd = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fn);
    printf("GUNYAH_VM_ADD_FUNCTION VCPU: vcpu_fd=%d errno=%d\n", vcpu_fd, errno);
    list_fds("after_add_vcpu");

    if (vcpu_fd < 0) {
        printf("FATAL: no vCPU fd\n");
        return 1;
    }

    /* 9. Check dmesg before start */
    printf("\n-- dmesg before START --\n");
    system("dmesg");
    system("dmesg -c > /dev/null 2>&1");

    /* 10. Start VM */
    errno = 0;
    ret = ioctl(vm_fd, GUNYAH_VM_START, 0);
    printf("GUNYAH_VM_START: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));

    if (ret < 0) {
        printf("VM_START failed — dmesg:\n");
        usleep(200000);
        system("dmesg");
        system("dmesg -c > /dev/null 2>&1");

        /* Try GUNYAH_VM_START without DTB — maybe DTB config is not needed for START? */
        printf("\n-- Retrying: create fresh VM, map mem, add vcpu, start (no DTB) --\n");
        close(vcpu_fd);
        close(vm_fd);

        vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
        printf("GUNYAH_CREATE_VM (fresh): vm_fd=%d\n", vm_fd);

        ioctl(vm_fd, GH_VM_SET_USER_MEM_REGION, &mr);

        /* Set PC only */
        ioctl(vm_fd, GUNYAH_VM_SET_BOOT_CONTEXT, &bc_pc);

        va.id = 0;
        vcpu_fd = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fn);
        printf("VCPU fd (retry): %d\n", vcpu_fd);

        errno = 0;
        ret = ioctl(vm_fd, GUNYAH_VM_START, 0);
        printf("GUNYAH_VM_START (no DTB): ret=%d errno=%d (%s)\n",
               ret, errno, strerror(errno));
        usleep(200000);
        system("dmesg");
        system("dmesg -c > /dev/null 2>&1");
    }

    if (ret < 0) {
        printf("VM_START still failed, cannot run vCPU\n");
        goto done;
    }

    /* 11. mmap vCPU run area */
    errno = 0;
    long vcpu_run_sz = ioctl(vcpu_fd, GUNYAH_VCPU_MMAP_SIZE, 0);
    printf("GUNYAH_VCPU_MMAP_SIZE: %ld errno=%d\n", vcpu_run_sz, errno);

    if (vcpu_run_sz <= 0) {
        printf("Cannot get vCPU run size\n");
        goto done;
    }

    struct gunyah_vcpu_run *vcpu_run = mmap(NULL, (size_t)vcpu_run_sz,
                                             PROT_READ|PROT_WRITE, MAP_SHARED,
                                             vcpu_fd, 0);
    if (vcpu_run == MAP_FAILED) {
        perror("mmap vcpu_run");
        goto done;
    }
    printf("vcpu_run mmap: %p\n", (void *)vcpu_run);

    /* 12. Run vCPU up to 5 iterations */
    printf("\n=== Running vCPU ===\n");
    for (int iter = 0; iter < 5; iter++) {
        vcpu_run->immediate_exit = 0;
        errno = 0;
        ret = ioctl(vcpu_fd, GUNYAH_VCPU_RUN, 0);
        printf("[%d] GUNYAH_VCPU_RUN: ret=%d errno=%d (%s)\n",
               iter, ret, errno, strerror(errno));

        if (ret < 0) break;

        printf("    exit_reason=%u\n", vcpu_run->exit_reason);
        switch (vcpu_run->exit_reason) {
            case GUNYAH_VCPU_EXIT_MMIO:
                printf("    MMIO: pa=0x%llx len=%u is_write=%u\n",
                       (unsigned long long)vcpu_run->mmio.phys_addr,
                       vcpu_run->mmio.len,
                       vcpu_run->mmio.is_write);
                /* Handle MMIO: just ACK it */
                if (!vcpu_run->mmio.is_write)
                    memset(vcpu_run->mmio.data, 0, vcpu_run->mmio.len);
                break;
            case GUNYAH_VCPU_EXIT_STATUS:
                printf("    STATUS: type=%u\n", vcpu_run->status.type);
                if (vcpu_run->status.type == GUNYAH_VM_STATUS_EXITED) {
                    printf("    => Guest exited normally\n");
                    goto vcpu_done;
                } else if (vcpu_run->status.type == GUNYAH_VM_STATUS_CRASHED) {
                    printf("    => Guest CRASHED\n");
                    goto vcpu_done;
                }
                break;
            case GUNYAH_VCPU_EXIT_PAGE_FAULT:
                printf("    PAGE_FAULT: pa=0x%llx\n",
                       (unsigned long long)vcpu_run->page_fault.phys_addr);
                break;
            default:
                printf("    UNKNOWN exit reason %u\n", vcpu_run->exit_reason);
                break;
        }
    }
vcpu_done:
    printf("\n-- dmesg after vCPU run --\n");
    system("dmesg");

    munmap(vcpu_run, (size_t)vcpu_run_sz);

done:
    printf("\n=== Done ===\n");
    close(vcpu_fd);
    close(vm_fd);
    close(dev_fd);
    munmap(mem, mem_size);
    return 0;
}

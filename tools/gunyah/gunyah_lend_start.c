/*
 * OneLineage Gunyah probe: lend guest memory, give the VM a valid config image,
 * start it, and run one vCPU far enough to leave an observable trace.
 *
 * Why this probe exists
 * ---------------------
 * Every earlier probe handed memory to the VM with GH_VM_SET_USER_MEM_REGION,
 * which the kernel turns into a *shared* parcel (two ACL entries, RM message
 * MEM_SHARE).  vendor's resource manager rejects that with
 *   "gunyah: RM rejected message 5600000b. Error: 10"
 * at GUNYAH_VM_START.
 *
 * The kernel chooses LEND or SHARE purely from the binding type:
 *   drivers/virt/gunyah/vm_mgr_mem.c: gunyah_share_parcel()
 *     n_acl_entries = 1 for VM_MEM_LEND  -> gunyah_rm_mem_share() sends MEM_LEND
 *     n_acl_entries = 2 for VM_MEM_SHARE -> ... sends MEM_SHARE
 * so GH_VM_ANDROID_LEND_USER_MEM is a different RM request, not a flag on the
 * same one.  The LEND path had never actually reached GUNYAH_VM_START with a
 * config image:
 *   - gunyah_corrected / _safe_probe: SHARE + DTB -> START rejected (5600000b)
 *   - gunyah_corrected2 test 3:      LEND  + DTB -> never called START
 *   - gunyah_corrected (lend run):   LEND, no DTB -> START failed earlier with
 *     "Failed to allocate parcel for the config image: -22" (parcel size 0)
 *
 * So this probe runs exactly one configuration, once:
 *   LEND region -> DTB inside that region -> PC -> vCPU -> START -> VCPU_RUN.
 *
 * The payload writes to an address no mapping covers, so a successful start
 * ends in GUNYAH_VCPU_EXIT_MMIO naming 0x0f000000 and the value 0x41.  That
 * exit can only be produced by instructions actually executing in the guest.
 *
 * Nothing here writes a partition, loads a module, or touches another VM.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "probe_dtb.h"

#define GUNYAH_IOCTL_TYPE	'G'
#define GH_ANDROID_IOCTL_TYPE	'A'

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
};

struct gunyah_fn_desc {
	uint32_t type;
	uint32_t arg_size;
	uint64_t arg;
};

struct gunyah_vm_boot_context {
	uint32_t reg;
	uint32_t reserved;
	uint64_t value;
};

struct gunyah_vcpu_run {
	uint8_t immediate_exit;
	uint8_t padding[7];
	uint32_t exit_reason;
	union {
		struct {
			uint64_t phys_addr;
			uint8_t data[8];
			uint32_t len;
			uint8_t is_write;
			uint8_t resume_action;
		} mmio;
		struct {
			uint32_t status;
			uint8_t exit_info[16];
		} status;
		struct {
			uint64_t phys_addr;
			int32_t attempt;
			uint8_t resume_action;
		} page_fault;
	};
};

#define GUNYAH_CREATE_VM		_IO(GUNYAH_IOCTL_TYPE, 0x0)
#define GUNYAH_VM_SET_DTB_CONFIG	_IOW(GUNYAH_IOCTL_TYPE, 0x2, struct gunyah_vm_dtb_config)
#define GUNYAH_VM_START			_IO(GUNYAH_IOCTL_TYPE, 0x3)
#define GUNYAH_VM_ADD_FUNCTION		_IOW(GUNYAH_IOCTL_TYPE, 0x4, struct gunyah_fn_desc)
#define GUNYAH_VCPU_RUN			_IO(GUNYAH_IOCTL_TYPE, 0x5)
#define GUNYAH_VCPU_MMAP_SIZE		_IO(GUNYAH_IOCTL_TYPE, 0x6)
#define GUNYAH_VM_SET_BOOT_CONTEXT	_IOW(GUNYAH_IOCTL_TYPE, 0xa, struct gunyah_vm_boot_context)

#define GH_VM_ANDROID_LEND_USER_MEM	_IOW(GH_ANDROID_IOCTL_TYPE, 0x11, \
					     struct gunyah_userspace_memory_region)

#define GUNYAH_FN_VCPU		1

#define REG_SET_X		0
#define REG_SET_PC		1
#define REG_SET_SP		2
#define BOOT_CONTEXT_REG(reg, idx)	((((reg) & 0xff) << 8) | ((idx) & 0xff))

#define RAM_GPA		0x80000000ULL
#define RAM_SIZE	(8ULL * 1024 * 1024)
#define DTB_SIZE	0x1000ULL
#define PAYLOAD_GPA	(RAM_GPA + DTB_SIZE)

/*
 * movz x1, #0x0f00, lsl #16   ; x1 = 0x0f000000, no memory there
 * mov  w0, #0x41              ; 'A'
 * str  w0, [x1]               ; must trap to the host as an MMIO write
 * b    .
 */
static const uint32_t payload[] = {
	0xd2a01e01,
	0x52800820,
	0xb9000020,
	0x14000000,
};

static void dmesg_tail(void)
{
	fflush(stdout);
	if (system("dmesg | grep -iE 'gunyah|gh_rm|vcpu' | tail -8"))
		printf("(dmesg not readable)\n");
}

int main(void)
{
	int dev_fd, vm_fd, vcpu_fd, ret;
	uint8_t *ram;
	uint64_t mmap_size;
	struct gunyah_userspace_memory_region region;
	struct gunyah_vm_dtb_config dtb;
	struct gunyah_vm_boot_context ctx;
	struct gunyah_fn_vcpu_arg vcpu_arg;
	struct gunyah_fn_desc fn;
	struct gunyah_vcpu_run *run;

	printf("=== OneLineage Gunyah LEND + DTB + START probe ===\n");
	printf("dtb blob: %u bytes (from probe.dtb)\n", probe_dtb_len);
	printf("RAM gpa=0x%llx size=0x%llx payload gpa=0x%llx\n",
	       (unsigned long long)RAM_GPA, (unsigned long long)RAM_SIZE,
	       (unsigned long long)PAYLOAD_GPA);

	if (probe_dtb_len > DTB_SIZE) {
		printf("FAIL: dtb larger than the config window\n");
		return 1;
	}

	dev_fd = open("/dev/gunyah", O_RDWR);
	if (dev_fd < 0) {
		perror("open /dev/gunyah");
		return 1;
	}

	vm_fd = ioctl(dev_fd, GUNYAH_CREATE_VM, 0);
	if (vm_fd < 0) {
		perror("GUNYAH_CREATE_VM");
		return 1;
	}
	printf("CREATE_VM: fd=%d\n", vm_fd);

	ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ram == MAP_FAILED) {
		perror("mmap ram");
		return 1;
	}
	memcpy(ram, probe_dtb, probe_dtb_len);
	memcpy(ram + DTB_SIZE, payload, sizeof(payload));

	/* LEND, not SHARE: one ACL entry, MEM_LEND instead of MEM_SHARE. */
	memset(&region, 0, sizeof(region));
	region.label = 1;
	region.flags = 0x7;		/* READ | WRITE | EXEC */
	region.guest_phys_addr = RAM_GPA;
	region.memory_size = RAM_SIZE;
	region.userspace_addr = (uint64_t)(uintptr_t)ram;

	errno = 0;
	ret = ioctl(vm_fd, GH_VM_ANDROID_LEND_USER_MEM, &region);
	printf("LEND_USER_MEM: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
	if (ret < 0)
		goto out_vm;

	dtb.guest_phys_addr = RAM_GPA;
	dtb.size = DTB_SIZE;
	errno = 0;
	ret = ioctl(vm_fd, GUNYAH_VM_SET_DTB_CONFIG, &dtb);
	printf("SET_DTB_CONFIG: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
	if (ret < 0)
		goto out_vm;

	/* reg is (set << 8) | index; 1 alone would be X1, not the PC. */
	ctx.reg = BOOT_CONTEXT_REG(REG_SET_PC, 0);
	ctx.reserved = 0;
	ctx.value = PAYLOAD_GPA;
	errno = 0;
	ret = ioctl(vm_fd, GUNYAH_VM_SET_BOOT_CONTEXT, &ctx);
	printf("SET_BOOT_CONTEXT(PC=0x%llx, reg=0x%x): ret=%d errno=%d (%s)\n",
	       (unsigned long long)ctx.value, ctx.reg, ret, errno, strerror(errno));
	if (ret < 0)
		goto out_vm;

	vcpu_arg.id = 0;
	fn.type = GUNYAH_FN_VCPU;
	fn.arg_size = sizeof(vcpu_arg);
	fn.arg = (uint64_t)(uintptr_t)&vcpu_arg;
	errno = 0;
	vcpu_fd = ioctl(vm_fd, GUNYAH_VM_ADD_FUNCTION, &fn);
	printf("ADD_FUNCTION VCPU[0]: fd=%d errno=%d (%s)\n",
	       vcpu_fd, errno, strerror(errno));
	if (vcpu_fd < 0)
		goto out_vm;

	mmap_size = ioctl(vcpu_fd, GUNYAH_VCPU_MMAP_SIZE, 0);
	printf("VCPU_MMAP_SIZE: %llu\n", (unsigned long long)mmap_size);
	run = mmap(NULL, mmap_size ? mmap_size : 4096,
		   PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
	if (run == MAP_FAILED) {
		perror("mmap vcpu_run");
		goto out_vm;
	}

	printf("\n-- GUNYAH_VM_START --\n");
	errno = 0;
	ret = ioctl(vm_fd, GUNYAH_VM_START, 0);
	printf("VM_START: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
	dmesg_tail();
	if (ret < 0) {
		printf("RESULT: resource manager refused the LEND start\n");
		goto out_vm;
	}

	printf("\n-- GUNYAH_VCPU_RUN --\n");
	memset(run, 0, 4096);
	run->immediate_exit = 0;
	errno = 0;
	ret = ioctl(vcpu_fd, GUNYAH_VCPU_RUN, 0);
	printf("VCPU_RUN: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
	if (ret == 0) {
		printf("exit_reason=%u\n", run->exit_reason);
		switch (run->exit_reason) {
		case 1:	/* GUNYAH_VCPU_EXIT_MMIO */
			printf("MMIO: addr=0x%llx len=%u write=%u data=0x%02x\n",
			       (unsigned long long)run->mmio.phys_addr,
			       run->mmio.len, run->mmio.is_write, run->mmio.data[0]);
			if (run->mmio.phys_addr == 0x0f000000ULL &&
			    run->mmio.data[0] == 0x41)
				printf("RESULT: GUEST EXECUTED (MMIO store observed)\n");
			else
				printf("RESULT: guest ran, unexpected MMIO\n");
			break;
		case 3:	/* GUNYAH_VCPU_EXIT_PAGE_FAULT */
			printf("PAGE_FAULT: addr=0x%llx attempt=%d\n",
			       (unsigned long long)run->page_fault.phys_addr,
			       run->page_fault.attempt);
			break;
		case 2:	/* GUNYAH_VCPU_EXIT_STATUS */
			printf("STATUS: status=%u\n", run->status.status);
			break;
		default:
			printf("RESULT: unexpected exit reason\n");
		}
	}
	dmesg_tail();

out_vm:
	printf("\n=== Done ===\n");
	return 0;
}

/*
 * Launch a QTVM in the phone's unused OEM slot with a CMA-backed guest RAM fd.
 *
 * Why this exists
 * ---------------
 * crosvm has no CMA code of its own (no `cma` string in the binary): it maps
 * whatever fd --file-backed-mapping hands it. The running trustedvm is given a
 * Gunyah CMA mem fd by its manager, so the kernel sees f_op == gunyah_cma_fops.
 * Passing a plain file instead makes gunyah_cma_share_parcel() fail its
 * `file->f_op != &gunyah_cma_fops` check and return EINVAL, which is exactly
 * what the slot probe hit ("Failed to share CMA memory: -22").
 *
 * So: open /dev/oemvm_cma, ask it for a mem fd (GH_ANDROID_CREATE_CMA_MEM_FD),
 * keep that fd open across exec, and point crosvm at /proc/self/fd/N.
 *
 * Usage: oemvm_launch <payload.img> [crosvm args...]
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define GH_ANDROID_IOCTL_TYPE	'A'
#define GH_ANDROID_CREATE_CMA_MEM_FD _IO(GH_ANDROID_IOCTL_TYPE, 0x14)

#define CROSVM	"/apex/com.android.virt/bin/crosvm"
#define CMA_DEV	"/dev/oemvm_cma"
/* The oem_vm reserved region is 0x04c00000 = 76 MiB. */
#define CMA_SIZE	0x4c00000ULL
#define SWIOTLB_MB	4ULL

int main(int argc, char **argv)
{
	const char *payload;
	char ram_arg[128], mem[32], swiotlb[32];
	int cma_fd, mem_fd;
	struct stat st;
	char **child;
	int i, n = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <payload.img>\n", argv[0]);
		return 2;
	}
	payload = argv[1];

	cma_fd = open(CMA_DEV, O_RDWR);
	if (cma_fd < 0) {
		perror("open " CMA_DEV);
		return 1;
	}

	mem_fd = ioctl(cma_fd, GH_ANDROID_CREATE_CMA_MEM_FD, 0);
	if (mem_fd < 0) {
		perror("GH_ANDROID_CREATE_CMA_MEM_FD");
		return 1;
	}

	if (fstat(mem_fd, &st) == 0)
		printf("cma mem fd=%d size=0x%llx\n", mem_fd,
		       (unsigned long long)st.st_size);
	else
		printf("cma mem fd=%d (fstat failed: %s)\n", mem_fd, strerror(errno));

	/* The fd must survive exec: clear CLOEXEC if the kernel set it. */
	fcntl(mem_fd, F_SETFD, 0);

	snprintf(ram_arg, sizeof(ram_arg),
		 "/proc/self/fd/%d,addr=0x80000000,size=0x%llx,rw,ram",
		 mem_fd, (unsigned long long)CMA_SIZE);
	snprintf(mem, sizeof(mem), "%llu", (CMA_SIZE >> 20) + SWIOTLB_MB);
	snprintf(swiotlb, sizeof(swiotlb), "%llu", SWIOTLB_MB);

	child = calloc((size_t)argc + 48, sizeof(char *));
	if (!child) {
		perror("calloc");
		return 1;
	}
	child[n++] = (char *)CROSVM;
	child[n++] = (char *)"--log-level";
	child[n++] = (char *)"debug";
	child[n++] = (char *)"run";
	child[n++] = (char *)"--disable-sandbox";
	child[n++] = (char *)"--protected-vm";
	child[n++] = (char *)"--unmap-guest-memory-on-fork";
	child[n++] = (char *)"--lock-guest-memory";
	child[n++] = (char *)"--name";
	child[n++] = (char *)"oemvm";
	child[n++] = (char *)"--cpus";
	child[n++] = (char *)"1";
	child[n++] = (char *)"--mem";
	child[n++] = mem;
	child[n++] = (char *)"--swiotlb";
	child[n++] = swiotlb;
	child[n++] = (char *)"--no-balloon";
	child[n++] = (char *)"--no-usb";
	child[n++] = (char *)"--no-pmu";
	child[n++] = (char *)"--serial=type=file,path=/data/local/tmp/oemvm-serial.log";
	child[n++] = (char *)"--file-backed-mapping";
	child[n++] = ram_arg;
	child[n++] = (char *)"--hypervisor";
	child[n++] = (char *)"gunyah[device=/dev/gunyah,"
			     "qcom_trusted_vm_id=49,qcom_trusted_vm_pas_id=34]";
	child[n++] = (char *)payload;
	/* Pass through any extra crosvm arguments the caller supplied. */
	for (i = 2; i < argc; i++)
		child[n++] = argv[i];
	child[n] = NULL;

	printf("exec: %s ... --mem %s --file-backed-mapping %s\n",
	       CROSVM, mem, ram_arg);
	fflush(stdout);
	execv(CROSVM, child);
	perror("execv " CROSVM);
	return 1;
}

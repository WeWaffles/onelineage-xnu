/*
 * prog2: the second program the boot's userspace execs.
 *
 * This is a real clang-compiled arm64 Mach-O (arm64-apple-ios, -static,
 * -nostdlib), not an image assembled by mk_init.py.  It exists so PID 2's
 * execve() lands on bytes that are not the init image: the harness serves it
 * from the second slot of the ramdisk, mockfs maps it at MOCKFS_PROG_OFFSET,
 * and the entry XNU records is this program's, not the harness's.
 *
 * The ABI is XNU's own: x16 carries the BSD syscall number, arguments in
 * x0..x7, and `svc #0x80` enters unix_syscall.  There is no libSystem and no
 * dyld in this boot, so the calls are written here directly.
 *
 *   write(1, "PGM2_OK\n", 8)   fd 1 is the console the parent dup2'd; the
 *                              descriptor survives exec
 *   getpid()                   proves this process is the exec'd one
 *   exit(0)                    a clean, bounded exit the parent can reap
 */
static long
sweet_syscall(long number, long a0, long a1, long a2)
{
	register long x16 __asm__("x16") = number;
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;

	__asm__ volatile("svc #0x80"
	    : "+r"(x0)
	    : "r"(x16), "r"(x1), "r"(x2)
	    : "memory", "cc");
	return x0;
}

#define SYS_exit   1
#define SYS_write  4
#define SYS_getpid 20

static const char msg[] = "PGM2_OK\n";

void
_start(void)
{
	(void)sweet_syscall(SYS_write, 1, (long)msg, sizeof(msg) - 1);
	(void)sweet_syscall(SYS_getpid, 0, 0, 0);
	(void)sweet_syscall(SYS_exit, 0, 0, 0);
	for (;;) {
		/* exit only returns if the kernel refused it; do not spin. */
	}
}

/*
 * prog2: the second program the boot's userspace execs.
 *
 * This is a real clang-compiled arm64 Mach-O (arm64-apple-ios, -static,
 * -nostdlib), not an image assembled by mk_init.py.  It exists so PID 2's
 * execve() lands on bytes that are not the init image.
 *
 * The ABI is XNU's own: x16 carries the BSD syscall number, arguments in
 * x0..x7, and `svc #0x80` enters unix_syscall.  There is no libSystem and no
 * dyld in this boot, so the calls are written here directly.
 *
 *   open("/launchd")            the one node mockfs serves, opened by the
 *                               child itself rather than inherited
 *   read(fd, buf, 8)            pull the Mach-O magic and cputype
 *   compare                     proves the bytes are the file's, not a page of
 *                               zeroes or a stale buffer
 *   write(1, "PGM2_OK\n", 8)     fd 1 is the console the parent dup2'd
 *   exit(7) / exit(9)           a status the parent can only see by reaping,
 *                               so wait4's status copyout is exercised too
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
#define SYS_read   3
#define SYS_write  4
#define SYS_open   5

/* Mach-O 64-bit magic followed by CPU_TYPE_ARM64, little-endian. */
#define MACHO_ARM64 0x0100000cfeadfacfULL

static const char ok_msg[] = "PGM2_OK\n";
static const char bad_msg[] = "PGM2_BAD\n";
static const char launchd[] = "/launchd";

void
_start(void)
{
	long fd, n, status = 9;
	/*
	 * The buffer must not live in __DATA: this image's __DATA segment has
	 * filesize 0, so it is pure zero-fill, and hw/m490 shows the child dying
	 * on its first access to that page (__bss at 0x100004000) right after a
	 * successful read.  A stack array keeps the bytes in memory the exec
	 * already backed.
	 */
	unsigned char buf[16];

	fd = sweet_syscall(SYS_open, (long)launchd, 0, 0);
	if (fd >= 0) {
		n = sweet_syscall(SYS_read, fd, (long)buf, 8);
		if (n == 8) {
			unsigned long w = 0;
			int i;

			for (i = 0; i < 8; i++) {
				w |= (unsigned long)buf[i] << (8 * i);
			}
			if (w == MACHO_ARM64) {
				status = 7;
			}
		}
	}

	(void)sweet_syscall(SYS_write, 1,
	    (long)(status == 7 ? ok_msg : bad_msg), 8);
	(void)sweet_syscall(SYS_exit, status, 0, 0);
	for (;;) {
		/* exit only returns if the kernel refused it; do not spin. */
	}
}

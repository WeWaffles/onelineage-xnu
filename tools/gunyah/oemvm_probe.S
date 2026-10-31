/*
 * Minimal ARM64 payload for the oemvm QTVM slot probe.
 *
 * crosvm loads this as the VM's kernel/firmware image. It does the smallest
 * thing that can only be observed if a real vCPU executed it: store 'A' to an
 * address no device covers, so the hypervisor exits to crosvm with an MMIO
 * access instead of completing it.
 *
 * Built as a static ELF64 with its text at 0x80000000, the guest base the
 * trustedvm also uses.
 */
	.section .text
	.global _start
_start:
	movz	x1, #0x0f00, lsl #16	/* x1 = 0x0f000000 */
	mov	w0, #0x41		/* 'A' */
	str	w0, [x1]		/* must trap to the host */
1:	b	1b			/* stay here if it somehow completes */

/*
 * jump_stub.S — ARM64 shutdown stub for olxnu_jump
 *
 * Copied to a GFP_KERNEL page at module init.  Called at the page's
 * PHYSICAL address after TTBR0 identity map is installed, so VA == PA.
 *
 * On entry (called as stub_fn(boot_args_pa, entry_pa) from do_jump):
 *   x0 = boot_args PA  (what XNU arm_init expects in x0)
 *   x1 = XNU entry PA
 *
 * The stub is also called with (entry, 0) for the M3 b. loop test.
 * For that path boot_args_pa is entry_pa and entry_pa is 0; we fall
 * back to branching to x0 when x1 == 0.
 *
 * Layout:
 *   [code]
 *   olxnu_stub_ba_slot:    .quad 0   (filled in by do_jump: boot_args_pa)
 *   olxnu_stub_entry_slot: .quad 0   (filled in by do_jump: entry_pa)
 *   olxnu_stub_end:
 *
 * do_jump stores boot_args_pa and entry_pa into the slots via offset
 * arithmetic, then loads them back here so x0/x1 are pristine when
 * XNU executes its first instruction.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

	.text
	.align 2

SYM_CODE_START(olxnu_stub_start)

	/* BTI landing pad — required because do_jump calls us via BLR */
	bti	c

	/* 1. Disable all interrupts, FIQs, SError, debug */
	msr	daifset, #0xf

	/*
	 * 2. Disable MMU, D-cache, I-cache, and BTI in SCTLR_EL1.
	 *    BT1 (bit 36) controls BTI for EL1 — clear it so the
	 *    payload entry (e.g. b .) doesn't need a BTI landing pad.
	 */
	mrs	x2, sctlr_el1
	bic	x2, x2, #(1 << 0)		/* M:   MMU enable      */
	bic	x2, x2, #(1 << 2)		/* C:   D-cache enable  */
	bic	x2, x2, #(1 << 12)		/* I:   I-cache enable  */
	bic	x2, x2, #0x1000000000		/* BT1: BTI at EL1      */
	msr	sctlr_el1, x2
	isb

	/* 3. Flush TLBs and I-cache (MMU already off) */
	tlbi	vmalle1
	dsb	nsh
	ic	iallu
	dsb	nsh
	isb

	/*
	 * Entry marker.  It has to come AFTER the MMU is off.
	 *
	 * The first version of this marker stored to the log region at entry,
	 * while translation was still on through the identity map that
	 * install_idmap() left behind.  That map covers the stub's own 2MB
	 * block and nothing else, so the store to 0x8883F0068 was a translation
	 * fault inside the stub — the marker's absence then said nothing about
	 * whether the branch arrived, and three runs (hw/m56..m58) were read as
	 * "the stub never ran" when they may have died in the marker itself.
	 *
	 * With the MMU off this is a plain physical store, so its presence means
	 * the branch arrived and the SCTLR/TLB/I-cache sequence completed:
	 *
	 *   XNUJMP5 absent          -> the branch never reached this page
	 *   XNUJMP5 only            -> the core dies in the M=0 -> M=1 -> M=0
	 *                              toggle (step 3b), i.e. re-enabling
	 *                              translation through the host's own map is
	 *                              refused
	 *   XNUJMP5 and XNUJMP6     -> the toggle is fine, the fault is later
	 *
	 * 0x8883F0068/0x8883F0070 are clear of the other channels (0x0000 XNU
	 * entry, 0x0020 module, 0x0028 XNUJMP2, 0x0038..0x0058 start.s,
	 * 0x0080/0x0100.. probes).
	 */
	movz	x2, #0x0068
	movk	x2, #0x883f, lsl #16
	movk	x2, #0x0008, lsl #32		/* x2 = 0x8883F0068 */
	movz	x3, #0x4e58
	movk	x3, #0x4a55, lsl #16
	movk	x3, #0x504d, lsl #32
	movk	x3, #0x0a35, lsl #48		/* "XNUJMP5\n" */
	str	x3, [x2]
	dmb	sy

	/* Enter XNU with the MMU off; the old extra toggle probe is removed. */

	/*
	 * 4. Load boot_args_pa and entry_pa from the data slots embedded
	 *    at the end of this stub.  We must do this BEFORE clearing
	 *    registers so the ADR PC-relative load works.
	 */
	adr	x2, olxnu_stub_ba_slot
	ldr	x0, [x2]		/* x0 = boot_args_pa */
	adr	x2, olxnu_stub_entry_slot
	ldr	x1, [x2]		/* x1 = entry_pa */

	/* 5. Clear all general-purpose registers except x0 (boot_args) and
	 *    x1 (entry).  Clearing x2 last.
	 */
	mov	x2,  xzr
	mov	x3,  xzr
	mov	x4,  xzr
	mov	x5,  xzr
	mov	x6,  xzr
	mov	x7,  xzr
	mov	x8,  xzr
	mov	x9,  xzr
	mov	x10, xzr
	mov	x11, xzr
	mov	x12, xzr
	mov	x13, xzr
	mov	x14, xzr
	mov	x15, xzr
	mov	x16, xzr
	mov	x17, xzr
	mov	x18, xzr
	mov	x19, xzr
	mov	x20, xzr
	mov	x21, xzr
	mov	x22, xzr
	mov	x23, xzr
	mov	x24, xzr
	mov	x25, xzr
	mov	x26, xzr
	mov	x27, xzr
	mov	x28, xzr
	mov	x29, xzr
	mov	x30, xzr

	/* 6. Control marker.
	 *
	 * MMU is off, so this store is Device-nGnRnE and cannot be sitting in a
	 * dirty cache line when the watchdog resets the board.  That makes it a
	 * valid control for the XNU markers: if this one survives into
	 * /proc/last_kmsg but XNU's does not, the evidence channel works and the
	 * payload never executed; if neither survives, the channel itself is
	 * broken across a WDT reset.
	 *
	 * Address 0x8883F0028 (vendor log region, preserved by the bootloader),
	 * clear of the kernel's markers at 0x8883F0000 (EL1) and 0x8883F0010
	 * (EL0) and of the jump module's channel control marker at 0x8883F0020.
	 */
	movz	x2, #0x0028
	movk	x2, #0x883f, lsl #16
	movk	x2, #0x0008, lsl #32		/* x2 = 0x8883F0028 */
	movz	x3, #0x4e58
	movk	x3, #0x4a55, lsl #16
	movk	x3, #0x504d, lsl #32
	movk	x3, #0x0a32, lsl #48		/* "XNUJMP2\n" */
	str	x3, [x2]
	dmb	sy

	/* 7. Branch to XNU (x0 = boot_args_pa, x1 = entry_pa).
	 *    If entry_pa is 0 (M3 test path), branch to x0 instead.
	 */
	cbz	x1, 1f
	br	x1
1:	br	x0

SYM_CODE_END(olxnu_stub_start)

	.align 3
/* Data slots — filled by do_jump before the stub executes */
SYM_DATA(olxnu_stub_ba_slot,    .quad 0)
SYM_DATA(olxnu_stub_entry_slot, .quad 0)
SYM_DATA(olxnu_stub_end,        .byte 0)

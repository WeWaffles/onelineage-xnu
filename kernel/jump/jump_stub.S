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

	/* 6. Branch to XNU (x0 = boot_args_pa, x1 = entry_pa).
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

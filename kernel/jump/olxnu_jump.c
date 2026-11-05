/*
 * olxnu_jump.c — Self-contained kexec-style EL1→XNU handoff module
 *
 * Bypasses kexec_mod.ko entirely.  Uses dcache_clean_inval_poc /
 * icache_inval_pou (both confirmed exported on this GKI build), builds
 * its own 3-level TTBR0 identity map (PGD→PUD→2MB PMD block), copies a
 * minimal ARM64 shutdown stub to a GFP_KERNEL page (linear-map so
 * virt_to_phys works), then branches to the stub at its PA.  The stub
 * disables MMU/caches and branches to the XNU payload entry point.
 *
 * Parameters (all set before triggering):
 *   payload_pa   — physical address where the XNU payload already lives
 *   payload_size — size for D-cache flush (default 8 MB)
 *   entry_pa     — XNU entry point PA (usually == payload_pa)
 *
 * Trigger: echo "go" > /proc/olxnu_jump/jump
 *
 * Safety: once "go" is written the phone RESETS.  The jump is one-way.
 * Write checkpoints are printed to dmesg before branching; they will
 * appear in /proc/last_kmsg on the next boot via vendor's RAMDUMP path.
 *
 * Build with: make -C /lab/device-abi-linux M=$(pwd) ARCH=arm64 LLVM=1 \
 *               NM=nm OBJCOPY=objcopy STRIP=strip modules
 */

#define MODULE_NAME "olxnu_jump"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/kprobes.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <asm/memory.h>
#include <asm/sysreg.h>
#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <linux/io.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("OneLineage");
MODULE_DESCRIPTION("XNU kexec jump for the arm64 target (self-contained, no kexec_mod.ko)");
MODULE_VERSION("1.0");

/* ── module parameters ──────────────────────────────────────────────── */
static unsigned long payload_pa    = 0;
static unsigned long payload_size  = 8 * 1024 * 1024; /* 8 MB */
static unsigned long entry_pa      = 0;
static unsigned long boot_args_pa  = 0;  /* XNU arm_init boot_args PA (x0); 0 = use entry_pa */
static unsigned long fb_pa         = 0;  /* XNU framebuffer PA (sweet-fbcon output) */
static unsigned long fb_size       = 10 * 1024 * 1024; /* default ~10 MB (1080x2400x4) */
/*
 * stub_offset — offset within the 64 MB payload window where the ARM64
 * shutdown stub is placed instead of a random GFP_KERNEL page.
 *
 * Random kernel pages are occasionally blocked by vendor RKP/Gunyah
 * stage-2 for NS-EL1 instruction fetch, causing the silent-jump flake
 * (XNUJMP3 lands, stub's XNUJMP2 never does). The payload window is
 * owned by alloc_contig_range() and is known-good for execution (XNU
 * runs from it successfully). Placing the stub near the end of the
 * window puts it inside a region EL2 already permits.
 *
 * Default: 0x3FF000 = last 4 KB page of a 64 MB (0x4000000) window,
 * safely past both the XNU image (~36 MB) and the framebuffer (~48 MB).
 * Set to 0 to fall back to get_zeroed_page() for M3-style tests.
 */
static unsigned long stub_offset   = 0x3FF000; /* payload window stub page */

module_param(payload_pa,   ulong, 0644);
module_param(payload_size, ulong, 0644);
module_param(entry_pa,     ulong, 0644);
module_param(boot_args_pa, ulong, 0644);
module_param(fb_pa,        ulong, 0644);
module_param(fb_size,      ulong, 0644);
module_param(stub_offset,  ulong, 0644);

MODULE_PARM_DESC(payload_pa,   "PA where XNU payload lives");
MODULE_PARM_DESC(payload_size, "Payload size for D-cache flush (default 8MB)");
MODULE_PARM_DESC(entry_pa,     "XNU entry PA");
MODULE_PARM_DESC(boot_args_pa, "XNU boot_args PA (x0 to arm_init); 0 = entry_pa (M3 test)");
MODULE_PARM_DESC(fb_pa,        "XNU sweet-fbcon framebuffer PA (minidump capture)");
MODULE_PARM_DESC(fb_size,      "XNU framebuffer size bytes (default 10MB)");
MODULE_PARM_DESC(stub_offset,  "Offset into payload window for stub page (0=GFP_KERNEL fallback)");

/* ── Qualcomm APSS WDT registers ─────────────────────────────────────── */
#define QCOM_APSS_WDT_BASE  0x17600000UL
#define QCOM_WDT_EN_OFF     0x08  /* WDT_EN: write 0 to disable, 1 to enable */
#define QCOM_WDT_RESET_OFF  0x04  /* Installed qcom_soc_wdt reset: write 1; +0xc is status. */

/* ── Qualcomm minidump region struct ─────────────────────────────────── */
#define MD_MAX_NAME_LENGTH  16
struct md_region {
	char  name[MD_MAX_NAME_LENGTH];
	u32   id;
	u64   virt_addr;
	u64   phys_addr;
	u64   size;
};
typedef int (*minidump_fn_t)(const struct md_region *);

/* ── runtime symbol resolution (kprobe→kallsyms_lookup_name pattern) ── */
typedef void (*dcache_fn_t)(unsigned long start, unsigned long end);
typedef void (*icache_fn_t)(unsigned long start, unsigned long end);
typedef void (*smp_stop_fn_t)(void);

static dcache_fn_t  fn_dcache_clean;
static icache_fn_t  fn_icache_inval;
static smp_stop_fn_t fn_smp_stop;

static void *ksym(const char *name)
{
	static unsigned long (*lookup_name)(const char *name);
	struct kprobe probe = { .symbol_name = "kallsyms_lookup_name" };
	int error;

	if (!lookup_name) {
		error = register_kprobe(&probe);
		if (error)
			return NULL;
		lookup_name = (void *)probe.addr;
		unregister_kprobe(&probe);
	}
	return (void *)lookup_name(name);
}

/* ── shutdown stub (defined in jump_stub.S) ─────────────────────────── */
extern char olxnu_stub_start[];
extern char olxnu_stub_end[];
extern u64  olxnu_stub_ba_slot;     /* data slot: boot_args PA */
extern u64  olxnu_stub_entry_slot;  /* data slot: XNU entry PA */

/* ── identity-map page tables (allocated in module_init) ─────────────  */
static unsigned long pgd_va, pud_va, pmd_va, stub_va, test_va;

/* ── helpers ────────────────────────────────────────────────────────── */

/* For GFP_KERNEL pages, the linear map guarantees virt_to_phys accuracy. */
static phys_addr_t lm_pa(unsigned long va)
{
	return virt_to_phys((void *)va);
}

/*
 * 4-level page table constants for T0SZ=16 (48-bit VA, 4KB pages).
 * Must NOT use PGDIR_SHIFT/PUD_SHIFT — this kernel is compiled with
 * VA_BITS=39 (PGDIR_SHIFT=30) but we configure T0SZ=16, requiring a
 * 4-level walk where the hardware reads L0 at bits[47:39].
 */
#define OLXNU_L0_SHIFT  39U
#define OLXNU_L1_SHIFT  30U
#define OLXNU_L2_SHIFT  21U
#define OLXNU_L_MASK    511UL  /* 9-bit index: 512 entries per level */
#define OLXNU_L2_SIZE   (1UL << OLXNU_L2_SHIFT)  /* 2 MB block */

/*
 * build_idmap — 4-level TTBR0 identity map for T0SZ=16.
 * L0[l0]→L1 table, L1[l1]→L2 table, L2[l2]→2MB block at stub_pa.
 *
 * Attributes: normal memory, AF set, inner-shareable, EL1 RWX.
 */
static void build_idmap(phys_addr_t stub_pa)
{
	u64 *pgd = (u64 *)pgd_va;  /* L0 table — indexed by bits[47:39] */
	u64 *pud = (u64 *)pud_va;  /* L1 table — indexed by bits[38:30] */
	u64 *pmd = (u64 *)pmd_va;  /* L2 table — indexed by bits[29:21] */

	phys_addr_t pud_pa  = lm_pa(pud_va);
	phys_addr_t pmd_pa  = lm_pa(pmd_va);
	phys_addr_t blk_pa  = stub_pa & ~(OLXNU_L2_SIZE - 1); /* 2MB align */

	unsigned long l0_idx = (stub_pa >> OLXNU_L0_SHIFT) & OLXNU_L_MASK;
	unsigned long l1_idx = (stub_pa >> OLXNU_L1_SHIFT) & OLXNU_L_MASK;
	unsigned long l2_idx = (stub_pa >> OLXNU_L2_SHIFT) & OLXNU_L_MASK;

	pr_info("OLXNU-IDMAP: l0[%lu] l1[%lu] l2[%lu] blk=0x%llx\n",
		l0_idx, l1_idx, l2_idx, (u64)blk_pa);

	/* table descriptors: bits[1:0] = 11 */
	pgd[l0_idx] = pud_pa | PMD_TYPE_TABLE;
	pud[l1_idx] = pmd_pa | PMD_TYPE_TABLE;

	/*
	 * 2MB block: normal mem, AF, inner-shareable, EL1 RX (read-only).
	 *
	 * AP[2]=1 (PMD_SECT_RDONLY) makes this block read-only for EL1.
	 * This is required on ARMv9 (Oryon/SM8850) because SCTLR_EL1.WXO
	 * (Write eXcludes eXecute) is enabled: a writable block cannot be
	 * executed from EL1.  Making it read-only satisfies WXO and PXN=0
	 * allows EL1 instruction fetch.  The stub is copied via the linear
	 * map (high VA, still writable there) before the idmap is installed.
	 */
	pmd[l2_idx] = blk_pa
		| PMD_ATTRINDX(MT_NORMAL)	/* MAIR index 4 */
		| PMD_TYPE_SECT			/* block descriptor */
		| PMD_SECT_AF			/* access flag */
		| PMD_SECT_S			/* inner-shareable */
		| PMD_SECT_RDONLY;		/* AP[2]=1: EL1 read-only → WXO-safe */

	dsb(ish);  /* ensure page table writes reach memory before TTBR0 install */
}

/*
 * install_idmap — flush TLBs, widen TCR_EL1.T0SZ, point TTBR0 at our PGD.
 * Called on the CPU that will execute the jump (secondary CPUs already parked).
 */
static void install_idmap(phys_addr_t stub_pa)
{
	phys_addr_t pgd_pa = lm_pa(pgd_va);
	u64 tcr;

	/* TLB flush */
	asm volatile(
		"dsb    ishst\n"
		"tlbi   vmalle1is\n"
		"dsb    ish\n"
		"isb\n"
		::: "memory");

	/* Extend T0SZ to 16, clear EPD0 to enable TTBR0 walks */
	tcr = read_sysreg(tcr_el1);
	tcr &= ~0x3FULL;	/* clear T0SZ[5:0] */
	tcr |= (64 - 48);	/* T0SZ = 16 */
	tcr &= ~(1ULL << 7);	/* EPD0=0: enable TTBR0 translation table walks */
	write_sysreg(tcr, tcr_el1);
	isb();

	write_sysreg(pgd_pa, ttbr0_el1);
	isb();

	/* TLB flush with new T0SZ */
	asm volatile(
		"dsb    ishst\n"
		"tlbi   vmalle1is\n"
		"dsb    ish\n"
		"isb\n"
		::: "memory");
}

/* ── WDT pet: refresh Qualcomm APSS non-secure watchdog ─────────────── */
static void pet_qcom_wdt(void)
{
	void __iomem *base = ioremap(QCOM_APSS_WDT_BASE, 0x1000);
	if (!base) {
		pr_warn("OLXNU: WDT ioremap failed\n");
		return;
	}
	writel_relaxed(1U, base + QCOM_WDT_RESET_OFF);
	wmb();
	iounmap(base);
	pr_info("OLXNU: WDT petted (PA=0x%lx+0x%x)\n",
		QCOM_APSS_WDT_BASE, QCOM_WDT_RESET_OFF);
}

/*
 * Write an EL1 jump marker to vendor's sec_pmsg store (survives a warm
 * reset, readable afterwards through /dev/pmsg0).
 *
 * sec_pmsg sits in a *reserved subrange of System RAM*, so ioremap() is the
 * wrong tool: ioremap_prot() warns (arch/arm64/mm/ioremap.c:28) when asked to
 * map RAM and returns NULL, which is why the marker silently never landed
 * during the 2026-10-31 M6 run.  memremap(MEMREMAP_WB) returns the linear-map
 * mapping for RAM, which is what we want to write through.
 *
 * The marker is placed 1 MB into the store so the small pmsg log the bootloader
 * maintains at the start does not overwrite it.
 */
#define SEC_PMSG_PA      0x888900000ULL
#define SEC_PMSG_SIZE    0x200000     /* 2 MB */
#define SEC_PMSG_OFFSET  0x100000     /* marker slot, away from the pmsg log */

static void sec_pmsg_write_el1_marker(void)
{
	u8 *pmsg;
	static const char marker[] = "XNUJMP1\n";

	pmsg = memremap(SEC_PMSG_PA + SEC_PMSG_OFFSET, 64, MEMREMAP_WB);
	if (!pmsg) {
		pr_warn("OLXNU: sec_pmsg memremap failed PA=0x%llx\n",
			SEC_PMSG_PA + SEC_PMSG_OFFSET);
		return;
	}
	memcpy(pmsg, marker, sizeof(marker) - 1);
	wmb();
	memunmap(pmsg);
	pr_info("OLXNU: EL1 sec_pmsg marker written PA=0x%llx\n",
		SEC_PMSG_PA + SEC_PMSG_OFFSET);
}

/* ── register XNU payload regions with Qualcomm minidump ────────────── */
static void register_xnu_minidump_region(const char *prefix,
					 unsigned long pa, unsigned long size)
{
	minidump_fn_t fn;
	struct md_region entry;
	unsigned long off;
	int idx = 1, ret;

	fn = ksym("msm_minidump_add_region");
	if (!fn) {
		pr_warn("OLXNU: msm_minidump_add_region not found\n");
		return;
	}

	/* Register in 16 MB chunks (minidump has per-entry size limits) */
	for (off = 0; off < size; off += 0x1000000, idx++) {
		unsigned long chunk = min((unsigned long)0x1000000, size - off);
		snprintf(entry.name, sizeof(entry.name), "%s%d", prefix, idx);
		entry.id        = 0;
		/*
		 * virt_addr must be the kernel VA, not the PA.
		 * phys_to_virt() is valid for pages in the linear map (System
		 * RAM); our payload and framebuffer PAs are within System RAM.
		 */
		entry.virt_addr = (u64)phys_to_virt(pa + off);
		entry.phys_addr = pa + off;
		entry.size      = chunk;
		ret = fn(&entry);
		pr_info("OLXNU: minidump %s%d PA=0x%lx VA=0x%llx sz=0x%lx ret=%d\n",
			prefix, idx, pa + off,
			entry.virt_addr, chunk, ret);
	}
}

static void register_xnu_minidump(unsigned long pa, unsigned long size)
{
	register_xnu_minidump_region("XNUPLD", pa, size);
}

static void register_xnu_fb_minidump(unsigned long pa, unsigned long size)
{
	register_xnu_minidump_region("XNUFB", pa, size);
}


/* ── stub preparation (shared by do_jump and /proc/olxnu_jump/stub) ─── */

/*
 * prepare_stub — copy the shutdown stub into stub_va, fill its data slots,
 * flush it to memory, and verify the copy word for word.
 *
 * The verification is the point.  A run that shows the module's control
 * markers but not the stub's own marker (XNUJMP2) cannot, on its own, tell
 * "the branch never reached the stub" apart from "the branch reached a
 * corrupt or stale copy".  Reading the copy back and comparing it against the
 * module's own text makes that difference explicit, and it happens before any
 * page-table change, so a mismatch is reported through normal pr_info.
 *
 * __nocfi: fn_dcache_clean/fn_icache_inval are kallsyms-resolved function
 * pointers, so every indirect call made here fails CONFIG_CFI_CLANG's check
 * unless the caller is marked __nocfi.  Calling this from a CFI-checked path
 * (the /proc reader below) without the annotation panics with
 * "Oops - CFI ... prepare_stub+0x..".
 *
 * Returns the physical address the stub will be branched to.
 */
static phys_addr_t __nocfi prepare_stub(unsigned long ba_pa, unsigned long e_pa)
{
	size_t stub_len = olxnu_stub_end - olxnu_stub_start;
	size_t ba_slot_off    = (size_t)&olxnu_stub_ba_slot    - (size_t)olxnu_stub_start;
	size_t entry_slot_off = (size_t)&olxnu_stub_entry_slot - (size_t)olxnu_stub_start;
	u32 *src = (u32 *)olxnu_stub_start;
	u32 *dst = (u32 *)stub_va;
	unsigned int bad = 0, first_bad = 0;
	unsigned int i;
	phys_addr_t pa;

	BUG_ON(stub_len > PAGE_SIZE);

	memcpy((void *)stub_va, olxnu_stub_start, stub_len);
	*(u64 *)(stub_va + ba_slot_off)    = (u64)ba_pa;
	*(u64 *)(stub_va + entry_slot_off) = (u64)e_pa;

	pa = lm_pa(stub_va);

	fn_dcache_clean(stub_va, stub_va + stub_len);
	fn_icache_inval(stub_va, stub_va + stub_len);
	dsb(ish);
	isb();

	/* Every word must match the source, except the two 64-bit data slots. */
	for (i = 0; i < stub_len / 4; i++) {
		u32 want = src[i];

		if (4 * i == ba_slot_off)
			want = (u32)ba_pa;
		else if (4 * i == ba_slot_off + 4)
			want = (u32)((u64)ba_pa >> 32);
		else if (4 * i == entry_slot_off)
			want = (u32)e_pa;
		else if (4 * i == entry_slot_off + 4)
			want = (u32)((u64)e_pa >> 32);
		if (dst[i] != want) {
			if (!bad)
				first_bad = i;
			bad++;
		}
	}

	pr_info("OLXNU-STUB: len=0x%zx va=0x%lx pa=0x%llx bad=%u%s\n",
		stub_len, stub_va, (u64)pa, bad,
		bad ? " (COPY MISMATCH)" : " (copy verified)");
	pr_info("OLXNU-STUB: words %08x %08x %08x %08x; slots @%zu@%zu = 0x%llx/0x%llx\n",
		dst[0], dst[1], dst[2], dst[3], ba_slot_off, entry_slot_off,
		(u64)ba_pa, (u64)e_pa);
	if (bad)
		pr_err("OLXNU-STUB: first mismatch at +0x%x: have %08x want %08x\n",
		       4 * first_bad, dst[first_bad], src[first_bad]);

	return pa;
}

/* ── the jump ───────────────────────────────────────────────────────── */

static void __nocfi do_jump(unsigned long ba_pa, unsigned long e_pa)
{
	phys_addr_t stub_pa;
	u8 *ctl;
	typedef void (*stub_fn_t)(unsigned long ba, unsigned long entry);

	/* Write EL1 marker to sec_pmsg (readable via pstore after reboot) */
	sec_pmsg_write_el1_marker();

	/* Register XNU payload with minidump so WP dump captures it */
	if (payload_pa && payload_size)
		register_xnu_minidump(payload_pa, payload_size);

	/* Register framebuffer with minidump — XNU sweet-fbcon writes here */
	if (fb_pa && fb_size)
		register_xnu_fb_minidump(fb_pa, fb_size);


	/* Pet WDT to give XNU the maximum possible run window */
	pet_qcom_wdt();

	pr_info("OLXNU-CP1: parking secondary CPUs\n");
	fn_smp_stop();
	local_irq_disable();
	pr_info("OLXNU-CP2: single-CPU mode\n");

	/* Flush payload from D-cache to main memory */
	if (payload_pa && payload_size) {
		unsigned long va_start = (unsigned long)phys_to_virt(payload_pa);
		fn_dcache_clean(va_start, va_start + payload_size);
		pr_info("OLXNU-CP3: payload cache flushed PA=0x%lx+0x%lx\n",
			payload_pa, payload_size);
	}

	/* Copy the stub, fill its data slots, flush it, and verify the copy */
	stub_pa = prepare_stub(ba_pa, e_pa);

	/*
	 * Control marker for the post-reset evidence channel.
	 *
	 * Written here by Linux — not by the stub, not by XNU — with the D-cache
	 * cleaned explicitly.  Its presence in /proc/last_kmsg after a WDT reset
	 * proves the channel works for writes made microseconds before the reset.
	 * Without it, a missing XNU marker cannot be told apart from a channel
	 * that simply does not survive the reset.
	 *
	 * The whole marker line is cleaned and invalidated, not just the control
	 * slot: the log buffer's old contents are still cached (dirty) there, and
	 * a later writeback would erase the uncached stores the stub and XNU make
	 * into the same line microseconds from now.  That is why the markers were
	 * invisible on the runs that did not do this.
	 *
	 * 0x8883F0020 is clear of the stub's marker (0x8883F0028) and the
	 * kernel's EL1/EL0 markers (0x8883F0000 / 0x8883F0010).
	 * 0x8883F0030 holds XNUJMP4, written after the switch (below).
	 */
	ctl = memremap(0x8883F0000UL, 128, MEMREMAP_WB);
	if (ctl) {
		memcpy(ctl + 0x20, "XNUJMP3\n", 8);
		wmb();
		fn_dcache_clean((unsigned long)ctl, (unsigned long)ctl + 128);
	} else {
		pr_warn("OLXNU: control marker memremap failed\n");
	}

	/* Build and install identity map for stub */
	build_idmap(stub_pa);
	install_idmap(stub_pa);
	pr_info("OLXNU-CP4: idmap installed stub_pa=0x%llx ba=0x%lx entry=0x%lx\n",
		(u64)stub_pa, ba_pa, e_pa);

	/*
	 * Post-switch marker (XNUJMP4).
	 *
	 * Written through the same linear-map alias the marker above used: a
	 * TTBR1 address, which our TTBR0 table does not touch, so it must still
	 * translate after the switch.  Landing it proves Linux itself fetched,
	 * stored and returned normally with TTBR0 pointing at the identity
	 * table.  If XNUJMP3 and XNUJMP4 both survive but the stub's XNUJMP2 does
	 * not, the page-table switch is exonerated and the fault is the branch
	 * or the stub page itself.
	 */
	if (ctl) {
		memcpy(ctl + 0x30, "XNUJMP4\n", 8);
		wmb();
		fn_dcache_clean((unsigned long)ctl, (unsigned long)ctl + 128);
		memunmap(ctl);
	}

	pr_info("OLXNU-CP5: JUMPING (last dmesg line before reset)\n");

	((stub_fn_t)(stub_pa))(ba_pa, e_pa);

	/* unreachable */
	BUG();
}

/* defined below, used by jump_write */
static int probe_write_marker(void);

/* ── procfs trigger ─────────────────────────────────────────────────── */

static ssize_t jump_write(struct file *f, const char __user *buf,
			  size_t len, loff_t *off)
{
	char cmd[8];

	if (len < 2 || len > 8)
		return -EINVAL;
	if (copy_from_user(cmd, buf, min(len, sizeof(cmd) - 1)))
		return -EFAULT;
	cmd[min(len, sizeof(cmd) - 1)] = '\0';

	/* "mark" writes only the EL1 sec_pmsg marker — used to validate the
	 * post-reset evidence channel without performing a jump. */
	if (strncmp(cmd, "mark", 4) == 0) {
		sec_pmsg_write_el1_marker();
		return len;
	}

	if (strncmp(cmd, "poke", 4) == 0) {
		probe_write_marker();
		return len;
	}

	if (strncmp(cmd, "go", 2) == 0) {
		if (!entry_pa) {
			pr_err("entry_pa not set — refusing jump\n");
			return -EINVAL;
		}
		/* boot_args_pa=0 means M3 test (no real XNU boot_args) */
		unsigned long ba = boot_args_pa ? boot_args_pa : entry_pa;
		pr_info("OLXNU: jump requested entry_pa=0x%lx boot_args_pa=0x%lx\n",
			entry_pa, ba);
		do_jump(ba, boot_args_pa ? entry_pa : 0);
	}
	return len;
}

static ssize_t jump_read(struct file *f, char __user *buf,
			 size_t len, loff_t *off)
{
	char tmp[256];
	int n;

	if (*off)
		return 0;
	n = snprintf(tmp, sizeof(tmp),
		"payload_pa=0x%lx payload_size=0x%lx entry_pa=0x%lx boot_args_pa=0x%lx\n"
		"test_pa=0x%llx (b. loop — safe M3 test)\n",
		payload_pa, payload_size, entry_pa, boot_args_pa,
		(u64)lm_pa(test_va));
	if (copy_to_user(buf, tmp, min((size_t)n, len)))
		return -EFAULT;
	*off = n;
	return min((size_t)n, len);
}

static const struct proc_ops jump_proc_ops = {
	.proc_write = jump_write,
	.proc_read  = jump_read,
};

/*
 * /proc/olxnu_jump/pmsg — dump the marker slot back to userspace.
 *
 * /dev/pmsg0 only exposes the pmsg *log records* maintained by the driver, not
 * raw store contents, so the marker has to be read through a mapping.  This is
 * the reader used to check the marker after a reset.
 */
static ssize_t pmsg_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
	u8 *pmsg;
	char tmp[96];
	int n, i;

	if (*off)
		return 0;

	pmsg = memremap(SEC_PMSG_PA + SEC_PMSG_OFFSET, 64, MEMREMAP_WB);
	if (!pmsg)
		return -ENOMEM;

	n = snprintf(tmp, sizeof(tmp),
		     "PA=0x%llx raw=", SEC_PMSG_PA + SEC_PMSG_OFFSET);
	for (i = 0; i < 16; i++) {
		u8 c = pmsg[i];
		/* printable bytes as-is, everything else as . */
		n += snprintf(tmp + n, sizeof(tmp) - n, "%c",
			      (c >= 0x20 && c < 0x7f) ? c : '.');
	}
	n += snprintf(tmp + n, sizeof(tmp) - n, " hex=");
	for (i = 0; i < 16 && n < (int)sizeof(tmp) - 4; i++)
		n += snprintf(tmp + n, sizeof(tmp) - n, "%02x", pmsg[i]);
	n += snprintf(tmp + n, sizeof(tmp) - n, "\n");

	memunmap(pmsg);

	if (copy_to_user(buf, tmp, min((size_t)n, len)))
		return -EFAULT;
	*off = n;
	return min((size_t)n, len);
}

static const struct proc_ops pmsg_proc_ops = {
	.proc_read = pmsg_read,
};

/*
 * Generic poke/peek over a reserved physical page — used to find a memory
 * channel that survives a reset (the EL0 marker needs one).  Set the address
 * through /sys/module/olxnu_jump/parameters/probe_pa, then:
 *
 *   echo poke > /proc/olxnu_jump/jump    # write XNUPT01 magic at probe_pa
 *   cat /proc/olxnu_jump/peek            # read it back
 */
#define POKE_MAGIC "XNUPT01\n"

static unsigned long probe_pa;
module_param(probe_pa, ulong, 0644);
MODULE_PARM_DESC(probe_pa, "PA for the poke/peek reset-survival probe");

static int probe_write_marker(void)
{
	u8 *p;

	if (!probe_pa) {
		pr_warn("poke: probe_pa not set\n");
		return -EINVAL;
	}

	p = memremap(probe_pa, 64, MEMREMAP_WB);
	if (!p) {
		pr_warn("poke: memremap 0x%lx failed\n", probe_pa);
		return -ENOMEM;
	}
	memcpy(p, POKE_MAGIC, sizeof(POKE_MAGIC) - 1);
	wmb();
	memunmap(p);

	pr_info("poke: wrote %s at PA=0x%lx\n", POKE_MAGIC, probe_pa);
	return 0;
}

static ssize_t peek_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
	u8 *p;
	char tmp[128];
	int n, i;

	if (*off)
		return 0;
	if (!probe_pa)
		return -EINVAL;

	p = memremap(probe_pa, 64, MEMREMAP_WB);
	if (!p)
		return -ENOMEM;

	n = snprintf(tmp, sizeof(tmp), "PA=0x%lx raw=", probe_pa);
	for (i = 0; i < 12; i++) {
		u8 c = p[i];
		n += snprintf(tmp + n, sizeof(tmp) - n, "%c",
			      (c >= 0x20 && c < 0x7f) ? c : '.');
	}
	n += snprintf(tmp + n, sizeof(tmp) - n, " hex=");
	for (i = 0; i < 12 && n < (int)sizeof(tmp) - 4; i++)
		n += snprintf(tmp + n, sizeof(tmp) - n, "%02x", p[i]);
	n += snprintf(tmp + n, sizeof(tmp) - n, "\n");

	memunmap(p);

	if (copy_to_user(buf, tmp, min((size_t)n, len)))
		return -EFAULT;
	*off = n;
	return min((size_t)n, len);
}

static const struct proc_ops peek_proc_ops = {
	.proc_read = peek_read,
};

/*
 * /proc/olxnu_jump/stub — show what the jump will actually execute.
 *
 * Runs the same copy-and-verify as do_jump with the currently configured
 * boot_args/entry, then prints the physical address, the page-table indices
 * that will map it, and the first instructions.  Checking this before
 * `echo go` tells a bad copy or a bad mapping apart from a bad branch without
 * spending a reset.
 */
static ssize_t __nocfi stub_read(struct file *f, char __user *buf, size_t len,
				 loff_t *off)
{
	phys_addr_t pa;
	unsigned long i;
	char *tmp;
	u32 *dst;
	int n = 0, ret;

	if (*off)
		return 0;

	tmp = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	pa  = prepare_stub(boot_args_pa, entry_pa);
	dst = (u32 *)stub_va;

	n += snprintf(tmp + n, PAGE_SIZE - n,
		"stub_len=0x%zx va=0x%lx pa=0x%llx\n",
		(size_t)(olxnu_stub_end - olxnu_stub_start), stub_va, (u64)pa);
	n += snprintf(tmp + n, PAGE_SIZE - n,
		"idmap blk=0x%llx l0[%lu] l1[%lu] l2[%lu]\n"
		"pgd=0x%llx pud=0x%llx pmd=0x%llx stub=%llx\n",
		(u64)(pa & ~(OLXNU_L2_SIZE - 1)),
		(unsigned long)((pa >> OLXNU_L0_SHIFT) & OLXNU_L_MASK),
		(unsigned long)((pa >> OLXNU_L1_SHIFT) & OLXNU_L_MASK),
		(unsigned long)((pa >> OLXNU_L2_SHIFT) & OLXNU_L_MASK),
		(u64)lm_pa(pgd_va), (u64)lm_pa(pud_va),
		(u64)lm_pa(pmd_va), (u64)(pa & ~(OLXNU_L2_SIZE - 1)));

	for (i = 0; i < 16 && (size_t)4 * i < olxnu_stub_end - olxnu_stub_start; i++)
		n += snprintf(tmp + n, PAGE_SIZE - n, "%08x%c", dst[i],
			      (i % 8 == 7) ? '\n' : ' ');

	ret = copy_to_user(buf, tmp, min((size_t)n, len));
	kfree(tmp);
	if (ret)
		return -EFAULT;
	*off = n;
	return min((size_t)n, len);
}

static const struct proc_ops stub_proc_ops = {
	.proc_read = stub_read,
};

/*
 * /proc/<name>/sysregs — the translation state this module is running under.
 *
 * Every hypothesis about why XNU's own MMU enable fails has to be measured
 * against the configuration that demonstrably works on this phone: this one.
 * The host kernel runs at the same EL1, in the same memory, with translation
 * enabled, and the jump stub re-enables M through these very tables, so this is
 * not a proxy for the working configuration — it *is* it.
 *
 * Read-only, no reset risk.
 */
#define OLXNU_MRS(name, reg) \
	asm volatile("mrs %0, " #reg : "=r"(name))

static ssize_t sysregs_read(struct file *f, char __user *buf, size_t len,
			    loff_t *off)
{
	u64 midr, pfr0, pfr1, mmfr0, mmfr1, mmfr2, sctlr, tcr, ttbr0, ttbr1, mair;
	u64 tsz, ips;
	char *tmp;
	int n = 0, ret;

	if (*off)
		return 0;

	tmp = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	OLXNU_MRS(midr, midr_el1);
	OLXNU_MRS(pfr0, id_aa64pfr0_el1);
	OLXNU_MRS(pfr1, id_aa64pfr1_el1);
	OLXNU_MRS(mmfr0, id_aa64mmfr0_el1);
	OLXNU_MRS(mmfr1, id_aa64mmfr1_el1);
	OLXNU_MRS(mmfr2, id_aa64mmfr2_el1);
	OLXNU_MRS(sctlr, sctlr_el1);
	OLXNU_MRS(tcr, tcr_el1);
	OLXNU_MRS(ttbr0, ttbr0_el1);
	OLXNU_MRS(ttbr1, ttbr1_el1);
	OLXNU_MRS(mair, mair_el1);

	n += snprintf(tmp + n, PAGE_SIZE - n,
		"midr=0x%llx pfr0=0x%llx pfr1=0x%llx\n"
		"mmfr0=0x%llx mmfr1=0x%llx mmfr2=0x%llx\n"
		"sctlr_el1=0x%llx tcr_el1=0x%llx\n"
		"ttbr0_el1=0x%llx ttbr1_el1=0x%llx mair_el1=0x%llx\n",
		midr, pfr0, pfr1, mmfr0, mmfr1, mmfr2,
		sctlr, tcr, ttbr0, ttbr1, mair);

	tsz = tcr & 0x3f;
	n += snprintf(tmp + n, PAGE_SIZE - n,
		"tcr: t0sz=%llu (va=%llu) tg0=%llu irgn0=%llu orgn0=%llu sh0=%llu\n",
		tsz, 64 - tsz, (tcr >> 14) & 3, (tcr >> 8) & 3, (tcr >> 10) & 3,
		(tcr >> 12) & 3);
	tsz = (tcr >> 16) & 0x3f;
	ips = (tcr >> 32) & 7;
	n += snprintf(tmp + n, PAGE_SIZE - n,
		"tcr: t1sz=%llu (va=%llu) tg1=%llu irgn1=%llu orgn1=%llu sh1=%llu "
		"ips=%llu epd0=%llu epd1=%llu tbi0=%llu tbi1=%llu\n",
		tsz, 64 - tsz, (tcr >> 30) & 3, (tcr >> 24) & 3, (tcr >> 26) & 3,
		(tcr >> 28) & 3, ips, (tcr >> 7) & 1, (tcr >> 23) & 1,
		(tcr >> 37) & 1, (tcr >> 38) & 1);
	n += snprintf(tmp + n, PAGE_SIZE - n,
		"mmfr0: parange=%llu asidbits=%llu tgran4=%llu tgran16=%llu "
		"tgran64=%llu tgran4_2=%llu tgran64_2=%llu tgran16_2=%llu\n",
		mmfr0 & 0xf, (mmfr0 >> 4) & 0xf, (mmfr0 >> 28) & 0xf,
		(mmfr0 >> 20) & 0xf, (mmfr0 >> 24) & 0xf, (mmfr0 >> 40) & 0xf,
		(mmfr0 >> 44) & 0xf, (mmfr0 >> 48) & 0xf);

	ret = copy_to_user(buf, tmp, min((size_t)n, len));
	kfree(tmp);
	if (ret)
		return -EFAULT;
	*off = n;
	return min((size_t)n, len);
}

static const struct proc_ops sysregs_proc_ops = {
	.proc_read = sysregs_read,
};

/* ── module lifecycle ───────────────────────────────────────────────── */

static struct proc_dir_entry *proc_dir;

/*
 * proc_name — procfs directory this instance publishes.
 *
 * A stale olxnu_jump_mod loaded earlier in the boot (Android loads modules
 * with MODULE_FLAG_PERMANENT, so it cannot be rmmod'd) keeps /proc/olxnu_jump.
 * Loading a second instance under its own directory makes the current build
 * usable on that boot without disturbing whatever is already there.
 */
static char *proc_name = "olxnu_jump";
module_param(proc_name, charp, 0444);
MODULE_PARM_DESC(proc_name, "procfs directory name (default olxnu_jump)");

static int __init olxnu_jump_init(void)
{
	u32 *p;
	int i;

	fn_dcache_clean = ksym("dcache_clean_inval_poc");
	fn_icache_inval = ksym("icache_inval_pou");
	fn_smp_stop     = ksym("smp_send_stop");
	if (!fn_dcache_clean || !fn_icache_inval || !fn_smp_stop) {
		pr_err("symbol resolution failed: dcache=%p icache=%p smp_stop=%p\n",
			fn_dcache_clean, fn_icache_inval, fn_smp_stop);
		return -ENOENT;
	}

	pgd_va  = get_zeroed_page(GFP_KERNEL);
	pud_va  = get_zeroed_page(GFP_KERNEL);
	pmd_va  = get_zeroed_page(GFP_KERNEL);
	test_va = get_zeroed_page(GFP_KERNEL);

	if (!pgd_va || !pud_va || !pmd_va || !test_va) {
		pr_err("page allocation failed\n");
		return -ENOMEM;
	}

	/*
	 * Place the stub in the owned payload window when possible.
	 *
	 * Random GFP_KERNEL pages are occasionally blocked for NS-EL1
	 * instruction fetch by vendor RKP / Gunyah stage-2, causing a
	 * silent jump: XNUJMP3 lands but the stub's XNUJMP2 never does.
	 * The payload window (alloc_contig_range owned) is the only range
	 * confirmed to permit execution — XNU runs from it.
	 *
	 * stub_offset defaults to 0x3FF000 (last 4 KB of the 64 MB window,
	 * past both the 36 MB image and the 10 MB framebuffer at +48 MB).
	 *
	 * prepare_stub() overwrites this page with the stub bytes before the
	 * jump, so its current contents (XNU payload padding) don't matter.
	 */
	if (payload_pa && stub_offset) {
		stub_va = (unsigned long)phys_to_virt(payload_pa + stub_offset);
		pr_info("OLXNU: stub in payload window PA=0x%lx VA=0x%lx\n",
			payload_pa + stub_offset, stub_va);
	} else {
		stub_va = get_zeroed_page(GFP_KERNEL);
		if (!stub_va) {
			pr_err("stub page allocation failed\n");
			return -ENOMEM;
		}
		pr_info("OLXNU: stub on GFP_KERNEL page PA=0x%llx\n",
			(u64)lm_pa(stub_va));
	}

	/* Fill test page with ARM64 "b ." (infinite loop = 0x14000000 LE) */
	p = (u32 *)test_va;
	for (i = 0; i < PAGE_SIZE / sizeof(u32); i++)
		p[i] = 0x14000000;

	proc_dir = proc_mkdir(proc_name, NULL);
	if (!proc_dir) {
		pr_err("procfs mkdir /proc/%s failed\n", proc_name);
		return -ENOMEM;
	}

	proc_create("jump", 0644, proc_dir, &jump_proc_ops);
	proc_create("pmsg", 0444, proc_dir, &pmsg_proc_ops);
	proc_create("peek", 0444, proc_dir, &peek_proc_ops);
	proc_create("stub", 0444, proc_dir, &stub_proc_ops);
	proc_create("sysregs", 0444, proc_dir, &sysregs_proc_ops);

	pr_info("loaded: proc=/proc/%s pages pgd=%pa pud=%pa pmd=%pa stub=%pa test=%pa\n",
		proc_name,
		&(phys_addr_t){ lm_pa(pgd_va) },
		&(phys_addr_t){ lm_pa(pud_va) },
		&(phys_addr_t){ lm_pa(pmd_va) },
		&(phys_addr_t){ lm_pa(stub_va) },
		&(phys_addr_t){ lm_pa(test_va) });
	pr_info("M3 test: entry_pa=0x%llx (b. loop), then echo go > /proc/olxnu_jump/jump\n",
		(u64)lm_pa(test_va));
	return 0;
}

static void __exit olxnu_jump_exit(void)
{
	proc_remove(proc_dir);
	if (pgd_va)  free_page(pgd_va);
	if (pud_va)  free_page(pud_va);
	if (pmd_va)  free_page(pmd_va);
	/* do not free stub_va when it points into the payload window */
	if (stub_va && !(payload_pa && stub_offset))
		free_page(stub_va);
	if (test_va) free_page(test_va);
}

module_init(olxnu_jump_init);
module_exit(olxnu_jump_exit);

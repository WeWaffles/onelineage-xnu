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
 * appear in /proc/last_kmsg on the next boot via Samsung's RAMDUMP path.
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

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("OneLineage");
MODULE_DESCRIPTION("XNU kexec jump for SM-S948U (self-contained, no kexec_mod.ko)");
MODULE_VERSION("1.0");

/* ── module parameters ──────────────────────────────────────────────── */
static unsigned long payload_pa    = 0;
static unsigned long payload_size  = 8 * 1024 * 1024; /* 8 MB */
static unsigned long entry_pa      = 0;
static unsigned long boot_args_pa  = 0;  /* XNU arm_init boot_args PA (x0); 0 = use entry_pa */

module_param(payload_pa,   ulong, 0644);
module_param(payload_size, ulong, 0644);
module_param(entry_pa,     ulong, 0644);
module_param(boot_args_pa, ulong, 0644);

MODULE_PARM_DESC(payload_pa,   "PA where XNU payload lives");
MODULE_PARM_DESC(payload_size, "Payload size for D-cache flush (default 8MB)");
MODULE_PARM_DESC(entry_pa,     "XNU entry PA");
MODULE_PARM_DESC(boot_args_pa, "XNU boot_args PA (x0 to arm_init); 0 = entry_pa (M3 test)");

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

/* ── the jump ───────────────────────────────────────────────────────── */

static void __nocfi do_jump(unsigned long ba_pa, unsigned long e_pa)
{
	phys_addr_t stub_pa;
	size_t stub_len = olxnu_stub_end - olxnu_stub_start;
	size_t ba_slot_off, entry_slot_off;
	typedef void (*stub_fn_t)(unsigned long ba, unsigned long entry);

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

	/* Copy stub to stub page */
	BUG_ON(stub_len > PAGE_SIZE);
	memcpy((void *)stub_va, olxnu_stub_start, stub_len);

	/*
	 * Fill in boot_args_pa and entry_pa into the data slots
	 * embedded at the end of the stub.  The slots are at the
	 * same offsets in the copied stub as in the original binary.
	 */
	ba_slot_off    = (size_t)&olxnu_stub_ba_slot    - (size_t)olxnu_stub_start;
	entry_slot_off = (size_t)&olxnu_stub_entry_slot - (size_t)olxnu_stub_start;
	*(u64 *)(stub_va + ba_slot_off)    = (u64)ba_pa;
	*(u64 *)(stub_va + entry_slot_off) = (u64)e_pa;

	stub_pa = lm_pa(stub_va);

	/* Flush stub (including filled-in data slots) from D-cache */
	fn_dcache_clean(stub_va, stub_va + stub_len);
	fn_icache_inval(stub_va, stub_va + stub_len);
	dsb(ish);
	isb();

	/* Build and install identity map for stub */
	build_idmap(stub_pa);
	install_idmap(stub_pa);
	pr_info("OLXNU-CP4: idmap installed stub_pa=0x%llx ba=0x%lx entry=0x%lx\n",
		(u64)stub_pa, ba_pa, e_pa);

	pr_info("OLXNU-CP5: JUMPING (last dmesg line before reset)\n");

	((stub_fn_t)(stub_pa))(ba_pa, e_pa);

	/* unreachable */
	BUG();
}

/* ── procfs trigger ─────────────────────────────────────────────────── */

static ssize_t jump_write(struct file *f, const char __user *buf,
			  size_t len, loff_t *off)
{
	char cmd[8];

	if (len < 2 || len > 6)
		return -EINVAL;
	if (copy_from_user(cmd, buf, min(len, sizeof(cmd) - 1)))
		return -EFAULT;
	cmd[min(len, sizeof(cmd) - 1)] = '\0';

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

/* ── module lifecycle ───────────────────────────────────────────────── */

static struct proc_dir_entry *proc_dir;

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
	stub_va = get_zeroed_page(GFP_KERNEL);
	test_va = get_zeroed_page(GFP_KERNEL);

	if (!pgd_va || !pud_va || !pmd_va || !stub_va || !test_va) {
		pr_err("page allocation failed\n");
		return -ENOMEM;
	}

	/* Fill test page with ARM64 "b ." (infinite loop = 0x14000000 LE) */
	p = (u32 *)test_va;
	for (i = 0; i < PAGE_SIZE / sizeof(u32); i++)
		p[i] = 0x14000000;

	proc_dir = proc_mkdir("olxnu_jump", NULL);
	if (!proc_dir) {
		pr_err("procfs mkdir failed\n");
		return -ENOMEM;
	}

	proc_create("jump", 0644, proc_dir, &jump_proc_ops);

	pr_info("loaded: pages pgd=%pa pud=%pa pmd=%pa stub=%pa test=%pa\n",
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
	if (stub_va) free_page(stub_va);
	if (test_va) free_page(test_va);
}

module_init(olxnu_jump_init);
module_exit(olxnu_jump_exit);

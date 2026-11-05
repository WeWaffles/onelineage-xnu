/*
 * olxnu_payload.c — Contiguous physical memory loader for XNU payload
 *
 * Strategy 1 (primary): alloc_contig_range() on the requested target PA.
 *   Takes the pages out of the buddy allocator and hands them to us
 *   exclusively, so streaming the image cannot corrupt live kernel data.
 *   This is the same primitive CMA uses to carve contiguous ranges.
 *
 * Strategy 1b (opt-in, unsafe): memremap() the range and borrow it.
 *   Only with borrow_unsafe=1.  Non-reserved System RAM still belongs to the
 *   page allocator, so writing into it can overwrite whatever the allocator
 *   handed out from there (see the RWC 117 note in try_acr_target()).
 *
 * Strategy 2 (CMA fallback): alloc_contig_range(MIGRATE_CMA=4) on the QDSS
 *   apps CMA pool at 0x82800000 (reusable, 32 MB).  This gives exactly-owned
 *   pages but limits physical_base to 0x82800000.
 *
 * Strategy 3 (last resort): dma_alloc_coherent() at half payload_size_mb.
 *
 * After loading:
 *   cat /proc/olxnu_payload/info      → PA, size, write_pos
 *   dd if=xnu.bin of=/proc/olxnu_payload/data bs=1M
 *   Then configure olxnu_jump_mod via /sys/module/.../parameters
 */

#define MODULE_NAME "olxnu_payload"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/vmalloc.h>
#include <linux/dma-mapping.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <asm/page.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("OneLineage");
MODULE_DESCRIPTION("XNU contiguous payload loader via alloc_contig_range");
MODULE_VERSION("1.0");

static unsigned int payload_size_mb = 64;
module_param(payload_size_mb, uint, 0444);
MODULE_PARM_DESC(payload_size_mb, "Payload size in MB (default 64)");

/*
 * XNU maps the kernel with 2 MB blocks, and the runs say alignment matters:
 * every allocation that landed at 0xb7404000 (a 2 MB base plus 0x4000) produced
 * no records at all across eight runs, while 8 of 9 at 0xb7400000 did
 * (RUNLOG.md, 2026-11-03).  Rather than ask the allocator again and hope, shift
 * the image up to the next 2 MB boundary inside the same block when there is
 * room for it.
 */
#define PAYLOAD_ALIGN     (2UL << 20)
#define PAYLOAD_ALIGN_MIN (8UL << 20)

/*
 * Default target PA: start of the 9.25 GB System RAM block.
 * ZONE_MOVABLE is empty on this device so alloc_contig_range(MOVABLE) fails;
 * we use phys_to_virt() directly — the pages are in the linear map and
 * we're about to clobber them for XNU anyway.
 */
static unsigned long target_pa = 0x8c0000000UL;
module_param(target_pa, ulong, 0444);
MODULE_PARM_DESC(target_pa, "Target PA for the payload (must be pageblock-aligned)");

/*
 * Borrowing non-reserved System RAM via memremap() is NOT safe: those pages
 * are still owned by the page allocator and can be in use (page tables,
 * slab, driver buffers) at the moment we write the image.  Opt in only for
 * debugging.
 */
static unsigned int borrow_unsafe = 0;
module_param(borrow_unsafe, uint, 0444);
MODULE_PARM_DESC(borrow_unsafe, "memremap() non-reserved System RAM instead of owning it (can corrupt live kernel data)");

/*
 * Non-reserved System RAM on this device (from /proc/iomem), minus the RBIN
 * tail.  The image must live inside this window: below it is firmware, above
 * it vendor's RAM compression region.
 */
#define OLXNU_SAFE_START 0x9FF000000UL
#define OLXNU_SAFE_END   0xAEAB0E000UL

static unsigned int auto_base = 0;
module_param(auto_base, uint, 0644);
MODULE_PARM_DESC(auto_base, "Scan the safe window for an isolatable payload window if target_pa fails");

static unsigned int scan_limit = 1024;
module_param(scan_limit, uint, 0644);
MODULE_PARM_DESC(scan_limit, "Max candidate windows to probe when auto_base=1 (default 1024)");

/* Isolation works at pageblock (2 MB) granularity, so slide by one pageblock. */
#define OLXNU_SCAN_STEP 0x200000UL

/*
 * QDSS apps CMA PA: qdss_apps_region@82800000, 32 MB, compatible=shared-dma-pool
 * reusable (MIGRATE_CMA pages in linear map).  Tried only if primary fails.
 */
#define QDSS_PA        0x82800000UL
#define QDSS_SIZE_MB   32U

/* ── runtime symbol resolution ──────────────────────────────────────── */

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

/*
 * alloc_contig_range(start_pfn, end_pfn, migratetype, gfp_mask)
 * Carves out a contiguous PFN range from ZONE_MOVABLE by migrating pages.
 * Returns 0 on success, negative on failure.
 */
typedef int (*acr_fn_t)(unsigned long, unsigned long, unsigned, unsigned);
typedef void (*fcr_fn_t)(unsigned long, unsigned long);

static acr_fn_t fn_acr;
static fcr_fn_t fn_fcr;

typedef void *(*vmap_fn_t)(struct page **, unsigned int, unsigned long, pgprot_t);

/* ── payload state ──────────────────────────────────────────────────── */

static struct page  **payload_pages;
static void          *payload_va;    /* VA to write payload data */
static phys_addr_t    payload_pa;    /* PA of first byte (contiguous) */
static size_t         payload_sz;
static loff_t         write_pos;

enum alloc_method { METHOD_NONE, METHOD_ACR_TARGET, METHOD_LINEAR,
		    METHOD_CMA_ACR, METHOD_CMA_AREA, METHOD_DMA };

/* mmzone.h migratetypes, spelled out to avoid header/version drift */
#define OLXNU_MIGRATE_UNMOVABLE 0
#define OLXNU_MIGRATE_MOVABLE   1
#define OLXNU_MIGRATE_CMA       4
static enum alloc_method used_method;

/* For METHOD_DMA */
static struct platform_device *pdev;
static void          *dma_va;
static dma_addr_t     dma_pa;

/* ── procfs: info ─────────────────────────────────────────────────── */

static const char *method_name(void)
{
	switch (used_method) {
	case METHOD_ACR_TARGET: return "alloc_contig_range(owned)";
	case METHOD_LINEAR:  return "memremap(MEMREMAP_WB, borrowed)";
	case METHOD_CMA_ACR: return "alloc_contig_range(CMA pool)";
	case METHOD_CMA_AREA: return "cma_alloc(named area)";
	case METHOD_DMA:     return "dma_alloc_coherent";
	default:             return "none";
	}
}

static ssize_t info_read(struct file *f, char __user *buf,
			  size_t len, loff_t *off)
{
	char tmp[512];
	int n;

	if (*off)
		return 0;
	n = snprintf(tmp, sizeof(tmp),
		"payload_pa=0x%llx\n"
		"payload_va=%px\n"
		"payload_sz=0x%zx (%zu MB actual, %u MB requested)\n"
		"write_pos=0x%llx (%llu bytes)\n"
		"alloc_method=%s\n"
		"ready=%s\n",
		(u64)payload_pa, payload_va, payload_sz, payload_sz >> 20,
		payload_size_mb,
		(u64)write_pos, (u64)write_pos,
		method_name(),
		(write_pos > 0) ? "YES" : "NO");
	if (copy_to_user(buf, tmp, min((size_t)n, len)))
		return -EFAULT;
	*off = n;
	return min((size_t)n, len);
}

static const struct proc_ops info_ops = {
	.proc_read = info_read,
};

/* ── procfs: data — streaming write interface ─────────────────────── */

static ssize_t data_write(struct file *f, const char __user *buf,
			   size_t len, loff_t *off)
{
	void *bounce;

	if (!payload_va)
		return -ENOMEM;
	if (write_pos + len > payload_sz) {
		pr_err("overflow: pos=0x%llx len=0x%zx sz=0x%zx\n",
			(u64)write_pos, len, payload_sz);
		return -ENOSPC;
	}
	/*
	 * HARDENED_USERCOPY rejects copy_from_user into a memremap VA (not a
	 * valid slab/vmalloc object).  Bounce through a kmalloc buffer.
	 */
	bounce = kvmalloc(len, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;
	if (copy_from_user(bounce, buf, len)) {
		kvfree(bounce);
		return -EFAULT;
	}
	memcpy((u8 *)payload_va + write_pos, bounce, len);
	kvfree(bounce);
	write_pos += len;
	return len;
}

static ssize_t data_read(struct file *f, char __user *buf,
			  size_t len, loff_t *off)
{
	if (!payload_va || *off >= (loff_t)payload_sz)
		return 0;
	len = min(len, (size_t)(payload_sz - *off));
	if (copy_to_user(buf, (u8 *)payload_va + *off, len))
		return -EFAULT;
	*off += len;
	return len;
}

static loff_t data_llseek(struct file *f, loff_t offset, int whence)
{
	loff_t new_pos;

	switch (whence) {
	case SEEK_SET: new_pos = offset; break;
	case SEEK_CUR: new_pos = write_pos + offset; break;
	case SEEK_END: new_pos = payload_sz + offset; break;
	default: return -EINVAL;
	}
	if (new_pos < 0 || (size_t)new_pos > payload_sz)
		return -EINVAL;
	write_pos = new_pos;
	return new_pos;
}

static const struct proc_ops data_ops = {
	.proc_write  = data_write,
	.proc_read   = data_read,
	.proc_lseek  = data_llseek,
};

/* ── module lifecycle ─────────────────────────────────────────────── */

static struct proc_dir_entry *proc_dir;

static int resolve_acr(void)
{
	if (!fn_acr)
		fn_acr = ksym("alloc_contig_range_noprof");
	if (!fn_acr)
		fn_acr = ksym("alloc_contig_range");
	if (!fn_fcr)
		fn_fcr = ksym("free_contig_range");
	if (!fn_acr || !fn_fcr) {
		pr_warn("acr: alloc_contig_range(_noprof) / free_contig_range not found\n");
		return -ENOSYS;
	}
	return 0;
}

/* Map an owned, contiguous PFN range and zero it. */
static int map_owned_range(unsigned long start_pfn, unsigned long nr_pages)
{
	unsigned long pfn;
	size_t i;

	payload_pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!payload_pages)
		return -ENOMEM;

	for (i = 0, pfn = start_pfn; i < nr_pages; i++, pfn++) {
		payload_pages[i] = pfn_to_page(pfn);
		if (!payload_pages[i]) {
			kvfree(payload_pages);
			payload_pages = NULL;
			return -EFAULT;
		}
	}

	payload_va = vmap(payload_pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!payload_va) {
		kvfree(payload_pages);
		payload_pages = NULL;
		return -ENOMEM;
	}

	/* Fresh, deterministic contents: XNU's image relies on zero fill. */
	memset(payload_va, 0, nr_pages << PAGE_SHIFT);
	return 0;
}

/*
 * Strategy 1: own the target range with alloc_contig_range().
 *
 * The previous primary strategy memremap()'d the target PA and wrote into it
 * directly, on the theory that the pages are "borrowed" and we are about to
 * jump to XNU one-way anyway.  That reasoning is wrong for the minutes *before*
 * the jump: the range is non-reserved System RAM, i.e. still owned by the page
 * allocator, which can hand any of those pages to anything — including a
 * process's page tables.  Streaming the 36 MB image then overwrites live
 * kernel data.  Observed 2026-10-31 while dd wrote to /proc/olxnu_payload/data:
 *
 *   Unable to handle kernel paging request at virtual address 00000012912aa404
 *   Internal error: Oops: 0000000096000005 [#1] PREEMPT SMP
 *   PC is at unmap_page_range+0xa4/0x1c4
 *   Kernel panic - not syncing: Oops: Fatal exception
 *   upload_cause = KERNEL PANIC ( panic_msg = Oops PC = unmap_page_range+0xa4/0x1c4 )
 *
 * alloc_contig_range() migrates/isolates the pages first and hands them to us
 * exclusively, so nothing else can allocate them afterwards.  Migratetype is
 * tried in order because the range's pageblocks may be any type.
 */
static int acr_claim(unsigned long pa, unsigned int *used_mt_out)
{
	unsigned long start_pfn = pa >> PAGE_SHIFT;
	unsigned long nr_pages  = payload_sz >> PAGE_SHIFT;
	unsigned long end_pfn   = start_pfn + nr_pages;
	static const unsigned int mts[] = { OLXNU_MIGRATE_MOVABLE,
					    OLXNU_MIGRATE_CMA,
					    OLXNU_MIGRATE_UNMOVABLE };
	unsigned int i;
	int ret = -EBUSY;

	for (i = 0; i < ARRAY_SIZE(mts); i++) {
		ret = fn_acr(start_pfn, end_pfn, mts[i], GFP_KERNEL);
		if (!ret) {
			if (used_mt_out)
				*used_mt_out = mts[i];
			break;
		}
	}
	if (ret)
		return ret;

	ret = map_owned_range(start_pfn, nr_pages);
	if (ret) {
		fn_fcr(start_pfn, nr_pages);
		return ret;
	}

	payload_pa  = (phys_addr_t)pa;
	used_method = METHOD_ACR_TARGET;
	return 0;
}

/*
 * Probe candidate windows when the requested base is not isolatable.
 *
 * The requested base is a "safe" (non-reserved) window, but non-reserved does
 * not mean unused: vendor's drivers pin page tables, ION/dma-buf and slab
 * there, and start_isolate_page_range() refuses the whole 64 MB window if a
 * single pageblock contains an unmovable page.  So the base is a *hint*: scan
 * the safe window in both directions and take the first window the kernel can
 * actually hand over.
 *
 * The chosen base changes phys_base, so the image must be rebuilt for it
 * (mk_sm8850_adt.py --phys-base <base>); the value is logged loudly.
 */
static int scan_acr(void)
{
	unsigned long probe, base = 0;
	unsigned int used_mt = 0, i;
	int ret = -ENOMEM;

	/*
	 * Slide in pageblock steps, not window-sized steps: a clean run of 32
	 * isolatable pageblocks can begin at *any* pageblock boundary, and
	 * testing only 64 MB-aligned offsets samples ~40 of ~1800 possible
	 * starts, which is why the first scan missed windows that exist.
	 * Failed probes are cheap (isolation bails out early), so a full sweep
	 * of the safe window costs milliseconds.
	 */
	for (i = 0; i <= scan_limit; i++) {
		unsigned long step = (unsigned long)i * OLXNU_SCAN_STEP;

		/* walk downward from the hint first, then upward */
		if (target_pa > step) {
			probe = target_pa - step;
			if (probe >= OLXNU_SAFE_START &&
			    probe + payload_sz <= OLXNU_SAFE_END) {
				ret = acr_claim(probe, &used_mt);
				if (!ret) { base = probe; goto found; }
			}
		}
		if (i == 0)
			continue;
		probe = target_pa + step;
		if (probe + payload_sz <= OLXNU_SAFE_END) {
			ret = acr_claim(probe, &used_mt);
			if (!ret) { base = probe; goto found; }
		}
	}

	pr_err("acr: no isolatable %u MB window found in 0x%lx-0x%lx (%u probes)\n",
		payload_size_mb, OLXNU_SAFE_START, OLXNU_SAFE_END, i);
	return -ENOMEM;

found:
	pr_info("acr OK: migratetype=%u PA=0x%llx VA=%px (%u MB owned)\n",
		used_mt, (u64)payload_pa, payload_va, payload_size_mb);
	if (base != target_pa)
		pr_warn("acr: CHOSEN BASE 0x%lx != requested 0x%lx — rebuild the image with\n"
			"          mk_sm8850_adt.py --phys-base 0x%lx and use the entry_pa /\n"
			"          boot_args_pa that build_sm8850_image.py prints\n",
			base, target_pa, base);
	return 0;
}

/* Strategy 1: own the target range with alloc_contig_range(). */
static int try_acr_target(void)
{
	unsigned int used_mt = 0;
	int ret;

	if (resolve_acr())
		return -ENOSYS;

	if (target_pa & ((1UL << PAGE_SHIFT) - 1)) {
		pr_err("acr: target_pa 0x%lx is not page aligned\n", target_pa);
		return -EINVAL;
	}

	pr_info("acr: claiming PA=0x%lx (%u MB)\n", target_pa, payload_size_mb);

	ret = acr_claim(target_pa, &used_mt);
	if (!ret) {
		pr_info("acr OK: migratetype=%u PA=0x%llx VA=%px (%u MB owned)\n",
			used_mt, (u64)payload_pa, payload_va, payload_size_mb);
		return 0;
	}

	pr_warn("acr: PA=0x%lx not isolatable: %d (pinned pages in range?)\n",
		target_pa, ret);
	if (!auto_base)
		return ret;

	pr_info("acr: auto_base=1, scanning for an isolatable window\n");
	return scan_acr();
}

/*
 * Strategy 1b (opt-in via borrow_unsafe=1): memremap the target PA with
 * write-back cache attributes and write into memory the allocator still owns.
 * Works for normal System RAM (existing direct map VA) AND no-map DTS reserved
 * regions (new ioremap_cache mapping via vmalloc area).  No-map regions are
 * physically present but excluded from the kernel linear map — phys_to_virt()
 * gives an unmapped VA there, hence memremap instead.
 *
 * NOT SAFE for non-reserved RAM; see try_acr_target().
 */
static int try_linear_map(void)
{
	unsigned long pfn_start = target_pa >> PAGE_SHIFT;
	unsigned long pfn_end   = (target_pa + payload_sz) >> PAGE_SHIFT;
	unsigned long pfn;
	void *va;

	/* Spot-check PFNs are physically present (every 2MB) */
	for (pfn = pfn_start; pfn < pfn_end; pfn += 512) {
		if (!pfn_valid(pfn)) {
			pr_warn("memremap: PFN 0x%lx not valid\n", pfn);
			return -EINVAL;
		}
	}

	va = memremap((phys_addr_t)target_pa, payload_sz, MEMREMAP_WB);
	if (!va) {
		pr_warn("memremap(0x%lx, 0x%zx) failed\n", target_pa, payload_sz);
		return -ENOMEM;
	}

	payload_va = va;
	payload_pa = (phys_addr_t)target_pa;
	used_method = METHOD_LINEAR;
	pr_warn("memremap: BORROWING PA=0x%llx VA=%px (%u MB) — unsafe\n",
		(u64)payload_pa, payload_va, payload_size_mb);
	return 0;
}

/*
 * Strategy 2: alloc_contig_range with MIGRATE_CMA on the QDSS apps pool.
 * qdss_apps_region@82800000 is a 32 MB reusable shared-dma-pool — its pages
 * are MIGRATE_CMA (type 4) and in the linear map.  alloc_contig_range(CMA)
 * can reclaim them even if QDSS grabbed a few.
 * Only tried if try_linear_map() fails AND payload_size_mb <= QDSS_SIZE_MB.
 */
static int try_cma_acr(unsigned long nr_pages)
{
	unsigned long start_pfn, end_pfn;
	int ret;

	if (resolve_acr())
		return -ENOSYS;

	start_pfn = QDSS_PA >> PAGE_SHIFT;
	end_pfn   = start_pfn + nr_pages;

	pr_info("cma_acr: alloc_contig_range(CMA) pfn [0x%lx,0x%lx) PA=0x%lx\n",
		start_pfn, end_pfn, QDSS_PA);

	/* MIGRATE_CMA = 4 */
	ret = fn_acr(start_pfn, end_pfn, OLXNU_MIGRATE_CMA, GFP_KERNEL);
	if (ret) {
		pr_warn("cma_acr: alloc_contig_range failed: %d\n", ret);
		return ret;
	}

	ret = map_owned_range(start_pfn, nr_pages);
	if (ret) {
		fn_fcr(start_pfn, nr_pages);
		return ret;
	}

	payload_pa = (phys_addr_t)QDSS_PA;
	used_method = METHOD_CMA_ACR;
	pr_info("cma_acr OK: PA=0x%llx VA=%px (%lu MB)\n",
		(u64)payload_pa, payload_va, nr_pages / 256);
	return 0;
}

/*
 * Strategy 2b: cma_alloc() on the kernel's CMA areas.
 *
 * A CMA area's pages are MIGRATE_CMA, and alloc_contig_range() inside cma_alloc()
 * is allowed to reclaim them even when the area is fully handed out to movable
 * users — which is exactly this device's state (CmaFree ~200 kB out of 733 MB).
 * Isolating plain buddy pageblocks cannot do that: any single fully-allocated or
 * pinned 2 MB block in a 64 MB window makes start_isolate_page_range() fail with
 * -EBUSY, which is why every window in the static "safe" zone failed after boot.
 *
 * dma_alloc_coherent() also ends up here, but only through the *default* CMA area
 * (36 MB on this device), which caps it near 16 MB — less than the ~36 MB the
 * XNU image spans.  So walk every CMA area and take the first that can satisfy
 * the whole request.
 */
typedef struct page *(*cma_alloc_fn_t)(struct cma *, unsigned long, unsigned int, bool);
typedef int          (*cma_release_fn_t)(struct cma *, const struct page *, unsigned long);
typedef int          (*cma_each_fn_t)(int (*)(struct cma *, void *), void *);
typedef const char  *(*cma_name_fn_t)(const struct cma *);

static cma_alloc_fn_t   fn_cma_alloc;
static cma_release_fn_t fn_cma_release;
static cma_each_fn_t    fn_cma_each;
static cma_name_fn_t    fn_cma_name;

/*
 * Restrict the CMA area search to names containing this substring.  Taking
 * pages out of a pool a driver has already mapped (display/GPU pools are
 * mapped into the SMMU and hashed by vendor's gcma) is asking for a
 * subsystem fault, so the caller can pin the search to a safe pool.
 */
static char *cma_name_filter;
static char *proc_name = "olxnu_payload";
module_param(proc_name, charp, 0444);
MODULE_PARM_DESC(proc_name, "procfs directory name (default olxnu_payload)");

module_param(cma_name_filter, charp, 0444);
MODULE_PARM_DESC(cma_name_filter, "Only cma_alloc() from CMA areas whose name contains this substring");
static struct cma      *used_cma;
static struct page     *cma_block;

struct cma_probe {
	unsigned long pages;
	unsigned long align;   /* log2(pages) to align the block to */
};

static int cma_probe_area(struct cma *cma, void *data)
{
	const struct cma_probe *probe = data;
	const char *name = fn_cma_name ? fn_cma_name(cma) : "?";
	struct page *p;

	if (cma_name_filter && strstr(name, cma_name_filter) == NULL)
		return 0;

	p = fn_cma_alloc(cma, probe->pages, probe->align, true);
	if (!p) {
		pr_info("cma_area: '%s' declined %lu MB\n", name, probe->pages >> 8);
		return 0;        /* area too small or exhausted — keep looking */
	}

	cma_block = p;
	used_cma  = cma;
	pr_info("cma_area: '%s' satisfied the request\n", name);
	return 1;                /* found: stop iterating */
}

static int try_cma_area(void)
{
	struct cma_probe probe = {
		.pages = payload_sz >> PAGE_SHIFT,
		/* 16 KB pages are what XNU runs with, so align the block that way */
		.align = 2,
	};
	int ret;

	if (!fn_cma_alloc || !fn_cma_each) {
		pr_warn("cma_area: cma_alloc/cma_for_each_area not found\n");
		return -ENOSYS;
	}

	cma_block = NULL;
	used_cma  = NULL;
	ret = fn_cma_each(cma_probe_area, &probe);
	if (ret != 1 || !cma_block || !used_cma) {
		pr_warn("cma_area: no CMA area could satisfy %lu MB\n",
			probe.pages >> 8);
		return -ENOMEM;
	}

	payload_pa  = page_to_phys(cma_block);
	payload_va  = page_address(cma_block);
	used_method = METHOD_CMA_AREA;

	memset(payload_va, 0, payload_sz);

	pr_info("cma_area OK: PA=0x%llx VA=%px (%zu MB owned, %lu pages)\n",
		(u64)payload_pa, payload_va, payload_sz >> 20, probe.pages);
	return 0;
}

static int try_dma_fallback(void)
{
	int ret;

	pdev = platform_device_alloc("olxnu_payload", 0);
	if (!pdev)
		return -ENOMEM;

	ret = platform_device_add(pdev);
	if (ret) {
		platform_device_put(pdev);
		return ret;
	}

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(48));
	if (ret)
		pr_warn("dma_set_mask: %d\n", ret);

	dma_va = dma_alloc_coherent(&pdev->dev, payload_sz, &dma_pa, GFP_KERNEL);
	if (!dma_va) {
		platform_device_unregister(pdev);
		return -ENOMEM;
	}
	used_method = METHOD_DMA;
	pr_info("dma_alloc_coherent OK: PA=0x%llx VA=%px (%u MB)\n",
		(u64)dma_pa, dma_va, payload_size_mb);
	return 0;
}

static int __init olxnu_payload_init(void)
{
	unsigned long nr_pages;
	int ret;

	payload_sz = (size_t)payload_size_mb * 1024 * 1024;
	nr_pages   = payload_sz / PAGE_SIZE;

	fn_cma_alloc   = ksym("cma_alloc");
	fn_cma_release = ksym("cma_release");
	fn_cma_each    = ksym("cma_for_each_area");
	fn_cma_name    = ksym("cma_get_name");

	/* Strategy 1: own the target range (safe against concurrent allocation) */
	ret = try_acr_target();
	if (ret && borrow_unsafe) {
		pr_warn("fallback: borrow_unsafe=1, memremap() the target range\n");
		ret = try_linear_map();
	}
	if (ret) {
		/* Strategy 2: alloc_contig_range(MIGRATE_CMA) on QDSS pool (32 MB max) */
		if (payload_size_mb <= QDSS_SIZE_MB) {
			pr_info("fallback: trying alloc_contig_range(CMA) on QDSS pool\n");
			ret = try_cma_acr(nr_pages);
		} else {
			pr_info("payload %u MB > QDSS %u MB; skipping CMA fallback\n",
				payload_size_mb, QDSS_SIZE_MB);
			ret = -ENOSPC;
		}
	}
	if (ret) {
		/* Strategy 2b: cma_alloc() on the largest CMA area that fits */
		pr_info("fallback: trying cma_alloc() on CMA areas\n");
		ret = try_cma_area();
	}
	if (ret) {
		/*
		 * Strategy 3: dma_alloc_coherent.
		 *
		 * This is the only strategy that reliably yields contiguous memory
		 * on a running Android: the DMA/ION path allocates through a pool the
		 * platform guarantees is physically contiguous, whereas isolation of
		 * buddy pageblocks fails once any 2 MB block in the window is pinned
		 * or fully allocated.  Try the full request first — the previous code
		 * always halved it, which silently turned a 64 MB request into 32 MB.
		 */
		unsigned int mb;

		for (mb = payload_size_mb; mb >= 8; mb /= 2) {
			pr_info("fallback: trying dma_alloc_coherent at %u MB\n", mb);
			payload_sz = (size_t)mb * 1024 * 1024;
			ret = try_dma_fallback();
			if (!ret)
				break;
		}
		if (ret) {
			pr_err("all allocation methods failed\n");
			return ret;
		}
		pr_warn("dma_alloc_coherent gave %u MB (requested %u MB) at PA=0x%llx\n"
			"         image must be built for phys_base=0x%llx\n",
			mb, payload_size_mb, (u64)payload_pa, (u64)payload_pa);
	}

	proc_dir = proc_mkdir(proc_name, NULL);
	if (!proc_dir)
		return -ENOMEM;
	proc_create("info", 0444, proc_dir, &info_ops);
	proc_create("data", 0644, proc_dir, &data_ops);

	/* If DMA path was used, update payload_pa from dma_pa */
	if (used_method == METHOD_DMA) {
		payload_va = dma_va;
		payload_pa = (phys_addr_t)dma_pa;
	}

	/*
	 * Align the window, do not hope for it.
	 *
	 * The block is normally much larger than the image (128 MB requested,
	 * 32 MB written), so a shifted start costs only the shift itself.
	 */
	{
		unsigned long delta =
		    (-(unsigned long)payload_pa) & (PAYLOAD_ALIGN - 1);

		if (delta && payload_sz > delta + PAYLOAD_ALIGN_MIN) {
			payload_pa += delta;
			payload_va = (char *)payload_va + delta;
			payload_sz -= delta;
			pr_info("aligned: +0x%lx -> PA=0x%llx, %zu MB usable\n",
			    delta, (u64)payload_pa, payload_sz >> 20);
		} else if (delta) {
			pr_warn("PA=0x%llx is not 2 MB aligned and the block has "
			    "no room to shift it; expect an unreliable run\n",
			    (u64)payload_pa);
		}
	}
	pr_info("ready: method=%s PA=0x%llx\n", method_name(), (u64)payload_pa);
	pr_info("load:  adb shell 'su -c dd if=/data/local/tmp/xnu.bin of=/proc/olxnu_payload/data bs=1M'\n");
	pr_info("check: cat /proc/olxnu_payload/info\n");
	return 0;
}

static void __exit olxnu_payload_exit(void)
{
	proc_remove(proc_dir);

	switch (used_method) {
	case METHOD_ACR_TARGET:
		if (payload_va)
			vunmap(payload_va);
		kvfree(payload_pages);
		if (fn_fcr)
			fn_fcr(target_pa >> PAGE_SHIFT, payload_sz / PAGE_SIZE);
		break;
	case METHOD_LINEAR:
		if (payload_va)
			memunmap(payload_va);
		break;
	case METHOD_CMA_ACR:
		vunmap(payload_va);
		kvfree(payload_pages);
		if (fn_fcr)
			fn_fcr(QDSS_PA >> PAGE_SHIFT, payload_sz / PAGE_SIZE);
		break;
	case METHOD_CMA_AREA:
		if (fn_cma_release && used_cma && cma_block)
			fn_cma_release(used_cma, cma_block,
				       payload_sz >> PAGE_SHIFT);
		break;
	case METHOD_DMA:
		dma_free_coherent(&pdev->dev, payload_sz, dma_va, dma_pa);
		platform_device_unregister(pdev);
		break;
	default:
		break;
	}
}

module_init(olxnu_payload_init);
module_exit(olxnu_payload_exit);

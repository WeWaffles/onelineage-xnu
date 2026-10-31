/*
 * olxnu_payload.c — Contiguous physical memory loader for XNU payload
 *
 * Strategy 1 (primary): phys_to_virt() on the target System RAM PA.
 *   ZONE_MOVABLE is empty on this device so alloc_contig_range(MOVABLE) always
 *   returns -EBUSY.  The target PA (default 0x8c0000000) is in ZONE_NORMAL
 *   with a valid linear-map VA.  We borrow those pages — they are in use by
 *   Android but we are about to jump to XNU one-way, so it doesn't matter.
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
#include <asm/page.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("OneLineage");
MODULE_DESCRIPTION("XNU contiguous payload loader via alloc_contig_range");
MODULE_VERSION("1.0");

static unsigned int payload_size_mb = 64;
module_param(payload_size_mb, uint, 0444);
MODULE_PARM_DESC(payload_size_mb, "Payload size in MB (default 64)");

/*
 * Default target PA: start of the 9.25 GB System RAM block.
 * ZONE_MOVABLE is empty on this device so alloc_contig_range(MOVABLE) fails;
 * we use phys_to_virt() directly — the pages are in the linear map and
 * we're about to clobber them for XNU anyway.
 */
static unsigned long target_pa = 0x8c0000000UL;
module_param(target_pa, ulong, 0444);
MODULE_PARM_DESC(target_pa, "Target PA (default 0x8c0000000; borrowed from linear map)");

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

static fcr_fn_t fn_fcr;

/* ── payload state ──────────────────────────────────────────────────── */

static struct page  **payload_pages;
static void          *payload_va;    /* VA to write payload data */
static phys_addr_t    payload_pa;    /* PA of first byte (contiguous) */
static size_t         payload_sz;
static loff_t         write_pos;

enum alloc_method { METHOD_NONE, METHOD_LINEAR, METHOD_CMA_ACR, METHOD_DMA };
static enum alloc_method used_method;

/* free_contig_range — resolved only when METHOD_CMA_ACR is used */
static fcr_fn_t fn_fcr;

/* For METHOD_DMA */
static struct platform_device *pdev;
static void          *dma_va;
static dma_addr_t     dma_pa;

/* ── procfs: info ─────────────────────────────────────────────────── */

static const char *method_name(void)
{
	switch (used_method) {
	case METHOD_LINEAR:  return "phys_to_virt(linear_map)";
	case METHOD_CMA_ACR: return "alloc_contig_range(CMA)";
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
		"payload_sz=0x%zx (%u MB)\n"
		"write_pos=0x%llx (%llu bytes)\n"
		"alloc_method=%s\n"
		"ready=%s\n",
		(u64)payload_pa, payload_va, payload_sz, payload_size_mb,
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
	if (!payload_va)
		return -ENOMEM;
	if (write_pos + len > payload_sz) {
		pr_err("overflow: pos=0x%llx len=0x%zx sz=0x%zx\n",
			(u64)write_pos, len, payload_sz);
		return -ENOSPC;
	}
	if (copy_from_user((u8 *)payload_va + write_pos, buf, len))
		return -EFAULT;
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

/*
 * Strategy 1: borrow the target System RAM PA directly via the linear map.
 * ZONE_MOVABLE is empty on this device; alloc_contig_range(MOVABLE) always
 * returns -EBUSY.  The pages at target_pa are in ZONE_NORMAL and mapped by
 * the kernel linear map — phys_to_virt() gives a valid writable VA.
 * We "steal" those pages from Android processes — they are in use but we are
 * about to jump one-way to XNU, so the corruption doesn't matter.
 */
static int try_linear_map(void)
{
	unsigned long pfn_start = target_pa >> PAGE_SHIFT;
	unsigned long pfn_end   = (target_pa + payload_sz) >> PAGE_SHIFT;
	unsigned long pfn;

	/* Verify PFNs are in the linear map (spot-check every 2MB) */
	for (pfn = pfn_start; pfn < pfn_end; pfn += 512) {
		if (!pfn_valid(pfn)) {
			pr_warn("linear: PFN 0x%lx not valid\n", pfn);
			return -EINVAL;
		}
	}

	payload_va = phys_to_virt((phys_addr_t)target_pa);
	payload_pa = (phys_addr_t)target_pa;
	used_method = METHOD_LINEAR;
	pr_info("linear map: PA=0x%llx VA=%px (%u MB) — borrowed from ZONE_NORMAL\n",
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
	acr_fn_t fn_acr;
	unsigned long start_pfn, end_pfn, pfn;
	struct page *p;
	size_t i;
	int ret;

	fn_acr = ksym("alloc_contig_range_noprof");
	if (!fn_acr)
		fn_acr = ksym("alloc_contig_range");
	fn_fcr = ksym("free_contig_range");
	if (!fn_acr || !fn_fcr) {
		pr_warn("cma_acr: alloc_contig_range(_noprof) not found\n");
		return -ENOSYS;
	}

	start_pfn = QDSS_PA >> PAGE_SHIFT;
	end_pfn   = start_pfn + nr_pages;

	pr_info("cma_acr: alloc_contig_range(CMA) pfn [0x%lx,0x%lx) PA=0x%lx\n",
		start_pfn, end_pfn, QDSS_PA);

	/* MIGRATE_CMA = 4 */
	ret = fn_acr(start_pfn, end_pfn, 4, GFP_KERNEL);
	if (ret) {
		pr_warn("cma_acr: alloc_contig_range failed: %d\n", ret);
		return ret;
	}

	payload_pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!payload_pages) {
		fn_fcr(start_pfn, nr_pages);
		return -ENOMEM;
	}
	for (i = 0, pfn = start_pfn; i < nr_pages; i++, pfn++) {
		p = pfn_to_page(pfn);
		if (!p) {
			kvfree(payload_pages);
			fn_fcr(start_pfn, nr_pages);
			return -EFAULT;
		}
		payload_pages[i] = p;
	}

	payload_va = vmap(payload_pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!payload_va) {
		kvfree(payload_pages);
		fn_fcr(start_pfn, nr_pages);
		return -ENOMEM;
	}

	payload_pa = (phys_addr_t)QDSS_PA;
	used_method = METHOD_CMA_ACR;
	pr_info("cma_acr OK: PA=0x%llx VA=%px (%lu MB)\n",
		(u64)payload_pa, payload_va, nr_pages / 256);
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

	/* Strategy 1: borrow pages via the linear map — no allocation needed */
	ret = try_linear_map();
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
		/* Strategy 3: dma_alloc_coherent at half size */
		unsigned int half = payload_size_mb / 2;
		pr_info("fallback: trying dma_alloc_coherent at %u MB\n", half);
		payload_sz = (size_t)half * 1024 * 1024;
		ret = try_dma_fallback();
		if (ret) {
			pr_err("all allocation methods failed\n");
			return ret;
		}
	}

	proc_dir = proc_mkdir("olxnu_payload", NULL);
	if (!proc_dir)
		return -ENOMEM;
	proc_create("info", 0444, proc_dir, &info_ops);
	proc_create("data", 0644, proc_dir, &data_ops);

	/* If DMA path was used, update payload_pa from dma_pa */
	if (used_method == METHOD_DMA) {
		payload_va = dma_va;
		payload_pa = (phys_addr_t)dma_pa;
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
	case METHOD_LINEAR:
		/* Nothing to free — we borrowed from the linear map */
		break;
	case METHOD_CMA_ACR:
		vunmap(payload_va);
		kvfree(payload_pages);
		if (fn_fcr)
			fn_fcr(QDSS_PA >> PAGE_SHIFT, payload_sz / PAGE_SIZE);
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

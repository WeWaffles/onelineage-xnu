/*
 * olxnu_ram_test.c — E1: does physical RAM survive a warm reset?
 *
 * Allocates one GFP_KERNEL page, writes a 64-byte magic record, and
 * prints its physical address.  The phone is then manually rebooted.
 * After reboot:
 *
 *   adb shell su -c "dd if=/dev/block/by-name/rawdump bs=4096 count=1 \
 *       skip=$((PA / 4096)) 2>/dev/null | xxd | head"
 *
 * If the magic pattern survives, the rawdump channel works for XNU output.
 * If not, XNU must use a different output strategy (e.g. write to a fixed
 * reserved-memory region that the bootloader avoids).
 *
 * This module does NOT reset the phone — it only writes and reports.
 * Load, record the PA, reboot manually, check rawdump.
 */

#define MODULE_NAME "olxnu_ram_test"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("OneLineage");
MODULE_DESCRIPTION("E1: RAM survival test — write magic, reboot, check rawdump");
MODULE_VERSION("1.0");

#define MAGIC_HDR  "OLXNU_RAM_MAGIC_v1"
#define MAGIC_BODY "ABCDEFGHIJKLMNOP" /* 16 bytes of known pattern */

static unsigned long test_va;
static phys_addr_t   test_pa;

static int ram_test_show(struct seq_file *m, void *v)
{
	seq_printf(m, "PA=0x%llx VA=0x%lx\n", (u64)test_pa, test_va);
	seq_printf(m, "check after reboot:\n");
	seq_printf(m, "  dd if=/dev/block/by-name/rawdump bs=4096 count=1"
		       " skip=%llu 2>/dev/null | xxd | head\n",
		       (u64)(test_pa / PAGE_SIZE));
	seq_printf(m, "  look for: %s\n", MAGIC_HDR);
	return 0;
}

static int ram_test_open(struct inode *inode, struct file *file)
{
	return single_open(file, ram_test_show, NULL);
}

static const struct proc_ops ram_test_ops = {
	.proc_open    = ram_test_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int __init olxnu_ram_test_init(void)
{
	u8 *p;

	test_va = get_zeroed_page(GFP_KERNEL);
	if (!test_va)
		return -ENOMEM;

	test_pa = virt_to_phys((void *)test_va);
	p = (u8 *)test_va;

	/* 64-byte magic record */
	memcpy(p,      MAGIC_HDR,  strlen(MAGIC_HDR));
	memcpy(p + 32, MAGIC_BODY, strlen(MAGIC_BODY));

	proc_create("olxnu_ram_test", 0444, NULL, &ram_test_ops);

	pr_info("magic written PA=0x%llx — reboot and check rawdump\n",
		(u64)test_pa);
	pr_info("  dd if=/dev/block/by-name/rawdump bs=4096 count=1"
		" skip=%llu 2>/dev/null | xxd | head\n",
		(u64)(test_pa / PAGE_SIZE));
	return 0;
}

static void __exit olxnu_ram_test_exit(void)
{
	remove_proc_entry("olxnu_ram_test", NULL);
	if (test_va)
		free_page(test_va);
}

module_init(olxnu_ram_test_init);
module_exit(olxnu_ram_test_exit);

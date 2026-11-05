// SPDX-License-Identifier: GPL-2.0
/* Diagnostic only: no handoff, symbol lookup, memory writes or device control. */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/utsname.h>
#include <linux/cpu.h>
#include <linux/mm.h>
static int __init s26_diag_init(void)
{
    pr_info("HANDOFF_DIAG: release=%s pagesize=%lu online_cpus=%u module_size=%zu\n",
            init_uts_ns.name.release, PAGE_SIZE, num_online_cpus(), sizeof(struct module));
    pr_info("HANDOFF_DIAG: diagnostic-only; no handoff interface registered\n");
    return 0;
}
static void __exit s26_diag_exit(void) { pr_info("HANDOFF_DIAG: unloaded\n"); }
module_init(s26_diag_init);
module_exit(s26_diag_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Host-lab-only read-only handoff capability diagnostic");

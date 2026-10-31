/*
 * Arch-specific compatibility layer for enabling kexec as loadable kernel
 * module.
 *
 * Copyright (C) 2021 Fabian Mastenbroek.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "kexec_mod_arm64: " fmt

#include <linux/version.h>
#include <linux/mm_types.h>
#include <linux/kexec.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/virt.h>

/* These kernel symbols need to be dynamically resolved at runtime
 * using kallsym due to them not being exposed to kernel modules */
static void (*__hyp_set_vectors_ptr)(phys_addr_t);
static bool (*cpus_are_stuck_in_kernel_ptr)(void);
static void (*dcache_clean_inval_poc_ptr)(unsigned long, unsigned long);
static void (*icache_inval_pou_ptr)(unsigned long, unsigned long);
static void *ksym(const char *name);

void kexec_dcache_clean_inval_poc(unsigned long start, unsigned long end)
{
	dcache_clean_inval_poc_ptr(start, end);
}

void kexec_icache_inval_pou(unsigned long start, unsigned long end)
{
	icache_inval_pou_ptr(start, end);
}

void __hyp_set_vectors(phys_addr_t phys_vector_base)
{
	__hyp_set_vectors_ptr(phys_vector_base);
}

void __hyp_set_vectors_nop(phys_addr_t phys_vector_base)
{}


/* These kernel symbols are stubbed since they are not available
 * in the host kernel */
bool cpus_are_stuck_in_kernel(void)
{
	return cpus_are_stuck_in_kernel_ptr();
}

/* These symbols need to be resolved using by extracting their
 * addresses from symbols that are exposed to kernel modules */
u64 idmap_t0sz = TCR_T0SZ(VA_BITS);
u32 __boot_cpu_mode[2];

/**
 * This function initializes the __boot_cpu_mode variable with that from the kernel.
 * Since it is not exported, this requires some hacks.
 */
static int __init_cpu_boot_mode(void)
{
	extern phys_addr_t kexec_pa_symbol(void *ptr);
	/*
	 * Hack to obtain pointer to __boot_mode_cpu
	 * Our approach is to decode the address to __boot_mode_cpu from the instructions
	 * of set_cpu_boot_mode_flag which is exported and references __boot_mode_cpu.
	 */
	u32 *set_cpu_boot_mode_flag_ptr = ksym("set_cpu_boot_mode_flag");
	void *page = (void *) (((u64)set_cpu_boot_mode_flag_ptr) & ~0xFFF);
	u16 lo = (set_cpu_boot_mode_flag_ptr[0] >> 29) & 0x3;
	u16 hi = (set_cpu_boot_mode_flag_ptr[0] >> 4) & 0xFFFF;
	u16 off = (set_cpu_boot_mode_flag_ptr[1] >> 10) & 0xFFF;
	u32 *__boot_cpu_mode_ptr = page + ((hi << 13) | (lo << 12)) + off;

	/* Verify whether address actually exists */
	if (kexec_pa_symbol(__boot_cpu_mode_ptr)) {
		__boot_cpu_mode[0] = __boot_cpu_mode_ptr[0];
		__boot_cpu_mode[1] = __boot_cpu_mode_ptr[1];

		pr_info("Detected boot CPU mode: 0x%x 0x%x.\n", __boot_cpu_mode[0], __boot_cpu_mode[1]);
		return 0;
	}

	return -1;
}

static void *__hyp_shim;

/**
 * This function allocates a page which will contain the hypervisor shim.
 *
 * Previously, we set vbar_el2 to point directly to __hyp_shim_vectors.
 * However, we found that sometimes, the shim vectors would span two
 * non-consecutive physical pages, which would cause it to jump into unknown
 * memory.
 *
 * Our solution is to allocate a single page on which we place the hypervisor
 * shim in order to ensure that relative jumps without the MMU still work
 * properly.
 */
static int __init_hyp_shim(void)
{
	extern const u32 __hyp_shim_size;
	extern void __hyp_shim_vectors(void);

	__hyp_shim = alloc_pages_exact(__hyp_shim_size, GFP_KERNEL);

	if (!__hyp_shim) {
		return -ENOMEM;
	}

	memcpy(__hyp_shim, __hyp_shim_vectors, __hyp_shim_size);

	pr_info("Hypervisor shim created at 0x%llx [%u bytes].\n", virt_to_phys(__hyp_shim), __hyp_shim_size);
	return 0;
}


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

int machine_kexec_compat_load(int detect_el2, int shim_hyp)
{
	if (!(cpus_are_stuck_in_kernel_ptr = ksym("cpus_are_stuck_in_kernel"))
	    || !(dcache_clean_inval_poc_ptr = ksym("dcache_clean_inval_poc"))
	    || !(icache_inval_pou_ptr = ksym("icache_inval_pou")))
		return -ENOENT;

	/* Find boot CPU mode */
	__boot_cpu_mode[0] = BOOT_CPU_MODE_EL1;
	__boot_cpu_mode[1] = BOOT_CPU_MODE_EL1;

	if (!detect_el2) {
		pr_info("EL2 kexec not supported.\n");
	} else if (__init_cpu_boot_mode() < 0) {
		pr_warn("Failed to detect boot CPU mode.\n");
	}

	/* Enable shimming the hypervisor vectors */
	__hyp_set_vectors_ptr = __hyp_set_vectors_nop;
	if (shim_hyp) {
		pr_info("Enabling shim for hypervisor vectors.\n");

		if (__init_hyp_shim() < 0) {
			pr_err("Failed to initialize hypervisor shim.\n");
		} else if (detect_el2 && !(__hyp_set_vectors_ptr = ksym("__hyp_set_vectors"))) {
			pr_err("Not able to shim hypervisor vectors.\n");
			__hyp_set_vectors_ptr = __hyp_set_vectors_nop;
		} else if (!detect_el2) {
			pr_warn("Hypervisor shim unnecessary without EL2 detection.\n");
		}
	} else {
		__hyp_shim = NULL;
	}
	return 0;
}

void machine_kexec_compat_unload(void)
{
	extern const u32 __hyp_shim_size;

	if (__hyp_shim) {
		free_pages_exact(__hyp_shim, __hyp_shim_size);
		__hyp_shim = NULL;
	}
}

void machine_kexec_compat_prereset(void)
{
	__hyp_set_vectors(virt_to_phys(__hyp_shim));
}

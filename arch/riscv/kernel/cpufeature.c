// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copied from arch/arm64/kernel/cpufeature.c
 *
 * Copyright (C) 2015 ARM Ltd.
 * Copyright (C) 2017 SiFive
 */

#include <linux/acpi.h>
#include <linux/bitmap.h>
#include <linux/of.h>
#include <asm/processor.h>
#include <asm/hwcap.h>
#include <asm/smp.h>
#include <asm/switch_to.h>
#include <linux/dmi.h>
#include <asm/dmi.h>
#include <asm/unaligned.h>

unsigned long elf_hwcap __read_mostly;
bool riscv_aia_available __read_mostly;
EXPORT_SYMBOL_GPL(riscv_aia_available);

/* Host ISA bitmap */
static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;

#ifdef CONFIG_FPU
__ro_after_init DEFINE_STATIC_KEY_FALSE(cpu_hwcap_fpu);
#endif

/**
 * riscv_isa_extension_base() - Get base extension word
 *
 * @isa_bitmap: ISA bitmap to use
 * Return: base extension word as unsigned long value
 *
 * NOTE: If isa_bitmap is NULL then Host ISA bitmap will be used.
 */
unsigned long riscv_isa_extension_base(const unsigned long *isa_bitmap)
{
	if (!isa_bitmap)
		return riscv_isa[0];
	return isa_bitmap[0];
}
EXPORT_SYMBOL_GPL(riscv_isa_extension_base);

/**
 * __riscv_isa_extension_available() - Check whether given extension
 * is available or not
 *
 * @isa_bitmap: ISA bitmap to use
 * @bit: bit position of the desired extension
 * Return: true or false
 *
 * NOTE: If isa_bitmap is NULL then Host ISA bitmap will be used.
 */
bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, int bit)
{
	const unsigned long *bmap = (isa_bitmap) ? isa_bitmap : riscv_isa;

	if (bit >= RISCV_ISA_EXT_MAX)
		return false;

	return test_bit(bit, bmap) ? true : false;
}
EXPORT_SYMBOL_GPL(__riscv_isa_extension_available);

void __init riscv_fill_hwcap(void)
{
	struct device_node *intc, *node;
	const char *isa;
	char print_str[BITS_PER_LONG + 1];
	size_t i, j, isa_len;
	static unsigned long isa2hwcap[256] = {0};

	isa2hwcap['i'] = isa2hwcap['I'] = COMPAT_HWCAP_ISA_I;
	isa2hwcap['m'] = isa2hwcap['M'] = COMPAT_HWCAP_ISA_M;
	isa2hwcap['a'] = isa2hwcap['A'] = COMPAT_HWCAP_ISA_A;
	isa2hwcap['f'] = isa2hwcap['F'] = COMPAT_HWCAP_ISA_F;
	isa2hwcap['d'] = isa2hwcap['D'] = COMPAT_HWCAP_ISA_D;
	isa2hwcap['c'] = isa2hwcap['C'] = COMPAT_HWCAP_ISA_C;

	elf_hwcap = 0;
	riscv_aia_available = true;

	bitmap_zero(riscv_isa, RISCV_ISA_EXT_MAX);

	for_each_of_cpu_node(node) {
		unsigned long this_hwcap = 0;
		unsigned long this_isa = 0;

		intc = of_find_compatible_node(node, NULL,
						"riscv,cpu-intc-aia");
		if (!intc)
			riscv_aia_available = false;
		else
			of_node_put(intc);

		if (riscv_of_processor_hartid(node) < 0)
			continue;

		if (of_property_read_string(node, "riscv,isa", &isa)) {
			pr_warn("Unable to find \"riscv,isa\" devicetree entry\n");
			continue;
		}

		i = 0;
		isa_len = strlen(isa);
#if IS_ENABLED(CONFIG_32BIT)
		if (!strncmp(isa, "rv32", 4))
			i += 4;
#elif IS_ENABLED(CONFIG_64BIT)
		if (!strncmp(isa, "rv64", 4))
			i += 4;
#endif
		for (; i < isa_len; ++i) {
			this_hwcap |= isa2hwcap[(unsigned char)(isa[i])];
			/*
			 * TODO: X, Y and Z extension parsing for Host ISA
			 * bitmap will be added in-future.
			 */
			if ('a' <= isa[i] && isa[i] < 'x')
				this_isa |= (1UL << (isa[i] - 'a'));
		}

		/*
		 * All "okay" hart should have same isa. Set HWCAP based on
		 * common capabilities of every "okay" hart, in case they don't
		 * have.
		 */
		if (elf_hwcap)
			elf_hwcap &= this_hwcap;
		else
			elf_hwcap = this_hwcap;

		if (riscv_isa[0])
			riscv_isa[0] &= this_isa;
		else
			riscv_isa[0] = this_isa;
	}

	/* We don't support systems with F but without D, so mask those out
	 * here. */
	if ((elf_hwcap & COMPAT_HWCAP_ISA_F) && !(elf_hwcap & COMPAT_HWCAP_ISA_D)) {
		pr_info("This kernel does not support systems with F but not D\n");
		elf_hwcap &= ~COMPAT_HWCAP_ISA_F;
	}

	memset(print_str, 0, sizeof(print_str));
	for (i = 0, j = 0; i < BITS_PER_LONG; i++)
		if (riscv_isa[0] & BIT_MASK(i))
			print_str[j++] = (char)('a' + i);
	pr_info("riscv: ISA extensions %s\n", print_str);

	memset(print_str, 0, sizeof(print_str));
	for (i = 0, j = 0; i < BITS_PER_LONG; i++)
		if (elf_hwcap & BIT_MASK(i))
			print_str[j++] = (char)('a' + i);
	pr_info("riscv: ELF capabilities %s\n", print_str);

#ifdef CONFIG_FPU
	if (elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D))
		static_branch_enable(&cpu_hwcap_fpu);
#endif
}

#ifdef CONFIG_ACPI
static const char riscv_exts[26] = "iemafdqclbjtpvnsuhkorwxyzg";

static int acpi_get_riscv_isa(struct acpi_table_header *table_hdr,
				unsigned int cpu,
				uint32_t *isa)
{
	struct acpi_rhct_hart_info_cap *entry;
	unsigned long table_end = (unsigned long)table_hdr + table_hdr->length;
	u32 acpi_cpu_id = get_acpi_id_for_cpu(cpu);

	entry = ACPI_ADD_PTR(struct acpi_rhct_hart_info_cap, table_hdr,
			     sizeof(struct acpi_table_rhct));
	while ((unsigned long)entry + entry->length <= table_end) {

		if (entry->length == 0) {
			pr_warn("acpi_get_riscv_isa: Invalid zero length subtable\n");
			break;
		}
		if (acpi_cpu_id == entry->acpi_proc_id) {
			*isa =  entry->isa;
			return 0;
		}
		entry = ACPI_ADD_PTR(struct acpi_rhct_hart_info_cap, entry,
				entry->length);
	}
	return -1;
}

void riscv_acpi_fill_hwcap(void)
{
	char print_str[BITS_PER_LONG + 1];
	size_t i, j, ret;
	unsigned int cpu;
	unsigned long elf_isa_mask = 0x112D;
	struct acpi_table_header *table;
	acpi_status status;

	elf_hwcap = 0;

	bitmap_zero(riscv_isa, RISCV_ISA_EXT_MAX);

	status = acpi_get_table(ACPI_SIG_RHCT, 0, &table);
	if (ACPI_FAILURE(status)) {
		pr_warn_once("No RHCT table found, CPU capabilities may be inaccurate\n");
		return;
	}

	riscv_aia_available = true;

	for_each_possible_cpu(cpu) {
		u32 this_hwcap = 0;
		u32 this_isa = 0;
		ret = acpi_get_riscv_isa(table, cpu, &this_isa);
		if(ret < 0) {
			pr_warn("Unable to get ISA for the hart - %d\n",
					cpu);
			continue;
		}

		this_hwcap |= (this_isa & elf_isa_mask);

		/*
		 * All "okay" hart should have same isa. Set HWCAP based on
		 * common capabilities of every "okay" hart, in case they don't
		 * have.
		 */
		if (elf_hwcap)
			elf_hwcap &= this_hwcap;
		else
			elf_hwcap = this_hwcap;

		if (riscv_isa[0])
			riscv_isa[0] &= this_isa;
		else
			riscv_isa[0] = this_isa;
	}
	acpi_put_table(table);

	/* We don't support systems with F but without D, so mask those out
	 * here. */
	if ((elf_hwcap & COMPAT_HWCAP_ISA_F) && !(elf_hwcap & COMPAT_HWCAP_ISA_D)) {
		pr_info("This kernel does not support systems with F but not D\n");
		elf_hwcap &= ~COMPAT_HWCAP_ISA_F;
	}

	memset(print_str, 0, sizeof(print_str));
	/*
	for (i = 0, j = 0; i < BITS_PER_LONG; i++)
		if (riscv_isa[0] & BIT_MASK(i))
			print_str[j++] = (char)('a' + i);
			*/
	for (i = 0, j = 0; i < sizeof(riscv_exts); i++) {
		if (riscv_isa[0] & RV(riscv_exts[i])) {
			print_str[j++] = riscv_exts[i];
		}
	}
	print_str[j] = '\0';
	pr_info("riscv: ISA extensions %s\n", print_str);

	memset(print_str, 0, sizeof(print_str));
	for (i = 0, j = 0; i < sizeof(riscv_exts); i++) {
		if (elf_hwcap & RV(riscv_exts[i])) {
			print_str[j++] = riscv_exts[i];
		}
	}
	/*
	for (i = 0, j = 0; i < BITS_PER_LONG; i++)
		if (elf_hwcap & BIT_MASK(i))
			print_str[j++] = (char)('a' + i);
			*/
	print_str[j] = '\0';
	pr_info("riscv: ELF capabilities %s\n", print_str);

#ifdef CONFIG_FPU
	if (elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D))
		static_branch_enable(&cpu_hwcap_fpu);
#endif
}

#endif

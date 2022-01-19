// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/of.h>
#include <asm/smp.h>

/*
 * Returns the hart ID of the given device tree node, or -ENODEV if the node
 * isn't an enabled and valid RISC-V hart node.
 */
int riscv_of_processor_hartid(struct device_node *node)
{
	const char *isa;
	u32 hart;

	if (!of_device_is_compatible(node, "riscv")) {
		pr_warn("Found incompatible CPU\n");
		return -ENODEV;
	}

	hart = of_get_cpu_hwid(node, 0);
	if (hart == ~0U) {
		pr_warn("Found CPU without hart ID\n");
		return -ENODEV;
	}

	if (!of_device_is_available(node)) {
		pr_info("CPU with hartid=%d is not available\n", hart);
		return -ENODEV;
	}

	if (of_property_read_string(node, "riscv,isa", &isa)) {
		pr_warn("CPU with hartid=%d has no \"riscv,isa\" property\n", hart);
		return -ENODEV;
	}
	if (isa[0] != 'r' || isa[1] != 'v') {
		pr_warn("CPU with hartid=%d has an invalid ISA of \"%s\"\n", hart, isa);
		return -ENODEV;
	}

	return hart;
}

/*
 * Find hart ID of the CPU DT node under which given DT node falls.
 *
 * To achieve this, we walk up the DT tree until we find an active
 * RISC-V core (HART) node and extract the cpuid from it.
 */
int riscv_of_parent_hartid(struct device_node *node)
{
	for (; node; node = node->parent) {
		if (of_device_is_compatible(node, "riscv"))
			return riscv_of_processor_hartid(node);
	}

	return -1;
}

#ifdef CONFIG_PROC_FS

static void print_isa(struct seq_file *f, const char *isa)
{
	/* Print the entire ISA as it is */
	seq_puts(f, "isa\t\t: ");
	seq_write(f, isa, strlen(isa));
	seq_puts(f, "\n");
}

static void print_mmu(struct seq_file *f, const char *mmu_type)
{
#if defined(CONFIG_32BIT)
	if (strcmp(mmu_type, "riscv,sv32") != 0)
		return;
#elif defined(CONFIG_64BIT)
	if (strcmp(mmu_type, "riscv,sv39") != 0 &&
	    strcmp(mmu_type, "riscv,sv48") != 0)
		return;
#endif

	seq_printf(f, "mmu\t\t: %s\n", mmu_type+6);
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	*pos = cpumask_next(*pos - 1, cpu_online_mask);
	if ((*pos) < nr_cpu_ids)
		return (void *)(uintptr_t)(1 + *pos);
	return NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

#ifdef CONFIG_ACPI

static const char riscv_exts[26] = "iemafdqclbjtpvnsuhkorwxyzg";

#if 0
static char *acpi_risv_i_ext[] = {
	"Zifenceiv2",
	"Zihintpausev2",
	"Zicsr",
	"Zicmobase"
};

static char *acpi_risv_m_ext[] = {
	"Zmmul"
};

static char *acpi_risv_a_ext[] = {
	"Zam"
};

static char *acpi_risv_f_ext[] = {
	"Zfinx",
	"Zhinx",
	"Zhinxmin",
	"Zfh"
};

static char *acpi_risv_d_ext[] = {
	"Zdinx"
};

static char *acpi_risv_c_ext[] = {
	"Zce"
};

static char *acpi_risv_b_ext[] = {
	"Zba",
	"Zbb",
	"Zbc",
	"Zbe",
	"Zbf",
	"Zbk",
	"Zbp",
	"Zbr",
	"Zbkb",
	"Zbkc",
	"Zbkx"
};

static char *acpi_risv_k_ext[] = {
	"Zknd",
	"Zkne",
	"Zknh",
	"Zksed",
	"Zksh",
	"Zkt",
	"Zkr"
};

static char *acpi_risv_j_ext[] = {
	"Zjpm",
};

static char *acpi_risv_t_ext[] = {
	"Ztso",
};

static char *acpi_risv_vm_ext[] = {
	"Svnapot",
	"Svpbmt",
	"Svinval"
};

static char *acpi_risv_timer_ext[] = {
	"Sstc",
};

static char *acpi_risv_pmu_ext[] = {
	"Sscof",
};

#endif

void acpi_print_isa(struct seq_file *m, uint32_t isa)
{
	char print_str[BITS_PER_LONG + 5];
	int i, j;

	memset(print_str, 0, sizeof(print_str));
	strcpy(print_str, "rv64");
	j = strlen(print_str);
	for (i = 0; i < sizeof(riscv_exts); i++) {
		if (isa & RV(riscv_exts[i])) {
			print_str[j++] = riscv_exts[i];
		}
	}

	print_str[j] = '\0';
	print_isa(m, print_str);
}

void acpi_print_mmu(struct seq_file *m, uint8_t mmu_type)
{
	char print_str[16];
	memset(print_str, 0, sizeof(print_str));

	if(mmu_type == ACPI_RHCT_HART_CAP_MMU_TYPE_39)
		strcpy(print_str, "riscv,sv39");
	else if(mmu_type == ACPI_RHCT_HART_CAP_MMU_TYPE_48)
		strcpy(print_str, "riscv,sv48");
	print_mmu(m, print_str);
}

#if 0
void acpi_print_extension(struct seq_file *m, struct acpi_rhct_hart_info_ext *extension_list, int
		num_ext)
{
	int i;
	seq_puts(m, "Extensions\t: ");
	for (i = 0; i < num_ext; i++) {
		switch (extension_list[i].ext)
		{
			case 0x0000 ... 0x0003:
				seq_write(m, acpi_risv_i_ext[extension_list[i].ext -
						ACPI_STD_EXT_I_BASE],
						strlen(acpi_risv_i_ext[extension_list[i].ext
							- ACPI_STD_EXT_I_BASE]));
				break;
			case 0x0100:
				seq_write(m, acpi_risv_m_ext[extension_list[i].ext -
						ACPI_STD_EXT_M_BASE],
						strlen(acpi_risv_m_ext[extension_list[i].ext
							- ACPI_STD_EXT_M_BASE]));
				break;
			case 0x0200:
				seq_write(m, acpi_risv_a_ext[extension_list[i].ext -
						ACPI_STD_EXT_A_BASE],
						strlen(acpi_risv_a_ext[extension_list[i].ext
							- ACPI_STD_EXT_A_BASE]));
				break;
			case 0x0300 ... 0x0303:
				seq_write(m, acpi_risv_f_ext[extension_list[i].ext -
						ACPI_STD_EXT_F_BASE],
						strlen(acpi_risv_f_ext[extension_list[i].ext
							- ACPI_STD_EXT_F_BASE]));
				break;
			case 0x0400:
				seq_write(m, acpi_risv_d_ext[extension_list[i].ext -
						ACPI_STD_EXT_D_BASE],
						strlen(acpi_risv_d_ext[extension_list[i].ext
							- ACPI_STD_EXT_D_BASE]));
				break;
			case 0x0500 ... 0x05ff:
			case 0x0600 ... 0x06ff:
				break;
			case 0x0700:
				seq_write(m, acpi_risv_c_ext[extension_list[i].ext -
						ACPI_STD_EXT_C_BASE],
						strlen(acpi_risv_c_ext[extension_list[i].ext
							- ACPI_STD_EXT_C_BASE]));
				break;
			case 0x0800 ... 0x080B:
				seq_write(m, acpi_risv_b_ext[extension_list[i].ext -
						ACPI_STD_EXT_B_BASE],
						strlen(acpi_risv_b_ext[extension_list[i].ext
							- ACPI_STD_EXT_B_BASE]));
				break;
			case 0x0900 ... 0x0906:
				seq_write(m, acpi_risv_k_ext[extension_list[i].ext -
						ACPI_STD_EXT_K_BASE],
						strlen(acpi_risv_k_ext[extension_list[i].ext
							- ACPI_STD_EXT_K_BASE]));
				break;
			case 0x0A00:
				seq_write(m, acpi_risv_j_ext[extension_list[i].ext -
						ACPI_STD_EXT_J_BASE],
						strlen(acpi_risv_j_ext[extension_list[i].ext
							- ACPI_STD_EXT_J_BASE]));
				break;
			case 0x0B00:
				seq_write(m, acpi_risv_t_ext[extension_list[i].ext -
						ACPI_STD_EXT_T_BASE],
						strlen(acpi_risv_t_ext[extension_list[i].ext
							- ACPI_STD_EXT_T_BASE]));
				break;
			case 0x0C00 ... 0x0Cff:
			case 0x0F00 ... 0x0Fff:
				break;
			case 0x1000 ... 0x1002:
				seq_write(m, acpi_risv_vm_ext[extension_list[i].ext -
						ACPI_SUPER_EXT_VM_BASE],
						strlen(acpi_risv_vm_ext[extension_list[i].ext
							- ACPI_SUPER_EXT_VM_BASE]));
				break;
			case 0x1100:
				seq_write(m, acpi_risv_timer_ext[extension_list[i].ext -
						ACPI_SUPER_EXT_TIMER_BASE],
						strlen(acpi_risv_timer_ext[extension_list[i].ext
							- ACPI_SUPER_EXT_TIMER_BASE]));
				break;
			case 0x1200:
				seq_write(m, acpi_risv_pmu_ext[extension_list[i].ext -
						ACPI_SUPER_EXT_PMU_BASE],
						strlen(acpi_risv_pmu_ext[extension_list[i].ext
							- ACPI_SUPER_EXT_PMU_BASE]));
				break;
			default:
				break;
		}
		seq_puts(m, " ");
	}
	seq_puts(m, "\n\n");
}
#endif


void acpi_print_hart_info(struct seq_file *m, struct acpi_table_header *table_hdr, unsigned long cpu)
{
	struct acpi_rhct_hart_info_cap *entry;
	unsigned long table_end = (unsigned long)table_hdr + table_hdr->length;
	u32 acpi_cpu_id = get_acpi_id_for_cpu(cpu);
	//struct acpi_rhct_hart_info_ext *extension_list;
	union acpi_rhct_hart_caps hwcap;
//	int num_ext;

	entry = ACPI_ADD_PTR(struct acpi_rhct_hart_info_cap, table_hdr,
			     sizeof(struct acpi_table_header));
	while ((unsigned long)entry + entry->length <= table_end) {

		if (entry->length == 0) {
			pr_warn("acpi_print_hart_info: Invalid zero length subtable\n");
			break;
		}
		if (acpi_cpu_id == entry->acpi_proc_id) {
			acpi_print_isa(m, entry->isa);
			hwcap.hart_cap = entry->hart_hwcap;

			acpi_print_mmu(m, hwcap.mmu_type);
			seq_puts(m, "\n");
			return;
		}
		entry = ACPI_ADD_PTR(struct acpi_rhct_hart_info_cap, entry,
				entry->length);
	}

}
#endif

static int c_show(struct seq_file *m, void *v)
{
	unsigned long cpu_id = (unsigned long)v - 1;
	struct device_node *node = of_get_cpu_node(cpu_id, NULL);
	const char *compat, *isa, *mmu;

	seq_printf(m, "processor\t: %lu\n", cpu_id);
	seq_printf(m, "hart\t\t: %lu\n", cpuid_to_hartid_map(cpu_id));
	if(acpi_disabled) {
		if (!of_property_read_string(node, "riscv,isa", &isa))
			print_isa(m, isa);
		if (!of_property_read_string(node, "mmu-type", &mmu))
			print_mmu(m, mmu);
		if (!of_property_read_string(node, "compatible", &compat)
		    && strcmp(compat, "riscv"))
			seq_printf(m, "uarch\t\t: %s\n", compat);
		seq_puts(m, "\n");
		of_node_put(node);
	}
#ifdef CONFIG_ACPI
	else {
		struct acpi_table_header *table;
		acpi_status status;

		status = acpi_get_table(ACPI_SIG_RHCT, 0, &table);
		if (ACPI_FAILURE(status)) {
			pr_warn_once("No RHCT table found, CPU capabilities may be inaccurate\n");
			return -1;
		}
		acpi_print_hart_info(m, table, cpu_id);

		acpi_put_table(table);

	}
#endif

	return 0;
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};

#endif /* CONFIG_PROC_FS */

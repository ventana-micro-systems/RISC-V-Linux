/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2013-2014, Linaro Ltd.
 *	Author: Al Stone <al.stone@linaro.org>
 *	Author: Graeme Gregory <graeme.gregory@linaro.org>
 *	Author: Hanjun Guo <hanjun.guo@linaro.org>
 *
 *  Copyright (C) 2021, Ventana Micro Systems Inc.
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 */

#ifndef _ASM_ACPI_H
#define _ASM_ACPI_H

#include <linux/efi.h>
#include <linux/memblock.h>
#include <linux/psci.h>
#include <linux/stddef.h>

#include <asm/cputype.h>
#include <asm/io.h>
#include <asm/ptrace.h>
#include <asm/smp_plat.h>
#include <asm/tlbflush.h>

/* Basic configuration for ACPI */
#ifdef	CONFIG_ACPI
pgprot_t __acpi_get_mem_attribute(phys_addr_t addr);

/* ACPI table mapping after acpi_permanent_mmap is set */
void __iomem *acpi_os_ioremap(acpi_physical_address phys, acpi_size size);
#define acpi_os_ioremap acpi_os_ioremap

typedef u64 phys_cpuid_t;
#define PHYS_CPUID_INVALID INVALID_HWID

#define acpi_strict 1	/* No out-of-spec workarounds on RISC-V */
extern int acpi_disabled;
extern int acpi_noirq;
extern int acpi_pci_disabled;

enum {
	ACPI_RHCT_HART_CAP_MMU_TYPE_39,
	ACPI_RHCT_HART_CAP_MMU_TYPE_48,
};

static inline void disable_acpi(void)
{
	acpi_disabled = 1;
	acpi_pci_disabled = 1;
	acpi_noirq = 1;
}

static inline void enable_acpi(void)
{
	acpi_disabled = 0;
	acpi_pci_disabled = 0;
	acpi_noirq = 0;
}

/*
 * The ACPI processor driver for ACPI core code needs this macro
 * to find out this cpu was already mapped (mapping from CPU hardware
 * ID to CPU logical ID) or not.
 */
#define cpu_physical_id(cpu) cpu_logical_map(cpu)

/*
 * It's used from ACPI core in kdump to boot UP system with SMP kernel.
 * Since MADT must provide at least one IMSIC structure for AIA
 * initialization, CPU will be always available in MADT on RISC-V.
 */
static inline bool acpi_has_cpu_in_madt(void)
{
	return true;
}

struct acpi_madt_rintc *acpi_cpu_get_madt_rintc(int cpu);
static inline u32 get_acpi_id_for_cpu(unsigned int cpu)
{
	return	acpi_cpu_get_madt_rintc(cpu)->uid;
}

static inline void arch_fix_phys_package_id(int num, u32 slot) { }
void __init acpi_init_cpus(void);
int apei_claim_sea(struct pt_regs *regs);
#else
static inline void acpi_init_cpus(void) { }
static inline int apei_claim_sea(struct pt_regs *regs) { return -ENOENT; }
#endif /* CONFIG_ACPI */

#ifdef	CONFIG_ACPI_APEI
/*
 * acpi_disable_cmcff is used in drivers/acpi/apei/hest.c for disabling
 * IA-32 Architecture Corrected Machine Check (CMC) Firmware-First mode
 * with a kernel command line parameter "acpi=nocmcoff". But we don't
 * have this IA-32 specific feature on RISCV, this definition is only
 * for compatibility.
 */
#define acpi_disable_cmcff 1
static inline pgprot_t arch_apei_get_mem_attribute(phys_addr_t addr)
{
	return __acpi_get_mem_attribute(addr);
}
#endif /* CONFIG_ACPI_APEI */

#ifdef CONFIG_ACPI_NUMA
int acpi_numa_get_nid(unsigned int cpu);
void acpi_map_cpus_to_nodes(void);
#else
static inline int acpi_numa_get_nid(unsigned int cpu) { return NUMA_NO_NODE; }
static inline void acpi_map_cpus_to_nodes(void) { }
#endif /* CONFIG_ACPI_NUMA */

#define ACPI_TABLE_UPGRADE_MAX_PHYS MEMBLOCK_ALLOC_ACCESSIBLE

#define ACPI_TABLE_FADT_MAJOR_REVISION 5
#define ACPI_TABLE_FADT_MINOR_REVISION 1

int riscv_get_hw_capability(unsigned int cpu, struct acpi_pptt_rv_hwcap *cap);

#define RV(x) ((unsigned long)1 << (x - 'a'))

enum riscv_extension_base {
	ACPI_STD_EXT_I_BASE = 0x0000,
	ACPI_STD_EXT_M_BASE = 0x0100,
	ACPI_STD_EXT_A_BASE = 0x0200,
	ACPI_STD_EXT_F_BASE = 0x0300,
	ACPI_STD_EXT_D_BASE = 0x0400,
	ACPI_STD_EXT_Q_BASE = 0x0500,
	ACPI_STD_EXT_L_BASE = 0x0600,
	ACPI_STD_EXT_C_BASE = 0x0700,
	ACPI_STD_EXT_B_BASE = 0x0800,
	ACPI_STD_EXT_K_BASE = 0x0900,
	ACPI_STD_EXT_J_BASE = 0x0a00,
	ACPI_STD_EXT_T_BASE = 0x0b00,
	ACPI_STD_EXT_P_BASE = 0x0c00,
	ACPI_STD_EXT_V_BASE = 0x0d00,
	ACPI_SUPER_EXT_VM_BASE = 0x1000,
	ACPI_SUPER_EXT_TIMER_BASE = 0x1100,
	ACPI_SUPER_EXT_PMU_BASE = 0x1200
};

#endif /*_ASM_ACPI_H*/

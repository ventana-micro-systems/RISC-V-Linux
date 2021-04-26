/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 */
#ifndef __LINUX_IRQCHIP_RISCV_IMSIC_H
#define __LINUX_IRQCHIP_RISCV_IMSIC_H

#include <linux/types.h>
#include <asm/csr.h>

#define IMSIC_MMIO_PAGE_SHIFT		12
#define IMSIC_MMIO_PAGE_SZ		(1UL << IMSIC_MMIO_PAGE_SHIFT)
#define IMSIC_MMIO_PAGE_LE		0x00
#define IMSIC_MMIO_PAGE_BE		0x04

#define IMSIC_MIN_ID			63
#define IMSIC_MAX_ID			2048

#define IMSIC_EIDELIVERY		0x70

#define IMSIC_EITHRESHOLD		0x72

#define IMSIC_EIP0			0x80
#define IMSIC_EIP63			0xbf
#define IMSIC_EIPx_BITS		32

#define IMSIC_EIE0			0xc0
#define IMSIC_EIE63			0xff
#define IMSIC_EIEx_BITS		32

#define IMSIC_FIRST			IMSIC_EIDELIVERY
#define IMSIC_LAST			IMSIC_EIE63

#define IMSIC_MMIO_SETIPNUM_LE		0x00
#define IMSIC_MMIO_SETIPNUM_BE		0x04

#ifdef CONFIG_RISCV_IMSIC

extern unsigned int imsic_num_ids(void);

extern unsigned int imsic_num_cpu_pages(void);

extern int imsic_cpu_page_phys(unsigned int cpu, unsigned int guest_index,
			       phys_addr_t *out_msi_pa);

extern void *imsic_cpu_page_virt(unsigned int cpu, unsigned int guest_index);

#else

static inline unsigned int imsic_num_ids(void)
{
	return 0;
}

static inline unsigned int imsic_num_cpu_pages(void)
{
	return 0;
}

static inline int imsic_cpu_page_phys(unsigned int cpu,
				      unsigned int guest_index,
				      phys_addr_t *out_msi_pa)
{
	return -ENODEV;
}

static inline void *imsic_cpu_page_virt(unsigned int cpu,
					unsigned int guest_index)
{
	return NULL;
}

#endif

#endif

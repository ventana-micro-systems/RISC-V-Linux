// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017-2018 SiFive
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */

#define pr_fmt(fmt) "riscv-intc: " fmt
#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/cpu.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/smp.h>
#include <asm/hwcap.h>

struct irq_domain *intc_domain = NULL;
struct fwnode_handle *intc_fwnode;

static asmlinkage void riscv_intc_irq(struct pt_regs *regs)
{
	unsigned long cause = regs->cause & ~CAUSE_IRQ_FLAG;

	if (unlikely(cause >= BITS_PER_LONG))
		panic("unexpected interrupt cause");

	generic_handle_domain_irq(intc_domain, cause);
}

static asmlinkage void riscv_intc_aia_irq(struct pt_regs *regs)
{
	unsigned long topi;

	while ((topi = csr_read(CSR_TOPI)))
		generic_handle_domain_irq(intc_domain,
					  topi >> TOPI_IID_SHIFT);
}

/*
 * On RISC-V systems local interrupts are masked or unmasked by writing
 * the SIE (Supervisor Interrupt Enable) CSR.  As CSRs can only be written
 * on the local hart, these functions can only be called on the hart that
 * corresponds to the IRQ chip.
 */

static void riscv_intc_irq_mask(struct irq_data *d)
{
	if (d->hwirq < BITS_PER_LONG)
		csr_clear(CSR_IE, BIT(d->hwirq));
	else
		csr_clear(CSR_IEH, BIT(d->hwirq - BITS_PER_LONG));
}

static void riscv_intc_irq_unmask(struct irq_data *d)
{
	if (d->hwirq < BITS_PER_LONG)
		csr_set(CSR_IE, BIT(d->hwirq));
	else
		csr_set(CSR_IEH, BIT(d->hwirq - BITS_PER_LONG));
}

static struct irq_chip riscv_intc_chip = {
	.name = "RISC-V INTC",
	.irq_mask = riscv_intc_irq_mask,
	.irq_unmask = riscv_intc_irq_unmask,
};

static int riscv_intc_domain_map(struct irq_domain *d, unsigned int irq,
				 irq_hw_number_t hwirq)
{
	irq_set_percpu_devid(irq);
	irq_domain_set_info(d, irq, hwirq, &riscv_intc_chip, d->host_data,
			    handle_percpu_devid_irq, NULL, NULL);

	return 0;
}

static int riscv_intc_domain_alloc(struct irq_domain *domain,
				   unsigned int virq, unsigned int nr_irqs,
				   void *arg)
{
	int i, ret;
	irq_hw_number_t hwirq;
	unsigned int type = IRQ_TYPE_NONE;
	struct irq_fwspec *fwspec = arg;

	ret = irq_domain_translate_onecell(domain, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		ret = riscv_intc_domain_map(domain, virq + i, hwirq + i);
		if (ret)
			return ret;
	}

	return 0;
}

static const struct irq_domain_ops riscv_intc_domain_ops = {
	.map = riscv_intc_domain_map,
	.xlate = irq_domain_xlate_onecell,
	.alloc = riscv_intc_domain_alloc
};

static int __init riscv_intc_init(struct device_node *node,
				  struct device_node *parent)
{
	int rc, hartid, nr_irqs;

	hartid = riscv_of_parent_hartid(node);
	if (hartid < 0) {
		pr_warn("unable to find hart id for %pOF\n", node);
		return 0;
	}

	/*
	 * The DT will have one INTC DT node under each CPU (or HART)
	 * DT node so riscv_intc_init() function will be called once
	 * for each INTC DT node. We only need to do INTC initialization
	 * for the INTC DT node belonging to boot CPU (or boot HART).
	 */
	if (riscv_hartid_to_cpuid(hartid) != smp_processor_id())
		return 0;

	nr_irqs = BITS_PER_LONG;
	if (riscv_aia_available && BITS_PER_LONG == 32)
		nr_irqs = nr_irqs * 2;

	intc_domain = irq_domain_add_linear(node, nr_irqs,
					    &riscv_intc_domain_ops, NULL);
	if (!intc_domain) {
		pr_err("unable to add IRQ domain\n");
		return -ENXIO;
	}

	if (riscv_aia_available)
		rc = set_handle_irq(&riscv_intc_aia_irq);
	else
		rc = set_handle_irq(&riscv_intc_irq);
	if (rc) {
		pr_err("failed to set irq handler\n");
		return rc;
	}

	/*
	 * Make INTC as the default domain which will allow drivers
	 * not having dedicated DT/ACPI fwnode (such as RISC-V SBI IPI
	 * driver, RISC-V timer driver, RISC-V PMU driver, etc) can
	 * directly create local interrupt mapping using standardized
	 * local interrupt numbers.
	 */
	irq_set_default_host(intc_domain);

	pr_info("%d local interrupts mapped%s\n",
		nr_irqs, (riscv_aia_available) ? " using AIA" : "");

	return 0;
}

IRQCHIP_DECLARE(riscv, "riscv,cpu-intc", riscv_intc_init);

#ifdef CONFIG_ACPI

/*
 * Need this only if we need to use probe model for INTC
 */

static int __init
riscv_intc_acpi_parse_madt(union acpi_subtable_headers *header,
			   const unsigned long end)
{
//	struct acpi_madt_rintc *rintc;

//	rintc = (struct acpi_madt_rintc *)header;

	// REVISIT
	// May be better to discover this capability from a common
	// HW feature table along with ISA, mmu type etc than from INTC table
//	riscv_aia_available = rintc->aia_csr_enabled;

	return 0;
}

static bool __init acpi_validate_rintc_table(struct acpi_subtable_header
					     *header,
					     struct acpi_probe_entry *ape)
{
	int count;
	/* Collect Information from MADT */
	count = acpi_table_parse_madt(ACPI_MADT_TYPE_RINTC,
				      riscv_intc_acpi_parse_madt, 0);
	if (count <= 0)
		return false;

	return true;
}

static int __init
riscv_intc_acpi_init(union acpi_subtable_headers *header,
		     const unsigned long end)
{
	int rc;
	int nr_irqs;
	struct fwnode_handle *fn;
	struct acpi_madt_rintc *rintc;

	rintc = (struct acpi_madt_rintc *)header;

	if (rintc->hartid != smp_processor_id()) {
		return 0;
	}

	if (intc_domain) {
		pr_info
		    ("riscv_intc_acpi_init: RISCV INTC already initialized\n");
		return 0;
	}

	nr_irqs = BITS_PER_LONG;
	if (riscv_aia_available && (BITS_PER_LONG == 32))
		nr_irqs = BITS_PER_LONG * 2;

	fn = irq_domain_alloc_named_fwnode("RISCV-INTC");
	intc_fwnode = fn;
	WARN_ON(fn == NULL);
	if (!fn)
		return -1;
	intc_domain = irq_domain_create_linear(fn, nr_irqs,
					       &riscv_intc_domain_ops, NULL);
	if (!intc_domain) {
		pr_err("unable to add IRQ domain\n");
		return -ENXIO;
	}

	if (riscv_aia_available)
		rc = set_handle_irq(&riscv_intc_aia_irq);
	else
		rc = set_handle_irq(&riscv_intc_irq);

	if (rc) {
		pr_err("failed to set irq handler\n");
		return rc;
	}
	pr_info("riscv_intc_acpi_init: %d local interrupts mapped\n", nr_irqs);

	return 0;
}

IRQCHIP_ACPI_DECLARE(riscv_intc, ACPI_MADT_TYPE_RINTC,
		     acpi_validate_rintc_table, 1, riscv_intc_acpi_init);
#endif

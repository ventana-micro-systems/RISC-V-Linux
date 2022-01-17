// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI based IPI support.
 *
 * Copyright (c) 2021 Western Digital Corporation or its affiliates.
 * Copyright (c) 2022 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "riscv-sbi-ipi: " fmt
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqdomain.h>
#include <linux/of.h>
#include <linux/smp.h>
#include <asm/sbi.h>

static int sbi_ipi_parent_irq __ro_after_init;
static struct irq_domain *sbi_ipi_domain __ro_after_init;
static DEFINE_PER_CPU(unsigned long, sbi_ipi_bits);

static void sbi_ipi_dummy(struct irq_data *d)
{
}

static void sbi_ipi_send_mask(struct irq_data *d, const struct cpumask *mask)
{
	int cpu;
	struct cpumask hartid_mask;

	/* Barrier before doing atomic bit update to IPI bits */
	smp_mb__before_atomic();
	for_each_cpu(cpu, mask)
		set_bit(d->hwirq, per_cpu_ptr(&sbi_ipi_bits, cpu));
	/* Barrier after doing atomic bit update to IPI bits */
	smp_mb__after_atomic();

	riscv_cpuid_to_hartid_mask(mask, &hartid_mask);

	sbi_send_ipi(cpumask_bits(&hartid_mask));
}

static struct irq_chip sbi_ipi_chip = {
	.name		= "RISC-V SBI IPI",
	.irq_mask	= sbi_ipi_dummy,
	.irq_unmask	= sbi_ipi_dummy,
	.ipi_send_mask	= sbi_ipi_send_mask,
};

static int sbi_ipi_domain_map(struct irq_domain *d, unsigned int irq,
			      irq_hw_number_t hwirq)
{
	irq_set_percpu_devid(irq);
	irq_domain_set_info(d, irq, hwirq, &sbi_ipi_chip, d->host_data,
			    handle_percpu_devid_irq, NULL, NULL);

	return 0;
}

static int sbi_ipi_domain_alloc(struct irq_domain *d, unsigned int virq,
				unsigned int nr_irqs, void *arg)
{
	int i, ret;
	irq_hw_number_t hwirq;
	unsigned int type = IRQ_TYPE_NONE;
	struct irq_fwspec *fwspec = arg;

	ret = irq_domain_translate_onecell(d, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		ret = sbi_ipi_domain_map(d, virq + i, hwirq + i);
		if (ret)
			return ret;
	}

	return 0;
}

static const struct irq_domain_ops sbi_ipi_domain_ops = {
	.translate	= irq_domain_translate_onecell,
	.alloc		= sbi_ipi_domain_alloc,
	.free		= irq_domain_free_irqs_top,
};

static void sbi_ipi_handle_irq(struct irq_desc *desc)
{
	int err;
	struct irq_chip *chip = irq_desc_get_chip(desc);
	unsigned long irqs, *bits = this_cpu_ptr(&sbi_ipi_bits);
	irq_hw_number_t hwirq;

	chained_irq_enter(chip, desc);

	while (true) {
		csr_clear(CSR_IP, IE_SIE);

		/* Order bit clearing and data access. */
		mb();

		irqs = xchg(bits, 0);
		if (!irqs)
			goto done;

		for_each_set_bit(hwirq, &irqs, BITS_PER_LONG) {
			err = generic_handle_domain_irq(sbi_ipi_domain,
							hwirq);
			if (unlikely(err))
				pr_warn_ratelimited(
					"can't find mapping for hwirq %lu\n",
					hwirq);
		}
	}

done:
	chained_irq_exit(chip, desc);
}

static int sbi_ipi_dying_cpu(unsigned int cpu)
{
	disable_percpu_irq(sbi_ipi_parent_irq);
	return 0;
}

static int sbi_ipi_starting_cpu(unsigned int cpu)
{
	enable_percpu_irq(sbi_ipi_parent_irq,
			  irq_get_trigger_type(sbi_ipi_parent_irq));
	return 0;
}

void __init sbi_ipi_init(void)
{
	int virq;
	struct irq_fwspec ipi;

	if (riscv_ipi_have_virq_range())
		return;

	sbi_ipi_parent_irq = irq_create_mapping(NULL, RV_IRQ_SOFT);
	if (!sbi_ipi_parent_irq) {
		pr_err("unable to create INTC IRQ mapping\n");
		return;
	}

	irq_set_chained_handler(sbi_ipi_parent_irq, sbi_ipi_handle_irq);

	sbi_ipi_domain = irq_domain_add_linear(NULL, BITS_PER_LONG,
						&sbi_ipi_domain_ops, NULL);
	if (!sbi_ipi_domain) {
		pr_err("unable to add SBI IPI IRQ domain\n");
		goto fail_dispose_mapping;
	}

	ipi.fwnode = sbi_ipi_domain->fwnode;
	ipi.param_count = 1;
	ipi.param[0] = 0;
	virq = __irq_domain_alloc_irqs(sbi_ipi_domain, -1, BITS_PER_LONG,
				       NUMA_NO_NODE, &ipi,
				       false, NULL);
	if (virq <= 0) {
		pr_err("unable to alloc IRQs from SBI IPI IRQ domain\n");
		goto fail_domain_remove;
	}

	riscv_ipi_set_virq_range(virq, BITS_PER_LONG);

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			  "irqchip/riscv/sbi-ipi:starting",
			  sbi_ipi_starting_cpu, sbi_ipi_dying_cpu);

	pr_info("providing IPIs for all CPUs\n");
	return;

fail_domain_remove:
	irq_domain_remove(sbi_ipi_domain);
fail_dispose_mapping:
	irq_dispose_mapping(sbi_ipi_parent_irq);
}

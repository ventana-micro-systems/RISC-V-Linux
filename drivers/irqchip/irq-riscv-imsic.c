// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 */

#define pr_fmt(fmt) "riscv-imsic: " fmt
#include <linux/acpi.h>
#include <linux/bitmap.h>
#include <linux/cpu.h>
#include <linux/dma-iommu.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqchip/riscv-imsic.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <asm/hwcap.h>
#include <linux/irqchip/riscv-intc.h>
#include <clocksource/timer-riscv.h>
#include <linux/delay.h>

#define IMSIC_DISABLE_EIDELIVERY	0
#define IMSIC_ENABLE_EIDELIVERY	1
#define IMSIC_DISABLE_EITHRESHOLD	0
#define IMSIC_ENABLE_EITHRESHOLD	(IMSIC_MAX_ID - 1)

#define imsic_csr_write(__c, __v)	\
do { \
	csr_write(CSR_ISELECT, __c); \
	csr_write(CSR_IREG, __v); \
} while (0)

#define imsic_csr_read(__c)	\
({ \
	unsigned long __v; \
	csr_write(CSR_ISELECT, __c); \
	__v = csr_read(CSR_IREG); \
	__v; \
})

struct imsic_mmio {
	phys_addr_t pa;
	void __iomem *va;
	unsigned long size;
};

struct imsic_priv {
	/*
	 * MSI Target Address Scheme
	 *
	 * XLEN-1                                                12     0
	 * |                                                     |     |
	 * -------------------------------------------------------------
	 * |xxxxxx|Group Index|xxxxxxxxxxx|HART Index|Guest Index|  0  |
	 * -------------------------------------------------------------
	 */
	u32 guest_index_bits;
	u32 hart_index_bits;
	u32 group_index_bits;
	u32 group_index_shift;

	/* Number of interrupt identities */
	u32 nr_ids;

	/* Global base address matching all MMIO regions */
	phys_addr_t base_addr;

	/* MMIO regions */
	u32 num_mmios;
	struct imsic_mmio *mmios;

	/* Global state of interrupt identities */
	raw_spinlock_t ids_lock;
	unsigned long *ids_used_bimap;
	unsigned long *ids_enabled_bimap;
	unsigned int *ids_target_cpu;

	/* Mask for connected CPUs */
	struct cpumask lmask;

#ifdef CONFIG_SMP
	/* IPI domain */
	u32 base_ipi;
	u32 nr_ipis;
	struct device_node *ipi_node;
	struct irq_domain *ipi_domain;
#endif

	/* IRQ domains */
	struct irq_domain *base_domain;
	struct irq_domain *pci_domain;
	struct irq_domain *plat_domain;
};

struct imsic_handler {
	phys_addr_t msi_pa;
	void __iomem *msi_va;
	struct imsic_priv *priv;
};

static bool imsic_init_done;
struct fwnode_handle *imsic_domain_id;

static int imsic_parent_irq;
static DEFINE_PER_CPU(struct imsic_handler, imsic_handlers);

unsigned int imsic_num_ids(void)
{
	struct imsic_handler *handler = this_cpu_ptr(&imsic_handlers);

	if (!handler || !handler->priv)
		return 0;

	return handler->priv->nr_ids;
}

EXPORT_SYMBOL_GPL(imsic_num_ids);

unsigned int imsic_num_cpu_pages(void)
{
	struct imsic_handler *handler = this_cpu_ptr(&imsic_handlers);

	if (!handler || !handler->priv)
		return 0;

	return BIT(handler->priv->guest_index_bits);
}

EXPORT_SYMBOL_GPL(imsic_num_cpu_pages);

int imsic_cpu_page_phys(unsigned int cpu, unsigned int guest_index,
			phys_addr_t * out_msi_pa)
{
	struct imsic_handler *handler;

	handler = per_cpu_ptr(&imsic_handlers, cpu);
	if (!handler || !handler->priv)
		return -ENODEV;
	if (BIT(handler->priv->guest_index_bits) <= guest_index)
		return -EINVAL;

	if (out_msi_pa)
		*out_msi_pa = handler->msi_pa +
		    (guest_index * IMSIC_MMIO_PAGE_SZ);

	return 0;
}

EXPORT_SYMBOL_GPL(imsic_cpu_page_phys);

void __iomem *imsic_cpu_page_virt(unsigned int cpu, unsigned int guest_index)
{
	struct imsic_handler *handler;

	handler = per_cpu_ptr(&imsic_handlers, cpu);
	if (!handler || !handler->priv)
		return NULL;
	if (BIT(handler->priv->guest_index_bits) <= guest_index)
		return NULL;

	return handler->msi_va + (guest_index * IMSIC_MMIO_PAGE_SZ);
}

EXPORT_SYMBOL_GPL(imsic_cpu_page_virt);

static int imsic_get_cpu(struct imsic_priv *priv,
			 const struct cpumask *mask_val, bool force,
			 unsigned int *out_target_cpu)
{
	struct cpumask amask;
	unsigned int cpu;

	cpumask_and(&amask, &priv->lmask, mask_val);

	if (force)
		cpu = cpumask_first(&amask);
	else
		cpu = cpumask_any_and(&amask, cpu_online_mask);

	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	if (out_target_cpu)
		*out_target_cpu = cpu;

	return 0;
}

static int imsic_get_cpu_msi_msg(unsigned int cpu, unsigned int id,
				 struct msi_msg *msg)
{
	phys_addr_t msi_addr;
	int err;

	err = imsic_cpu_page_phys(cpu, 0, &msi_addr);
	if (err)
		return err;

	msg->address_hi = upper_32_bits(msi_addr);
	msg->address_lo = lower_32_bits(msi_addr);
	msg->data = id;

	return err;
}

static void imsic_id_set_target(struct imsic_priv *priv,
				unsigned int id, unsigned int target_cpu)
{
	raw_spin_lock(&priv->ids_lock);
	priv->ids_target_cpu[id] = target_cpu;
	raw_spin_unlock(&priv->ids_lock);
}

static unsigned int imsic_id_get_target(struct imsic_priv *priv,
					unsigned int id)
{
	unsigned int ret;

	raw_spin_lock(&priv->ids_lock);
	ret = priv->ids_target_cpu[id];
	raw_spin_unlock(&priv->ids_lock);

	return ret;
}

static void __imsic_id_enable(void *data)
{
	csr_write(CSR_SETEIENUM, (unsigned long)data);
}

static void imsic_id_enable(struct imsic_priv *priv, unsigned int id)
{
	struct cpumask amask;

	raw_spin_lock(&priv->ids_lock);
	bitmap_set(priv->ids_enabled_bimap, id, 1);
	raw_spin_unlock(&priv->ids_lock);

	cpumask_and(&amask, &priv->lmask, cpu_online_mask);
	on_each_cpu_mask(&amask, __imsic_id_enable,
			 (void *)(unsigned long)id, 1);
}

static void __imsic_id_disable(void *data)
{
	csr_write(CSR_CLREIENUM, (unsigned long)data);
}

static void imsic_id_disable(struct imsic_priv *priv, unsigned int id)
{
	struct cpumask amask;

	raw_spin_lock(&priv->ids_lock);
	bitmap_clear(priv->ids_enabled_bimap, id, 1);
	raw_spin_unlock(&priv->ids_lock);

	cpumask_and(&amask, &priv->lmask, cpu_online_mask);
	on_each_cpu_mask(&amask, __imsic_id_disable,
			 (void *)(unsigned long)id, 1);
}

static void imsic_ids_local_sync(struct imsic_priv *priv)
{
	int i;

	raw_spin_lock(&priv->ids_lock);
	for (i = 1; i <= priv->nr_ids; i++) {
		if ((priv->base_ipi <= i) &&
		    (i < (priv->base_ipi + priv->nr_ipis)))
			continue;
		if (test_bit(i, priv->ids_enabled_bimap))
			csr_write(CSR_SETEIENUM, i);
		else
			csr_write(CSR_CLREIENUM, i);
	}
	raw_spin_unlock(&priv->ids_lock);
}

static void imsic_ids_local_delivery(struct imsic_priv *priv, bool enable)
{
	if (enable) {
		imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_ENABLE_EITHRESHOLD);
		imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_ENABLE_EIDELIVERY);
	} else {
		imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_DISABLE_EIDELIVERY);
		imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_DISABLE_EITHRESHOLD);
	}
}

static int imsic_ids_alloc(struct imsic_priv *priv,
			   unsigned int max_id, unsigned int order)
{
	int ret;

	if ((priv->nr_ids < max_id) || (max_id < BIT(order)))
		return -EINVAL;

	raw_spin_lock(&priv->ids_lock);
	ret = bitmap_find_free_region(priv->ids_used_bimap, max_id + 1, order);
	raw_spin_unlock(&priv->ids_lock);

	return ret;
}

static void imsic_ids_free(struct imsic_priv *priv, unsigned int base_id,
			   unsigned int order)
{
	raw_spin_lock(&priv->ids_lock);
	bitmap_release_region(priv->ids_used_bimap, base_id, order);
	raw_spin_unlock(&priv->ids_lock);
}

static int __init imsic_ids_init(struct imsic_priv *priv)
{
	int i;

	raw_spin_lock_init(&priv->ids_lock);

	/* Allocate used bitmap */
	priv->ids_used_bimap = kcalloc(BITS_TO_LONGS(priv->nr_ids + 1),
				       sizeof(unsigned long), GFP_KERNEL);
	if (!priv->ids_used_bimap)
		return -ENOMEM;

	/* Allocate enabled bitmap */
	priv->ids_enabled_bimap = kcalloc(BITS_TO_LONGS(priv->nr_ids + 1),
					  sizeof(unsigned long), GFP_KERNEL);
	if (!priv->ids_enabled_bimap) {
		kfree(priv->ids_used_bimap);
		return -ENOMEM;
	}

	/* Allocate target CPU array */
	priv->ids_target_cpu = kcalloc(priv->nr_ids + 1,
				       sizeof(unsigned int), GFP_KERNEL);
	if (!priv->ids_target_cpu) {
		kfree(priv->ids_enabled_bimap);
		kfree(priv->ids_used_bimap);
		return -ENOMEM;
	}
	for (i = 0; i <= priv->nr_ids; i++)
		priv->ids_target_cpu[i] = UINT_MAX;

	/* Reserve ID#0 because it is special and never implemented */
	bitmap_set(priv->ids_used_bimap, 0, 1);

	return 0;
}

static void __init imsic_ids_cleanup(struct imsic_priv *priv)
{
	kfree(priv->ids_target_cpu);
	kfree(priv->ids_enabled_bimap);
	kfree(priv->ids_used_bimap);
}

#ifdef CONFIG_SMP
static void imsic_ipi_mask(struct irq_data *d)
{
	struct imsic_priv *priv = irq_data_get_irq_chip_data(d);
	unsigned long hwirq = priv->base_ipi + d->hwirq;

	__imsic_id_disable((void *)hwirq);
}

static void imsic_ipi_unmask(struct irq_data *d)
{
	struct imsic_priv *priv = irq_data_get_irq_chip_data(d);
	unsigned long hwirq = priv->base_ipi + d->hwirq;

	__imsic_id_enable((void *)hwirq);
}

static void imsic_ipi_send_mask(struct irq_data *d, const struct cpumask *mask)
{
	int cpu;
	void __iomem *msi_va;
	struct imsic_priv *priv = irq_data_get_irq_chip_data(d);
	unsigned long hwirq = priv->base_ipi + d->hwirq;

	for_each_cpu(cpu, mask) {
		msi_va = imsic_cpu_page_virt(cpu, 0);
		if (!msi_va) {
			pr_warn("CPU%d: failed to get MSI address\n", cpu);
			continue;
		}
		writel(hwirq, msi_va);
	}
}

static struct irq_chip imsic_ipi_chip = {
	.name = "RISC-V IMSIC-IPI",
	.irq_mask = imsic_ipi_mask,
	.irq_unmask = imsic_ipi_unmask,
	.ipi_send_mask = imsic_ipi_send_mask,
};

static int imsic_ipi_domain_map(struct irq_domain *d, unsigned int irq,
				irq_hw_number_t hwirq)
{
	irq_set_percpu_devid(irq);
	irq_domain_set_info(d, irq, hwirq, &imsic_ipi_chip, d->host_data,
			    handle_percpu_devid_irq, NULL, NULL);

	return 0;
}

static int imsic_ipi_domain_alloc(struct irq_domain *d, unsigned int virq,
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
		ret = imsic_ipi_domain_map(d, virq + i, hwirq + i);
		if (ret)
			return ret;
	}

	return 0;
}

static const struct irq_domain_ops imsic_ipi_domain_ops = {
	.translate = irq_domain_translate_onecell,
	.alloc = imsic_ipi_domain_alloc,
	.free = irq_domain_free_irqs_top,
};

static int __init imsic_ipi_set_virq(struct imsic_priv *priv)
{
	int virq;
	struct irq_fwspec ipi = {
		.fwnode = priv->ipi_domain->fwnode,
		.param_count = 1,
		.param[0] = 0,
	};

	virq = __irq_domain_alloc_irqs(priv->ipi_domain, -1, priv->nr_ipis,
				       NUMA_NO_NODE, &ipi, false, NULL);
	if (virq <= 0)
		return -ENOMEM;

	riscv_ipi_set_virq_range(virq, priv->nr_ipis, true);

	return 0;
}

static int __init imsic_ipi_domain_init(struct imsic_priv *priv,
					struct device_node *node)
{
	int rc;
	u32 base, nr;

	/* Find IPI base */
	rc = of_property_read_u32_index(node, "imsic,ipi-range", 0, &base);
	if (rc)
		return 0;

	/* Find IPI count */
	rc = of_property_read_u32_index(node, "imsic,ipi-range", 1, &nr);
	if (rc)
		return 0;

	/* Sanity check on IPI range */
	if (!base || priv->nr_ids < base)
		return -EINVAL;
	if (!nr || priv->nr_ids < (base + nr - 1))
		return -EINVAL;
	priv->base_ipi = base;
	priv->nr_ipis = nr;

	/* Reserve IDs for IPI */
	bitmap_set(priv->ids_used_bimap, priv->base_ipi, priv->nr_ipis);

	/* Find boot CPU node */
	priv->ipi_node = of_get_cpu_node(smp_processor_id(), NULL);
	if (!priv->ipi_node) {
		bitmap_clear(priv->ids_used_bimap, priv->base_ipi,
			     priv->nr_ipis);
		return -ENODEV;
	}

	/* Create IMSIC IPI domain using boot CPU node */
	priv->ipi_domain = irq_domain_add_linear(priv->ipi_node,
						 priv->nr_ipis,
						 &imsic_ipi_domain_ops, priv);
	if (!priv->ipi_domain) {
		of_node_put(priv->ipi_node);
		bitmap_clear(priv->ids_used_bimap, priv->base_ipi,
			     priv->nr_ipis);
		return -ENOMEM;
	}

	/* Set arch virq range */
	rc = imsic_ipi_set_virq(priv);
	if (rc) {
		irq_domain_remove(priv->ipi_domain);
		of_node_put(priv->ipi_node);
		bitmap_clear(priv->ids_used_bimap, priv->base_ipi,
			     priv->nr_ipis);
		return rc;
	}

	return 0;
}

static void __init imsic_ipi_domain_cleanup(struct imsic_priv *priv)
{
	irq_domain_remove(priv->ipi_domain);
	of_node_put(priv->ipi_node);
	bitmap_clear(priv->ids_used_bimap, priv->base_ipi, priv->nr_ipis);
}
#else
static int __init imsic_ipi_domain_init(struct imsic_priv *priv,
					struct device_node *node)
{
	return 0;
}

static void __init imsic_ipi_domain_cleanup(struct imsic_priv *priv)
{
}
#endif

static void imsic_irq_mask(struct irq_data *d)
{
	imsic_id_disable(irq_data_get_irq_chip_data(d), d->hwirq);
}

static void imsic_irq_unmask(struct irq_data *d)
{
	imsic_id_enable(irq_data_get_irq_chip_data(d), d->hwirq);
}

static void imsic_irq_eoi(struct irq_data *d)
{
	/*
	 * Provide dummy EOI callback so that MSIs of IMSIC base domain
	 * can be chained by next-level interrupt conroller such as APLIC.
	 */
}

static void imsic_irq_compose_msi_msg(struct irq_data *d, struct msi_msg *msg)
{
	struct imsic_priv *priv = irq_data_get_irq_chip_data(d);
	unsigned int cpu;
	int err;

	cpu = imsic_id_get_target(priv, d->hwirq);
	WARN_ON(cpu == UINT_MAX);

	err = imsic_get_cpu_msi_msg(cpu, d->hwirq, msg);
	WARN_ON(err);

	iommu_dma_compose_msi_msg(irq_data_get_msi_desc(d), msg);
}

#ifdef CONFIG_SMP
static int imsic_irq_set_affinity(struct irq_data *d,
				  const struct cpumask *mask_val, bool force)
{
	struct imsic_priv *priv = irq_data_get_irq_chip_data(d);
	unsigned int target_cpu;
	int rc;

	rc = imsic_get_cpu(priv, mask_val, force, &target_cpu);
	if (rc)
		return rc;

	imsic_id_set_target(priv, d->hwirq, target_cpu);

	return IRQ_SET_MASK_OK;
}
#endif

static struct irq_chip imsic_irq_base_chip = {
	.name = "RISC-V IMSIC-BASE",
	.irq_mask = imsic_irq_mask,
	.irq_unmask = imsic_irq_unmask,
	.irq_eoi = imsic_irq_eoi,
#ifdef CONFIG_SMP
	.irq_set_affinity = imsic_irq_set_affinity,
#endif
	.irq_compose_msi_msg = imsic_irq_compose_msi_msg,
};

static int imsic_irq_domain_alloc(struct irq_domain *domain,
				  unsigned int virq,
				  unsigned int nr_irqs, void *args)
{
	struct imsic_priv *priv = domain->host_data;
	msi_alloc_info_t *info = args;
	phys_addr_t msi_addr;
	int i, hwirq, err = 0;
	unsigned int cpu;

	err = imsic_get_cpu(priv, &priv->lmask, false, &cpu);
	if (err)
		return err;

	err = imsic_cpu_page_phys(cpu, 0, &msi_addr);
	if (err)
		return err;

	hwirq = imsic_ids_alloc(priv, priv->nr_ids, get_count_order(nr_irqs));
	if (hwirq < 0)
		return hwirq;

	err = iommu_dma_prepare_msi(info->desc, msi_addr);
	if (err)
		goto fail;

	for (i = 0; i < nr_irqs; i++) {
		imsic_id_set_target(priv, hwirq + i, cpu);
		irq_domain_set_info(domain, virq + i, hwirq + i,
				    &imsic_irq_base_chip, priv,
				    handle_simple_irq, NULL, NULL);
		irq_set_noprobe(virq + i);
		irq_set_affinity(virq + i, &priv->lmask);
	}

	return 0;

 fail:
	imsic_ids_free(priv, hwirq, get_count_order(nr_irqs));
	return err;
}

static void imsic_irq_domain_free(struct irq_domain *domain,
				  unsigned int virq, unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	struct imsic_priv *priv = domain->host_data;

	imsic_ids_free(priv, d->hwirq, get_count_order(nr_irqs));
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

static const struct irq_domain_ops imsic_base_domain_ops = {
	.alloc = imsic_irq_domain_alloc,
	.free = imsic_irq_domain_free,
};

#ifdef CONFIG_RISCV_IMSIC_PCI

static void imsic_pci_mask_irq(struct irq_data *d)
{
	pci_msi_mask_irq(d);
	irq_chip_mask_parent(d);
}

static void imsic_pci_unmask_irq(struct irq_data *d)
{
	pci_msi_unmask_irq(d);
	irq_chip_unmask_parent(d);
}

static struct irq_chip imsic_pci_irq_chip = {
	.name = "RISC-V IMSIC-PCI",
	.irq_mask = imsic_pci_mask_irq,
	.irq_unmask = imsic_pci_unmask_irq,
	.irq_eoi = irq_chip_eoi_parent,
	.irq_write_msi_msg = pci_msi_domain_write_msg,
};

static struct msi_domain_ops imsic_pci_domain_ops = {
};

static struct msi_domain_info imsic_pci_domain_info = {
	.flags = (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		  MSI_FLAG_PCI_MSIX | MSI_FLAG_MULTI_PCI_MSI),
	.ops = &imsic_pci_domain_ops,
	.chip = &imsic_pci_irq_chip,
};

#endif

static struct irq_chip imsic_plat_irq_chip = {
	.name = "RISC-V IMSIC-PLAT",
};

static struct msi_domain_ops imsic_plat_domain_ops = {
};

static struct msi_domain_info imsic_plat_domain_info = {
	.flags = (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS),
	.ops = &imsic_plat_domain_ops,
	.chip = &imsic_plat_irq_chip,
};

static int __init imsic_irq_domains_init(struct imsic_priv *priv,
					 struct device_node *node)
{
	/* Create Base IRQ domain */
	priv->base_domain = irq_domain_create_tree(&node->fwnode,
						   &imsic_base_domain_ops,
						   priv);
	if (!priv->base_domain) {
		pr_err("Failed to create IMSIC base domain\n");
		return -ENOMEM;
	}
	irq_domain_update_bus_token(priv->base_domain, DOMAIN_BUS_NEXUS);

#ifdef CONFIG_RISCV_IMSIC_PCI
	/* Create PCI MSI domain */
	priv->pci_domain = pci_msi_create_irq_domain(&node->fwnode,
						     &imsic_pci_domain_info,
						     priv->base_domain);
	if (!priv->pci_domain) {
		pr_err("Failed to create IMSIC PCI domain\n");
		irq_domain_remove(priv->base_domain);
		return -ENOMEM;
	}
#endif

	/* Create Platform MSI domain */
	priv->plat_domain = platform_msi_create_irq_domain(&node->fwnode,
							   &imsic_plat_domain_info,
							   priv->base_domain);
	if (!priv->plat_domain) {
		pr_err("Failed to create IMSIC platform domain\n");
		if (priv->pci_domain)
			irq_domain_remove(priv->pci_domain);
		irq_domain_remove(priv->base_domain);
		return -ENOMEM;
	}

	return 0;
}

/*
 * To handle an interrupt, we read the TOPEI CSR and write zero in one
 * instruction. If TOPEI CSR is non-zero then we translate TOPEI.ID to
 * Linux interrupt number and let Linux IRQ subsystem handle it.
 */
static void imsic_handle_irq(struct irq_desc *desc)
{
	struct imsic_handler *handler = this_cpu_ptr(&imsic_handlers);
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct imsic_priv *priv = handler->priv;
	irq_hw_number_t hwirq, base_hwirq;
	struct irq_domain *domain;
	int err;

	WARN_ON_ONCE(!handler->priv);

	chained_irq_enter(chip, desc);

	while ((hwirq = csr_swap(CSR_TOPEI, 0))) {
		hwirq = hwirq >> TOPEI_ID_SHIFT;
		domain = priv->base_domain;
		base_hwirq = 0;

#ifdef CONFIG_SMP
		if ((priv->base_ipi <= hwirq) &&
		    (hwirq < (priv->base_ipi + priv->nr_ipis))) {
			domain = priv->ipi_domain;
			base_hwirq = priv->base_ipi;
		}
#endif

		err = generic_handle_domain_irq(domain, hwirq - base_hwirq);
		if (unlikely(err))
			pr_warn_ratelimited("hwirq %lu mapping not found\n",
					    hwirq);
	}

	chained_irq_exit(chip, desc);
}

static int imsic_dying_cpu(unsigned int cpu)
{
	struct imsic_handler *handler = this_cpu_ptr(&imsic_handlers);
	struct imsic_priv *priv = handler->priv;

	/* Enable per-CPU parent interrupt */
	if (imsic_parent_irq)
		disable_percpu_irq(imsic_parent_irq);

	/* Locally disable interrupt delivery */
	imsic_ids_local_delivery(priv, false);

	return 0;
}

static int imsic_starting_cpu(unsigned int cpu)
{
	struct imsic_handler *handler = this_cpu_ptr(&imsic_handlers);
	struct imsic_priv *priv = handler->priv;

	/* Enable per-CPU parent interrupt */
	if (imsic_parent_irq)
		enable_percpu_irq(imsic_parent_irq,
				  irq_get_trigger_type(imsic_parent_irq));
	else
		pr_warn("cpu%d: parent irq not available\n", cpu);

	/*
	 * Interrupts identities might have been enabled/disabled while
	 * this CPU was not running so sync-up local enable/disable state.
	 */
	imsic_ids_local_sync(priv);

	/* Locally enable interrupt delivery */
	imsic_ids_local_delivery(priv, true);

	return 0;
}

static int __init imsic_init(struct device_node *node,
			     struct device_node *parent)
{
	struct resource res;
	phys_addr_t base_addr;
	int rc, nr_parent_irqs;
	struct imsic_mmio *mmio;
	struct imsic_priv *priv;
	struct imsic_handler *handler;
	u32 i, tmp, nr_handlers = 0;

	if (imsic_init_done) {
		pr_err("%pOFP: already initialized hence ignoring\n", node);
		return -ENODEV;
	}

	if (!riscv_aia_available) {
		pr_err("%pOFP: AIA support not available\n", node);
		return -ENODEV;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	/* Find number of parent interrupts */
	nr_parent_irqs = of_irq_count(node);
	if (!nr_parent_irqs) {
		pr_err("%pOFP: no parent irqs available\n", node);
		return -EINVAL;
	}

	/* Find number of guest index bits in MSI address */
	rc = of_property_read_u32(node, "imsic,guest-index-bits",
				  &priv->guest_index_bits);
	if (rc)
		priv->guest_index_bits = 0;
	tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT;
	if (tmp < priv->guest_index_bits) {
		pr_err("%pOFP: guest index bits too big\n", node);
		return -EINVAL;
	}

	/* Find number of HART index bits */
	rc = of_property_read_u32(node, "imsic,hart-index-bits",
				  &priv->hart_index_bits);
	if (rc) {
		/* Assume default value */
		priv->hart_index_bits = __fls(nr_parent_irqs);
		if (BIT(priv->hart_index_bits) < nr_parent_irqs)
			priv->hart_index_bits++;
	}
	tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT - priv->guest_index_bits;
	if (tmp < priv->hart_index_bits) {
		pr_err("%pOFP: HART index bits too big\n", node);
		return -EINVAL;
	}

	/* Find number of group index bits */
	rc = of_property_read_u32(node, "imsic,group-index-bits",
				  &priv->group_index_bits);
	if (rc)
		priv->group_index_bits = 0;
	tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT -
	    priv->guest_index_bits - priv->hart_index_bits;
	if (tmp < priv->group_index_bits) {
		pr_err("%pOFP: group index bits too big\n", node);
		return -EINVAL;
	}

	/* Find first bit position of group index */
	tmp = IMSIC_MMIO_PAGE_SHIFT + priv->guest_index_bits +
	    priv->hart_index_bits;
	rc = of_property_read_u32(node, "imsic,group-index-shift",
				  &priv->group_index_shift);
	if (rc)
		priv->group_index_shift = tmp;
	if (priv->group_index_shift < tmp) {
		pr_err("%pOFP: group index shift too small\n", node);
		return -EINVAL;
	}
	tmp = priv->group_index_bits + priv->group_index_shift - 1;
	if (tmp >= BITS_PER_LONG) {
		pr_err("%pOFP: group index shift too big\n", node);
		return -EINVAL;
	}

	/* Find number of interrupt identities */
	rc = of_property_read_u32(node, "imsic,num-ids", &priv->nr_ids);
	if (rc) {
		pr_err("%pOFP: number of interrupt identities not found\n",
		       node);
		return rc;
	}
	if ((priv->nr_ids < IMSIC_MIN_ID) ||
	    (priv->nr_ids >= IMSIC_MAX_ID) ||
	    ((priv->nr_ids & IMSIC_MIN_ID) != IMSIC_MIN_ID)) {
		pr_err("%pOFP: invalid number of interrupt identities\n", node);
		return -EINVAL;
	}

	/* Compute base address */
	rc = of_address_to_resource(node, 0, &res);
	if (rc) {
		pr_err("%pOFP: first MMIO resource not found\n", node);
		return -EINVAL;
	}
	priv->base_addr = res.start;
	priv->base_addr &= ~(BIT(priv->guest_index_bits +
				 priv->hart_index_bits +
				 IMSIC_MMIO_PAGE_SHIFT) - 1);
	priv->base_addr &= ~((BIT(priv->group_index_bits) - 1) <<
			     priv->group_index_shift);

	/* Find number of MMIO register sets */
	while (!of_address_to_resource(node, priv->num_mmios, &res))
		priv->num_mmios++;

	/* Allocate MMIO register sets */
	priv->mmios = kcalloc(priv->num_mmios, sizeof(*mmio), GFP_KERNEL);
	if (!priv->mmios) {
		rc = -ENOMEM;
		goto out_free_priv;
	}

	/* Parse and map MMIO register sets */
	for (i = 0; i < priv->num_mmios; i++) {
		mmio = &priv->mmios[i];
		rc = of_address_to_resource(node, i, &res);
		if (rc) {
			pr_err("%pOFP: unable to parse MMIO regset %d\n",
			       node, i);
			goto out_iounmap;
		}
		mmio->pa = res.start;
		mmio->size = res.end - res.start + 1;

		base_addr = mmio->pa;
		base_addr &= ~(BIT(priv->guest_index_bits +
				   priv->hart_index_bits +
				   IMSIC_MMIO_PAGE_SHIFT) - 1);
		base_addr &= ~((BIT(priv->group_index_bits) - 1) <<
			       priv->group_index_shift);
		if (base_addr != priv->base_addr) {
			rc = -EINVAL;
			pr_err("%pOFP: address mismatch for regset %d\n",
			       node, i);
			goto out_iounmap;
		}

		tmp = BIT(priv->guest_index_bits) - 1;
		if ((mmio->size / IMSIC_MMIO_PAGE_SZ) & tmp) {
			rc = -EINVAL;
			pr_err("%pOFP: size mismatch for regset %d\n", node, i);
			goto out_iounmap;
		}

		mmio->va = of_iomap(node, i);
		if (!mmio->va) {
			rc = -EIO;
			pr_err("%pOFP: unable to map MMIO regset %d\n",
			       node, i);
			goto out_iounmap;
		}
	}

	/* Initialize interrupt identity management */
	rc = imsic_ids_init(priv);
	if (rc) {
		pr_err("%pOFP: failed to initialize interrupt management\n",
		       node);
		goto out_iounmap;
	}

	/* Configure handlers for target CPUs */
	for (i = 0; i < nr_parent_irqs; i++) {
		struct of_phandle_args parent;
		unsigned long reloff;
		int j, cpu, hartid;

		if (of_irq_parse_one(node, i, &parent)) {
			pr_warn("%pOFP: failed to parse parent irq%d\n",
				node, i);
			continue;
		}

		/*
		 * Skip interrupt pages other than external interrupts for
		 * out privilege level.
		 */
		if (parent.args[0] != RV_IRQ_EXT) {
			pr_warn("%pOFP: invalid hwirq for parent irq%d\n",
				node, i);
			continue;
		}

		hartid = riscv_of_parent_hartid(parent.np);
		if (hartid < 0) {
			pr_warn("%pOFP: hart ID for parent irq%d not found\n",
				node, i);
			continue;
		}

		cpu = riscv_hartid_to_cpuid(hartid);
		if (cpu < 0) {
			pr_warn("%pOFP: invalid cpuid for parent irq%d\n",
				node, i);
			continue;
		}

		/* Find parent domain and register chained handler */
		if (!imsic_parent_irq && irq_find_host(parent.np)) {
			imsic_parent_irq = irq_of_parse_and_map(node, i);
			if (imsic_parent_irq)
				irq_set_chained_handler(imsic_parent_irq,
							imsic_handle_irq);
		}

		/* Find MMIO location of MSI page */
		mmio = NULL;
		reloff = i * BIT(priv->guest_index_bits) * IMSIC_MMIO_PAGE_SZ;
		for (j = 0; priv->num_mmios; j++) {
			if (reloff < priv->mmios[j].size) {
				mmio = &priv->mmios[j];
				break;
			}

			reloff -= priv->mmios[j].size;
		}
		if (!mmio) {
			pr_warn("%pOFP: MMIO not found for parent irq%d\n",
				node, i);
			continue;
		}

		handler = per_cpu_ptr(&imsic_handlers, cpu);
		if (handler->priv) {
			pr_warn("%pOFP: CPU%d handler already configured.\n",
				node, cpu);
			goto done;
		}

		cpumask_set_cpu(cpu, &priv->lmask);
		handler->msi_pa = mmio->pa + reloff;
		handler->msi_va = mmio->va + reloff;
		handler->priv = priv;

 done:
		nr_handlers++;
	}

	/* Initialize IPI domain */
	rc = imsic_ipi_domain_init(priv, node);
	if (rc) {
		pr_err("%pOFP: Failed to initialize IPI domain\n", node);
		goto out_ids_cleanup;
	}

	/* Initialize IRQ and MSI domains */
	rc = imsic_irq_domains_init(priv, node);
	if (rc) {
		pr_err("%pOFP: Failed to initialize IRQ and MSI domains\n",
		       node);
		goto out_ipi_domain_cleanup;
	}

	/* Setup cpuhp state */
	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			  "irqchip/riscv/imsic:starting",
			  imsic_starting_cpu, imsic_dying_cpu);

	/*
	 * Only one IMSIC instance allowed in a platform for clean
	 * implementation of SMP IRQ affinity and per-CPU IPIs.
	 *
	 * This means on a multi-socket (or multi-die) platform we
	 * will have multiple MMIO regions for one IMSIC instance.
	 */
	imsic_init_done = true;

	pr_info("%pOFP: mapped %d interrupts using %d handlers\n",
		node, priv->nr_ids, nr_handlers);

	return 0;

 out_ipi_domain_cleanup:
	imsic_ipi_domain_cleanup(priv);
 out_ids_cleanup:
	imsic_ids_cleanup(priv);
 out_iounmap:
	for (i = 0; i < priv->num_mmios; i++) {
		if (priv->mmios[i].va)
			iounmap(priv->mmios[i].va);
	}
	kfree(priv->mmios);
 out_free_priv:
	kfree(priv);
	return rc;
}

IRQCHIP_DECLARE(riscv_imsic, "riscv,imsics", imsic_init);

#ifdef CONFIG_ACPI
union AcpiImsicHartIndex {
	struct {
		uint32_t lhxw:4;
		uint32_t hhxw:3;
		uint32_t lhxs:3;
		uint32_t hhxs:5;
		uint32_t reserved:17;
	};
	uint32_t hart_index;
};

struct socket_imsic {
	uint64_t imsic_addr;
	uint32_t imsic_size;
};

static struct {
	int mode;
	int guest_index_bits;
	int hart_index_bits;
	int group_index_bits;
	int group_index_shift;
	int num_interrupt_id;
	int total_num_harts;
	int num_sockets;
	int ext_irq_num;
	int ipi_base;
	int ipi_count;
	struct socket_imsic *socket;
} acpi_data __initdata;

static bool __init acpi_validate_imsic_table(struct acpi_subtable_header
					     *header,
					     struct acpi_probe_entry *ape)
{
	struct acpi_madt_imsic *imsic;
	int size, i, j;
	union AcpiImsicHartIndex hart_index;

	imsic = (struct acpi_madt_imsic *)header;

	// skip M-mode data
	if (imsic->mode != 1) {
		pr_warn("imsic_acpi_parse_madt: Skipping M-mode table\n");
		return false;
	}

	size = sizeof(*acpi_data.socket) * imsic->num_sockets;
	acpi_data.socket = kzalloc(size, GFP_KERNEL);
	//TBD : ERROR check
	hart_index.hart_index = imsic->hart_index;
	acpi_data.mode = imsic->mode;
	acpi_data.total_num_harts = imsic->total_num_harts;
	acpi_data.guest_index_bits = hart_index.lhxs;
	acpi_data.hart_index_bits = hart_index.lhxw;
	acpi_data.group_index_bits = hart_index.hhxw;
	acpi_data.group_index_shift = hart_index.hhxs;
	acpi_data.num_interrupt_id = imsic->num_interrupt_id;
	acpi_data.ipi_base = imsic->ipi_base;
	acpi_data.ipi_count = imsic->ipi_count;
	acpi_data.num_sockets = imsic->num_sockets;
	for (i = 0; i < acpi_data.num_sockets; i++) {
		acpi_data.socket[i].imsic_addr =
		    imsic->socket_imsic[i].imsic_addr;
		acpi_data.socket[i].imsic_size =
		    imsic->socket_imsic[i].imsic_size;
	}

	acpi_data.ext_irq_num = imsic->ext_irq_num;
	return true;
}

static struct fwnode_handle *imsic_get_fwnode(struct device *dev)
{
	return imsic_domain_id;
}

static int __init imsic_acpi_irq_domains_init(struct imsic_priv *priv)
{
	struct fwnode_handle *fn;

	fn = irq_domain_alloc_named_fwnode("IMSIC-Base");
	imsic_domain_id = fn;
	/* Create Base IRQ domain */
	priv->base_domain = irq_domain_create_tree(fn,
						   &imsic_base_domain_ops,
						   priv);
	if (!priv->base_domain) {
		pr_err("Failed to create IMSIC base domain\n");
		return -ENOMEM;
	}
	irq_domain_update_bus_token(priv->base_domain, DOMAIN_BUS_NEXUS);

#ifdef CONFIG_RISCV_IMSIC_PCI
	/* Create PCI MSI domain */
	priv->pci_domain = pci_msi_create_irq_domain(fn,
						     &imsic_pci_domain_info,
						     priv->base_domain);
	if (!priv->pci_domain) {
		pr_err("Failed to create IMSIC PCI domain\n");
		irq_domain_remove(priv->base_domain);
		return -ENOMEM;
	}
#endif

	/* Create Platform MSI domain */
	priv->plat_domain = platform_msi_create_irq_domain(fn,
							   &imsic_plat_domain_info,
							   priv->base_domain);
	if (!priv->plat_domain) {
		pr_err("Failed to create IMSIC platform domain\n");
		if (priv->pci_domain)
			irq_domain_remove(priv->pci_domain);
		irq_domain_remove(priv->base_domain);
		return -ENOMEM;
	}

	pci_msi_register_fwnode_provider(&imsic_get_fwnode);
	return 0;
}

static int __init imsic_acpi_ipi_domain_init(struct imsic_priv *priv)
{
	int rc;
	u32 base, nr;
	struct fwnode_handle *fn;

	fn = irq_domain_alloc_named_fwnode("IMSIC-IPI");

	/* Find IPI base */
	base = acpi_data.ipi_base;

	/* Find IPI count */
	nr = acpi_data.ipi_count;

	/* Sanity check on IPI range */
	if (!base || priv->nr_ids < base)
		return -EINVAL;
	if (!nr || priv->nr_ids < (base + nr - 1))
		return -EINVAL;
	priv->base_ipi = base;
	priv->nr_ipis = nr;

	/* Reserve IDs for IPI */
	bitmap_set(priv->ids_used_bimap, priv->base_ipi, priv->nr_ipis);

	/* Create IMSIC IPI domain using boot CPU node */
	priv->ipi_domain = irq_domain_create_linear(fn, priv->nr_ipis,
						    &imsic_ipi_domain_ops,
						    priv);

	if (!priv->ipi_domain) {
		pr_err
		    ("imsic_acpi_ipi_domain_init: irq_domain_create_linear failed\n");
		imsic_ids_free(priv, priv->base_ipi, priv->nr_ipis);
		return -ENOMEM;
	}

	/* Set arch virq range */
	rc = imsic_ipi_set_virq(priv);
	if (rc) {
		pr_err
		    ("imsic_acpi_ipi_domain_init: imsic_ipi_set_virq failed\n");
		irq_domain_remove(priv->ipi_domain);
		imsic_ids_free(priv, priv->base_ipi, priv->nr_ipis);
		return rc;
	}

	return 0;
}

static int __init imsic_acpi_init(union acpi_subtable_headers *header,
				  const unsigned long end)
{
	phys_addr_t base_addr;
	int rc, nr_parent_irqs;
	struct imsic_mmio *mmio;
	struct imsic_priv *priv;
	struct imsic_handler *handler;
	u32 i, j, tmp, nr_handlers = 0;

	if (acpi_data.mode != 1) {
		pr_warn
		    ("imsic_acpi_init: M-mode information useful only for No_MMU platforms\n");
		return -ENODEV;
	}

	if (!intc_domain) {
		return -EPROBE_DEFER;
	}

	if (imsic_init_done) {
		pr_warn("imsic_acpi_init: Already initialized!\n");
		return -ENODEV;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	/* Find number of parent interrupts */
	nr_parent_irqs = acpi_data.total_num_harts;
	if (!nr_parent_irqs) {
		pr_err("imsic_acpi_init: no parent irqs available\n");
		return -EINVAL;
	}

	/* Find number of guest index bits in MSI address */
	priv->guest_index_bits = acpi_data.guest_index_bits;
	tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT;
	if (tmp < priv->guest_index_bits) {
		pr_err("imsic_acpi_init: guest index bits too big\n");
		return -EINVAL;
	}

	/* Find number of HART index bits */
	priv->hart_index_bits = acpi_data.hart_index_bits;
	tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT - priv->guest_index_bits;
	if (tmp < priv->hart_index_bits) {
		pr_err("imsic_acpi_init: HART index bits too big\n");
		return -EINVAL;
	}

	/* Find number of group index bits */
	priv->group_index_bits = acpi_data.group_index_bits;
	tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT -
	    priv->guest_index_bits - priv->hart_index_bits;
	if (tmp < priv->group_index_bits) {
		pr_err("imsic_acpi_init: group index bits too big\n");
		return -EINVAL;
	}

	/* Find first bit position of group index */
	tmp = IMSIC_MMIO_PAGE_SHIFT + priv->guest_index_bits +
	    priv->hart_index_bits;
	priv->group_index_shift = acpi_data.group_index_shift;
	if (priv->group_index_shift < tmp) {
		pr_err("imsic_acpi_init: group index shift too small - %d\n",
		       priv->group_index_shift);
		return -EINVAL;
	}
	tmp = priv->group_index_bits + priv->group_index_shift - 1;
	if (tmp >= BITS_PER_LONG) {
		pr_err("imsic_acpi_init: group index shift too big\n");
		return -EINVAL;
	}

	/* Find number of interrupt identities */
	priv->nr_ids = acpi_data.num_interrupt_id;
	if ((priv->nr_ids < IMSIC_MIN_ID) ||
	    (priv->nr_ids >= IMSIC_MAX_ID) ||
	    ((priv->nr_ids & IMSIC_MIN_ID) != IMSIC_MIN_ID)) {
		pr_err(": invalid number of interrupt identities\n");
		return -EINVAL;
	}

	/* Compute base address */
	priv->base_addr = acpi_data.socket[0].imsic_addr;
	priv->base_addr &= ~(BIT(priv->guest_index_bits +
				 priv->hart_index_bits +
				 IMSIC_MMIO_PAGE_SHIFT) - 1);
	priv->base_addr &= ~((BIT(priv->group_index_bits) - 1) <<
			     priv->group_index_shift);

	priv->num_mmios = acpi_data.num_sockets;
	/* Allocate MMIO register sets */
	priv->mmios = kcalloc(priv->num_mmios, sizeof(*mmio), GFP_KERNEL);
	if (!priv->mmios) {
		rc = -ENOMEM;
		goto out_free_priv;
	}

	/* Parse and map MMIO register sets */
	for (i = 0; i < priv->num_mmios; i++) {
		mmio = &priv->mmios[i];
		mmio->pa = acpi_data.socket[i].imsic_addr;
		mmio->size = acpi_data.socket[i].imsic_size;

		base_addr = mmio->pa;
		base_addr &= ~(BIT(priv->guest_index_bits +
				   priv->hart_index_bits +
				   IMSIC_MMIO_PAGE_SHIFT) - 1);
		base_addr &= ~((BIT(priv->group_index_bits) - 1) <<
			       priv->group_index_shift);
		if (base_addr != priv->base_addr) {
			rc = -EINVAL;
			pr_err
			    ("imsic_acpi_init: address mismatch for regset %d\n",
			     i);
			goto out_iounmap;
		}

		tmp = BIT(priv->guest_index_bits) - 1;
		if ((mmio->size / IMSIC_MMIO_PAGE_SZ) & tmp) {
			rc = -EINVAL;
			pr_err("imsic_acpi_init: size mismatch for regset %d\n",
			       i);
			goto out_iounmap;
		}

		mmio->va = ioremap(mmio->pa, mmio->size);
		if (!mmio->va) {
			rc = -EIO;
			pr_err
			    ("imsic_acpi_init: unable to map MMIO regset %d\n",
			     i);
			goto out_iounmap;
		}
	}

	/* Initialize interrupt management */
	rc = imsic_ids_init(priv);
	if (rc) {
		pr_err
		    ("imsic_acpi_init: failed to initialize interrupt management\n");
		goto out_iounmap;
	}

	/* Configure handlers for target CPUs */
	for (i = 0; i < nr_parent_irqs; i++) {
		unsigned long reloff;
		int cpu, hartid;

		hartid = cpuid_to_hartid_map(i);
		if (hartid < 0) {
			pr_warn
			    ("imsic_acpi_init: hart ID for parent irq%d not found\n",
			     i);
			continue;
		}

		cpu = riscv_hartid_to_cpuid(hartid);
		if (cpu < 0) {
			pr_warn
			    ("imsic_acpi_init: invalid cpuid for parent irq%d\n",
			     i);
			continue;
		}

		/* Find parent domain and register chained handler */
		if (!imsic_parent_irq) {
			imsic_parent_irq =
			    irq_create_mapping(intc_domain, RV_IRQ_EXT);
			if (!rc)
				irq_set_chained_handler
				    (imsic_parent_irq, imsic_handle_irq);
		}

		/* Find MMIO location of MSI page */
		mmio = NULL;
		reloff = i * BIT(priv->guest_index_bits) * IMSIC_MMIO_PAGE_SZ;
		for (j = 0; priv->num_mmios; j++) {
			if (reloff < priv->mmios[j].size) {
				mmio = &priv->mmios[j];
				break;
			}

			reloff -= priv->mmios[j].size;
		}
		if (!mmio) {
			pr_warn
			    ("imsic_acpi_init: MMIO not found for parent irq%d\n",
			     i);
			continue;
		}

		handler = per_cpu_ptr(&imsic_handlers, cpu);
		if (handler->priv) {
			pr_warn
			    ("imsic_acpi_init: CPU%d handler already configured.\n",
			     cpu);
			goto done;
		}

		cpumask_set_cpu(cpu, &priv->lmask);
		handler->msi_pa = mmio->pa + reloff;
		handler->msi_va = mmio->va + reloff;
		handler->priv = priv;

 done:
		nr_handlers++;
	}

	/* Initialize IPI domain */
	rc = imsic_acpi_ipi_domain_init(priv);
	if (rc) {
		pr_err("imsic_acpi_init: Failed to initialize IPI domain\n");
		goto out_irqs_cleanup;
	}

	/* Initialize IRQ and MSI domains */
	rc = imsic_acpi_irq_domains_init(priv);
	if (rc) {
		pr_err
		    ("imsic_acpi_init: Failed to initialize IRQ and MSI domains\n");
		goto out_ipi_domain_cleanup;
	}

	/* Setup cpuhp state */
	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			  "irqchip/riscv/imsic:starting",
			  imsic_starting_cpu, imsic_dying_cpu);

	acpi_set_irq_model(ACPI_IRQ_MODEL_RISCV_AIA, imsic_domain_id);

	/*
	 * Only one IMSIC instance allowed in a platform for clean
	 * implementation of SMP IRQ affinity and per-CPU IPIs.
	 *
	 * This means on a multi-socket (or multi-die) platform we
	 * will have multiple MMIO regions for one IMSIC instance.
	 */
	imsic_init_done = true;

	pr_info("imsic_acpi_init: mapped %d interrupts using %d handlers\n",
		priv->nr_ids, nr_handlers);

	return 0;

 out_ipi_domain_cleanup:
	imsic_ipi_domain_cleanup(priv);
 out_irqs_cleanup:
	imsic_ids_cleanup(priv);
 out_iounmap:
	for (i = 0; i < priv->num_mmios; i++) {
		if (priv->mmios[i].va)
			iounmap(priv->mmios[i].va);
	}
	kfree(priv->mmios);
 out_free_priv:
	kfree(priv);

	return 0;
}

IRQCHIP_ACPI_DECLARE(riscv_imsic, ACPI_MADT_TYPE_IMSIC,
		     acpi_validate_imsic_table, 1, imsic_acpi_init);
#endif

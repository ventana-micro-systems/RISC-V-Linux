unsigned long get_riscv_timebase_freq(void);
int riscv_intc_acpi_init(void);
extern struct irq_domain *intc_domain;
extern struct fwnode_handle *intc_fwnode;

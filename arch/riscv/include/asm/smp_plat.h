/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RISC-V specific SMP header
 */
#ifndef __ASMARM_SMP_PLAT_H
#define __ASMARM_SMP_PLAT_H

/*
 * Logical CPU mapping.
 */
extern u64 __cpu_logical_map[NR_CPUS];
extern u64 cpu_logical_map(unsigned int cpu);


#endif

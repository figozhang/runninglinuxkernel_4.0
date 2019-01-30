#include <linux/module.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>

static DEFINE_PER_CPU(long, cpuvar) = 10;
static long __percpu *cpualloc;

static int __init my_init(void)
{
	int cpu;

	pr_info("module loaded at 0x%p\n", my_init);

	/* modify the cpuvar value */
	for_each_possible_cpu(cpu)
		per_cpu(cpuvar, cpu) = 15;

	pr_info("init: cpuvar on cpu%d  = %ld\n",
			smp_processor_id(), get_cpu_var(cpuvar)++);
	put_cpu_var(cpuvar);

	/* alloc a percpu value */
	cpualloc = alloc_percpu(long);

	/* set all cpu for this value */
	for_each_possible_cpu(cpu)
		*per_cpu_ptr(cpualloc, cpu) = 100;

	return 0;
}

static void __exit my_exit(void)
{
	int cpu;
	pr_info("exit module...\n");

	for_each_possible_cpu(cpu)
		pr_info("cpuvar cpu%d = %ld\n", cpu, per_cpu(cpuvar, cpu));

	pr_info("exit: cpualloc = %ld\n", *per_cpu_ptr(cpualloc, smp_processor_id()));
	free_percpu(cpualloc);

	pr_info("Bye: module unloaded from 0x%p\n", my_exit);
}

module_init(my_init);
module_exit(my_exit);

MODULE_AUTHOR("Ben ShuShu");
MODULE_LICENSE("GPL v2");

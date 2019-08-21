/*
 * bakery_lock.c - Lamport's bakery algorithm
 *
 * Copyright (C) 2015 ARM Limited. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.txt file.
 *
 *
 * Simplest implementation of Lamport's bakery lock [1]. Applies only to device
 * memory with attributes non-gathering and non-reordering.
 *
 * This algorithm's strength resides in the fact that it doesn't rely on
 * hardware synchronisation mechanisms and as such, doesn't require normal
 * cacheable memory on ARMv8. CPUs write only to their own memory locations,
 * and read from all other CPUs' ones, in order to decide whose turn it is to
 * have the lock.
 *
 * The algorithm correctness is based on the following assumptions:
 *
 * 1) Accesses to choosing[k] (here tickets[k].choosing) are done atomically.
 *    In other words, simultaneous read and write to choosing[k] do not occur.
 *    In this implementation, it is guaranteed by single-copy atomicity, for
 *    accesses of type Device with non-gathering attributes. The algorithm
 *    doesn't require accesses to number[k] to be atomic, even though this
 *    implementation guarantees that as well.
 *
 * 2) Storage of number[k] allows it to become large enough for practical use of
 *    the lock. Indeed, if the lock is contended all of the time, the value of
 *    max(number[1..N]) will keep increasing, and this algorithm doesn't handle
 *    wrapping of the ticket number. In this implementation, we assume that we
 *    will never reach 32766 (0x7fff) overlapping calls to bakery_lock.
 *
 * [1] Lamport, L. "A New Solution of Dijkstra's Concurrent Programming Problem"
 */

#include <bakery_lock.h>
#include <cpu.h>

/*
 * Return the result of (number_a, cpu_a) < (number_b, cpu_b)
 */
static unsigned int less_than(unsigned long cpu_a, unsigned long number_a,
			      unsigned long cpu_b, unsigned long number_b)
{
	if (number_a == number_b)
		return cpu_a < cpu_b;

	return number_a < number_b;
}

static unsigned int choose_number(bakery_ticket_t *tickets, unsigned self)
{
	int cpu;
	unsigned int max_number = 0;
	bakery_ticket_t ticket;

	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		if (cpu == self)
			continue;

		ticket = read_ticket_once(tickets[cpu]);

		if (max_number < ticket.number)
			max_number = ticket.number;
	}

	return 1 + max_number;
}

/**
 * Wait for our turn to enter a critical section
 *
 * @tickets: array of size NR_CPUS, indexed by logical IDs.
 * @self:    logical ID of the current CPU
 *
 * Note: since this implementation assumes that all loads and stores to tickets
 * are of Device type with non-gathering and non-reordering attributes, we
 * expect all of them to be performed, in program order. As a result, the
 * following function is pretty relaxed in terms of barriers: we only
 * synchronize before sev(), and introduce system-wide memory barriers around
 * the critical section.
 */
void bakery_lock(bakery_ticket_t *tickets, unsigned self)
{
	int cpu, number_self;
	bakery_ticket_t ticket;

	/* Doorway */
	write_ticket_once(tickets[self], 1, 0);
	number_self = choose_number(tickets, self);
	write_ticket_once(tickets[self], 0, number_self);

	dsb(st);
	sev();

	/* Bakery */
	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		uint16_t number_cpu;

		if (cpu == self)
			continue;

		ticket = read_ticket_once(tickets[cpu]);
		while (ticket.choosing) {
			wfe();
			ticket = read_ticket_once(tickets[cpu]);
		}

		number_cpu = ticket.number;

		/*
		 * Wait until that CPU updates its ticket. We only need to do
		 * the comparison once, since any update to tickets[cpu].number
		 * will be to a value greater than ours, or zero.
		 */
		if (number_cpu != 0 && less_than(cpu,  number_cpu,
						 self, number_self)) {
			do {
				wfe();
				ticket = read_ticket_once(tickets[cpu]);
			} while (number_cpu == ticket.number);
		}
	}

	dmb(sy);
}

void bakery_unlock(bakery_ticket_t *tickets, unsigned self)
{
	dmb(sy);

	write_ticket_once(tickets[self], 0, 0);

	dsb(st);
	sev();
}

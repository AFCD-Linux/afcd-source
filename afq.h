#ifndef __NET_SCHED_AFQ_H
#define __NET_SCHED_AFQ_H

#include <linux/types.h>
#include <linux/bug.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <net/dsfield.h>

/*	
 *	Approximate fair queue parameters
 */

struct afq_stats {
	u32		fair_drop;	/* Drops for fairness */
	u32		tail_drop;	/* Drops at the tail of queue */
	u32		total_packet_count;	/* Total packet count*/
	u32		flow_count;	/* Total flow count*/
	u32		ft_id;
	u32		ft_val;
};

struct afq_parms {
	/* Afq parameters */
	u32		limit;	/* Queue length limit */
};

struct afq_vars {
	/* Afq variables*/
	u32	perturbation;	/* Hash perturbation */	
	u32	shadow_buffer_point;	/* Shadow buffer point*/
	u32 qlen_pre;	/* Previous q_len in last sample*/
};

static inline void afq_set_parms(struct afq_parms *p,
				 u32 limit)
{
	p->limit = limit;
}

#endif

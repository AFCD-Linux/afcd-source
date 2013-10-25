#ifndef __NET_SCHED_AFCODEL_H
#define __NET_SCHED_AFCODEL_H

/*
 * AF-CODEL - Approximate Fair Control-delay queue,
 * Lin Xue, 11/20/2012, xuelin@cct.lsu.edu
 *
 * AF-CODEL is based on:
 * Codel - The Controlled-Delay Active Queue Management algorithm
 *
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *  Copyright (C) 2012 Michael D. Taht <dave.taht@bufferbloat.net>
 *  Copyright (C) 2012 Eric Dumazet <edumazet@google.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */
 
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/ktime.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/reciprocal_div.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <net/dsfield.h>
#include <net/flow_keys.h>
#include <net/afq.h>
#include <net/codel.h>

/*	
	afcodel queue stats, parameters, and vars are from afq and codel
 */

struct afcodel_stats {
	struct codel_stats	codelstats;
	struct afq_stats	afqstats;
};

struct afcodel_parms {
	struct codel_params codelparams;
	struct afq_parms	afqparams;
};

struct afcodel_vars {
	struct codel_vars	codelvars;
	struct afq_vars		afqvars;
	codel_time_t pre_drop;
};

/* Shadow buffer (a circular buffer) */	
#define SHADOW_BUFFER_SIZE	2000
static u32 shadow_buffer[SHADOW_BUFFER_SIZE];

/*Flow table*/
#define FLOW_TABLE_SIZE	2000
static u32 flow_table[FLOW_TABLE_SIZE];

/*Sample interval*/
#define SAMPLE_INTERVAL	500

static u32 flow_first_above_time[FLOW_TABLE_SIZE];
static u64 flow_target[FLOW_TABLE_SIZE];

#define AFQ_MAX_PROB	0xFFFF

static u32 afcodel_skb_hash(const struct sk_buff *skb, 
					struct afq_vars *afqvars) 
{
	struct flow_keys keys;
	u32 skb_hash;

	/* Do hash for skb*/
	skb_flow_dissect(skb, &keys);
	skb_hash = jhash_3words((__force u32)keys.dst,
			   (__force u32)keys.src,
			   (__force u32)keys.ports,
			   afqvars->perturbation);

	return skb_hash;
}

static bool afcodel_should_drop(const struct sk_buff *skb,
			      struct Qdisc *sch,
			      struct afcodel_vars *vars,
			      struct afcodel_parms *params,
			      struct afcodel_stats *stats,
			      codel_time_t now)
{
	bool ok_to_drop;
	u32 skb_hash;
	u32 m_fair = SHADOW_BUFFER_SIZE;	/* fair share matches */
	u32 r, p;

	if (!skb) {
//		vars->first_above_time = 0;
		return false;
	}

	skb_hash = afcodel_skb_hash(skb, &vars->afqvars);

	if(stats->afqstats.flow_count > 1 && (flow_table[skb_hash % FLOW_TABLE_SIZE])) {
		m_fair = SHADOW_BUFFER_SIZE / stats->afqstats.flow_count;
		flow_target[skb_hash % FLOW_TABLE_SIZE] = (u64)params->codelparams.target * 1000 *
			((u64)m_fair * (u64)m_fair * (u64)m_fair * (u64)m_fair) / 
				((u64)flow_table[skb_hash % FLOW_TABLE_SIZE] * 
					(u64)flow_table[skb_hash % FLOW_TABLE_SIZE] * 
					(u64)flow_table[skb_hash % FLOW_TABLE_SIZE] * 
					(u64)flow_table[skb_hash % FLOW_TABLE_SIZE] * 100);
//					(u64)flow_table[skb_hash % FLOW_TABLE_SIZE] * 
//					stats->afqstats.flow_count * stats->afqstats.flow_count 
//					* stats->afqstats.flow_count * stats->afqstats.flow_count);
		
//printk(KERN_INFO "%u, ft %u\n", skb_hash % FLOW_TABLE_SIZE, fair_target);
	}

	vars->codelvars.ldelay = (now - codel_get_enqueue_time(skb)) * 1000;
	sch->qstats.backlog -= qdisc_pkt_len(skb);

	if (unlikely(qdisc_pkt_len(skb) > stats->codelstats.maxpacket))
		stats->codelstats.maxpacket = qdisc_pkt_len(skb);

	if (codel_time_before(vars->codelvars.ldelay, flow_target[skb_hash % FLOW_TABLE_SIZE]) ||
	    sch->qstats.backlog <= stats->codelstats.maxpacket) {
		/* went below - stay below for at least interval */
		flow_first_above_time[skb_hash % FLOW_TABLE_SIZE] = 0;
		return false;
	}
	ok_to_drop = false;
	if (flow_first_above_time[skb_hash % FLOW_TABLE_SIZE] == 0) {
		/* just went above from below. If we stay above
		 * for at least interval we'll say it's ok to drop
		 */
		flow_first_above_time[skb_hash % FLOW_TABLE_SIZE] = (now + params->codelparams.interval/10) * 1000;
	} else if (codel_time_after(now * 1000, flow_first_above_time[skb_hash % FLOW_TABLE_SIZE])) {
		r = net_random() & AFQ_MAX_PROB;
		p = AFQ_MAX_PROB;
		if(r < p) {
			ok_to_drop = true;
		}
	}

	// To avoid bursty traffic
//	if(vars->codelvars.ldelay > 1000 * 1000 * 1000 || 
	if(
		flow_table[skb_hash % FLOW_TABLE_SIZE] < m_fair) {
//		flow_table[skb_hash % FLOW_TABLE_SIZE] < m_fair	||
//		(now - vars->pre_drop) < 500000 ) {
		ok_to_drop = false;
	}
	
	if(ok_to_drop) {
//printk(KERN_INFO "%u, ft %llu, d %u\n", skb_hash % FLOW_TABLE_SIZE, 
//	flow_target[skb_hash % FLOW_TABLE_SIZE], vars->codelvars.ldelay * 1000);
	vars->pre_drop = now;
	}
	
	return ok_to_drop;
}

typedef struct sk_buff * (*afcodel_skb_dequeue_t)(struct codel_vars *vars,
						struct Qdisc *sch);

static struct sk_buff *afcodel_dequeue(struct Qdisc *sch,
				     struct afcodel_parms *params,
				     struct afcodel_vars *vars,
				     struct afcodel_stats *stats,
				     afcodel_skb_dequeue_t dequeue_func)
{
	struct sk_buff *skb = dequeue_func(&vars->codelvars, sch);
	codel_time_t now;
	bool drop;
	u32 skb_hash;

	if (!skb) {
		vars->codelvars.dropping = false;
		return skb;
	}

	skb_hash = afcodel_skb_hash(skb, &vars->afqvars);

	now = codel_get_time();
	drop = afcodel_should_drop(skb, sch, vars, params, stats, now);
	if (vars->codelvars.dropping) {
		if (!drop) {
			/* sojourn time below target - leave dropping state */
			vars->codelvars.dropping = false;
		} else if (codel_time_after_eq(now, vars->codelvars.drop_next)) {
			/* It's time for the next drop. Drop the current
			 * packet and dequeue the next. The dequeue might
			 * take us out of dropping state.
			 * If not, schedule the next drop.
			 * A large backlog might result in drop rates so high
			 * that the next drop should happen now,
			 * hence the while loop.
			 */
			while (vars->codelvars.dropping &&
			       codel_time_after_eq(now, vars->codelvars.drop_next)) {
				vars->codelvars.count++; /* dont care of possible wrap
						* since there is no more divide
						*/
				codel_Newton_step(&vars->codelvars);
				if (params->codelparams.ecn && INET_ECN_set_ce(skb)) {
					stats->codelstats.ecn_mark++;
					vars->codelvars.drop_next =
						codel_control_law(vars->codelvars.drop_next,
								  params->codelparams.interval,
								  vars->codelvars.rec_inv_sqrt);
					goto end;
				}
//printk(KERN_INFO "%u\n", skb_hash % FLOW_TABLE_SIZE);
				
				qdisc_drop(skb, sch);
				stats->codelstats.drop_count++;
				skb = dequeue_func(&vars->codelvars, sch);

				if (!afcodel_should_drop(skb, sch, vars, params, stats, now)) {
					/* leave dropping state */
					vars->codelvars.dropping = false;
				} else {
					/* and schedule the next drop */
					vars->codelvars.drop_next =
						codel_control_law(vars->codelvars.drop_next,
								  params->codelparams.interval,
								  vars->codelvars.rec_inv_sqrt);
				}
			}
		}
	} else if (drop) {
		u32 delta;

		if (params->codelparams.ecn && INET_ECN_set_ce(skb)) {
			stats->codelstats.ecn_mark++;
		} else {
//printk(KERN_INFO "%u\n", skb_hash % FLOW_TABLE_SIZE);
		
			qdisc_drop(skb, sch);
			stats->codelstats.drop_count++;

			skb = dequeue_func(&vars->codelvars, sch);
			drop = afcodel_should_drop(skb, sch, vars, params, stats, now);
		}
		vars->codelvars.dropping = true;
		/* if min went above target close to when we last went below it
		 * assume that the drop rate that controlled the queue on the
		 * last cycle is a good starting point to control it now.
		 */
		delta = vars->codelvars.count - vars->codelvars.lastcount;
		if (delta > 1 &&
		    codel_time_before(now - vars->codelvars.drop_next,
				      16 * params->codelparams.interval)) {
			vars->codelvars.count = delta;
			/* we dont care if rec_inv_sqrt approximation
			 * is not very precise :
			 * Next Newton steps will correct it quadratically.
			 */
			codel_Newton_step(&vars->codelvars);
		} else {
			vars->codelvars.count = 1;
			vars->codelvars.rec_inv_sqrt = ~0U >> REC_INV_SQRT_SHIFT;
		}
		vars->codelvars.lastcount = vars->codelvars.count;
		vars->codelvars.drop_next = codel_control_law(now, params->codelparams.interval,
						    vars->codelvars.rec_inv_sqrt);
	}
end:
	return skb;
}

#endif

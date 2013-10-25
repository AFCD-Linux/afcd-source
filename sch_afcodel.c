/*
 * AF-CODEL (Approximate fair control-delay) queue management scheme
 * Lin Xue, 11/20/2012, xuelin@cct.lsu.edu
 * 
 * AF-CODEL is based on Codel queue management scheme:
 * Codel - The Controlled-Delay Active Queue Management algorithm
 *
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *
 *  Implemented on linux by :
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

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/prefetch.h>
#include <net/pkt_sched.h>
#include <net/afcodel.h>

#define DEFAULT_AFCODEL_LIMIT 1000

struct afcodel_sched_data {
	struct afcodel_parms params;
	struct afcodel_vars	vars;
	struct afcodel_stats	stats;
	u32			drop_overlimit;
};

static int afcodel_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct afcodel_sched_data *q = qdisc_priv(sch);
	u32 afq_hash;
	u32 sb_val, sb_id;
	struct flow_keys keys;

	q->stats.afqstats.total_packet_count++;

	if (likely(qdisc_qlen(sch) < sch->limit)) {
		/* Hash for flow*/
		skb_flow_dissect(skb, &keys);
		afq_hash = jhash_3words((__force u32)keys.dst,
				   (__force u32)keys.src,
				   (__force u32)keys.ports,
				   q->vars.afqvars.perturbation);
		
		codel_set_enqueue_time(skb);

		if (!(q->stats.afqstats.total_packet_count % SAMPLE_INTERVAL)) {
			/* Go to shadow buffer*/
			sb_id = q->vars.afqvars.shadow_buffer_point % SHADOW_BUFFER_SIZE;
		
			if (shadow_buffer[sb_id]) {
				/* Overwrite the old entry in shadow buffer*/
				sb_val = shadow_buffer[sb_id];
				flow_table[sb_val % FLOW_TABLE_SIZE]--; 
//printk(KERN_INFO "overwrite sb %u, ft is %u\n", sb_val, flow_table[sb_val % FLOW_TABLE_SIZE]);			
				if (!flow_table[sb_val % FLOW_TABLE_SIZE])
					q->stats.afqstats.flow_count--;
			}
		
			/* Fill the shadow buffer*/
			shadow_buffer[sb_id] = afq_hash;
			q->vars.afqvars.shadow_buffer_point++;
		
//printk(KERN_INFO "sb pt %u\n", q->vars.afqvars.shadow_buffer_point);
	
			if (!flow_table[afq_hash % FLOW_TABLE_SIZE])
				q->stats.afqstats.flow_count++;
		
			flow_table[afq_hash % FLOW_TABLE_SIZE]++;
			q->stats.afqstats.ft_id = afq_hash % FLOW_TABLE_SIZE;
			q->stats.afqstats.ft_val = flow_table[afq_hash % FLOW_TABLE_SIZE];
		
	//printk(KERN_INFO "hash %u, ft %u is %u\n", afq_hash, 
	//	afq_hash % FLOW_TABLE_SIZE, flow_table[afq_hash % FLOW_TABLE_SIZE]);
		}
		
		return qdisc_enqueue_tail(skb, sch);

	}		

	q = qdisc_priv(sch);
	q->drop_overlimit++;
	q->stats.afqstats.tail_drop++;
	sch->qstats.drops++;

	return qdisc_drop(skb, sch);
}

/* This is the specific function called from codel_dequeue()
 * to dequeue a packet from queue. Note: backlog is handled in
 * codel, we dont need to reduce it here.
 */
static struct sk_buff *dequeue(struct codel_vars *vars, struct Qdisc *sch)
{
	struct sk_buff *skb = __skb_dequeue(&sch->q);

	prefetch(&skb->end); /* we'll need skb_shinfo() */
	return skb;
}

static struct sk_buff *afcodel_qdisc_dequeue(struct Qdisc *sch)
{
	struct afcodel_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	skb = afcodel_dequeue(sch, &q->params, &q->vars, &q->stats, dequeue);

	/* We cant call qdisc_tree_decrease_qlen() if our qlen is 0,
	 * or HTB crashes. Defer it for next round.
	 */
	if (q->stats.codelstats.drop_count && sch->q.qlen) {
		qdisc_tree_decrease_qlen(sch, q->stats.codelstats.drop_count);
		q->stats.codelstats.drop_count = 0;
	}
	if (skb)
		qdisc_bstats_update(sch, skb);
	return skb;
}


static const struct nla_policy afcodel_policy[TCA_AFCODEL_MAX + 1] = {
	[TCA_AFCODEL_TARGET]	= { .type = NLA_U32 },
	[TCA_AFCODEL_LIMIT]	= { .type = NLA_U32 },
	[TCA_AFCODEL_INTERVAL]	= { .type = NLA_U32 },
	[TCA_AFCODEL_ECN]		= { .type = NLA_U32 },
};

static int afcodel_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct afcodel_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_AFCODEL_MAX + 1];
	unsigned int qlen;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_AFCODEL_MAX, opt, afcodel_policy);
	if (err < 0)
		return err;

	sch_tree_lock(sch);

	if (tb[TCA_AFCODEL_TARGET]) {
		u32 target = nla_get_u32(tb[TCA_AFCODEL_TARGET]);

		q->params.codelparams.target = ((u64)target * NSEC_PER_USEC) >> CODEL_SHIFT;
	}

	if (tb[TCA_AFCODEL_INTERVAL]) {
		u32 interval = nla_get_u32(tb[TCA_AFCODEL_INTERVAL]);

		q->params.codelparams.interval = ((u64)interval * NSEC_PER_USEC) >> CODEL_SHIFT;
	}

	if (tb[TCA_AFCODEL_LIMIT])	{
		sch->limit = nla_get_u32(tb[TCA_AFCODEL_LIMIT]);
		q->params.afqparams.limit = sch->limit;
printk(KERN_INFO "limit is %u\n", sch->limit);
		
	}

	if (tb[TCA_AFCODEL_ECN])
		q->params.codelparams.ecn = !!nla_get_u32(tb[TCA_AFCODEL_ECN]);

	qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = __skb_dequeue(&sch->q);

		sch->qstats.backlog -= qdisc_pkt_len(skb);
		qdisc_drop(skb, sch);
	}
	qdisc_tree_decrease_qlen(sch, qlen - sch->q.qlen);

	sch_tree_unlock(sch);
	return 0;
}

static int afcodel_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct afcodel_sched_data *q = qdisc_priv(sch);

	sch->limit = DEFAULT_AFCODEL_LIMIT;
	
	codel_params_init(&q->params.codelparams);
	codel_vars_init(&q->vars.codelvars);
	codel_stats_init(&q->stats.codelstats);
	q->vars.afqvars.perturbation = net_random();
	q->vars.afqvars.shadow_buffer_point = 0;
	q->vars.pre_drop = 0;
	memset(shadow_buffer, 0, SHADOW_BUFFER_SIZE * sizeof(shadow_buffer[0]));
	memset(flow_table, 0, FLOW_TABLE_SIZE * sizeof(flow_table[0]));
	memset(flow_first_above_time, 0, FLOW_TABLE_SIZE * sizeof(flow_first_above_time[0]));
	memset(flow_target, 0, FLOW_TABLE_SIZE * sizeof(flow_target[0]));

	if (opt) {
		int err = afcodel_change(sch, opt);

		if (err)
			return err;
	}
/*
	if (sch->limit >= 1)
		sch->flags |= TCQ_F_CAN_BYPASS;
	else
		sch->flags &= ~TCQ_F_CAN_BYPASS;
*/
	return 0;
}

static int afcodel_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct afcodel_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_AFCODEL_TARGET,
			codel_time_to_us(q->params.codelparams.target)) ||
	    nla_put_u32(skb, TCA_AFCODEL_LIMIT,
			sch->limit) ||
	    nla_put_u32(skb, TCA_AFCODEL_INTERVAL,
			codel_time_to_us(q->params.codelparams.interval)) ||
	    nla_put_u32(skb, TCA_AFCODEL_ECN,
			q->params.codelparams.ecn))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;
}

static int afcodel_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	const struct afcodel_sched_data *q = qdisc_priv(sch);
	struct tc_afcodel_xstats st = {
		.maxpacket	= q->stats.codelstats.maxpacket,
		.count		= q->vars.codelvars.count,
		.lastcount	= q->vars.codelvars.lastcount,
		.drop_overlimit = q->drop_overlimit,
		.ldelay		= codel_time_to_us(q->vars.codelvars.ldelay),
		.dropping	= q->vars.codelvars.dropping,
		.ecn_mark	= q->stats.codelstats.ecn_mark,
		.fairdrop	= q->stats.afqstats.fair_drop,
		.taildrop	= q->stats.afqstats.tail_drop,
		.flowcount	= q->stats.afqstats.flow_count,
		.total_packet_count = q->stats.afqstats.total_packet_count,
		.ftid		= q->stats.afqstats.ft_id,
		.ftval		= q->stats.afqstats.ft_val,
	};

	if (q->vars.codelvars.dropping) {
		codel_tdiff_t delta = q->vars.codelvars.drop_next - codel_get_time();

		if (delta >= 0)
			st.drop_next = codel_time_to_us(delta);
		else
			st.drop_next = -codel_time_to_us(-delta);
	}

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static void afcodel_reset(struct Qdisc *sch)
{
	struct afcodel_sched_data *q = qdisc_priv(sch);

	qdisc_reset_queue(sch);
	codel_vars_init(&q->vars.codelvars);
	sch->q.qlen = 0;
	q->vars.afqvars.perturbation = net_random();
	q->vars.afqvars.shadow_buffer_point = 0;
	q->vars.pre_drop = 0;
	memset(shadow_buffer, 0, SHADOW_BUFFER_SIZE * sizeof(shadow_buffer[0]));
	memset(flow_table, 0, FLOW_TABLE_SIZE * sizeof(flow_table[0]));
	memset(flow_first_above_time, 0, FLOW_TABLE_SIZE * sizeof(flow_first_above_time[0]));
	memset(flow_target, 0, FLOW_TABLE_SIZE * sizeof(flow_target[0]));
}

static struct Qdisc_ops afcodel_qdisc_ops __read_mostly = {
	.id		=	"afcodel",
	.priv_size	=	sizeof(struct afcodel_sched_data),

	.enqueue	=	afcodel_qdisc_enqueue,
	.dequeue	=	afcodel_qdisc_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	afcodel_init,
	.reset		=	afcodel_reset,
	.change 	=	afcodel_change,
	.dump		=	afcodel_dump,
	.dump_stats	=	afcodel_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init afcodel_module_init(void)
{
	return register_qdisc(&afcodel_qdisc_ops);
}

static void __exit afcodel_module_exit(void)
{
	unregister_qdisc(&afcodel_qdisc_ops);
}

module_init(afcodel_module_init)
module_exit(afcodel_module_exit)

MODULE_DESCRIPTION("Approximate Fair Controlled Delay queue discipline");
MODULE_AUTHOR("Dave Taht");
MODULE_AUTHOR("Eric Dumazet");
MODULE_AUTHOR("Lin Xue");
MODULE_LICENSE("Dual BSD/GPL");


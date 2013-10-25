/*
 * A Linux implementation of Appoximate Fair Dropping Queue (AFQ)
 * 
 * Approximate fairness through differential dropping
 * Pan, R. and Breslau, L. and Prabhakar, B. and Shenker, S.
 * ACM SIGCOMM Computer Communication Review 2003
 * 
 * Lin Xue, xuelin@cct.lsu.edu, 11/11/2012
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <net/afq.h>
#include <net/flow_keys.h>

/* Parameters of AFQ */
struct afq_sched_data {
	struct Qdisc	*qdisc;
	struct afq_parms	parms;
	struct afq_vars		vars;
	struct afq_stats	stats;
};

/* Shadow buffer (a circular buffer) */	
#define SHADOW_BUFFER_SIZE	2000
static u32 shadow_buffer[SHADOW_BUFFER_SIZE];

/*Flow table*/
#define FLOW_TABLE_SIZE	100
static u32 flow_table[FLOW_TABLE_SIZE];

/*Sample interval*/
#define SAMPLE_INTERVAL	500

#define AFQ_MAX_PROB	0xFFFF

static int afq_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct afq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	u32 afq_hash;
	u32 r, p;	/* r is random probability, p is drop probability. both 32 bits*/
	u32 sb_val, sb_id;
	u32 m_fair;	/* fair share matches */
	struct flow_keys keys;
	int ret;

	
	/* Hash for flow*/
	skb_flow_dissect(skb, &keys);
	afq_hash = jhash_3words((__force u32)keys.dst,
		       (__force u32)keys.src,
		       (__force u32)keys.ports,
		       q->vars.perturbation);

	if (unlikely(sch->q.qlen >= q->parms.limit)) {
		sch->qstats.overlimits++;
		q->stats.tail_drop++;
		goto drop;
	}
		
	q->stats.total_packet_count++;

	if (!(q->stats.total_packet_count % SAMPLE_INTERVAL)) {
		/* Go to shadow buffer*/
		sb_id = q->vars.shadow_buffer_point % SHADOW_BUFFER_SIZE;

		if (shadow_buffer[sb_id]) {
			/* Overwrite the old entry in shadow buffer*/
			sb_val = shadow_buffer[sb_id];
			flow_table[sb_val % FLOW_TABLE_SIZE]--;	
//printk(KERN_INFO "overwrite sb %u, ft is %u\n", sb_val, flow_table[sb_val % FLOW_TABLE_SIZE]);			
			if (!flow_table[sb_val % FLOW_TABLE_SIZE])
				q->stats.flow_count--;
		}

		/* Fill the shadow buffer*/
		shadow_buffer[sb_id] = afq_hash;
		q->vars.shadow_buffer_point++;

//printk(KERN_INFO "sb pt %u\n", q->vars.shadow_buffer_point);

		if (!flow_table[afq_hash % FLOW_TABLE_SIZE])
			q->stats.flow_count++;

		flow_table[afq_hash % FLOW_TABLE_SIZE]++;
		q->stats.ft_id = afq_hash % FLOW_TABLE_SIZE;
		q->stats.ft_val = flow_table[afq_hash % FLOW_TABLE_SIZE];

//printk(KERN_INFO "hash %u, ft %u is %u\n", afq_hash, 
//	afq_hash % FLOW_TABLE_SIZE, flow_table[afq_hash % FLOW_TABLE_SIZE]);

	}

	if(q->stats.flow_count > 1 && (flow_table[afq_hash % FLOW_TABLE_SIZE])) {
		/* Goto fair drop function
		 *	m_fair is: 	  
		 *		     	shadow buffer size
		 *		==================
		 *		  		flow count
		 *
		 * 	m_fair is adjusted by sample q_len:
		 *		m_fair (t) = m_fair(t - 1) + alpha(q_len(t - 1) - q_target) - beta(q_len(t) - q_target)
		 *		alpha = 1.7
		 *		beta = 1.8
		 *		(details see "Approximate Fairness through Differential Dropping")
		 *
		 * 	fair drop probability is according to :           
		  *				shadow buffer size
		 *     	1 - ==================
		 *     		flow entry val * flow count
		 *  	(scale by AFQ_MAX_PROB)
		 */

		m_fair = SHADOW_BUFFER_SIZE / q->stats.flow_count + 
				17 * (q->vars.qlen_pre - q->parms.limit / 5) / 10 - 
				18 * (sch->q.qlen - q->parms.limit / 5) / 10;
//printk(KERN_INFO "mf %u\n", m_fair); 
		
		if((1) > ((6 * m_fair)/ (5 * flow_table[afq_hash % FLOW_TABLE_SIZE]))) {
			p = 1 * AFQ_MAX_PROB / 1000 - 
			(m_fair * AFQ_MAX_PROB / 
			(1000 * flow_table[afq_hash % FLOW_TABLE_SIZE]));
//printk(KERN_INFO "1 p %u\n", p); 
		}
		else {
//printk(KERN_INFO "2 p 0\n"); 
			p = 0;
		}
		
		r = net_random() & AFQ_MAX_PROB;

		//if ((r < p) && (sch->q.qlen > (q->parms.limit / 5))) {
		if (r < p) {
			
//printk(KERN_INFO "fd %u, %u, p %u, r %u\n", 
//		afq_hash % FLOW_TABLE_SIZE, flow_table[afq_hash % FLOW_TABLE_SIZE], 
//		p, r);
printk(KERN_INFO "%u\n", afq_hash % FLOW_TABLE_SIZE);
			
			q->stats.fair_drop++;
			goto drop;
		}

		
		if (!(q->stats.total_packet_count % SAMPLE_INTERVAL)) {
			/* Sample q_len*/
			q->vars.qlen_pre = sch->q.qlen;
		}
	}

	ret = qdisc_enqueue(skb, child);
	if (likely(ret != NET_XMIT_SUCCESS))
printk(KERN_INFO "r %d\n", ret);
		
	if (likely(ret == NET_XMIT_SUCCESS)) {
		sch->q.qlen++;
	} else if (net_xmit_drop_count(ret)) {
//printk(KERN_INFO "ef %u, %u\n", 
//		afq_hash % FLOW_TABLE_SIZE, flow_table[afq_hash % FLOW_TABLE_SIZE]);
	
		q->stats.tail_drop++;
		sch->qstats.drops++;
	}
	return ret;

drop:
	qdisc_drop(skb, sch);
	return NET_XMIT_CN;
}

static struct sk_buff *afq_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;
	struct afq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;

	skb = child->dequeue(child);
	if (skb) {
		qdisc_bstats_update(sch, skb);
		sch->q.qlen--;
	}
	return skb;
}

static struct sk_buff *afq_peek(struct Qdisc *sch)
{
	struct afq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;

	return child->ops->peek(child);
}

static unsigned int afq_drop(struct Qdisc *sch)
{
	struct afq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	unsigned int len;

printk(KERN_INFO "afq drop\n");

	if (child->ops->drop && (len = child->ops->drop(child)) > 0) {
		sch->qstats.drops++;
		sch->q.qlen--;
		return len;
	}

	return 0;
}

static void afq_reset(struct Qdisc *sch)
{
	struct afq_sched_data *q = qdisc_priv(sch);

	qdisc_reset(q->qdisc);
	sch->q.qlen = 0;
	q->vars.perturbation = net_random();
	q->vars.shadow_buffer_point = 0;
	memset(shadow_buffer, 0, SHADOW_BUFFER_SIZE * sizeof(shadow_buffer[0]));
	memset(flow_table, 0, FLOW_TABLE_SIZE * sizeof(flow_table[0]));
}

static void afq_destroy(struct Qdisc *sch)
{
	struct afq_sched_data *q = qdisc_priv(sch);

	qdisc_destroy(q->qdisc);
}

static const struct nla_policy afq_policy[TCA_AFQ_MAX + 1] = {
	[TCA_AFQ_LIMIT]	= { .type = NLA_U32 },
};

static int afq_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct afq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child;
	struct nlattr *tb[TCA_AFQ_MAX + 1];
	u32 limit;
	int err;

	if (!opt)
		return -EINVAL;
	
	err = nla_parse_nested(tb, TCA_AFQ_MAX, opt, afq_policy);
	if (err < 0)
		return err;
	
	limit = nla_get_u32(tb[TCA_AFQ_LIMIT]);
	sch->limit = limit;

	child = fifo_create_dflt(sch, &pfifo_qdisc_ops, limit);
	if (IS_ERR(child))
		return PTR_ERR(child);

	sch_tree_lock(sch);
	
	qdisc_tree_decrease_qlen(q->qdisc, q->qdisc->q.qlen);
	qdisc_destroy(q->qdisc);
	q->qdisc = child;

	afq_set_parms(&q->parms, limit);
	
	sch_tree_unlock(sch);

	return 0;
}

static int afq_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct afq_sched_data *q = qdisc_priv(sch);

	q->qdisc = &noop_qdisc;
	q->vars.perturbation = net_random();
	q->vars.shadow_buffer_point = 0;
	memset(shadow_buffer, 0, SHADOW_BUFFER_SIZE * sizeof(shadow_buffer[0]));
	memset(flow_table, 0, FLOW_TABLE_SIZE * sizeof(flow_table[0]));
	return afq_change(sch, opt);
}

static int afq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct afq_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = NULL;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;
	
	if (nla_put_u32(skb, TCA_AFQ_LIMIT, q->parms.limit))
		goto nla_put_failure;
	
	return nla_nest_end(skb, opts);

	nla_put_failure:
		nla_nest_cancel(skb, opts);
		return -1;
}

static int afq_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct afq_sched_data *q = qdisc_priv(sch);
	struct tc_afq_xstats st = {
		.fairdrop	= q->stats.fair_drop,
		.taildrop	= q->stats.tail_drop,
		.flowcount	= q->stats.flow_count,
		.total_packet_count = q->stats.total_packet_count,
		.ftid		= q->stats.ft_id,
		.ftval		= q->stats.ft_val,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int afq_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct afq_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(1);
	tcm->tcm_info = q->qdisc->handle;
	return 0;
}

static int afq_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct afq_sched_data *q = qdisc_priv(sch);

	if (new == NULL)
		new = &noop_qdisc;

	sch_tree_lock(sch);
	*old = q->qdisc;
	q->qdisc = new;
	qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
	qdisc_reset(*old);
	sch_tree_unlock(sch);
	return 0;
}

static struct Qdisc *afq_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct afq_sched_data *q = qdisc_priv(sch);
	return q->qdisc;
}

static unsigned long afq_get(struct Qdisc *sch, u32 classid)
{
	return 1;
}

static void afq_put(struct Qdisc *sch, unsigned long arg)
{
}

static void afq_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	if (!walker->stop) {
		if (walker->count >= walker->skip)
			if (walker->fn(sch, 1, walker) < 0) {
				walker->stop = 1;
				return;
			}
		walker->count++;
	}
}

static const struct Qdisc_class_ops afq_class_ops = {
	.graft		=	afq_graft,
	.leaf		=	afq_leaf,
	.get		=	afq_get,
	.put		=	afq_put,
	.walk		=	afq_walk,
	.dump		=	afq_dump_class,
};

static struct Qdisc_ops afq_qdisc_ops __read_mostly = {
	.id		=	"afq",
	.priv_size	=	sizeof(struct afq_sched_data),
	.enqueue	=	afq_enqueue,
	.dequeue	=	afq_dequeue,
	.peek		=	afq_peek,
	.drop		=	afq_drop,
	.init		=	afq_init,
	.reset		=	afq_reset,
	.destroy	=	afq_destroy,
	.change		=	afq_change,
	.dump		=	afq_dump,
	.dump_stats	=	afq_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init afq_module_init(void)
{
	return register_qdisc(&afq_qdisc_ops);
}

static void __exit afq_module_exit(void)
{
	unregister_qdisc(&afq_qdisc_ops);
}

module_init(afq_module_init)
module_exit(afq_module_exit)

MODULE_LICENSE("GPL");


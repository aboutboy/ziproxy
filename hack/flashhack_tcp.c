
/*
 * flahshhack_tcp.c
 *
 *  Created on: 2012-03-03
 *      Author: phost
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/sock.h>

#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_nat_rule.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("phost");
MODULE_DESCRIPTION("Hack the tcph urg_ptr with dport");
MODULE_VERSION("1.0");

#define DPORT_MIN 10000
#define DPORT_MAX 90000

#undef DEBUGLOG

#ifndef NOOP
#define NOOP ((void)0)
#endif

static char *         markdip= "192.168.56.101";
static unsigned short markdport=23456;

module_param(markdport, ushort, S_IRUSR);
module_param(markdip,   charp,  S_IRUSR); 

#ifdef DEBUGLOG
static void
hex_dump(const unsigned char *buf, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
  {
    if (i && !(i % 16))
      printk("\n");
    printk("%c ", *(buf + i));
  }
  printk("\n");
}

static void
hex_dump_hex(const unsigned char *buf, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
  {
    if (i && !(i % 16))
      printk("\n");
    printk("%02x ", *(buf + i));
  }
  printk("\n");
}
#else
#define hex_dump(buf, len) NOOP
#define hex_dump_hex(buf, len) NOOP
#endif

unsigned int
hack_tcph_with_xport(unsigned int hooknum, struct sk_buff *skb,
                     const struct net_device *in, const struct net_device *out,
                     int (*okfn) (struct sk_buff *))
{
  struct iphdr *iph = NULL;
  struct tcphdr *tcph = NULL;

  // struct rtable *rt = skb_rtable(skb);
  int oldlen, datalen;

  __be32 daddr, saddr;
  __be16 dport, sport;

  /* get ip header */
  iph = ip_hdr(skb);

  if(iph->daddr == in_aton(markdip))
  {
    if (iph->protocol == IPPROTO_TCP)
    {
      /* get tcp header, tcp_hdr(skb) doesn't work alwasy, e.g.
       * in NF_INET_POST_ROUTING with NF_IP_PRI_MANGLE priority */
      tcph = (void *)iph + iph->ihl*4;
  
      sport = tcph->source;
      dport = tcph->dest;
      saddr = iph->saddr;
      daddr = iph->daddr;
  
      if (ntohs(dport) > DPORT_MAX || ntohs(dport) < DPORT_MIN)
      {
        return NF_ACCEPT;
      }
  
      if (!skb_make_writable(skb, skb->len))
      {
        return NF_ACCEPT;
      }
  
      SKB_LINEAR_ASSERT(skb);
  
      oldlen = skb->len - iph->ihl*4;
      datalen = oldlen;
  
      /* check the urg flag, if it's not set, then set the res1 flag,
       * and save the dport into the urg_ptr */
      if (tcph->urg != 0 || tcph->res1 != 0)
      {
        printk("WARNING: a TCP request received with urg %d res1 %d before hacking tcph\n",
               tcph->urg, tcph->res1);
  
        //printk("    tcp packet to : %u.%u.%u.%u:%u\n",
               //NIPQUAD(daddr), ntohs(dport));
        printk("    ---------ip total len =%d--------\n", ntohs(iph->tot_len));
        printk("    ---------tcph->doff =%d--------\n", tcph->doff*4);
  
        return NF_ACCEPT;
      }
      else
      {
        tcph->res1 = 1;
        tcph->urg = 1;
        tcph->urg_ptr = dport;
      }
  
      if (skb->ip_summed != CHECKSUM_PARTIAL)
      {
#ifdef DEBUGLOG
        printk("========= debug 9 =========\n");
        printk("  rt %x skb %x skb->dev %x skb->dev->features %x\n",
         (rt == NULL) ? NULL : rt,
         (skb == NULL) ? NULL : skb,
         (skb == NULL) ? NULL : skb->dev,
         (skb->dev == NULL) ? NULL : skb->dev->features);
#endif
  
        // if (!(rt->rt_flags & RTCF_LOCAL) &&
        //    skb->dev->features & NETIF_F_V4_CSUM)
        if (skb->dev->features & NETIF_F_V4_CSUM)
        {
          skb->ip_summed = CHECKSUM_PARTIAL;
          skb->csum_start = skb_headroom(skb) +
                            skb_network_offset(skb) +
                            iph->ihl * 4;
          skb->csum_offset = offsetof(struct tcphdr, check);
          tcph->check = ~tcp_v4_check(datalen,
                                      iph->saddr, iph->daddr, 0);
        }
        else
        {
          tcph->check = 0;
          tcph->check = tcp_v4_check(datalen,
                                     iph->saddr, iph->daddr,
                                     csum_partial(tcph,
                                                  datalen, 0));
        }
      }
      else
      {
        inet_proto_csum_replace2(&tcph->check, skb,
                                 htons(oldlen), htons(datalen), 1);
      }
    }
  }

  return NF_ACCEPT;
}

static struct nf_hook_ops http_hooks =
{
  .pf = NFPROTO_IPV4,
  .priority = NF_IP_PRI_MANGLE, // NF_IP_PRI_FIRST, //NF_IP_PRI_LAST ;NF_IP_PRI_NAT_SRC ;
  .hooknum = NF_INET_PRE_ROUTING, // DNF_INET_FORWARD, // NF_INET_POST_ROUTING,
  .hook = hack_tcph_with_xport,
  .owner = THIS_MODULE,
};

static int __init hacktcph_init(void)
{
  printk("hacktcph_init successfully with %s:%u\n", markdip, markdport);
  return nf_register_hook(&http_hooks);
}

static void __exit hacktcph_cleanup(void)
{
  printk("hacktcph_cleanup successfully with %s:%u\n", markdip, markdport);
  nf_unregister_hook(&http_hooks);
}

module_init(hacktcph_init);
module_exit(hacktcph_cleanup);

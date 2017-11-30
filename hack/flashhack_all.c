
/*
 * flahshhack_all.c
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
MODULE_DESCRIPTION("Hack HTTP protocol proxy port");
MODULE_VERSION("1.0");

#define DPORT_MIN 10000
#define DPORT_MAX 90000

#undef DEBUGLOG
//#define DEBUGLOG 1
#undef INVALID_LOG
//#define INVALID_LOG 1
#define HTTP 1

#ifndef NOOP
#define NOOP ((void)0)
#endif

static char *         proxyip= "192.168.56.101";
static unsigned short proxyport=0;
static unsigned short minport=10000;
static unsigned short maxport=60000;

module_param(minport, ushort, S_IRUSR);
module_param(maxport, ushort, S_IRUSR);
module_param(proxyport, ushort, S_IRUSR);
module_param(proxyip, charp,  S_IRUSR); 

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

char *
locate_http_in_http_request(char *start, int len)
{
  char data[7] = " HTTP/1";
  char *i = start;

  if (start == NULL)
    return NULL;

  i += 4;
  while ( (i - start < len - 7) && (*i != ' ' || *(i+1) != 'H' || *(i+2) != 'T' || *(i+3) != 'T' ||
         *(i+4) != 'P' || *(i+5) != '/' || *(i+6) != '1') )
  {
#ifdef DEBUGLOG
    printk("%02x ", *i);
#endif
    i++;
  }

  if (*(int *) (i) == *(int *) data)
  {
#ifdef DEBUGLOG
    printk("\n...........found........ \n");
#endif
    return i;
  }
  else
    return NULL;
}

unsigned int
hack_http_with_pport(unsigned int hooknum, struct sk_buff *skb,
                     const struct net_device *in, const struct net_device *out,
                     int (*okfn) (struct sk_buff *))
{
  struct iphdr *iph = NULL;
  struct tcphdr *tcph = NULL;
  char *payload = NULL;
  int payload_len;

  // struct rtable *rt = skb_rtable(skb);
  int oldlen, datalen;

  __be32 daddr, saddr;
  __be16 dport, sport;

  /* get ip header */
  iph = ip_hdr(skb);

  /* get tcp header, tcp_hdr(skb) doesn't work alwasy, e.g.
   * in NF_INET_POST_ROUTING with NF_IP_PRI_MANGLE priority */
  tcph = (void *)iph + iph->ihl*4;
  
  sport = tcph->source;
  dport = tcph->dest;
  saddr = iph->saddr;
  daddr = iph->daddr;

#ifdef DEBUGLOG
  printk("WARNING: a TCP request received with urg %d res1 %d before hacking tcph\n",
         tcph->urg, tcph->res1);
  //printk("    tcp packet to : %u.%u.%u.%u:%u\n",
         //NIPQUAD(daddr), ntohs(dport));
  printk("    ---------ip total len =%d--------\n", ntohs(iph->tot_len));
  printk("    ---------tcph->doff =%d--------\n", tcph->doff*4);
#endif

/*
  if( ((iph->daddr & 0xFFFFFF00) == (in_aton(proxyip) & 0xFFFFFF00)) &&
     ( ((proxyport > 0) && ((ntohs(dport) == proxyport))) ||
       ((proxyport == 0) && (ntohs(dport) < maxport) && (ntohs(dport) > minport))) )
*/
  if(  ( ((proxyport > 0) && ((ntohs(dport) == proxyport))) ||
       ((proxyport == 0) && (ntohs(dport) <= maxport) && (ntohs(dport) >= minport))) )
  {
    if (iph->protocol == IPPROTO_TCP)
    {

      /* get the payload, it doesn't work always with other ways */
      payload = (void *) skb->data + iph->ihl * 4 + tcph->doff * 4;
      if (payload == NULL)
        return NF_ACCEPT;

      /* on i386 with ipv4, both the ip/tcp head in 20 bytes */
      payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4;

#ifdef DEBUGLOG
      printk(".................paylod debug 001....................\n");
      printk("%20s\n", payload);
 
      printk(".................paylod debug 002....................\n");
      hex_dump_hex(payload,
                   ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4);
      printk(".................paylod debug 003....................\n");
      printk("  payload_len %d iph->tot_len %d iph->ihl %d tcph->doff %d\n",
             payload_len, ntohs(iph->tot_len), iph->ihl, tcph->doff);
#endif

      if (payload_len < 20)     //determine if it begins with "GET xyz HTTP/1.1"
        return NF_ACCEPT;
  
/*
      if ((0 == strncmp(payload, "GET ", 4)) || 
          (0 == strncmp(payload, "PUT ", 4)) ||
          (0 == strncmp(payload, "POST ", 5)) ||
          (0 == strncmp(payload, "HEAD ", 5)) ||
          (0 == strncmp(payload, "DELETE ", 7)) ||
          (0 == strncmp(payload, "CONNECT ", 8)) )
*/
      if (
           (   ( *(payload + 0) == 'G' || *(payload + 0) == 'g' )
            && ( *(payload + 1) == 'E' || *(payload + 1) == 'e' )
            && ( *(payload + 2) == 'T' || *(payload + 2) == 't' )
            && ( *(payload + 3) == ' ' || *(payload + 3) == ' ' )
           ) ||
           (   ( *(payload + 0) == 'P' || *(payload + 0) == 'p' )
            && ( *(payload + 1) == 'U' || *(payload + 1) == 'u' )
            && ( *(payload + 2) == 'T' || *(payload + 2) == 't' )
            && ( *(payload + 3) == ' ' || *(payload + 3) == ' ' )
           ) ||
           (   ( *(payload + 0) == 'P' || *(payload + 0) == 'p' )
            && ( *(payload + 1) == 'O' || *(payload + 1) == 'o' )
            && ( *(payload + 2) == 'S' || *(payload + 2) == 's' )
            && ( *(payload + 3) == 'T' || *(payload + 3) == 't' )
            && ( *(payload + 4) == ' ' || *(payload + 4) == ' ' )
           ) ||
           (   ( *(payload + 0) == 'H' || *(payload + 0) == 'h' )
            && ( *(payload + 1) == 'E' || *(payload + 1) == 'e' )
            && ( *(payload + 2) == 'A' || *(payload + 2) == 'a' )
            && ( *(payload + 3) == 'D' || *(payload + 3) == 'd' )
            && ( *(payload + 4) == ' ' || *(payload + 4) == ' ' )
           ) ||
           (   ( *(payload + 0) == 'D' || *(payload + 0) == 'd' )
            && ( *(payload + 1) == 'E' || *(payload + 1) == 'e' )
            && ( *(payload + 2) == 'L' || *(payload + 2) == 'l' )
            && ( *(payload + 3) == 'E' || *(payload + 3) == 'e' )
            && ( *(payload + 4) == 'T' || *(payload + 4) == 't' )
            && ( *(payload + 5) == 'E' || *(payload + 5) == 'e' )
            && ( *(payload + 6) == ' ' || *(payload + 6) == ' ' )
           ) ||
           (   ( *(payload + 0) == 'C' || *(payload + 0) == 'c' )
            && ( *(payload + 1) == 'O' || *(payload + 1) == 'o' )
            && ( *(payload + 2) == 'N' || *(payload + 2) == 'n' )
            && ( *(payload + 3) == 'N' || *(payload + 3) == 'n' )
            && ( *(payload + 4) == 'E' || *(payload + 4) == 'e' )
            && ( *(payload + 5) == 'C' || *(payload + 5) == 'c' )
            && ( *(payload + 6) == 'T' || *(payload + 6) == 't' )
            && ( *(payload + 7) == ' ' || *(payload + 7) == ' ' )
           )
         )
      {
  
        if (!skb_make_writable(skb, skb->len))
        {
          return NF_ACCEPT;
        }

        char *head = NULL;
#ifdef HTTP
        head = locate_http_in_http_request(payload, payload_len);
#else
        return NF_ACCEPT;
#endif
        if (! head)
        {
          /* cannot find the ' HTTP/' pattern in the payload */
#ifdef INVALID_LOG
          printk("WARNING: Got a HTTP request started with GET but cannot find the HTTP/\n");
          printk("%20s\n", payload);
#endif

          return NF_ACCEPT;
        }

        /* get a valid HTTP request:
           payload: |GET http://www.myhost.com/hello.html HTTP/1.1
                                                         |
                                                         head start from here
         */

        /* insert the proxy port info to replay the HTTP/ string */
        /*
        char content[7];
        int i;
        snprintf(content, 7, " %d", ntohs(dport));
        for (i=0; i<6; i++)
        {
          *(head+i) = content[i];
        }
        */
        struct proxyinfo
        {
          __be32 addr;
          __be16 port;
        } proxy;
        proxy.addr = daddr;
        proxy.port = dport;
        // memcpy(head+1, &proxy, sizeof(struct proxyinfo));
        memcpy(head+1, &proxy, 6);

#ifdef DEBUGLOG
        printk(".................paylod debug 101....................\n");
        printk("%20s\n", payload);
 
        printk(".................paylod debug 102....................\n");
        hex_dump_hex(payload,
                   ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4);
        printk(".................paylod debug 103....................\n");
#endif
    
        SKB_LINEAR_ASSERT(skb);
    
        oldlen = skb->len - iph->ihl*4;
        datalen = oldlen;
    
#ifdef TCPH
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
#endif
    
        if (skb->ip_summed != CHECKSUM_PARTIAL)
        {
#ifdef DEBUGLOG2
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
  }

  return NF_ACCEPT;
}

static struct nf_hook_ops http_hooks =
{
  .pf = NFPROTO_IPV4,
  .priority = NF_IP_PRI_MANGLE, // NF_IP_PRI_FIRST, //NF_IP_PRI_LAST ;NF_IP_PRI_NAT_SRC ;
  .hooknum = NF_INET_PRE_ROUTING, // DNF_INET_FORWARD, // NF_INET_POST_ROUTING,
  .hook = hack_http_with_pport,
  .owner = THIS_MODULE,
};

static int __init flashhack_init(void)
{
  printk("flashhack_init successfully with %s, %u: %u - %u\n", proxyip, proxyport, minport, maxport);
  return nf_register_hook(&http_hooks);
}

static void __exit flashhack_cleanup(void)
{
  printk("flashhack_cleanup successfully with %s, %u: %u - %u\n", proxyip, proxyport, minport, maxport);
  nf_unregister_hook(&http_hooks);
}

module_init(flashhack_init);
module_exit(flashhack_cleanup);


/*
 * hackhttp_http.c
 *
 *  Created on: 2012-03-03
 *      Author: phost, hufh
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
MODULE_AUTHOR("phost, hufh");
MODULE_DESCRIPTION("Inject port info into a HTTP request");
MODULE_VERSION("1.0");

#define DEBUGLOG 1
#undef ACCEPT
#define ACCEPT_XPORT

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

char *
locate_accept_in_http_request(char *start)
{
  char data[10] = "\r\nAccept: ";
  char *i = start;

  i += 4;
  while (*i != '\r' || *(i+1) != '\n' || *(i+2) != 'A' || *(i+3) != 'c' ||
         *(i+4) != 'c' || *(i+5) != 'e' || *(i+6) != 'p' || *(i+7) != 't' ||
         *(i+8) != ':' || *(i+9) != ' ')
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

char *
locate_http_in_http_request(char *start)
{
  char data[7] = " HTTP/1";
  char *i = start;

  i += 4;
  while (*i != ' ' || *(i+1) != 'H' || *(i+2) != 'T' || *(i+3) != 'T' ||
         *(i+4) != 'P' || *(i+5) != '/' || *(i+6) != '1')
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

char *
is_mp3_request(char *start)
{
  // char data[4] = ".mp3";
  char data[4] = "\r\n\r\n";
  char *i = start;

  i += 4;                       //
  while (*i != '\n' || *(i-1) != '\r' || *(i-2) != '\n' || *(i-3) != '\r')
  {
#ifdef DEBUGLOG
    printk("%02x ", *i);
#endif
    i++;
  }

#ifdef DEBUGLOG
  printk("\n&&&&&&&&&&&&&&&\n%20s\n", i);
  printk("\n&&&&&____&&&&&&\n");
  printk("is_mp3_request \n");
#endif
  if (*(int *) (i - 3) == *(int *) data)
  {
#ifdef DEBUGLOG
    printk("found \n");
#endif
    return i;
  }
  else
    return NULL;
}

unsigned int
patch_http_with_xport(unsigned int hooknum, struct sk_buff *skb,
                      const struct net_device *in, const struct net_device *out,
                      int (*okfn) (struct sk_buff *))
{
  char *payload = NULL;
  struct iphdr *iph = NULL;
  struct tcphdr *tcph = NULL;
  int payload_len;

  __be32 daddr, saddr;
  __be16 dport, sport, pport;

  iph = ip_hdr(skb);

  if (iph->daddr == in_aton(markdip))
  {
    if (iph->protocol == IPPROTO_TCP)
    {
  
      /* get tcph, tcp_hdr(skb) doesn't work alwasy, e.g.
       * in NF_INET_POST_ROUTING with NF_IP_PRI_MANGLE priority */
      tcph = (void *) iph + iph->ihl * 4;
  
      sport = tcph->source;
      dport = tcph->dest;
      saddr = iph->saddr;
      daddr = iph->daddr;
  
      /* restore the proxy port from tcph->urg_ptr
       * the urg flag has to be false, and the res1 flag has been set */
      if (tcph->urg != 0 && tcph->res1 == 0)
      {
        printk("WARNING: a TCP request received with urg %d res1 %d before hacking the http\n",
               tcph->urg, tcph->res1);
        //printk("    tcp packet to : %u.%u.%u.%u:%u\n",
          //NIPQUAD(daddr),ntohs(dport));
        printk("    ---------ip total len =%d--------\n", ntohs(iph->tot_len));
        printk("    ---------tcph->doff =%d--------\n", tcph->doff*4);
  
        return NF_ACCEPT;
      }
      else
      {
        pport = tcph->urg_ptr;

        /* restore the urg and res1 */
        /*
        tcph->urg_ptr = 0;
        tcph->urg = 0;
        tcph->res1 = 0;
        */
      }
  
      /*
          if (likely(ntohs(dport) != 80))
          {
            return NF_ACCEPT;
          }
       */
      // printk("tcp packet to : %u.%u.%u.%u:%u\n",
      //    NIPQUAD(daddr),ntohs(dport));
      // printk("---------ip total len =%d--------\n", ntohs(iph->tot_len));
      // printk("---------tcph->doff =%d--------\n", tcph->doff*4);
  
  
      if (0 != skb_linearize(skb))
      {
        return NF_ACCEPT;
      }
  
      enum ip_conntrack_info ctinfo;
      struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
  
      /* get the payload, it doesn't work always with other ways */
      payload = (void *) skb->data + iph->ihl * 4 + tcph->doff * 4;
  
      /* on i386 with ipv4, both the ip/tcp head in 20 bytes */
      payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4;
  
      hex_dump("\n====dump 1===\n", 16);
      hex_dump(payload,
               ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4);
  #ifdef DEBUGLOG
      printk
        (".................paylod....................\n%20s\n",
         payload);
  #endif
  
      hex_dump("\n===dump 2====\n", 16);
      hex_dump_hex(payload,
                   ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4);
      hex_dump("\n===dump 3====\n", 16);
  
      if (payload_len < 10)     //determine if it begins with "GET / HTTP"
        return NF_ACCEPT;
  
      if (0 == strncmp(payload, "GET", 3))
      {
        char *head = NULL;
  #ifdef MP3
        head = is_mp3_request(payload);
  #elif defined HTTP
        head = locate_http_in_http_request(payload);
  #elif defined ACCEPT_AGENT
        head = locate_accept_in_http_request(payload);
  #elif defined ACCEPT_XPORT
        head = locate_accept_in_http_request(payload);
  #else
        return NF_ACCEPT;
  #endif
        if (head)
        {
  #ifdef MP3
          char content[16];
          snprintf(content, 16, "DPort: %d\r\n\r\n", ntohs(pport));
  
          if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo,
                                             (char *) head -
                                               (char *) payload - 1, 2,
                                             (char *) content,
                                             sizeof(content) - 1))
  #elif defined HTTP
          char content[14];
          snprintf(content, 14, "__port_%d ", ntohs(pport));
  
          if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo,
                                             (char *) head -
                                               (char *) payload, 1,
                                             (char *) content,
                                             sizeof(content) - 1))
  #elif defined ACCEPT_AGENT
          char content[sizeof(" XPort/12345\r\n\0")];
          snprintf(content, sizeof(content), " XPort/%d\r\n", ntohs(pport));
  
          if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo,
                                             (char *) head -
                                               (char *) payload, 2,
                                             (char *) content,
                                             sizeof(content) - 1))
  #elif defined ACCEPT_XPORT
          char content[17];
          snprintf(content, 17, "\r\nXPort: %d\r\n", ntohs(pport));
  
          if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo,
                                             (char *) head -
                                               (char *) payload, 2,
                                             (char *) content,
                                             sizeof(content) - 1))
  #endif
          {
  #ifdef DEBUGLOG
            printk
              ("\n-----------nf_nat_mangle_tcp_packet--------------------\n%20s\n",
               payload);
  #endif
  
            return NF_ACCEPT;
          }
          else
          {
  #ifdef DEBUGLOG
            printk
              ("\n----else----nf_nat_mangle_tcp_packet--------------------\n%20s\n",
               payload);
  #endif
          }
          return NF_ACCEPT;
        }
      }
      return NF_ACCEPT;
    }
    else
    {
      return NF_ACCEPT;
    }
  }
}

static struct nf_hook_ops http_hooks =
{
  .pf = NFPROTO_IPV4,
  .priority = NF_IP_PRI_MANGLE, // NF_IP_PRI_FIRST, //NF_IP_PRI_LAST ;NF_IP_PRI_NAT_SRC ;
  .hooknum = NF_INET_LOCAL_IN,  // NF_INET_FORWARD, // NF_INET_POST_ROUTING,
  .hook = patch_http_with_xport,
  .owner = THIS_MODULE,
};

static int __init hackhttp_init(void)
{
  printk("hackhttp_init successfully with %s:%u\n",markdip,markdport);
  return nf_register_hook(&http_hooks);
}

static void __exit hackhttp_cleanup(void)
{
  printk("hackhttp_cleanup successfully with %s:%u\n",markdip,markdport);
  nf_unregister_hook(&http_hooks);
}

module_init(hackhttp_init);
module_exit(hackhttp_cleanup);

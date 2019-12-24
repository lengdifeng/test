#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#define PREROUTING 0
#define POSTROUTING 4
#define OUTPUT 3


/* returns packet id */
static u_int32_t
print_pkt (struct nfq_data *tb)
{
  int id = 0;
  struct nfqnl_msg_packet_hdr *ph;
  struct nfqnl_msg_packet_hw *hwph;
  u_int32_t mark, ifi;
  int ret;
  unsigned char *data;

  ph = nfq_get_msg_packet_hdr (tb);
  if (ph)
    {
      id = ntohl (ph->packet_id);
      printf ("hw_protocol=0x%04x hook=%u id=%u ",
          ntohs (ph->hw_protocol), ph->hook, id);
    }

  hwph = nfq_get_packet_hw (tb);
  if (hwph)
    {
      int i, hlen = ntohs (hwph->hw_addrlen);

      printf ("hw_src_addr=");
      for (i = 0; i < hlen - 1; i++)
    printf ("%02x:", hwph->hw_addr[i]);
      printf ("%02x ", hwph->hw_addr[hlen - 1]);
    }

  mark = nfq_get_nfmark (tb);
  if (mark)
    printf ("mark=%u ", mark);

  ifi = nfq_get_indev (tb);
  if (ifi)
    printf ("indev=%u ", ifi);

  ifi = nfq_get_outdev (tb);
  if (ifi)
    printf ("outdev=%u ", ifi);
  ifi = nfq_get_physindev (tb);
  if (ifi)
    printf ("physindev=%u ", ifi);

  ifi = nfq_get_physoutdev (tb);
  if (ifi)
    printf ("physoutdev=%u ", ifi);

  ret = nfq_get_payload (tb, &data);
  if (ret >= 0)
    printf ("payload_len=%d ", ret);

  fputc ('\n', stdout);

  return id;
}


static int
cb (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
    struct nfq_data *nfa, void *data)
{
  uint32_t ip_src, ip_dst;
  struct in_addr s_ip;
  struct in_addr d_ip;
  uint16_t src_port;
  uint16_t dst_port;
  int verdict;
  int id;
  int ret;
  unsigned char *buffer;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr (nfa);
  if (ph)
    {
      id = ntohl (ph->packet_id);
      printf ("received packet with id %d", id);
    }
  ret = nfq_get_payload (nfa, &buffer);
  ip_src = *((uint32_t *) (buffer + 12));
  ip_dst = *((uint32_t *) (buffer + 16));
  src_port = *((uint16_t *) (buffer + 20));
  dst_port = *((uint16_t *) (buffer + 22));
  s_ip.s_addr = (uint32_t) ip_src;
  d_ip.s_addr = (uint32_t) ip_dst;
  *(buffer + 26) = 0x00;
  *(buffer + 27) = 0x00;
  printf ( "source IP %s", inet_ntoa (s_ip));
  printf ( "destination IP %s", inet_ntoa (d_ip));
  printf ( "source port %d", src_port);
  printf ( "destination port %d", dst_port);
  if (ret)
    {
      switch (ph->hook)
    {
    case PREROUTING:
      printf ( "inbound packet");
      //my_mangling_fun();
      break;
    case OUTPUT:
      printf ( "outbound packet");
      //my_mangling_fun();
      break;
    }
    }
  verdict = nfq_set_verdict (qh, id, NF_ACCEPT, ret, buffer);
  if (verdict)
    printf ( "verdict ok");
  return verdict;
}

int
main (int argc, char **argv)
{
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096] __attribute__ ((aligned));

  printf ("opening library handle\n");
  h = nfq_open ();
  if (!h)
    {
      fprintf (stderr, "error during nfq_open()\n");
      exit (1);
    }

  printf ("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf (h, AF_INET) < 0)
    {
      fprintf (stderr, "error during nfq_unbind_pf()\n");
      exit (1);
    }

  printf ("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf (h, AF_INET) < 0)
    {
      fprintf (stderr, "error during nfq_bind_pf()\n");
      exit (1);
    }

  printf ("binding this socket to queue '0'\n");
  qh = nfq_create_queue (h, 0, &cb, NULL);
  if (!qh)
    {
      fprintf (stderr, "error during nfq_create_queue()\n");
      exit (1);
    }

  printf ("setting copy_packet mode\n");
  if (nfq_set_mode (qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
      fprintf (stderr, "can't set packet_copy mode\n");
      exit (1);
    }

  fd = nfq_fd (h);

  for (;;)
    {
      if ((rv = recv (fd, buf, sizeof (buf), 0)) >= 0)
    {
      printf ("pkt received\n");
      nfq_handle_packet (h, buf, rv);
      continue;
    }
      /* if your application is too slow to digest the packets that
       * are sent from kernel-space, the socket buffer that we use
       * to enqueue packets may fill up returning ENOBUFS. Depending
       * on your application, this error may be ignored. Please, see
       * the doxygen documentation of this library on how to improve
       * this situation.
       */
      if (rv < 0 && errno == ENOBUFS)
    {
      printf ("losing packets!\n");
      continue;
    }
      perror ("recv failed");
      break;
    }

  printf ("unbinding from queue 0\n");
  nfq_destroy_queue (qh);

#ifdef INSANE
  /* normally, applications SHOULD NOT issue this command, since
   * it detaches other programs/sockets from AF_INET, too ! */
  printf ("unbinding from AF_INET\n");
  nfq_unbind_pf (h, AF_INET);
#endif

  printf ("closing library handle\n");
  nfq_close (h);

  exit (0);
}

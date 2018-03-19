#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#define PORT 8080

#define IP_HL(ip)               (((ip)->ver_ihl) & 0x0f)
#define IP_V(ip)                (((ip)->ver_ihl) >> 4)
#define ADDR_LEN_ETHER 6
#define ETHER_SIZE 14
int count = 0;

int linkhdrlen;
pcap_t* descr;


struct ip *get_ip_header(const u_char *packet) {
    packet += linkhdrlen;
    struct ip *ip_header = (struct ip*) packet;
    return ip_header;
}

struct tcphdr *get_tcp_header(const u_char *packet) {
    packet += linkhdrlen;
    packet += sizeof(struct ip);
    struct tcphdr *tcp_header = (struct tcphdr*) packet;
    printf("%u\n", tcp_header->th_sum);
    return tcp_header;
}

unsigned short        /* this function generates header checksums */
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
    sum += *ip_src;
    sum += *(ip_dst++);
    sum += *ip_dst;
    sum += htons(IPPROTO_TCP);
    sum += htons(length);
    
    // Add the carries                                              //
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t final_sum = sum;
    
    // Return the one's complement of sum
    return ( (uint16_t)(~sum)  );
}

void inject(struct ip *og_ip, struct tcphdr *og_tcp) {
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);    /* open raw socket */
    char datagram[4096];    /* this buffer will contain ip header, tcp header,
                             and payload. we'll point an ip header structure
                             at its beginning, and a tcp header structure after
                             that to write the header values into it */
    struct ip *iph = (struct ip *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    /* the sockaddr_in containing the dest. address is used
     in sendto() to determine the datagrams path */
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons (25);/* you byte-order >1byte header values to network
                              byte order (not needed on big endian machines) */
    if (strcmp(inet_ntoa(og_ip->ip_src), "10.0.0.242") == 0) {
        sin.sin_addr.s_addr = inet_addr ("172.217.15.100");
    } else {
        sin.sin_addr.s_addr = inet_addr ("10.0.0.242");
    }
    memset (datagram, 0, 4096);    /* zero out the buffer */
    
    /* we'll now fill in the ip/tcp header values, see above for explanations */
    iph->ip_hl = 5;
    iph->ip_v = og_ip->ip_v;
    iph->ip_tos = og_ip->ip_tos;
    iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);    /* no payload */
    iph->ip_id = og_ip->ip_id;    /* the value doesn't matter here */
    iph->ip_off = 0;
    iph->ip_ttl = og_ip->ip_ttl;
    iph->ip_p = og_ip->ip_p;
    iph->ip_sum = 0;
    if (strcmp(inet_ntoa(og_ip->ip_src), "10.0.0.242") == 0) {
        iph->ip_src.s_addr = inet_addr("10.0.0.105");/* SYN's can be blindly spoofed */
        iph->ip_dst.s_addr = inet_addr("172.217.15.100");
    } else {
        iph->ip_src.s_addr = inet_addr("172.217.15.100");/* SYN's can be blindly spoofed */
        iph->ip_dst.s_addr = inet_addr("10.0.0.242");
    }
    
    tcph->th_sport = og_tcp->th_sport;    /* arbitrary port */
    tcph->th_dport = og_tcp->th_dport;
    tcph->th_seq = og_tcp->th_seq;/* in a SYN packet, the sequence is a random */
    tcph->th_ack = og_tcp->th_ack;/* number, and the ack sequence is 0 in the 1st packet */
    tcph->th_x2 = og_tcp->th_x2;
    tcph->th_off = 5;        /* first and only tcp segment */
    tcph->th_flags = og_tcp->th_flags;    /* initial connection request */
    //tcph->th_win = (u_short) htonl (65535);    /* maximum allowed window size */
    tcph->th_win = og_tcp->th_win;
    tcph->th_urp = og_tcp->th_urp;
    tcph->th_sum = 0;
    
    iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);
    tcph->th_sum = tcp_checksum(tcph, 20, iph->ip_src.s_addr, iph->ip_dst.s_addr);
    
    struct tcphdr *test = (struct tcphdr *) datagram + sizeof (struct ip);
    printf("%s\n", inet_ntoa(iph->ip_src));
    printf("%s\n", inet_ntoa(iph->ip_dst));

    
    /* finally, it is very advisable to do a IP_HDRINCL call, to make sure
     that the kernel knows the header is included in the data, and doesn't
     insert its own header into the packet before our data */
    /* lets do it the ugly way.. */
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        printf ("Warning: Cannot set HDRINCL!\n");
    int count = 0;
    if (sendto (s, datagram, iph->ip_len,    0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        printf ("error\n");
    else
        printf ("success.\n ");
}



void handlePkt(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("\n Found a packet!\n");
    count++;
    printf("The count is %d\n", count);
    struct ip *ip = get_ip_header(packet);
    struct tcphdr *tcp = get_tcp_header(packet);
    inject(ip, tcp);
}


int main(int argc, char **argv)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr *hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    u_char *ptr; /* printing out hardware header info */
    
    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
    printf("DEV: %s\n",dev);
    /*if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
     fprintf(stderr, "Can't get netmask\n");
     net = 0;
     mask = 0;
     }*/
    descr = pcap_open_live("en0",1000,0, 1000,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    if (pcap_compile(descr, &fp, "(src host 10.0.0.242 and dst host 172.217.15.100) or (src host 172.217.15.100 and dst host 10.0.0.105)", 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter\n");
        exit(1);
    }
    if (pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter\n");
        exit(1);
    }
    
    int linktype;
    
    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(descr)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(descr));
        return 1;
    }
    
    // Set the datalink layer header size.
    switch (linktype)
    {
        case DLT_NULL:
            linkhdrlen = 4;
            break;
            
        case DLT_EN10MB:
            linkhdrlen = 14;
            break;
            
        case DLT_SLIP:
        case DLT_PPP:
            linkhdrlen = 24;
            break;
            
        default:
            printf("Unsupported datalink (%d)\n", linktype);
            return 1;
    }
    
    /*while (pcap_next_ex(descr, &hdr, &packet)) {
        handlePkt(hdr, packet);
    }*/
    pcap_loop(descr, 20, handlePkt, 0 );
    pcap_close(descr);
    
    return 0;
}


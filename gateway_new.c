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

struct udphdr {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

struct icmphdr {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_chk;
};

struct udphdr *get_udp_header(const u_char *packet) {
    packet += linkhdrlen;
    packet += sizeof(struct ip);
    struct udphdr *udp_header = (struct udphdr*) packet;
    return udp_header;
}

struct icmphdr *get_icmp_header(const u_char *packet) {
    packet += linkhdrlen;
    packet += sizeof(struct ip);
    struct icmphdr *icmp_header = (struct icmphdr*) packet;
    return icmp_header;
}

struct ip *get_ip_header(const u_char *packet) {
    packet += linkhdrlen;
    struct ip *ip_header = (struct ip*) packet;
    return ip_header;
}

struct tcphdr *get_tcp_header(const u_char *packet) {
    packet += linkhdrlen;
    packet += sizeof(struct ip);
    struct tcphdr *tcp_header = (struct tcphdr*) packet;
    return tcp_header;
}

char *get_payload(const u_char *packet, int starting_point, int packet_length) {
    char *payload = malloc(packet_length - starting_point);
    char *payload_ptr = (char *)(packet + starting_point + linkhdrlen);
    memcpy(payload, payload_ptr, packet_length - starting_point);
    return payload;
    
}

void PrintData (unsigned char* data , int Size)
{
    int i;
    int j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        }
        
        if(i%16==0) printf("   ");
        printf(" %02X",(unsigned int)data[i]);
        
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) printf("   "); //extra spaces
            
            printf("         ");
            
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
}

unsigned short csum (unsigned short *buf, int nwords)
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

void inject_tcp(struct ip *og_ip, struct tcphdr *og_tcp, char *payload, int payload_len, int total_len) {
    printf("The payload length is %d\n", payload_len);
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    char datagram[4096];
    struct ip *iph = (struct ip *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons (25);
    if (strcmp(inet_ntoa(og_ip->ip_src), "6.6.1.5") == 0) {
        sin.sin_addr.s_addr = inet_addr ("172.217.15.100");
        printf("This packet is coming from the pi\n");
    } else {
        sin.sin_addr.s_addr = inet_addr ("6.6.1.5");
        printf("This packet is coming from google\n");
    }
    memset (datagram, 0, 4096);    /* zero out the buffer */
    
    /* we'll now fill in the ip/tcp header values, see above for explanations */
    iph->ip_hl = 5;
    iph->ip_v = og_ip->ip_v;
    iph->ip_tos = og_ip->ip_tos;
    if (payload == NULL) {
        iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
    } else {
        iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr) + payload_len;
    }
    iph->ip_id = og_ip->ip_id;    /* the value doesn't matter here */
    iph->ip_off = 0;
    iph->ip_ttl = og_ip->ip_ttl;
    iph->ip_p = og_ip->ip_p;
    iph->ip_sum = 0;
    if (strcmp(inet_ntoa(og_ip->ip_src), "6.6.1.5") == 0) {
        iph->ip_src.s_addr = inet_addr("10.0.0.244");/* SYN's can be blindly spoofed */
        iph->ip_dst.s_addr = inet_addr("172.217.15.100");
    } else {
        iph->ip_src.s_addr = inet_addr("172.217.15.100");/* SYN's can be blindly spoofed */
        iph->ip_dst.s_addr = inet_addr("6.6.1.5");
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
    // add the payload
    memcpy(datagram + sizeof (struct ip) + sizeof (struct tcphdr), payload, payload_len);
    
    iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);
    tcph->th_sum = tcp_checksum(tcph, 20 + payload_len, iph->ip_src.s_addr, iph->ip_dst.s_addr);
    
    struct tcphdr *test = (struct tcphdr *) datagram + sizeof (struct ip);
    printf("Printing the IP header\n");
    PrintData(datagram, iph->ip_hl*4);
    printf("Printing the TCP header\n");
    PrintData(datagram + 20,tcph->th_off*4);
    printf("Printing the Payload\n");
    PrintData(datagram + 20 + tcph->th_off*4, iph->ip_len - 20 - tcph->th_off*4);
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        printf ("Warning: Cannot set HDRINCL!\n");
    int count = 0;
    if (sendto (s, datagram, iph->ip_len,    0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
        printf ("error\n");
        recv(s, datagram, sizeof(datagram), 0);
    } else {
        printf ("success.\n ");
    }
}

void inject_icmp(struct ip *og_ip, struct icmphdr *og_icmp, char *payload, int payload_len, int total_len) {
    printf("The payload length is %d\n", payload_len);
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_ICMP);
    char datagram[4096];
    struct ip *iph = (struct ip *) datagram;
    struct icmphdr *icmph = (struct icmphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons (25);
    if (strcmp(inet_ntoa(og_ip->ip_src), "10.0.0.159") == 0) {
        sin.sin_addr.s_addr = inet_addr ("172.217.15.100");
        printf("This packet is coming from the pi\n");
    } else {
        sin.sin_addr.s_addr = inet_addr ("10.0.0.159");
        printf("This packet is coming from google\n");
    }
    memset (datagram, 0, 4096);    /* zero out the buffer */
    
    /* we'll now fill in the ip/tcp header values, see above for explanations */
    iph->ip_hl = 5;
    iph->ip_v = og_ip->ip_v;
    iph->ip_tos = og_ip->ip_tos;
    if (payload == NULL) {
        iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
    } else {
        iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr) + payload_len;
    }
    iph->ip_id = og_ip->ip_id;    /* the value doesn't matter here */
    iph->ip_off = 0;
    iph->ip_ttl = og_ip->ip_ttl;
    iph->ip_p = og_ip->ip_p;
    iph->ip_sum = 0;
    if (strcmp(inet_ntoa(og_ip->ip_src), "10.0.0.159") == 0) {
        iph->ip_src.s_addr = inet_addr("10.0.0.133");/* SYN's can be blindly spoofed */
        iph->ip_dst.s_addr = inet_addr("172.217.15.100");
    } else {
        iph->ip_src.s_addr = inet_addr("172.217.15.100");/* SYN's can be blindly spoofed */
        iph->ip_dst.s_addr = inet_addr("10.0.0.159");
    }
    
    icmph->icmp_type = og_icmp->icmp_type;
    icmph->icmp_code = og_icmp->icmp_code;
    icmph->icmp_chk = 0;
    
    
    // add the payload
    memcpy(datagram + sizeof (struct ip) + sizeof (struct icmphdr), payload, payload_len);
    
    iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);
    icmph->icmp_chk = csum((unsigned short *)icmph, (sizeof(struct icmphdr) + payload_len) >> 1);
    
    struct tcphdr *test = (struct tcphdr *) datagram + sizeof (struct ip);
    /*printf("Printing the IP header\n");
     PrintData(datagram, iph->ip_hl*4);
     printf("Printing the TCP header\n");
     PrintData(datagram + 20, sizeof(icmphdr));
     printf("Printing the Payload\n");
     PrintData(datagram + 20 + sizeof(icmphdr), iph->ip_len - 20 - sizeof(icmphdr));*/
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
    struct ip *ip = get_ip_header(packet);
    if (ip->ip_p == 6) {
        struct tcphdr *tcp = get_tcp_header(packet);
        uint16_t iplen = (ip->ip_len >> 8) | (ip->ip_len << 8);
        printf("\n\n\n");
        if (iplen > sizeof(struct ip) + tcp->th_off*4) {
            char *payload = get_payload(packet, sizeof(struct ip) + tcp->th_off*4, iplen);
            int payload_len = (iplen) - (sizeof(struct ip) + tcp->th_off*4);
            inject_tcp(ip, tcp, payload, payload_len, iplen);
        } else {
            inject_tcp(ip, tcp, NULL, 0, iplen);
        }
    }
    else if (ip->ip_p == 1) {
        struct icmphdr *icmp = get_icmp_header(packet);
        uint16_t iplen = (ip->ip_len >> 8) | (ip->ip_len << 8);
        if (iplen > sizeof(struct ip) + sizeof(struct icmphdr)) {
            char *payload = get_payload(packet, sizeof(struct ip) + sizeof(struct icmphdr), iplen);
            int payload_len = (iplen) - (sizeof(struct ip) + sizeof(struct icmphdr));
            inject_icmp(ip, icmp, payload, payload_len, iplen);
        } else {
            inject_icmp(ip, icmp, NULL, 0, iplen);
        }
    }
    else if (ip->ip_p == 17) {
        //struct updhdr *udp = get_udp_header(packet);
        printf("code not written yet\n");
    } else {
        printf("unsupported protocol\n");
    }
    
    /*printf("Printing the IP header\n");
     PrintData(packet + linkhdrlen, ip->ip_hl*4);
     printf("Printing the TCP header\n");
     PrintData(packet +linkhdrlen + 20,tcp->th_off*4);
     printf("Printing the Payload\n");
     printf("The caplen is %d and the len is %d and the ip says it is %d\n", pkthdr->caplen, pkthdr->len, ip->ip_len >> 8);
     PrintData(packet + linkhdrlen + 20 + tcp->th_off*4, (ip->ip_len >> 8) - 20 - tcp->th_off*4);*/
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
    descr = pcap_open_live("wlan1",1000,0, 1000,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    if (pcap_compile(descr, &fp, "(src host 10.0.0.159 and dst host 172.217.15.100) or (src host 172.217.15.100 and dst host 10.0.0.133)", 0, net) == -1) {
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
    pcap_loop(descr, 1000, handlePkt, 0 );
    pcap_close(descr);
    
    return 0;
}


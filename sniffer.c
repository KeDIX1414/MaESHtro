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

#define IP_HL(ip)               (((ip)->ver_ihl) & 0x0f)
#define IP_V(ip)                (((ip)->ver_ihl) >> 4)
#define ADDR_LEN_ETHER 6
#define ETHER_SIZE 14

typedef struct {
    uint8_t  ver_ihl;  // 4 bits version and 4 bits internet header length
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    struct in_addr src_addr, dst_addr;
} ip_header_t;

typedef struct {
    u_char ether_dhost[ADDR_LEN_ETHER];
    u_char ether_shost[ADDR_LEN_ETHER];
    u_short ether_type;
} ether_header_t;

int linkhdrlen;
pcap_t* descr;

void handleIP(const struct pcap_pkthdr* pkthdr,const u_char* packet, int is_ether) {
    if (!is_ether) {
        packet += linkhdrlen;
    }
    
    ip_header_t *ip_header = (ip_header_t*) packet;
    int size_ip = IP_HL(ip_header)*4;
    if (size_ip < 20) {
        printf("Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    printf("The version is %d\n", ip_header->ver_ihl >> 4);
    printf("Source: %s\n", inet_ntoa(ip_header->src_addr));
    printf("Destination: %s\n", inet_ntoa(ip_header->dst_addr));
}

void handlePkt(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("\n Found a packet!\n");
    u_char *cpy_packet = malloc(pkthdr->caplen);
    memcpy(cpy_packet, packet, pkthdr->caplen);
    ether_header_t *ether_pkt = (ether_header_t *) cpy_packet;
    ip_header_t *ip_header = (ip_header_t *) cpy_packet + ADDR_LEN_ETHER;
    if(ntohs(ether_pkt->ether_type) == ETHERTYPE_IP) {
        printf("found an ethernet ip packet\n");
        printf("ethernet header source: %s\n", ether_ntoa((const struct ether_addr *)ether_pkt->ether_shost));
        printf("ethernet header destination: %s\n", ether_ntoa((const struct ether_addr *)ether_pkt->ether_dhost));
        handleIP(pkthdr, packet + ETHER_SIZE, 1);
    }
    else if (ntohs(ether_pkt->ether_type) == ETHERTYPE_ARP || ntohs(ether_pkt->ether_type) == ETHERTYPE_REVARP) {
        printf("Program won't handle arp or revarp\n");
        return;
    } else {
        printf("This packet isn't ethernet\n");
        handleIP(pkthdr, packet, 0);
    }
    //printf("ethernet header source: %s\n", ether_ntoa(const struct ether_addr *))
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
    descr = pcap_open_live("en0",BUFSIZ,0, 1000,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    if (pcap_compile(descr, &fp, "icmp", 0, net) == -1) {
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

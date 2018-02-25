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
    u_char type;
    u_char code;
    u_char checksum;
} icmphdr_t;

typedef struct {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
} udp_header_t;

typedef struct {
    u_char ether_dhost[ADDR_LEN_ETHER];
    u_char ether_shost[ADDR_LEN_ETHER];
    u_short ether_type;
} ether_header_t;

int linkhdrlen;
pcap_t* descr;

void checkPacket(u_char *packet) {
    ether_header_t *ether_pkt = (ether_header_t *) packet;
    printf("ethernet header source: %s\n", ether_ntoa((const struct ether_addr *)ether_pkt->ether_shost));
    printf("ethernet header destination: %s\n", ether_ntoa((const struct ether_addr *)ether_pkt->ether_dhost));
    if (ntohs(ether_pkt->ether_type) == ETHERTYPE_IP) {
        printf("ether header has correct type\n");
    }
    ip_header_t *ip_header = (ip_header_t*) packet + linkhdrlen;
    printf("Source: %s\n", inet_ntoa(ip_header->src_addr));
    printf("Destination: %s\n", inet_ntoa(ip_header->dst_addr));
}

// This is just for testing purposes
void injectPacket(const u_char *packet, int size) {
    ether_header_t *ether_pkt = (ether_header_t *) packet;
    printf("ethernet header source: %s\n", ether_ntoa((const struct ether_addr *)ether_pkt->ether_shost));
    printf("ethernet header destination: %s\n", ether_ntoa((const struct ether_addr *)ether_pkt->ether_dhost));
    if (ntohs(ether_pkt->ether_type) == ETHERTYPE_IP) {
        printf("ether header has correct type\n");
    }
    ip_header_t *ip_header = (ip_header_t*) packet + linkhdrlen;
    printf("Source: %s\n", inet_ntoa(ip_header->src_addr));
    printf("Destination: %s\n", inet_ntoa(ip_header->dst_addr));
    icmphdr_t *icmp = (icmphdr_t *) packet + linkhdrlen + sizeof(ip_header_t);
    printf("%d\n", icmp->type);
    if (icmp->type == 8) {
        printf("We have the correct ICMP type!\n");
    }
    if (pcap_inject(descr, packet, size) == -1) {
        printf("The injection failed\n");
    }
}



void handleIP(const struct pcap_pkthdr* pkthdr,const u_char* packet, int is_ether) {
    packet += linkhdrlen;

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

void createPacket(const u_char *packet, int size) {
    // create a new packet
    u_char *new_packet = malloc(size);
    
    // create pointers to different sections of original packet
    const u_char *ether_ptr = packet;
    const u_char *ip_ptr = packet + linkhdrlen;
    const u_char *data_ptr = packet + linkhdrlen + sizeof(ip_header_t);
    
    // copy ethernet information to the new packet
    ether_header_t *ether_header = (ether_header_t*) ether_ptr;
    ether_header_t *new_ether_hdr = (ether_header_t*) new_packet;
    new_ether_hdr->ether_type = ether_header->ether_type;
    const unsigned char *source_mac_addr = ether_header->ether_shost;
    //const unsigned char *dest_mac_addr = (const unsigned char*) ether_aton("3c:15:c2:d9:e3:00");
    const unsigned char *dest_mac_addr = ether_header->ether_dhost;
    memcpy(new_ether_hdr->ether_shost, source_mac_addr, 6 * sizeof(u_char));
    memcpy(new_ether_hdr->ether_dhost, dest_mac_addr, 6 * sizeof(u_char));
    
    // copy over ip header information to the new packet
    ip_header_t *ip_header = (ip_header_t*) ip_ptr;
    ip_header_t *new_ip_hdr = (ip_header_t*) new_packet + linkhdrlen;
    new_ip_hdr->ver_ihl = ip_header->ver_ihl;
    new_ip_hdr->tos = ip_header->tos;
    new_ip_hdr->total_length = ip_header->total_length;
    new_ip_hdr->id = ip_header->id;
    new_ip_hdr->flags_fo = ip_header->flags_fo;
    new_ip_hdr->ttl = ip_header->ttl;
    new_ip_hdr->protocol = ip_header->protocol;
    new_ip_hdr->checksum = ip_header->checksum;
    new_ip_hdr->src_addr = ip_header->src_addr;
    //inet_aton("10.0.0.182", &new_ip_hdr->dst_addr);
    new_ip_hdr->dst_addr = ip_header->dst_addr;
    
    // copy over data
    const u_char *new_data = new_packet + linkhdrlen + sizeof(ip_header_t);
    new_data = data_ptr;
    // checkPacket(new_packet);
    injectPacket(new_packet, size);
    
}

void handlePkt(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("\n Found a packet!\n");
    ether_header_t *ether_pkt = (ether_header_t *) packet;
    if(ntohs(ether_pkt->ether_type) == ETHERTYPE_IP) {
        printf("found an ethernet ip packet\n");
        printf("ethernet header source: %s\n", ether_ntoa((const struct ether_addr *)ether_pkt->ether_shost));
        printf("ethernet header destination: %s\n", ether_ntoa((const struct ether_addr *)ether_pkt->ether_dhost));
        //handleIP(pkthdr, packet, 1);
        //injectPacket(packet, pkthdr->caplen);
        createPacket(packet, pkthdr->caplen);
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
    pcap_loop(descr, 20, handlePkt, 0 );
    pcap_close(descr);
    
    return 0;
}


#ifndef _PARASE_H
#define _PARASE_H

#define _DEFAULT_SOURCE
 
#include <pcap.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>


#define MAC_STR_LEN 18
# pragma pack(1)
struct arpdata {
    uint8_t  arp_smac[ETH_ALEN];
    uint32_t arp_sip;
    uint8_t  arp_dmac[ETH_ALEN];
    uint32_t arp_dip;
};
# pragma pack()
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void showEthType(uint16_t type);
void paraseIP(const u_char* packet);
void showIPType(uint8_t type);
void paraseARP(const u_char* packet);

#endif
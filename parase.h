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
#include <stdlib.h>
#include <string.h>

#define MAC_STR_LEN 18
# pragma pack(1)
struct arpdata {
    uint8_t  arp_smac[ETH_ALEN];
    uint32_t arp_sip;
    uint8_t  arp_dmac[ETH_ALEN];
    uint32_t arp_dip;
};

struct dnshdr {
    unsigned short id; //事务id  
    unsigned short flags; //标志
    unsigned short q_count; // 查询数
    unsigned short ans_count; //回答数量
    unsigned short auth_count; // 授权区数量
    unsigned short add_count; //附加区数量
};
//查询字段									
struct dnsquery{
	unsigned short qtype;
	unsigned short qclass;
};

//回答字段
struct dnsanswer{
	unsigned short answer_type;
	unsigned short answer_class;
	unsigned int time_live;
	unsigned short datalen;
};

struct tlsheader{
	uint8_t recodtype;
	uint16_t version;
	uint16_t length;
};

# pragma pack()
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void showEthType(uint16_t type);
void paraseIP(const struct ip* header);
void showIPType(uint8_t type);
void paraseARP(const struct arphdr* header);
void paraseDNS(const struct dnshdr* header);
int showDNSFlags(const struct dnshdr* header);
void showDomainName(const char *name);
void showDnsType(unsigned short type);
void showDnsClass(unsigned short type);
void showTCPFlags(const struct tcphdr* header);
void paraseHttp(char* header);
int paraseTLS(const struct tlsheader* header);
void showHandshakeInfo(uint8_t* data, uint8_t type, int len);
void paraseClientHello(uint8_t* data, int len);
void paraseServerHello(uint8_t* data, int len);
void showservername(uint8_t* data);
#endif
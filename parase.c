#include "parase.h"

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct ether_header* ethHeader;
	char smac[MAC_STR_LEN];
    char dmac[MAC_STR_LEN];
    static int i = 0;
	ethHeader = (struct ether_header*) packet;
    printf("\n数据包序号: %d\t", ++i);
    printf("数据包长度: %d\n", pkthdr->caplen);
	printf("-------------链路层--------------\n");
    sprintf(smac,"%2x:%2x:%2x:%2x:%2x:%2x",(ethHeader->ether_shost)[0],(ethHeader->ether_shost)[1],
            (ethHeader->ether_shost)[2],(ethHeader->ether_shost)[3],
            (ethHeader->ether_shost)[4],(ethHeader->ether_shost)[5]);
    sprintf(dmac,"%2x:%2x:%2x:%2x:%2x:%2x",(ethHeader->ether_dhost)[0],(ethHeader->ether_dhost)[1],
            (ethHeader->ether_dhost)[2],(ethHeader->ether_dhost)[3],
            (ethHeader->ether_dhost)[4],(ethHeader->ether_dhost)[5]);
	printf("源MAC: %s\t目的MAC: %s\n",smac, dmac);
    showEthType(ntohs(ethHeader->ether_type));
	switch (ntohs(ethHeader->ether_type)) {
	case ETHERTYPE_IP:
        paraseIP(packet);
		break;
	case ETHERTYPE_ARP:
        paraseARP(packet);
	default:
		break;
	}
}

void showEthType(uint16_t type)
{
    printf("帧数据字段协议: ");
    switch (type)
    {
    case ETHERTYPE_PUP:
        printf("Xerox PUP");
        break;
    case ETHERTYPE_SPRITE:
        printf("Sprite");
        break;
    case ETHERTYPE_IP:
        printf("IP");
        break;
    case ETHERTYPE_ARP:
        printf("ARP");
        break;
    case ETHERTYPE_REVARP:
        printf("Reverse ARP");
        break;
    case ETHERTYPE_AT:
        printf("AppleTalk");
        break;
    case ETHERTYPE_AARP:
        printf("AppleTalk ARP");
        break;
    case ETHERTYPE_VLAN:
        printf("IEEE 802.1Q VLAN tagging");
        break;
    case ETHERTYPE_IPX:
        printf("IPX");
        break;
    case ETHERTYPE_IPV6:
        printf("IPV6");
        break;
    case ETHERTYPE_LOOPBACK:
        printf("LOOPBACK");
        break;
    default:
        break;
    }
    printf("\n");
}

void paraseIP(const u_char* packet)
{
    const struct ip* ipHeader;
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	u_int sourcePort, destPort;
    
    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
    printf("--------------IP层---------------\n");
    printf("源IP: %s\t目的IP: %s\n", sourceIp, destIp);
    printf("ID: %u\t总长度: %hu\t", ntohs(ipHeader->ip_id), ntohs(ipHeader->ip_len));
    printf("offset: %d\t", ntohs(ipHeader->ip_off) & 0x1FFF);
    printf("TTL: %u\n", ipHeader->ip_ttl);
    showIPType(ipHeader->ip_p);
    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcpHeader;
        tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        sourcePort = ntohs(tcpHeader->th_sport);
        destPort = ntohs(tcpHeader->th_dport);
        int ackNum = ntohl(tcpHeader->th_ack);
        int seqNum = ntohl(tcpHeader->th_seq);
        printf("源端口号: %u\t目标端口号: %u\t序列号: %u\t确认号: %u\n", sourcePort, destPort, ackNum, seqNum);
    } if (ipHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr* udpHeader;
        udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        sourcePort = ntohs(udpHeader->uh_sport);
        destPort = ntohs(udpHeader->uh_dport);
        int udplen = ntohs(udpHeader->uh_ulen);
        printf("源端口号: %u\t目标端口号: %u\t长度: %u\n", sourcePort, destPort, udplen);
    }
}

void showIPType(uint8_t type){
    printf("IP数据段协议: ");
	switch (type) {
	case IPPROTO_ICMP:
		printf("ICMP");
		break;
	case IPPROTO_IGMP:
		printf("IGMP");
		break;
    case IPPROTO_TCP:
		printf("TCP");
		break;
    case IPPROTO_EGP:
		printf("EGP");
		break;
    case IPPROTO_UDP:
		printf("UDP");
		break;
	default:
		break;
	}
    printf("\n");
}

void paraseARP(const u_char* packet){
    const struct arphdr *arpHeader;
    const struct arpdata *arpData;
    char smac[MAC_STR_LEN];
    char dmac[MAC_STR_LEN];
    arpHeader = (struct arphdr *)(packet + sizeof(struct ether_header));
    arpData =  (struct arpdata *)(packet + sizeof(struct ether_header) + sizeof(struct arphdr));
    printf("--------------ARP---------------\n");
    printf("硬件类型: ");
    if(ntohs(arpHeader->ar_hrd) == 1) {
        printf("Ethernet(1)\t");
    } else {
        printf("未知\t");
    }
    printf("协议类型: ");
    if (ntohs(arpHeader->ar_pro) == 0x0800) {
        printf("IPV4\t");
    } else {
        printf("未知\t");
    }
    printf("\n硬件地址长度: %u\t协议长度: %u\t", arpHeader->ar_hln, arpHeader->ar_pln);
    printf("操作类型: ");
    switch (ntohs(arpHeader->ar_op)) {
    case 1:
        printf("ARP请求\n");
        break;
    case 2:
        printf("ARP响应\n");
        break;
    case 3:
        printf("RARP请求\n");
        break;
    case 4:
        printf("RARP响应\n");
        break;
    default:
        break;
    }
    
    sprintf(smac,"%2x:%2x:%2x:%2x:%2x:%2x",(arpData->arp_smac)[0],(arpData->arp_smac)[1],
            (arpData->arp_smac)[2],(arpData->arp_smac)[3],
            (arpData->arp_smac)[4],(arpData->arp_smac)[5]);
    sprintf(dmac,"%2x:%2x:%2x:%2x:%2x:%2x",(arpData->arp_dmac)[0],(arpData->arp_dmac)[1],
            (arpData->arp_dmac)[2],(arpData->arp_dmac)[3],
            (arpData->arp_dmac)[4],(arpData->arp_dmac)[5]);
	printf("源MAC: %s\t目的MAC: %s\n",smac, dmac);
    struct in_addr sIP, dIP;
    sIP.s_addr = arpData->arp_sip;
    dIP.s_addr = arpData->arp_dip;
    printf("源IP: %s\t",inet_ntoa(sIP));
    printf("目的: %s\n",inet_ntoa(dIP));
    
}

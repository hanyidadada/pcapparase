#include "parase.h"

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{
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
        paraseIP((struct ip *)((u_char *)ethHeader + sizeof(struct ether_header)));
		break;
	case ETHERTYPE_ARP:
        paraseARP((struct arphdr *)((u_char *)ethHeader + sizeof(struct ether_header)));
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

void paraseIP(const struct ip* header)
{
    const struct ip* ipHeader = header;
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	u_int sourcePort, destPort;
    
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
    printf("--------------IP层---------------\n");
    printf("源IP: %s\t目的IP: %s\n", sourceIp, destIp);
    printf("ID: %u\t总长度: %hu\t", ntohs(ipHeader->ip_id), ntohs(ipHeader->ip_len));
    printf("offset: %d\t", ntohs(ipHeader->ip_off) & 0x1FFF);
    printf("TTL: %u\n", ipHeader->ip_ttl);
    showIPType(ipHeader->ip_p);
    if (ipHeader->ip_p == IPPROTO_TCP) {
        printf("--------------TCP---------------\n");
        const struct tcphdr* tcpHeader;
        tcpHeader = (struct tcphdr*)((u_char *)ipHeader + sizeof(struct ip));
        sourcePort = ntohs(tcpHeader->th_sport);
        destPort = ntohs(tcpHeader->th_dport);
        int ackNum = ntohl(tcpHeader->th_ack);
        int seqNum = ntohl(tcpHeader->th_seq);
        printf("源端口号: %u\t目标端口号: %u\t序列号: %u\t确认号: %u\n", sourcePort, destPort, ackNum, seqNum);
    } if (ipHeader->ip_p == IPPROTO_UDP) {
        printf("--------------UDP---------------\n");
        const struct udphdr* udpHeader;
        udpHeader = (struct udphdr *)((u_char *)ipHeader + sizeof(struct ip));
        sourcePort = ntohs(udpHeader->uh_sport);
        destPort = ntohs(udpHeader->uh_dport);
        int udplen = ntohs(udpHeader->uh_ulen);
        printf("源端口号: %u\t目标端口号: %u\t长度: %u\n", sourcePort, destPort, udplen);
        if (sourcePort == 53 || destPort == 53) {
            paraseDNS((struct dnshdr*)((u_char *)udpHeader + sizeof(struct udphdr)));
        }
    }
}

void showIPType(uint8_t type)
{
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

void paraseARP(const struct arphdr *header)
{
    const struct arphdr *arpHeader = header;
    const struct arpdata *arpData;
    char smac[MAC_STR_LEN];
    char dmac[MAC_STR_LEN];
    arpData =  (struct arpdata *)((u_char *)header + sizeof(struct arphdr));
    // printf("%d\n", (int)((int)arpData - (int)arpHeader));
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
    printf("目的IP: %s\n",inet_ntoa(dIP));
    
}

void paraseDNS(const struct dnshdr* header)
{
    const struct dnshdr* dnsHeader = header;
    const struct dnsquery* dnsQuery;
    printf("--------------DNS---------------\n");
    printf("事务id: 0x%4x\n", ntohs(dnsHeader->id));
    int type = showDNSFlags(dnsHeader);
    printf("Questions: %u\n", ntohs(dnsHeader->q_count));
    printf("Answer RRs: %u\n", ntohs(dnsHeader->ans_count));
    printf("Authority RRs: %u\n", ntohs(dnsHeader->auth_count));
    printf("Additional RRs: %u\n", ntohs(dnsHeader->add_count));
    const char *querry_name = (const char *)((u_char *)dnsHeader + sizeof(struct dnshdr));
    printf("Query:\n");
    showDomainName(querry_name);        
    dnsQuery = (const struct dnsquery *)(querry_name + strlen(querry_name)+1);
    showDnsType(ntohs(dnsQuery->qtype));
    showDnsClass(ntohs(dnsQuery->qclass));
    if(type) {
        printf("Answers: \n");
        querry_name = (const char *)((u_char *)dnsQuery + sizeof(struct dnsquery));
        for (int i = 0; i < ntohs(dnsHeader->ans_count); i++) {
            printf("----%d----\n", i+1);
            int bitflag = (*((unsigned char *)querry_name) & 0xC0) >> 6;
            int offset = 0;
            if (bitflag == 3) {
                offset = (ntohs(*((unsigned short *)querry_name)) & 0x3FFF);
                showDomainName((const char *)((u_char *)dnsHeader + offset));
                offset = 1;
                // showDomainName(querry_name);
            } else {
                showDomainName(querry_name);
                offset = strlen(querry_name);
            }
            const struct dnsanswer *dnsAnswer;
            dnsAnswer = (const struct dnsanswer *)(querry_name + offset  + 1);
            showDnsType(ntohs(dnsAnswer->answer_type));
            showDnsClass(ntohs(dnsAnswer->answer_class));
            printf("TTL: %u\n", ntohl(dnsAnswer->time_live));
            unsigned short datalen = ntohs(dnsAnswer->datalen);
            printf("Data length: %d\n", datalen);
            if (ntohs(dnsAnswer->answer_type) == 1) {
                struct in_addr IP;
                IP.s_addr = *(uint32_t*)((u_char *)dnsAnswer + sizeof(struct dnsanswer));
                printf("Address: %s\n", inet_ntoa(IP));
            } else if (ntohs(dnsAnswer->answer_type) == 5){
                querry_name = (const char *)(u_char *)dnsAnswer + sizeof(struct dnsanswer);
                showDomainName(querry_name);
                // querry_name = (const char *)(querry_name + strlen(querry_name) + 1);
            }
            querry_name = (const char *)((u_char *)dnsAnswer + sizeof(struct dnsanswer) + datalen);
            
        }
        
    } else {
        return;
    }
}

int showDNSFlags(const struct dnshdr* header)
{
    char response_flag = 1;
    printf("标志（Flags）:");
    printf("0x%4x\n", ntohs(header->flags));
    int qr = ntohs(header->flags) & (unsigned short)0x8000;
    int opcode = (ntohs(header->flags) & (unsigned short)0x7800) >> 11;
    int aa = ntohs(header->flags) & (unsigned short)0x0400;
    int tc = ntohs(header->flags) & (unsigned short)0x0200;
    int rd = ntohs(header->flags) & (unsigned short)0x0100;
    int ra = ntohs(header->flags) & (unsigned short)0x0080;
    int zero = ntohs(header->flags) & (unsigned short)0x0040;
    int isauthored = ntohs(header->flags) & (unsigned short)0x0020;
    int noauthored = ntohs(header->flags) & (unsigned short)0x0010;
    int rcode = ntohs(header->flags) & (unsigned short)0x000F;

    if (qr) {
        printf("1... .... .... .... = Response: Message is a response\n");
    } else {
        printf("0... .... .... .... = Response: Message is a query\n");
        response_flag = 0;
    }

    if (opcode == 0) {
        printf(".000 0... .... .... = Opcode: Standard query (0)\n");
    } else {
        printf("Opcode Unknown\n");
    }
    
    if (response_flag && aa) {
        printf(".... .1.. .... .... = Authoritative: Server is an authority for domain\n");
    } else if (response_flag && !aa) {
        printf(".... .0.. .... .... = Authoritative: Server is not an authority for domain\n");
    }
    
    if (tc){
        printf(".... ..1. .... .... = Truncated: Message is truncated\n");
    } else {
        printf(".... ..0. .... .... = Truncated: Message is not truncated\n");   
    }

    if (rd) {
        printf(".... ...1 .... .... = Recursion desired: Do query recursively\n");
    } else {
        printf(".... ...0 .... .... = Recursion desired: Do not query recursively\n");
    }

    if (response_flag && ra){
        printf(".... .... 1... .... = Recursion available: Server can do recursive queries\n");
    } else if (response_flag && !ra) {
        printf(".... .... 0... .... = Recursion available: Server can't do recursive queries\n");
    }
    
    if (zero) {
        printf(".... .... .1.. .... = Z: reserved (1)\n");
    } else {
        printf(".... .... .0.. .... = Z: reserved (0)\n");
    } 

    if (response_flag && isauthored) {
        printf(".... .... ..1. .... = Answer authenticated: Answer/authority portion was authenticated by the server\n");
    } else if (response_flag && !isauthored) {
        printf(".... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server\n");
    }

    if (noauthored) {
        printf(".... .... ...1 .... = Non-authenticated data: Acceptable\n");
    } else {
        printf(".... .... ...0 .... = Non-authenticated data: Unacceptable\n");
    }

    if (response_flag){
        if (rcode) {
            printf(".... .... .... %d%d%d%d = Reply code: No error (%u)\n", rcode/1000, rcode%1000/100, rcode%100/10,rcode%10, rcode);
        } else {
            printf(".... .... .... 0000 = Reply code: No error (0)\n");
        } 
    }
    return response_flag;  
}
void showDomainName(const char *name)
{
    printf("Name: ");
    int i = 0;
    while (1) {
       unsigned char j = name[i++];
       for (int q = 0; q < j; q++, i++) {
            printf("%c", name[i]);
       }
       if (name[i] == '\0'){
            break;
       }
       printf(".");
    }
    printf("\n");
}

void showDnsType(unsigned short type)
{
    switch (type) {
    case 1:
        printf("Type: A (Host Address) (1)\n");
        break;
    case 2:
        printf("Type: NS (Authoritative Name Server) (2)\n");
        break;
    case 5:
        printf("Type: CNAME (Canonical NAME for an alias) (5))\n");
        break;
    case 15:
        printf("Type: MX (Mail Exchange) (15)\n");
        break;
    default:
        break;
    }
}


void showDnsClass(unsigned short type)
{
    switch (type) {
    case 0x0001:
        printf("Class: IN (0x0001)\n");
        break;
    case 0x0003:
        printf("Class: CHAOS (0x0003)\n");
        break;
    default:
        break;
    }
}

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>
#include "Ethernet-structure.h"
#define SIZE_ETHERNET 14

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void my_strprint(u_char* x,int num){
	for(int i=0;i<num;i++) printf("%02x:",x[i]);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	u_char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	printf("\nEthernet Header");
	printf("\nsrc mac : ");
	my_strprint((u_char *)ethernet->ether_shost,6);
	printf("\ndst mac : ");
	my_strprint((u_char *)ethernet->ether_dhost,6);		
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("\n   * Invalid IP header length: %u bytes\n", size_ip);
		continue;
	}
	printf("\nIP Header");
	printf("\nip src : %d.%d.%d.%d",(ntohl(ip->ip_src)&0xff000000)>>24,(ntohl(ip->ip_src)&0x00ff0000)>>16,(ntohl(ip->ip_src)&0x0000ff00)>>8,(ntohl(ip->ip_src)&0x000000ff));
	printf("\nip dst : %d.%d.%d.%d",(ntohl(ip->ip_dst)&0xff000000)>>24,(ntohl(ip->ip_dst)&0x00ff0000)>>16,(ntohl(ip->ip_dst)&0x0000ff00)>>8,(ntohl(ip->ip_dst)&0x000000ff));
	if(ip->ip_p!=0x06){
		printf("\ndon't have tcp header");	
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("\n   * Invalid TCP header length: %u bytes\n", size_tcp);
		continue;
	}
	
	printf("\nTCP Header");
	printf("\nsrc port : %d",ntohs(tcp->th_sport));
	printf("\ndst port : %d",ntohs(tcp->th_dport));
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	printf("\nPayload(Data) : ");
	my_strprint((u_char *)payload,16);
    }
    pcap_close(handle);
    return 0;
}

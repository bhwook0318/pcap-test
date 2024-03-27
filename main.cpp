#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdint.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_eth(struct libnet_ethernet_hdr* eth_hdr) {
	int i;

	printf("Ethernet Header\n");

	printf("src MAC : ");
    	for(i = 0; i < 6 ; i++) printf("%02x : ", eth_hdr->ether_shost[i]);
	printf("\n");

	printf("dst MAC : ");
	for(i = 0; i < 6; i++) printf("%02x : ", eth_hdr->ether_dhost[i]);
	printf("\n");
}

void print_ip(struct libnet_ipv4_hdr* ip_hdr) {
	printf("IP Header\n");
	
	uint32_t src = ntohl(ip_hdr->ip_src.s_addr);
	uint32_t dst = ntohl(ip_hdr->ip_dst.s_addr);

	printf("src ip : ");
	printf("%d.%d.%d.%d\n",src>>24, (u_char)(src>>16),(u_char)(src>>8),(u_char)(src));
	
	printf("dst ip : ");
	printf("%d.%d.%d.%d\n",dst>>24, (u_char)(dst>>16),(u_char)(dst>>8),(u_char)(dst));
}

void print_tcp(struct libnet_tcp_hdr* tcp_hdr) {
	printf("TCP Header\n");

	printf("src port : %d\n", ntohs(tcp_hdr->th_sport));
	printf("dst port : %d\n", ntohs(tcp_hdr->th_dport));
}

void print_payload(u_char* packet, u_int offset, u_int length) {
	int i;
	printf("Payload data\n");

	printf("data : ");
	if (length <= offset) printf("NULL\n");
	else {
		u_int d = length - offset;
		if (d > 20) d = 20;
		for (i = 0; i < d; i++) printf("%02x", *(packet + offset + i);
	}
	printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		/* Todo */
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(eth_hdr->ether_type) != 0x0800) continue;
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*)((char*)eth_hdr + 14);
		if (ip_hdr->ip_p != 0x06) continue;
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)((char*)ip_hdr + 20);
		uint32_t offset = 14 + (ip_hdr->ip_hl) * 4 + (tcp_hdr->th_off) * 4;

		printf("--------------------------------------------------\n");
		print_mac(eth_hdr);
		print_ip(ip_hdr);
		print_tcp(tcp_hdr);
		print_payload(packet, offset, header->caplen);
	}

	pcap_close(pcap);
}

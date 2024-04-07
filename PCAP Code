#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>

/* Ethernet Header 구조체 */
struct ethernet_header
{
	u_char eth_DesMAC[6];//Destination MAC
	u_char eth_SrcMAC[6];//Source MAC
	u_short eth_type[2];//ipv4 타입인지 확인이 필요
};

/* IP Header 구조체 */
struct IP_header
{
	unsigned char iph_ihl:4;
	unsigned char iph_version:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3;
	unsigned short int iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;//프로토콜 타입
	unsigned short int iph_chksum;
	struct in_addr iph_SrcIP;//Source IP
	struct in_addr iph_DesIP;//Destination IP
};

/* TCP Header 구조체 */
struct tcp_header
{
	u_short tcp_SrcPORT;
	u_short tcp_DesPORT;
	u_int tcp_seq;
	u_int tcp_ack;
	u_char tcp_offset;
	u_char tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
};

/* 출력 함수 */
void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethernet_header *eth = (struct ethernet_header *)packet;
	struct ip_header *ip = (struct IP_header *)(packet + sizeof(struct ethernet_header));
  struct tcpheader *tcp = (struct tcp_header *)(packet + sizeof(struct ethernet_header) + ip->iph_ihl * 4);
	
	printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->eth_DesMAC));
	printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->eth_SrcMAC));
	printf("----------\n");
	printf("Source IP: %s\n", inet_ntoa(ip->iph_SrcIP));
	printf("Destination IP: %s\n", inet_ntoa(ip->iph_DesIP));
	printf("----------\n");
	printf("Source Port: %d\n", ntohs(tcp->tcp_SrcPORT));
  printf("Destination Port: %d\n", ntohs(tcp->tcp_DesPORT));
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);//네트워크 디바이스 열기
	pcap_loop(handle, 0, packet_capture, NULL);//패킷 캡처 시작
	pcap_close(handle);//핸들 닫기
	
	return 0;
}

#include <iostream>
#include <fstream>
#include <pcap.h>
#include <netinet/in.h>
#include <algorithm>

#include "header.h"
#include "mac.h"
#include "ethhdr.h"

#define ETHHDR_LEN 14

#define PROTOCOL_TCP 6
#define FIN 1
#define RST 4
#define ACK 16

#define PORT_HTTP 80
#define PORT_HTTPS 443
#define REDIRECT_LEN 56

using namespace std;

Mac myMac;
char* dev;
char* pat;

void usage(){
    cout << "syntax : tcp-block <interface> <pattern>" << endl;
    cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"" << endl;
}


// G Library 참고
uint16_t calcIPChecksum(libnet_ipv4_hdr* ipHdr) {
	uint32_t res = 0;
	uint16_t *p;

	// Add ipHdr buffer as array of uint16_t
	p = reinterpret_cast<uint16_t*>(ipHdr);
	for (int i = 0; i < int(sizeof(libnet_ipv4_hdr)) / 2; i++) {
		res += ntohs(*p);
		p++;
	}

	// Do not consider padding because ip header length is always multilpe of 2.

	// Decrease checksum from sum
	res -= ntohs(ipHdr->ip_sum);

	// Recalculate sum
	while (res >> 16) {
		res = (res & 0xFFFF) + (res >> 16);
	}
	res = ~res;

	return uint16_t(res);
}

uint16_t calcTCPChecksum(libnet_ipv4_hdr* ipHdr, libnet_tcp_hdr* tcpHdr) {
	uint32_t res = 0;
	int tcpHdrDataLen = ntohs(ipHdr->ip_len) - sizeof(libnet_ipv4_hdr);

	// Add tcpHdr & data buffer as array of uint16_t
	uint16_t* p = reinterpret_cast<uint16_t*>(tcpHdr);
	for (int i = 0; i < tcpHdrDataLen / 2; i++) {
		res += htons(*p);
		p++;
	}

	// If length is odd, add last data(padding)
	if ((tcpHdrDataLen / 2) * 2 != tcpHdrDataLen)
		res += uint32_t(*(reinterpret_cast<uint8_t*>(p)) << 8);

	// Decrease checksum from sum
	res -= ntohs(tcpHdr->th_sum);

	// Add src address
	uint32_t src = ntohl(ipHdr->ip_src);
	res += ((src & 0xFFFF0000) >> 16) + (src & 0x0000FFFF);

	// Add dst address
	uint32_t dst = ntohl(ipHdr->ip_dst);
	res += ((dst & 0xFFFF0000) >> 16) + (dst & 0x0000FFFF);

	// Add extra information
	res += uint32_t(tcpHdrDataLen) + IPPROTO_TCP;

	// Recalculate sum
	while (res >> 16) {
		res = (res & 0xFFFF) + (res >> 16);
	}
	res = ~res;

	return uint16_t(res);
}

Mac getSelfMac(const char* ifname){
	string eth = ifname;

	string dir = "/sys/class/net/" + eth + "/address";
	ifstream mac_stream(dir);
	string mac_string;

	if(!mac_stream.is_open()) {
		cout << "[*] Cannot find MAC address file located in " << dir << endl;
		exit(0);
	}

	mac_stream >> mac_string;
   	cout << "[*] IF MAC address => "  << mac_string << endl;

	return Mac(mac_string);
}

void filter(pcap_t* handle){
    bool isHTTPS;
    while (true) {  
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
    	}
        EthHdr* ethHdr = (EthHdr*) packet;
        if(ethHdr->type()!= EthHdr::Ip4) continue;

        libnet_ipv4_hdr* ipHdr = (libnet_ipv4_hdr*) (packet+ETHHDR_LEN);
        if(ipHdr->ip_p!= PROTOCOL_TCP) continue;


        libnet_tcp_hdr* tcpHdr = (libnet_tcp_hdr*) ((u_char*)ipHdr + (ipHdr->ip_hl<<2));
        uint16_t dport = tcpHdr->dport();
        if(dport!=PORT_HTTP && dport != PORT_HTTPS) continue;
        
        if(dport==PORT_HTTPS) isHTTPS = true;
        else isHTTPS = false;

        char* payload = (char*)tcpHdr + (tcpHdr->th_off<<2);
        int payloadLen = ntohs(ipHdr->ip_len)-(ipHdr->ip_hl<<2)-(tcpHdr->th_off<<2);

        string text = string(payload, payloadLen);
        string pattern = string(pat, strlen(pat));
        if (text.find(pattern)==string::npos) continue;
        cout << "[*] Match" << endl;

        // block(handle,packet);
        Packet fwdPkt, bwdPkt;  
        memset(&fwdPkt,0,sizeof(Packet));
        memset(&bwdPkt,0,sizeof(Packet));
        if(!isHTTPS) strcpy(bwdPkt.payload, "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n");

        fwdPkt.eth_ = *ethHdr;
        fwdPkt.eth_.smac_ = myMac; 

        fwdPkt.ip_ = *ipHdr;
        fwdPkt.ip_.ip_len = htons(sizeof(libnet_ipv4_hdr)+sizeof(libnet_tcp_hdr));
        fwdPkt.ip_.ip_sum = htons(calcIPChecksum(&fwdPkt.ip_));

        fwdPkt.tcp_ = *tcpHdr;
        fwdPkt.tcp_.th_seq = htonl(tcpHdr->th_seq+payloadLen);
        fwdPkt.tcp_.th_off = sizeof(libnet_tcp_hdr)>>2;
        fwdPkt.tcp_.th_flags = RST | ACK;
        fwdPkt.tcp_.th_sum = htons(calcTCPChecksum(&fwdPkt.ip_,&fwdPkt.tcp_));


        bwdPkt.eth_ = *ethHdr;
        bwdPkt.eth_.smac_ = myMac;
        bwdPkt.eth_.dmac_ = ethHdr->smac_;

        bwdPkt.ip_ = *ipHdr;
        bwdPkt.ip_.ip_ttl = 128;
        bwdPkt.ip_.ip_src = ipHdr->ip_dst;
        bwdPkt.ip_.ip_dst = ipHdr->ip_src;

        if(isHTTPS)
            bwdPkt.ip_.ip_len = htons(sizeof(libnet_ipv4_hdr)+sizeof(libnet_tcp_hdr));
        //HTTP
        bwdPkt.ip_.ip_len = htons(sizeof(libnet_ipv4_hdr)+sizeof(libnet_tcp_hdr)+REDIRECT_LEN);
        bwdPkt.ip_.ip_sum = htons(calcIPChecksum(&bwdPkt.ip_));

        bwdPkt.tcp_ = *tcpHdr;
        bwdPkt.tcp_.th_sport = tcpHdr->th_dport;
        bwdPkt.tcp_.th_dport = tcpHdr->th_sport;
        
        bwdPkt.tcp_.th_seq = tcpHdr->th_ack;
        bwdPkt.tcp_.th_ack = tcpHdr->th_seq + payloadLen;
        bwdPkt.tcp_.th_off = sizeof(libnet_tcp_hdr)>>2;

        if(isHTTPS) bwdPkt.tcp_.th_flags = RST | ACK;
        //HTTP
        bwdPkt.tcp_.th_flags = FIN | ACK;
        bwdPkt.tcp_.th_sum = htons(calcTCPChecksum(&bwdPkt.ip_,&bwdPkt.tcp_));

        int pktSize = sizeof(EthHdr)+sizeof(libnet_ipv4_hdr)+sizeof(libnet_tcp_hdr);
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fwdPkt), pktSize);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        if(isHTTPS) res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fwdPkt), pktSize);
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fwdPkt), pktSize+REDIRECT_LEN);

        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
}


int main(int argc, char** argv) {
    
    char errbuf[PCAP_ERRBUF_SIZE];
	
    if(argc!=3){
        usage();
        return 0;
    }
    dev = argv[1];
    pat = argv[2]; 

    myMac = getSelfMac(dev);

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}    
    filter(handle);
    pcap_close(handle);
}
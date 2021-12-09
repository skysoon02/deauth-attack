#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/in.h>
#include <map>
#include <string>
#include <iostream>
#include <iomanip>

#include "mac.h"
#include "IEEE802.11Hdr.h"
#include "radioTapHdr.h"

using namespace std;

struct station{
	string BSSID;
	int Beacons;
	string ESSID;
	//int Datas;
};


void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}


int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "error: pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
	
	map<Mac,station> stations;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		RadioTapHdr* radioTapHdr = (RadioTapHdr*)packet;
		WifiHdr* wifiHdr = (WifiHdr*)(packet + radioTapHdr->len);
		
		if(wifiHdr->type()==WifiHdr::Management && wifiHdr->subType()==WifiHdr::Beacon){
			auto iter = stations.find(wifiHdr->BSSID());
			if(iter==stations.end()){
				string ESSID = string((char*)wifiHdr + sizeof(WifiHdr) + 12 + 2, *((char*)wifiHdr + sizeof(WifiHdr) + 12 + 1));
				station tmp_station = {string(wifiHdr->BSSID()), 0, ESSID};
				stations.insert({wifiHdr->BSSID(), tmp_station});
			}
			else{
				iter->second.Beacons++;
			}
			system("clear");
			printf("%-19s %-9s %-5s\n", "BSSID", "Beacons", "ESSID");
			for(auto iter : stations){
				cout << iter.second.BSSID;
				cout << setw(10) << iter.second.Beacons;
				cout << "   " << iter.second.ESSID << endl;
			}
			continue;
		}
		//if(wifiHdr->type()==WifiHdr.Data)
	}
	pcap_close(pcap);
}

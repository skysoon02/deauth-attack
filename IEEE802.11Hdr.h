/*reference:
overall
	https://en.wikipedia.org/wiki/802.11_Frame_Types
	https://blogs.arubanetworks.com/industries/802-11-mac-header-breakdown/
relationship between toDS, fromDS and addresses
	https://mrncciew.com/2014/09/28/cwap-mac-headeraddresses/ 
*/
#pragma once

#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push, 1)
struct WifiHdr final {
	uint8_t ver_type;
	uint8_t flag;
	uint16_t duration;
	Mac addr[3];
	uint16_t seq;
		//Receiver Address = BSSID
		//Destination Address
	//omit...
    
    uint8_t subType(){ return (ver_type & 0xF0)>>4; };
    uint8_t type(){ return (ver_type & 0x0C)>>2; };
    bool checkBeacon() { return ver_type & 0xFC == Beacon; }
    bool checkData() { return ver_type & 0xFC == Data; }
    bool checkFromAP() { return flag & 0x02 == fromAP; }
    Mac BSSID(){
    	switch(flag & 0x02 == fromAP){
    		case 0:	return addr[2]; //fromDS=0, toDS=0
    		case 1: return addr[0];	//fromDS=0, toDS=1
    		case 2: return addr[1];	//fromDS=1, toDS=0
    	}
    	return Mac::nullMac();
    }
    
    enum: uint8_t {
    	//type
    	Management = 0x00,
    	Control = 0x01,
    	Data = 0x02,
    	Extension = 0x03,
		//subType
		Beacon = 0x8,
		//DS
		fromAP = 0x02	//fromDS=1, toDS=0
	};
};
typedef WifiHdr *PWifiHdr;
#pragma pack(pop)

//reference: https://www.radiotap.org/
#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct RadioTapHdr final {
	uint8_t ver;
	uint8_t pad;
	uint16_t len;
	uint32_t present;
};
typedef RadioTapHdr *PRadioTapHdr;
#pragma pack(pop)

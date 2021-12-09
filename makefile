LDLIBS=-lpcap

all: airodump

airodump: main.o radioTapHdr.o IEEE802.11Hdr.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o

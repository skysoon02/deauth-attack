LDLIBS=-lpcap

all: deauth-attack

deauth-attack: main.o radioTapHdr.o IEEE802.11Hdr.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o

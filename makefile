CC=gcc
CFLAGS=-std=gnu99
LDFLAGS = -lpcap

all: sniffer_daemon sniffer_client
 
sniffer_daemon: sniffer_daemon.o
	$(CC) sniffer_daemon.o -o sniffer_daemon $(LDFLAGS)
	rm -f sniffer_daemon.o
sniffer_client: sniffer_client.o
	$(CC) sniffer_client.o -o sniffer_client $(LDFLAGS)
	rm -f sniffer_client.o
.PHONY: clean
clean:
	rm -f sniffer_daemon
	rm -f sniffer_client
	
.PHONY: install
install:
	cp sniffer_daemon /usr/bin
	cp sniffer_client /usr/bin

.PHONY: uninstall
uninstall:
	rm -f /usr/bin/sniffer_daemon
	rm -f /usr/bin/sniffer_client

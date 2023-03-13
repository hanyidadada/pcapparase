#include "parase.h"

int main(int argc, char const *argv[]) {
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];

    if(argc  != 2) {
        printf("Usage: ./a.out [filename]\n");
        return 2;
    }
	// open capture file for offline processing
	descr = pcap_open_offline(argv[1], errbuf);
	if (descr == NULL) {
		printf("pcap_open_offline() failed: %s\n", errbuf);
		return 1;
	}

	// start packet processing loop, just like live capture
	if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
		printf("pcap_loop() failed\n");
		return 1;
	}
	printf("capture finished\n");
	pcap_close(descr);
  	return 0;
}


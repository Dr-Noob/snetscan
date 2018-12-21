#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "cap.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  printf("new pkg!\n");
}

void* cap(void* args) {
	struct cap_struct *s = (struct cap_struct*)args;

	pcap_t *handle;
	char dev[] = "wlp1s0";
	//char dev[] = "enp0s20f0u5";
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;

	/* Filter */
	struct bpf_program fp;
	char filter_exp[] = "arp";

	/* Sniffing */
	const u_char *packet;
	struct pcap_pkthdr header;

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
	  fprintf(stderr, "%s\n", errbuf);
	  return NULL;
	}

  if ((handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf)) == NULL) {
    fprintf(stderr, "%s\n", errbuf);
    return NULL;
  }

  s->ctx = handle;

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "%s\n", pcap_geterr(handle));
		 return NULL;
  }

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "%s\n", pcap_geterr(handle));
		return NULL;
	}

  if(pcap_setnonblock(handle, 1, errbuf) == -1) {
    fprintf(stderr, "%s\n", errbuf);
		return NULL;
  }

  printf("Capture ready\n");
  if(sem_post(s->sem) == -1) {
    perror("client");
    return NULL;
  }

	if(pcap_loop(handle, -1, got_packet, NULL) == -1) {
		fprintf(stderr, "%s\n", pcap_geterr(handle));
		return NULL;
	}

	return NULL;
}

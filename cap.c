#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cap.h"

#define SIZE_ETHERNET 14
#define ETH_ADDR_LEN	6
#define IP_ADDR_LEN	  4

struct arp_hdr {
	u_int16_t arp_htype;
	u_int16_t arp_ptype;
	u_char    arp_hlen;
	u_char    arp_plen;
	u_int16_t arp_oper;
	u_char    arp_sha[ETH_ADDR_LEN];
	u_char    arp_sip[IP_ADDR_LEN];
	u_char    arp_dha[ETH_ADDR_LEN];
	u_char    arp_dip[IP_ADDR_LEN];
};

/* We assume we can just receive ARP here */
void got_packet (u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  struct host_list *tmp = (struct host_list *)args;
	char sourceip[16];
	const struct arp_hdr *arp = (struct arp_hdr *)(packet + SIZE_ETHERNET);
  snprintf (sourceip, 16, "%d.%d.%d.%d", arp->arp_sip[0], arp->arp_sip[1], arp->arp_sip[2], arp->arp_sip[3]);

  while(tmp->next != NULL)
    tmp = tmp->next;
  tmp->next = malloc(sizeof(struct host_list));
  strncpy(tmp->next->ip, sourceip, 16);
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

  s->list = malloc(sizeof(struct host_list));

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

	if(pcap_loop(handle, -1, got_packet, (u_char *)s->list) == -1) {
		fprintf(stderr, "%s\n", pcap_geterr(handle));
		return NULL;
	}

	return NULL;
}

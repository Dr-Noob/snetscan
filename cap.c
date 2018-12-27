#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

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
	struct host_list *p;
	bool repeated = false;
	char sourceip[16];
	char sourcemac[18];
	int ip;
	const struct arp_hdr *arp = (struct arp_hdr *)(packet + SIZE_ETHERNET);

  snprintf (sourceip,  16, "%d.%d.%d.%d", arp->arp_sip[0], arp->arp_sip[1], arp->arp_sip[2], arp->arp_sip[3]);
	snprintf (sourcemac, 18, "%x:%x:%x:%x:%x:%x", arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
  ip = inet_addr(sourceip);

  while(!repeated && tmp->next != NULL && tmp->next->ip <= ip) {
    tmp = tmp->next;
		if(tmp->ip == ip)repeated = true;
	}
	if(!repeated) {
		if(tmp->next == NULL) {
		  tmp->next = malloc(sizeof(struct host_list));
		  tmp->next->next = NULL;
	  }
		else {
      p = tmp->next;
			tmp->next = malloc(sizeof(struct host_list));
			tmp->next->next = p;
		}

		tmp->next->ip = ip;
		strncpy(tmp->next->ip_str, sourceip, 16);
		strncpy(tmp->next->mac_str, sourcemac, 18);
	}
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

  *s->ok = true;
  s->list = malloc(sizeof(struct host_list));
	s->list->next = NULL;

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
	  fprintf(stderr, "%s\n", errbuf);
		*s->ok = false;
		if(sem_post(s->sem) == -1)
	    perror("client");

	  return NULL;
	}

  if ((handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf)) == NULL) {
    fprintf(stderr, "%s\n", errbuf);
		*s->ok = false;
		if(sem_post(s->sem) == -1)
	    perror("client");

    return NULL;
  }

  s->ctx = handle;

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "%s\n", pcap_geterr(handle));
		 *s->ok = false;
		 if(sem_post(s->sem) == -1)
 	    perror("client");

		 return NULL;
  }

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "%s\n", pcap_geterr(handle));
		*s->ok = false;
		if(sem_post(s->sem) == -1)
	    perror("client");

		return NULL;
	}

  if(pcap_setnonblock(handle, 1, errbuf) == -1) {
    fprintf(stderr, "%s\n", errbuf);
		*s->ok = false;
		if(sem_post(s->sem) == -1)
	    perror("client");

		return NULL;
  }

  if(sem_post(s->sem) == -1) {
    perror("client");
		*s->ok = false;
    return NULL;
  }

	if(pcap_loop(handle, -1, got_packet, (u_char *)s->list) == -1) {
		fprintf(stderr, "%s\n", pcap_geterr(handle));
		*s->ok = false;
		return NULL;
	}

	return NULL;
}

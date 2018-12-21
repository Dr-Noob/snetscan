#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <pthread.h>
#include <pcap.h>

#include "cap.h"

int main() {
	libnet_t *l;
	int bytes_written;
	char errbuf[LIBNET_ERRBUF_SIZE];
	u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u_int8_t mac_zero_addr[6] =      {0x0,   0x0,  0x0,  0x0,  0x0,  0x0};

  /* This host */
	const char* devname;
	u_int32_t src_ip_addr;
	struct libnet_ether_addr *src_mac_addr;

	/* Target host */
	u_int32_t target_ip_addr;
	char target_ip_addr_str[16] = "192.168.1.1";

  /* Capture thread */
	sem_t thread_sem;
	pthread_t cap_thread;
  struct cap_struct caps;

	if(sem_init(&thread_sem, 0 , 0) == -1) {
    perror("client");
    return EXIT_FAILURE;
  }

	caps.sem = &thread_sem;

	if(pthread_create(&cap_thread, NULL, &cap, &caps) == -1) {
    perror("pthread_create");
    return EXIT_FAILURE;
  }

	if(sem_wait(&thread_sem) == -1) {
    perror("client");
    return EXIT_FAILURE;
  }

	if ((l = libnet_init(LIBNET_LINK, NULL, errbuf)) == NULL) {
		fprintf(stderr, "libnet_init: %s\n", errbuf);
		return EXIT_FAILURE;
	}

	if((devname = libnet_getdevice(l)) == NULL) {
		fprintf(stderr, "%s\n", libnet_geterror(l));
		libnet_destroy(l);
		return EXIT_FAILURE;
	}

	printf("Using interface: '%s'\n",devname);

	if ((src_ip_addr = libnet_get_ipaddr4(l)) == -1 ) {
		fprintf(stderr, "%s\n", libnet_geterror(l));
		libnet_destroy(l);
		return EXIT_FAILURE;
	}

	if ((src_mac_addr = libnet_get_hwaddr(l)) == NULL ) {
		fprintf(stderr, "%s\n", libnet_geterror(l));
		libnet_destroy(l);
		return EXIT_FAILURE;
	}

	printf("Target IP address: '%s'\n", target_ip_addr_str);

	if ((target_ip_addr = libnet_name2addr4(l, target_ip_addr_str, LIBNET_DONT_RESOLVE)) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(l));
		libnet_destroy(l);
		return EXIT_FAILURE;
	}

	if (libnet_autobuild_arp (ARPOP_REQUEST, src_mac_addr->ether_addr_octet, (u_int8_t*)(&src_ip_addr), mac_zero_addr, (u_int8_t*)(&target_ip_addr), l) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(l));
		libnet_destroy(l);
		return EXIT_FAILURE;
	}

	if (libnet_autobuild_ethernet (mac_broadcast_addr, ETHERTYPE_ARP, l) == -1 ) {
		fprintf(stderr, "%s\n", libnet_geterror(l));
		libnet_destroy(l);
		return EXIT_FAILURE;
	}

  printf("Lets send\n");
	bytes_written = libnet_write(l);
	if (bytes_written == -1)
	  fprintf(stderr, "%s\n", libnet_geterror(l));

	libnet_destroy(l);

	sleep(1);
	/* End cap thread */
  pcap_breakloop(caps.ctx);

	if(pthread_join(cap_thread, NULL) == -1)  {
    perror("pthread_join");
    return EXIT_FAILURE;
  }

	struct host_list *list = caps.list->next;
	while(list->next != NULL) {
		printf("%s\n", list->ip);
		list = list->next;
	}
	printf("%s\n", list->ip);

}

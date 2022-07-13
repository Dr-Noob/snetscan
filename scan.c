#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <pthread.h>
#include <pcap.h>
#include <stdbool.h>

#include "args.h"
#include "cap.h"
#include "printer.h"

#define RESET   "\033[0m"
#define BOLD    "\033[1m"
static const char* VERSION = "0.11";

void printHelp(char *argv[]) {
  printf("Usage: %s --dev DEVICE [--help] [--version]\n\
  Options: \n\
  --dev      Set network interface\n\
  --help     Print this help and exit\n\
  --version  Print snetscan version and exit\n",
  argv[0]);
}

void printVersion() {
  printf("snetscan v%s\n",VERSION);
}

void printInterfaces() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces;
  pcap_if_t *temp;

  if(pcap_findalldevs(&interfaces, errbuf) == -1) {
    printf("%s\n", errbuf);
    return;
  }

  printf("Available devices are: \n");
  for(temp=interfaces; temp != NULL; temp=temp->next) {
    if(temp->addresses != NULL) {
      printf("       * " BOLD "%s" RESET "\n",temp->name);
    }
  }

  pcap_freealldevs(interfaces);
}

bool validForScan(pcap_if_t *iface) {
  if(!(iface->flags & PCAP_IF_LOOPBACK) &&
    #ifndef PCAP_IF_CONNECTION_STATUS
      iface->flags & PCAP_IF_UP) {
    #else
      (iface->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_CONNECTED) {
    #endif
    if(iface->addresses != NULL) {
      pcap_addr_t* list = iface->addresses;
      for(; list->next != NULL; list = list->next) {
        struct sockaddr* saddr = list->addr;
        if(saddr->sa_family == AF_INET) {
          //printf("Found candidate (%s) with address %s\n", iface->name, inet_ntoa(((struct sockaddr_in*)list->addr)->sin_addr));
          return true;
        }
      }
    }
  }

  return false;
}

/*
 * Search for a network device that can
 * be scanned. If more than one device is found,
 * the function returns NULL, because in that case
 * it is not clear what device should be used.
 * If only one is found, that device is returned.
 */
char* getDefaultDevice() {
  char* devname = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces;
  pcap_if_t *temp;

  if(pcap_findalldevs(&interfaces, errbuf) == -1) {
    printf("%s\n", errbuf);
    return NULL;
  }

  bool found = false;
  for(temp=interfaces; temp != NULL; temp=temp->next) {
    if(validForScan(temp)) {
      if(found) {
        return NULL;
      }
      else {
        found = true;
        devname = temp->name;
      }
    }
  }

  return devname;
}

int main(int argc, char* argv[]) {
  parseArgs(argc, argv);

  if(showHelp()) {
    printHelp(argv);
    return EXIT_SUCCESS;
  }

  if(showVersion()) {
    printVersion();
    return EXIT_SUCCESS;
  }

  /* pcap */
  bpf_u_int32 mask;
  bpf_u_int32 net;
  char pcap_errbuf[PCAP_ERRBUF_SIZE];

  /* libnet */
  libnet_t *l;
  libnet_ptag_t arp_tag = 0;
  int bytes_written;
  char errbuf[LIBNET_ERRBUF_SIZE];
  u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  u_int8_t mac_zero_addr[6]      = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

  /* This host */
  const char* devname;
  u_int32_t src_ip_addr;
  struct libnet_ether_addr *src_mac_addr;

  /* Capture thread */
  sem_t thread_sem;
  pthread_t cap_thread;
  struct cap_struct caps;
  struct host_list *list;

  /* User did not specify any device */
  if((devname = getDevice()) == NULL) {
    /* Try to find the interface in use */
    devname = getDefaultDevice();

    if(devname == NULL) {
      printf("ERROR: DEVICE option was not specified and no device could be selected automatically\n");
      printInterfaces();
      printHelp(argv);
      return EXIT_SUCCESS;
    }
  }

  if ((l = libnet_init(LIBNET_LINK, devname, errbuf)) == NULL) {
    fprintf(stderr, "libnet_init: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  printf("Using interface: '%s'\n",devname);

  if(sem_init(&thread_sem, 0 , 0) == -1) {
    perror("client");
    return EXIT_FAILURE;
  }

  caps.sem = &thread_sem;
  caps.ok = malloc(sizeof(bool));
  caps.dev = devname;

  if(pthread_create(&cap_thread, NULL, &cap, &caps) == -1) {
    perror("pthread_create");
    return EXIT_FAILURE;
  }

  if(sem_wait(&thread_sem) == -1) {
    perror("client");
    return EXIT_FAILURE;
  }

  if(!*caps.ok) {
    return EXIT_FAILURE;
  }

  if (pcap_lookupnet(devname, &net, &mask, pcap_errbuf) == -1) {
    fprintf(stderr, "%s\n", errbuf);
    return EXIT_FAILURE;
  }

  if ((src_ip_addr = libnet_get_ipaddr4(l)) == (u_int32_t)-1) {
    fprintf(stderr, "%s\n", libnet_geterror(l));
    libnet_destroy(l);
    return EXIT_FAILURE;
  }

  if ((src_mac_addr = libnet_get_hwaddr(l)) == NULL) {
    fprintf(stderr, "%s\n", libnet_geterror(l));
    libnet_destroy(l);
    return EXIT_FAILURE;
  }

  mask = htonl(mask);
  uint32_t network_address   = htonl(src_ip_addr) & mask;
  uint32_t broadcast_address = htonl(src_ip_addr) | ~mask;
  printf("Scanning from %d.%d.%d.%d to %d.%d.%d.%d\n", ((network_address + 1) & 0xFF000000) >> 24,
                                                       ((network_address + 1) & 0x00FF0000) >> 16,
                                                       ((network_address + 1) & 0x0000FF00) >> 8,
                                                        (network_address + 1) & 0x000000FF,
                                                       ((broadcast_address - 1) & 0xFF000000) >> 24,
                                                       ((broadcast_address - 1) & 0x00FF0000) >> 16,
                                                       ((broadcast_address - 1) & 0x0000FF00) >> 8,
                                                        (broadcast_address - 1) & 0x000000FF);

  for (uint32_t ip = network_address + 1; ip < broadcast_address; ip++) {
    uint32_t target_ip_addr = ntohl(ip);
    if ((arp_tag = libnet_build_arp (ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REQUEST, src_mac_addr->ether_addr_octet, (u_int8_t*)(&src_ip_addr), mac_zero_addr, (u_int8_t*)(&target_ip_addr), NULL, 0, l, arp_tag)) == -1) {
      fprintf(stderr, "%s\n", libnet_geterror(l));
      libnet_destroy(l);
      return EXIT_FAILURE;
    }

    if(ip == network_address + 1) {
      /* Just build at first iteration(reused in the others iterations) */
      if (libnet_autobuild_ethernet (mac_broadcast_addr, ETHERTYPE_ARP, l) == -1 ) {
        fprintf(stderr, "%s\n", libnet_geterror(l));
	libnet_destroy(l);
	return EXIT_FAILURE;
      }
    }

    bytes_written = libnet_write(l);
    if (bytes_written == -1) {
      fprintf(stderr, "%s\n", libnet_geterror(l));
    }
  }

  libnet_destroy(l);

  printf("Waiting for requests...\n");
  sleep(1);

  /* End cap thread */
  pcap_breakloop(caps.ctx);

  if(pthread_join(cap_thread, NULL) == -1)  {
    perror("pthread_join");
    return EXIT_FAILURE;
  }
  free(caps.ok);

  return print_hosts(caps.list->next, src_ip_addr);
}

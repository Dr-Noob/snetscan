#ifndef __CAP__
#define __CAP__

#include <pcap.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>

struct host_list {
  uint32_t ip; /* used to sort the list */
  char ip_str [16];
  char mac_str[18];
  struct host_list *next;
};

struct cap_struct {
  sem_t      *sem;        /* sync cap and main thread */
  pcap_t     *ctx;        /* give main thread pcap ctx to break the loop */
  bool       *ok;         /* is the cap thread ok? */
  const char *dev;        /* device to use in both threads */
  struct host_list *list; /* list of hosts in the network */
};

void* cap(void* args);

#endif

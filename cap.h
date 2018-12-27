#ifndef __CAP__
#define __CAP__

#include <pcap.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>

struct host_list {
  uint32_t ip;
  char ip_str [16];
  char mac_str[18];
  struct host_list *next;
};

struct cap_struct {
  sem_t  *sem;
  pcap_t *ctx;
  bool   *ok;
  struct host_list *list;
};

void* cap(void* args);

#endif

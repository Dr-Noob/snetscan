#ifndef __CAP__
#define __CAP__

#include <pcap.h>
#include <semaphore.h>

struct cap_struct {
  sem_t  *sem;
  pcap_t *ctx;
  int count;
};

void* cap(void* args);

#endif

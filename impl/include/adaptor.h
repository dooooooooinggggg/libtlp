#include <stdio.h>
#include <stdint.h>

#define NETTLP 1
#define DEVMEM 2
#define PMEM 3

int read_pmem(uintptr_t addr, int method);

#ifndef _ADAPTOR_H_
#define _ADAPTOR_H_

#include <stdio.h>
#include <stdint.h>

#define NETTLP 1
#define DEVMEM 2
#define PMEM 3

int read_pmem(uintptr_t addr, int method);

// gcc -g -Wall -I../include -I../../include  -L../lib -L../../lib  mem_read.c  -ltlp -lpthread -o mem_read
// gcc -g -Wall -I../include                  -L../lib              pgd-walk.c  -ltlp -lpthread -o pgd-walk

#endif

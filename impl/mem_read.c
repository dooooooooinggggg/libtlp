#include <stdio.h>
#include <stdint.h>

#define NETTLP 1
#define DEVMEM 2
#define PMEM 3

#include <libtlp.h>
#include "util.h"

int read_pmem(uintptr_t addr, int method)
{
    printf("read at 0x%lx\n", addr);

    switch (method)
    {
    case NETTLP:
        /* code */
        break;
    case DEVMEM:
        /* code */
        break;
    case PMEM:
        /* code */
        break;

    default:
        printf("Not implemented this method\n");
        break;
    }

    return 0;
}

int main(int argc, char **argv)
{
    printf("mem_read\n");
    uintptr_t addr;

    int result;

    addr = 31;

    printf("%d\n", DEVMEM);
    result = read_pmem_testtest(1);
    result = read_pmem(addr, DEVMEM);

    return 0;
}

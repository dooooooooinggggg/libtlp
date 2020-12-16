#include <stdio.h>
#include <stdint.h>

#include "adaptor.h"

int main(int argc, char **argv)
{
    printf("mem_read\n");
    uintptr_t addr;

    addr = 31;

    read_pmem(addr, DEVMEM);

    return 0;
}

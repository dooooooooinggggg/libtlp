#include <stdio.h>
#include <stdint.h>
// #include <sys/types.h>
// #include <sys/stat.h>
#include <fcntl.h>

#define METHOD_NETTLP 1
#define METHOD_DEVMEM 2
#define METHOD_PMEM 3

#define DEVMEM "/dev/mem"

#include <libtlp.h>
#include "util.h"

int read_devmem(uintptr_t addr)
{
    printf("read from devmem\n");

    int fd;
    if ((fd = open(DEVMEM, O_RDWR | O_SYNC)) < 0)
    {
        perror("open");
        return -1;
    }

    printf("fd: %d\n", fd);

    close(fd);

    return 0;
}

int read_mem(uintptr_t addr, int method)
{
    printf("read at 0x%lx\n", addr);

    switch (method)
    {
    case METHOD_NETTLP:
        /* code */
        break;
    case METHOD_DEVMEM:
        /* code */
        return read_devmem(addr);
    case METHOD_PMEM:
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

    printf("%d\n", METHOD_DEVMEM);
    result = read_mem(addr, METHOD_DEVMEM);

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <tlp.h>

#include "util.h"
#include "azkaban.h"

void usage(void)
{
    printf("usage\n"
           "    -a swapper/0's phys addr through xxd command(ex, 0x023f3ed0)\n"
           "    -b offset byte of comm in task_struct\n");
}

int main(int argc, char **argv)
{
    int ch;
    uintptr_t offset;
    uintptr_t swapper_phys_addr;

    while ((ch = getopt(argc, argv, "a:b:")) != -1)
    {
        switch (ch)
        {
        case 'a':
            sscanf(optarg, "0x%lx", &swapper_phys_addr);
            break;

        case 'b':
            sscanf(optarg, "%lu", &offset);
            break;

        default:
            usage();
            return -1;
        }
    }

    if (offset == 0 || swapper_phys_addr == 0)
    {
        usage();
        return -1;
    }

    printf("Offset: %lu\n", offset);
    printf("swapper_phys_addr: %lu\n", swapper_phys_addr);

    printf("Phys Addr: %lu\n", swapper_phys_addr - offset);

    return 0;
}

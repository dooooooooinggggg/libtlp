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
    int ret, size, mrrs;
    struct nettlp nt;
    uintptr_t addr;
    uint16_t busn, devn;
    char buf[4096];

    // size Bytes, addr from systemmap
    size = 2048;

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

    /*
    * init
    */
    memset(&nt, 0, sizeof(nt));
    busn = 0;
    devn = 0;
    mrrs = 0;

    // b option
    ret = sscanf("02:00", "%hx:%hx", &busn, &devn);
    nt.requester = (busn << 8 | devn);

    // r option
    ret = inet_pton(AF_INET, "192.168.10.1", &nt.remote_addr);
    if (ret < 1)
    {
        perror("inet_pton");
        return -1;
    }

    // l option
    ret = inet_pton(AF_INET, "192.168.10.3", &nt.local_addr);
    if (ret < 1)
    {
        perror("inet_pton");
        return -1;
    }

    ret = nettlp_init(&nt);
    if (ret < 0)
    {
        perror("nettlp_init");
        return ret;
    }

    /*
    * / init
    */

    uintptr_t start, end;
    start = 0;
    end = 10737418240;

    for (addr = start; addr < end; addr += size)
    {
        memset(buf, 0, sizeof(buf));
        ret = dma_read(&nt, addr, buf, size);

        if (ret < 0)
        {
            fprintf(stderr, "Cannot read: 0x%lx(%lu)\n", addr, addr);
            continue;
        }

        if (ret > 0)
        {
            if (asciisearch(buf, size, "swapper/0"))
            {
                printf("Found!: 0x%lx(%lu)\n", addr, addr);
                asciiprint(buf, size);
                asciidump(buf, size);
                return 1;
            }
        }
    }

    printf("Canndo found......\n");

    return 0;
}

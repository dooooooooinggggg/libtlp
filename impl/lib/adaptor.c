#include <stdio.h>
#include <stdint.h>

#include <libtlp.h>

#include <adaptor.h>
#include <devmem.h>

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
        printf("not implemented this method\n");
        break;
    }
    return 0;
}

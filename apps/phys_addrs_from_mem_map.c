#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "azkaban.h"

#define ARR_LEN 20

/*
* PML4
* https://elixir.bootlin.com/linux/v4.15/source/Documentation/x86/x86_64/mm.txt
*/

int main(void)
{
    char vm_addrs[ARR_LEN][3][128] = {
        {"0x0000000000000000", "0x00007fffffffffff", "(=47 bits) user space, different per mm hole caused by [47:63] sign extension"},
        {"0xffff800000000000", "ffff87ffffffffff", "(=43 bits) guard hole, reserved for hypervisor"},
        {"0xffff880000000000", "0xffffc7ffffffffff", "(=64 TB) direct mapping of all phys. memory"},
        {"0xffffc80000000000", "0xffffc8ffffffffff", "hole"},
        {"0xffffc90000000000", "0xffffe8ffffffffff", "(=45 bits) vmalloc/ioremap space"},
        {"0xffffe90000000000", "0xffffe9ffffffffff", "(=40 bits) hole"},
        {"0xffffea0000000000", "0xffffeaffffffffff", "(=40 bits) virtual memory map (1TB)"},
        {"0xffffec0000000000", "0xfffffbffffffffff", "(=44 bits) kasan shadow memory (16TB)"},
        // vaddr_end for KASLR
        {"0xfffffe0000000000", "0xfffffe7fffffffff", "(=39 bits) cpu_entry_area mapping"},
        {"0xfffffe8000000000", "0xfffffeffffffffff", "(=39 bits) LDT remap for PTIs"},
        {"0xffffff0000000000", "0xffffff7fffffffff", "(=39 bits) %esp fixup stacks"},
        {"0xffffffef00000000", "0xfffffffeffffffff", "(=64 GB) EFI region mapping space"},
        {"0xffffffff80000000", "0xffffffff9fffffff", "(=512 MB)  kernel text mapping, from phys 0"},
        // {"0x", "0x", ""}, // ffffffffa0000000 - [fixmap start]   (~1526 MB) module mapping space (variable)
        // {"0x", "0x", ""}, // [fixmap start]   - ffffffffff5fffff kernel-internal fixmap range
        {"0xffffffffff600000", "0xffffffffff600fff", "(=4 kB) legacy vsyscall ABI"},
        // {"0xffffffffffe00000", "0xffffffffffffffff", "(=2 MB) unused hole"},
    };

    for (int i = 0; i < ARR_LEN; i++)
    {
        if (!strcmp(vm_addrs[i][2], ""))
            continue;

        unsigned long vm_start, vm_end, phys_start, phys_end;

        vm_start = strtoul(vm_addrs[i][0], NULL, 16);
        vm_end = strtoul(vm_addrs[i][1], NULL, 16);

        phys_start = __phys_addr_nodebug(vm_start);
        phys_end = __phys_addr_nodebug(vm_end);

        printf("%luGBi(%luByte)(VM: 0x%lx)\n%s\n%luGBi(%luByte)(VM: 0x%lx)\n\n",
               gb_from_lx(phys_start),
               phys_start,
               vm_start,
               vm_addrs[i][2], // description
               gb_from_lx(phys_end),
               phys_end,
               vm_end);
    }
}

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
// #include <arpa/inet.h>

#ifdef __APPLE__
#else
#include <linux/types.h>
#endif

#include <libtlp.h>

unsigned long gb_from_lx(unsigned long x)
{
    return x >> 30; // GBiでの表示
}

#ifdef __APPLE__
#define _AC(X, Y) X
#else
#include <linux/const.h>
#endif

/*
* upa env
*/
// #define OFFSET_HEAD_STATE 16
// #define OFFSET_HEAD_PID 2216
// #define OFFSET_HEAD_CHILDREN 2240
// #define OFFSET_HEAD_SIBLING 2256
// #define OFFSET_HEAD_COMM 2632
// #define OFFSET_HEAD_REAL_PARENT 2224

/*
* tatsu env
*/
#define OFFSET_HEAD_STATE 16
#define OFFSET_HEAD_PID 2216
#define OFFSET_HEAD_CHILDREN 2248
#define OFFSET_HEAD_SIBLING 2264
#define OFFSET_HEAD_COMM 2640
#define OFFSET_HEAD_REAL_PARENT 2232

/* from arch_x86/include/asm/page_64_types.h */
#define KERNEL_IMAGE_SIZE (1024 * 1024 * 1024)

#define __START_KERNEL_map _AC(0xffffffff80000000, UL)

// #define __PAGE_OFFSET_BASE _AC(0xffff888000000000, UL) // 使ってない

// #define __PAGE_OFFSET 0xffff8ae280000000 // この値は一体
#define __PAGE_OFFSET_BASE _AC(0xffff888000000000, UL)
#define __PAGE_OFFSET __PAGE_OFFSET_BASE

/* from arch/x86/include/asm/page_types.h */
#define PAGE_OFFSET ((unsigned long)__PAGE_OFFSET)

// #define phys_base 0x21ce00000 /* x86 */ // この値は一体
#define phys_base 0x0 /* x86 */
// #define phys_base 0x1000000

// https://elixir.bootlin.com/linux/v4.15/source/arch/x86/include/asm/page_64.h#L14
static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
    // unsigned long before = x;
    unsigned long y = x - __START_KERNEL_map;

    /* use the carry flag to determine if x was < __START_KERNEL_map */
    x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

    // printf("0x%lx -> 0x%lx(%luGB)\n", before, x, gb_from_lx(x));

    return x;
}





/*
* =========================================================================
*/

#define unlikely(x) __builtin_expect(!!(x), 0)

// static inline int phys_addr_valid(resource_size_t addr)
// {
// #ifdef CONFIG_PHYS_ADDR_T_64BIT
//     return !(addr >> boot_cpu_data.x86_phys_bits);
// #else
//     return 1;
// #endif
// }
/* from arch/x86/mm/physaddr.c */
unsigned long
__phys_addr(unsigned long x)
{
    // unsigned long before = x;

    unsigned long y = x - __START_KERNEL_map;
    /* use the carry flag to determine if x was < __START_KERNEL_map */
    if (unlikely(x > y))
    {
        x = y + phys_base;
        // VIRTUAL_BUG_ON(y >= KERNEL_IMAGE_SIZE);
    }
    else
    {
        x = y + (__START_KERNEL_map - PAGE_OFFSET);
        /* carry flag will be set if starting x was >= PAGE_OFFSET */
        // VIRTUAL_BUG_ON((x > y) || !phys_addr_valid(x));
    }

    // printf("0x%lx -> 0x%lx(%luGB)\n", before, x, gb_from_lx(x));
    return x;
}

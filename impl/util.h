#include <string.h>

/* utility for test */

#ifndef _TLP_TEST_UTIL_H_
#define _TLP_TEST_UTIL_H_

#include <libtlp.h>

void dump_nettlp(struct nettlp *nt)
{
        printf("======== struct nettlp ========\n");
        printf("port:        %d\n", nt->port);
        printf("remote_addr: %s\n", inet_ntoa(nt->remote_addr));
        printf("local_addr:  %s\n", inet_ntoa(nt->local_addr));
        printf("requester:   %02x:%02x\n", (nt->requester & 0xFF00) >> 8, nt->requester & 0x00FF);
        printf("sockfd:      %d\n", nt->sockfd);
        printf("===============================\n");
}

void hexdump(void *buf, int len)
{
        int n;
        unsigned char *p = buf;

        printf("\nHex dump\n");

        for (n = 0; n < len; n++)
        {
                printf("%02x", p[n]);

                if ((n + 1) % 2 == 0)
                        printf(" ");
                if ((n + 1) % 32 == 0)
                        printf("\n");
        }
        printf("\n");
}

void asciidump(void *buf, int len)
{
        int n;
        unsigned char *p = buf;

        printf("\nASCII dump\n");

        for (n = 0; n < len; n++)
        {
                putc(p[n], stdout);

                if ((n + 1) % 4 == 0)
                        printf(" ");
                if ((n + 1) % 32 == 0)
                        printf("\n");
        }
        printf("\n");
}

void asciiprint(void *buf, int len)
{
        int n;
        unsigned char *p = buf;

        for (n = 0; n < len; n++)
        {
                putc(p[n], stdout);
        }
}

int asciisearch(void *buf, int len, char arg_s[16])
{
        int n;
        unsigned char *p = buf;

        char str[len];

        for (n = 0; n < len; n++)
        {
                str[n] = p[n];
        }

        char *search_res = strstr(str, arg_s);
        if (search_res != NULL)
        {
                return 1;
        }

        return 0;
}

#endif /* _TLP_TEST_UTIL_H_ */

/*
$ clang dga.c
$ ./a.out 3 29 2022
subdomain: qymkfervy
*/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <err.h>

int main(int ac, char**av)
{
    if (ac != 4)
        errx(EXIT_FAILURE, "usage: %s <month> <day> <year>\n", av[0]);

    char subdomain[10];
    uint64_t month = (uint64_t)atoi(av[1]);
    uint64_t day = (uint64_t)atoi(av[2]);
    uint64_t year = (uint64_t)atoi(av[3]);
    for(unsigned i = 0 ; i < sizeof(subdomain) - 1; ++i)
    {
        month = ((month ^ 4 * month) >> 1) ^ 16 * (month & 0xFFFFFFF2);
        year = ((year ^ 8 * year) >> 4) ^ ((year & 0xFFFFFFF4) << 8);
        day = ((day ^ (day << 16)) >> 2) ^ ((day & 0xFFFFFFFA) << 4);
        subdomain[i] = (char)(((year ^ month ^ day) % 25) + 'a');
    }

    subdomain[sizeof(subdomain)-1] = 0;
    printf("subdomain: %s\n", subdomain);
}

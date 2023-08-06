#ifndef __SHARED__
#define __SHARED__
#include <gmp.h>
#include <stdint.h>

static void store(mpz_t n, uint8_t* b, uint32_t s)
{
    for (uint32_t i = 0; i < s; i++)
    {
        b[s - (i + 1)] = mpz_get_ui(n);
        mpz_div_ui(n, n, 256);
    }
}

static void load(mpz_t n, uint8_t* b, uint32_t s)
{
    mpz_set_ui(n, 0);
    for (uint32_t i = 0; i < s; i++)
    {
        mpz_mul_ui(n, n, 256);
        mpz_add_ui(n, n, b[i]);
    }
}


void pbuf(uint8_t* b, uint64_t s)
{
    for (uint64_t i = 0; i < s; i++)
    {
        printf("%02X ", b[i]);
    }
    putchar('\n');
}


#endif
#ifndef __PRIGEN__
#define __PRIGEN__
#include <stdio.h>
#include <stdint.h>
#include <gmp.h>

static void PRIGEN_GetRandom(mpz_t n, uint16_t bytes, FILE *f)
{
    mpz_set_ui(n, 0);
    for (uint16_t i = 0; i < bytes; i++)
    {
        mpz_mul_2exp(n, n, 8);
        uint8_t c = fgetc(f);
        if (i == 0) c |= 0b10000000;
        if (i == bytes - 1) c |= 1;
        mpz_add_ui(n, n, c);
    }
}

static void PRIGEN_ComputeDS(mpz_t n, mpz_t d, uint16_t *s)
{
    mpz_t t;
    mpz_init(t);
    mpz_set(d, n);
    mpz_sub_ui(d, d, 1);
    *s = 0;
    for (;;)
    {
        mpz_mod_ui(t, d, 2);
        if (mpz_sgn(t) != 0) break;
        mpz_div_ui(d, d, 2);
        *s = (*s) + 1;
    }
    mpz_clear(t);
}

static uint8_t PRIGEN_PrimeTestOnce(mpz_t n, mpz_t d, uint16_t s, uint16_t witness)
{
    mpz_t x, m, a, two;
    uint8_t ret = 0;
    mpz_init(x);
    mpz_init(m);
    mpz_init(a);
    mpz_init(two);
    mpz_set_ui(two, 2);
    mpz_sub_ui(m, n, 1);
    mpz_set_ui(a, witness);

    for (uint16_t i = 0; i < s; i++)
    {
        if (i == 0)
        {
            mpz_powm(x, a, d, n);
            if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, m) == 0)
            {
                ret = 1;
                break;
            }
        }
        else
        {
            mpz_powm(x, x, two, n);
            if (mpz_cmp(x, m) == 0)
            {
                ret = 1;
                break;
            }
            if (mpz_cmp_ui(x, 1) == 0)
            {
                ret = 0;
                break;
            }
        }
    }

    mpz_clear(x);
    mpz_clear(m);
    mpz_clear(a);
    mpz_clear(two);
    return ret;
}

static uint8_t PRIGEN_PrimeTest(mpz_t n)
{
    mpz_t d;
    mpz_init(d);
    uint16_t s = 0;
    PRIGEN_ComputeDS(n, d, &s);

    for (uint8_t a = 2; a < 12; a++)
    {
        if (!PRIGEN_PrimeTestOnce(n, d, s, a))
        {
            mpz_clear(d);
            return 0;
        }
    }

    mpz_clear(d);
    return 1;
}

static void PRIGEN_GeneratePrime(mpz_t n, int bytes)
{
    FILE *f = fopen(DEVICE, "r");
    do
    {
        PRIGEN_GetRandom(n, bytes, f);
    } while (!PRIGEN_PrimeTest(n));
    fclose(f);
}

/* Generate prime of X bytes */
uint8_t* prigen(int bytes)
{
    uint8_t* buffer = malloc(bytes);
    FILE *f = fopen(DEVICE, "r");
    mpz_t n, t;
    mpz_init(n);
    do
    {
        PRIGEN_GetRandom(n, bytes, f);
    } while (!PRIGEN_PrimeTest(n));
    mpz_export(buffer, NULL, 1, 1, 0, 0, n);
    mpz_clear(n);
    fclose(f);
    return buffer;
}
#endif
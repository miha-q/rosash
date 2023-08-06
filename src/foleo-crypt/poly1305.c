#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>

static void poly1305_clamp(uint8_t* r)
{
	r[3] &= 15;
	r[7] &= 15;
	r[11] &= 15;
	r[15] &= 15;
	r[4] &= 252;
	r[8] &= 252;
	r[12] &= 252;
}

//generates random r and s
//(technically r can be constant)
static uint8_t* poly1305_keys()
{
	uint8_t *r = malloc(32);
	FILE *f = fopen("/dev/random", "r");
	fread(r, 1, 32, f);
	fclose(f);
}

static void poly1305_b2n_le(mpz_t n, uint8_t *b, uint8_t s, uint8_t init)
{
	mpz_set_ui(n, init);
	for (int8_t i = s - 1; i >= 0; i--)
	{
		mpz_mul_ui(n, n, 256);
		mpz_add_ui(n, n, b[i]);
	}
}

static void poly1305_dump(char *p, mpz_t n)
{
	char *nh = mpz_get_str(NULL, 16, n);
	printf("%s = %s\n", p, nh);
	free(nh);
}

//bS and bR are read little-endian and 16-bytes
//return value must be freed
uint8_t* poly1305(uint8_t* bR, uint8_t* bS, uint8_t* bM, uint32_t bMs)
{
	uint8_t bP[] =
	{
		0xfb, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0x03
	};

	poly1305_clamp(bR);

	mpz_t P, r, s, Acc, b;
	mpz_init(P);
	mpz_init(b);
	mpz_init(r);
	mpz_init(s);
	mpz_init(Acc);
	mpz_set_ui(Acc, 0);
	poly1305_b2n_le(P, bP, 17, 0);
	poly1305_b2n_le(s, bS, 16, 0);
	poly1305_b2n_le(r, bR, 16, 0);

	for (uint64_t i = 0;; i++)
	{
		uint64_t bytesLeft = bMs - (i * 16);
		poly1305_b2n_le(b, bM + i * 16, bytesLeft < 16 ? bytesLeft : 16, 1);
		mpz_add(Acc, Acc, b);
		mpz_mul(Acc, Acc, r);
		mpz_mod(Acc, Acc, P);
		if (bytesLeft < 16) break;
	}
	mpz_add(Acc, Acc, s);

	uint8_t *ret = malloc(16);
	for (uint8_t i = 0; i < 16; i++)
	{
		ret[i] = mpz_get_ui(Acc);
		mpz_div_ui(Acc, Acc, 256);
	}
	mpz_clear(P);
	mpz_clear(b);
	mpz_clear(r);
	mpz_clear(s);
	mpz_clear(Acc);
	return ret;
}

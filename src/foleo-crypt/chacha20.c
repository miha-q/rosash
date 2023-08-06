#include <stdio.h>
#include <stdint.h>


static uint32_t chacha20_lr(uint32_t a, uint8_t b)
{
	return (a << b) | (a >> (32 - b));
}

static void chacha20_QR(uint32_t *cc, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	cc[a] += cc[b]; cc[d] ^= cc[a]; cc[d] = chacha20_lr(cc[d], 16);
	cc[c] += cc[d]; cc[b] ^= cc[c]; cc[b] = chacha20_lr(cc[b], 12);
	cc[a] += cc[b]; cc[d] ^= cc[a]; cc[d] = chacha20_lr(cc[d], 8);
	cc[c] += cc[d]; cc[b] ^= cc[c]; cc[b] = chacha20_lr(cc[b], 7);
}

static void chacha20_DR(uint32_t *cc)
{
	chacha20_QR(cc, 0, 4,  8, 12);
	chacha20_QR(cc, 1, 5,  9, 13);
	chacha20_QR(cc, 2, 6, 10, 14);
	chacha20_QR(cc, 3, 7, 11, 15);
	chacha20_QR(cc, 0, 5, 10, 15);
	chacha20_QR(cc, 1, 6, 11, 12);
	chacha20_QR(cc, 2, 7,  8, 13);
	chacha20_QR(cc, 3, 4,  9, 14);
}

static void chacha20_CB(uint32_t *cc)
{
	uint8_t i;
	uint32_t x[16];
	for (i = 0; i < 16; i++)
	{
		x[i] = cc[i];
	}
	for (i = 0; i < 10; i++)
	{
		chacha20_DR(cc);
	}
	for (i = 0; i < 16; i++)
	{
		cc[i] += x[i];
	}
}

static void chacha20_S(uint32_t *cc, uint8_t *cs)
{
	for (uint8_t i = 0; i < 16; i++)
	{
		cs[4 * i] = (cc[i] & 0xFF);
		cs[4 * i + 1] = ((cc[i] >> 8) & 0xFF);
		cs[4 * i + 2] = ((cc[i] >> 16) & 0xFF);
		cs[4 * i + 3] = ((cc[i] >> 24) & 0xFF);
	}
}

uint8_t* chacha20(uint8_t key[32], uint8_t nonce[12], uint32_t block)
{
	uint32_t cc[] =
	{
       0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,

	   key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24),
	   key[4] | (key[5] << 8) | (key[6] << 16) | (key[7] << 24),
	   key[8] | (key[9] << 8) | (key[10] << 16) | (key[11] << 24),
	   key[12] | (key[13] << 8) | (key[14] << 16) | (key[15] << 24),

	   key[16] | (key[17] << 8) | (key[18] << 16) | (key[19] << 24),
	   key[20] | (key[21] << 8) | (key[22] << 16) | (key[23] << 24),
	   key[24] | (key[25] << 8) | (key[26] << 16) | (key[27] << 24),
	   key[28] | (key[29] << 8) | (key[30] << 16) | (key[31] << 24),

       block,

	   nonce[0] | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24),
	   nonce[4] | (nonce[5] << 8) | (nonce[6] << 16) | (nonce[7] << 24),
	   nonce[8] | (nonce[9] << 8) | (nonce[10] << 16) | (nonce[11] << 24)
	};

	//for (uint8_t i = 0; i < 16; i++)
	//{
	//	if (i % 4 == 0) printf("\n");
	//	printf("%08X ", cc[i]);
	//}
	//putchar('\n');

	chacha20_CB(cc);
	uint8_t* cs = malloc(64);
	chacha20_S(cc, cs);
	return cs;
}


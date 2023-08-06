#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "foleo-crypt/chacha20.c"
#include "foleo-crypt/sha256.c"
#include "foleo-crypt/poly1305.c"
#include "foleo-crypt/rsa.c"

void main()
{

    uint8_t key[] =
    {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t block = 1;
    uint8_t* r = chacha20(key, nonce, block);

    for (uint8_t i = 0; i < 64; i++)
        printf("%02X ", r[i]);
    putchar('\n');
    free(r);

    r = chacha20(key, nonce, ++block);

    for (uint8_t i = 0; i < 64; i++)
        printf("%02X ", r[i]);
    putchar('\n');
    free(r);

    /*
    mpz_t n;
    mpz_init(n);

    uint8_t *p = prigen(128);
    uint8_t *q = prigen(128);
    uint8_t e[] = { 1, 0, 1 };

    rsakey_t kv = rsa_private(p, 128, q, 128, e, 3);
    rsakey_t kb = rsa_public(p, 128, q, 128, e, 3);

    uint8_t plaintext[] = "The quick brown fox.";
    //gmp_printf("c=|%Zd|\n", n);


    uint8_t *ciphertext = rsa_encrypt(kb, RSA_OAEP, plaintext, strlen(plaintext) + 1);

    //pbuf(ciphertext, 256);
    uint16_t newsize;
    uint8_t *newplaintext = rsa_decrypt(kv, RSA_OAEP, ciphertext, &newsize);

    printf(">%s<\n", newplaintext);

    //pbuf(newplaintext, 256);
    
//
    //if (newplaintext == NULL)
    //{
    //    printf("failed\n");
    //}
//
//
    //printf("%s\n", plaintext);
    ////printf("%s\n", ciphertext);
    //printf("%i\n", newsize);

    free(ciphertext);
    free(newplaintext);

    free(p);
    free(q);
    rsa_free(kv);
    rsa_free(kb);

    */
}


/*


	uint8_t bS[] =
	{
		0x01, 0x03, 0x80, 0x8a,
		0xfb, 0x0d, 0xb2, 0xfd,
		0x4a, 0xbf, 0xf6, 0xaf,
		0x41, 0x49, 0xf5, 0x1b
	};
	uint8_t bR[] =
	{
		0x85, 0xd6, 0xbe, 0x78,
		0x57, 0x55, 0x6d, 0x33,
		0x7f, 0x44, 0x52, 0xfe,
		0x42, 0xd5, 0x06, 0xa8
	};

	uint8_t msg[] =
	{
		0x43, 0x72, 0x79, 0x70,
		0x74, 0x6f, 0x67, 0x72,
		0x61, 0x70, 0x68, 0x69,
		0x63, 0x20, 0x46, 0x6f,
	
  		0x72, 0x75, 0x6d, 0x20,
		0x52, 0x65, 0x73, 0x65,
		0x61, 0x72, 0x63, 0x68,
		0x20, 0x47, 0x72, 0x6f,

  		0x75, 0x70,
	};

    uint8_t* r = poly1305(bR, bS, msg, sizeof(msg));

    for (uint8_t i = 0; i < 16; i++)
    {
        printf("%02X ", r[i]);
    }
    putchar('\n');

    free(r);


*/
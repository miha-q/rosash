#ifndef __SHA256__
#define __SHA256__
#include <stdio.h>
#include <stdint.h>

static uint32_t sha256_rr(uint32_t a, uint32_t b)
{
    return (a >> b) | (a << (32 - b));
}

static uint32_t sha256_init[] =
{
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

static uint32_t sha256_h[] =
{
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

static uint32_t sha256_k[] =
{
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_process_block(uint32_t *p)
{

    uint8_t i;
    uint32_t w[64];
    for (i = 0; i < 64; i++) w[i] = 0;
    for (i = 0; i < 16; i++) w[i] = p[i];
    
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t s0, s1, t1, t2, ch, maj;
    for (i = 16; i < 64; i++)
    {
        s0 = sha256_rr(w[i - 15], 7) ^ sha256_rr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        s1 = sha256_rr(w[i - 2], 17) ^ sha256_rr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    i = 0;
    
    A = sha256_h[0];
    B = sha256_h[1];
    C = sha256_h[2];
    D = sha256_h[3];
    E = sha256_h[4];
    F = sha256_h[5];
    G = sha256_h[6];
    H = sha256_h[7];

    for (i = 0; i < 64; i++)
    {
        s1 = sha256_rr(E, 6) ^ sha256_rr(E, 11) ^ sha256_rr(E, 25);
        ch = (E & F) ^ ((~E) & G);
        t1 = H + s1 + ch + sha256_k[i] + w[i];
        s0 = sha256_rr(A, 2) ^ sha256_rr(A, 13) ^ sha256_rr(A, 22);
        maj = (A & B) ^ (A & C) ^ (B & C);
        t2 = s0 + maj;

        H = G;
        G = F;
        F = E;
        E = D + t1;
        D = C;
        C = B;
        B = A;
        A = t1 + t2;
    }

    sha256_h[0] += A;
    sha256_h[1] += B;
    sha256_h[2] += C;
    sha256_h[3] += D;
    sha256_h[4] += E;
    sha256_h[5] += F;
    sha256_h[6] += G;
    sha256_h[7] += H;

}

static uint32_t* sha256_pad(uint8_t* msg, uint32_t size, uint32_t* newsize)
{
    uint64_t osize = size * 8;
    uint8_t *msg_padded = malloc(size);
    for (uint64_t i = 0; i < size; i++)
    {
        msg_padded[i] = msg[i];
    }
    if (size % 64 != 0 || size == 0)
    {
        msg_padded = realloc(msg_padded, size + 1);
        msg_padded[size] = 0x80;
        size++;

        while ((size + 8) % 64 != 0)
        {
            msg_padded = realloc(msg_padded, size + 1);
            msg_padded[size] = 0;
            size++;
        }

        msg_padded = realloc(msg_padded, size + 8);
        msg_padded[size + 0] = (osize >> 56) & 0xFF;
        msg_padded[size + 1] = (osize >> 48) & 0xFF;
        msg_padded[size + 2] = (osize >> 40) & 0xFF;
        msg_padded[size + 3] = (osize >> 32) & 0xFF;
        msg_padded[size + 4] = (osize >> 24) & 0xFF;
        msg_padded[size + 5] = (osize >> 16) & 0xFF;
        msg_padded[size + 6] = (osize >>  8) & 0xFF;
        msg_padded[size + 7] = (osize >>  0) & 0xFF;
        size += 8;
    }
    
    uint32_t* output = malloc((size / 4) * sizeof(uint32_t));
    for (uint64_t i = 0; i < size / 4; i++)
    {
        output[i] = msg_padded[i * 4] << 24;
        output[i] |= msg_padded[i * 4 + 1] << 16;
        output[i] |= msg_padded[i * 4 + 2] << 8;
        output[i] |= msg_padded[i * 4 + 3];
    }
    free(msg_padded);
    *newsize = size / 4;
    return output;
}

uint8_t* sha256(uint8_t* msg, uint32_t size)
{
    //set initial state
    for (uint8_t i = 0; i < sizeof(sha256_h) / sizeof(uint32_t); i++)
    {
        sha256_h[i] = sha256_init[i];
    }

    //pad the message
    uint32_t newsize;
    uint32_t* padded = sha256_pad(msg, size, &newsize);

    //run the algorithm
    for (uint32_t i = 0; i < newsize / 16; i++)
    {
        sha256_process_block(padded + (i * 16));
    }
    
    //done
    free(padded);

    //breakout
    uint8_t* out = malloc(sizeof(sha256_h) * sizeof(uint32_t));
    for (uint32_t i = 0; i < sizeof(sha256_h); i++)
    {
        out[i * sizeof(uint32_t) + 0] = sha256_h[i] >> 24;
        out[i * sizeof(uint32_t) + 1] = sha256_h[i] >> 16;
        out[i * sizeof(uint32_t) + 2] = sha256_h[i] >>  8;
        out[i * sizeof(uint32_t) + 3] = sha256_h[i];
    }
    return out;
}
#endif
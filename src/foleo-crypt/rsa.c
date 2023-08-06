#ifndef __RSA__
#define __RSA__
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmp.h>
#include "shared.c"
#include "prigen.c"
#define RSA_ENCRYPTION 1
#define RSA_SIGNATURE 2
#define RSA_OAEP 3
#define RSA_PSS 4

typedef struct
{
    mpz_t n, k;
    uint16_t bitWidth;
} rsakey_t;

//Keys and their sizes in terms of BYTES
rsakey_t rsa_public(uint8_t* p, uint16_t pS, uint8_t* q, uint16_t qS, uint8_t* e, uint16_t eS)
{
    mpz_t np, nq, ne;
    mpz_init(np);
    mpz_init(nq);
    mpz_init(ne);
    mpz_set_ui(np, 0);
    mpz_set_ui(nq, 0);
    mpz_set_ui(ne, 0);

    load(np, p, pS);
    load(nq, q, qS);
    load(ne, q, qS);

    rsakey_t ret;
    ret.bitWidth = (pS + qS) * 8;
    mpz_init(ret.n);
    mpz_init(ret.k);
    mpz_mul(ret.n, np, nq);
    mpz_set(ret.k, ne);

    mpz_clear(np);
    mpz_clear(nq);
    mpz_clear(ne);
    return ret;
}

rsakey_t rsa_private(uint8_t* p, uint16_t pS, uint8_t* q, uint16_t qS, uint8_t* e, uint16_t eS)
{
    mpz_t np, nq, ne;
    mpz_init(np);
    mpz_init(nq);
    mpz_init(ne);
    mpz_set_ui(np, 0);
    mpz_set_ui(nq, 0);
    mpz_set_ui(ne, 0);

    load(np, p, pS);
    load(nq, q, qS);
    load(ne, q, qS);

    rsakey_t ret;
    ret.bitWidth = (pS + qS) * 8;
    mpz_init(ret.n);
    mpz_init(ret.k);
    mpz_mul(ret.n, np, nq);
    mpz_set(ret.k, ne);

    mpz_sub_ui(np, np, 1);
    mpz_sub_ui(nq, nq, 1);
    mpz_mul(np, np, nq);
    mpz_invert(ret.k, ret.k, np);

    mpz_clear(np);
    mpz_clear(nq);
    mpz_clear(ne);
    return ret;
}

rsakey_t rsa_open(uint8_t *bufferK, uint16_t byteSizeK, uint8_t *bufferN, uint16_t byteSizeN)
{
    rsakey_t ret;
    ret.bitWidth = byteSizeN * 8;
    mpz_init(ret.k);
    mpz_init(ret.n);
    mpz_set_ui(ret.k, 0);
    mpz_set_ui(ret.n, 0);

    load(ret.k, bufferK, byteSizeK);
    load(ret.n, bufferN, byteSizeN);
 
    return ret;
}

void rsa_free(rsakey_t key)
{
    key.bitWidth = -1;
    mpz_clear(key.n);
    mpz_clear(key.k);
}

//convert to PKCS#1 v1.5 encryption block
//  note this is considered insecure and OAEP should be used instead
//  OAEP is handled by a separate library in this framework
static uint8_t* RSA_Pad(uint16_t size, uint8_t *buffer, uint16_t bufferSizeInBytes)
{
    size /= 8;
    if (bufferSizeInBytes - 11 > size)
    {
        return NULL;
    }
    uint8_t *block = malloc(size);
    uint16_t i = 0;
    block[i++] = 0x00;
    block[i++] = 0x02;

    uint16_t psLen = size - (3 + bufferSizeInBytes);
    uint8_t *ps = malloc(psLen);
    FILE *f = fopen(DEVICE, "r");
    fread(ps, 1, psLen, f);

    for (uint16_t j = 0; j < psLen; j++)
    {
        while (ps[j] == 0x00)
        {
            ps[j] = fgetc(f);
        }
        block[i++] = ps[j];
    }
    free(ps);

    block[i++] = 0x00;
    fclose(f);

    for (uint16_t j = 0; j < bufferSizeInBytes; j++)
    {
        block[i++] = buffer[j];
    }
    return block;
}

//Removes the PKCS#1 v1.5 padding scheme
static uint8_t* RSA_DePad(uint16_t size, uint8_t *block, uint16_t *bufferSizeInBytes)
{
    uint16_t i = 2;
    if (block[0] != 0x00 || (block[1] != 0x01 && block[1] != 0x02))
    {
        *bufferSizeInBytes = -1;
        return NULL;
    }
    while (block[i++] != 0)
    {
        if (i == size / 8)
        { 
            *bufferSizeInBytes = -1;
            return NULL;
        }
    }
    if (i < 11)
    {
        *bufferSizeInBytes = -1;
        return NULL;
    }
    
    *bufferSizeInBytes = (size / 8) - i;
    uint8_t *buffer = malloc(*bufferSizeInBytes);
    for (uint16_t j = 0; i < (size / 8); i++)
    {
        buffer[j++] = block[i];
    }
    return buffer;
}

//convert to PKCS#1 v1.5 signature block
//  note this is NOT considered insecure but PSS is often used instead
//  PSS is handled by a separate library in this framework
static uint8_t* RSA_PadSig(uint16_t size, uint8_t *buffer, uint16_t bufferSizeInBytes)
{
    size /= 8;
    if (bufferSizeInBytes - 11 > size)
    {
        return NULL;
    }
    uint8_t *block = malloc(size);
    uint16_t i = 0;
    block[i++] = 0x00;
    block[i++] = 0x01;

    uint16_t psLen = size - (3 + bufferSizeInBytes);
    for (uint16_t j = 0; j < psLen; j++)
    {
        block[i++] = 0xFF;
    }

    block[i++] = 0x00;

    for (uint16_t j = 0; j < bufferSizeInBytes; j++)
    {
        block[i++] = buffer[j];
    }
    return block;
}

uint8_t *RSA_Apply(rsakey_t key, uint8_t *block)
{
    uint8_t *newblock = malloc(key.bitWidth / 8);
    mpz_t n;
    mpz_init(n);
    mpz_set_ui(n, 0);

    load(n, block, key.bitWidth / 8);
    mpz_powm(n, n, key.k, key.n);
    store(n, newblock, key.bitWidth / 8);

    mpz_clear(n);
    return newblock;
}


uint8_t* RSA_MGF1(uint8_t* (hashfunc)(uint8_t*, uint32_t), uint32_t hashsize, uint8_t* seed, uint32_t seedsize, uint32_t totalsize)
{
    uint8_t* premask = malloc(seedsize + sizeof(uint32_t));
    for (uint32_t i = 0; i < seedsize; i++) premask[i] = seed[i];

    uint8_t* mask = malloc(0);
    for (uint32_t counter = 0; counter * hashsize < totalsize; counter++)
    {
        premask[seedsize + 0] = counter >> 24; 
        premask[seedsize + 1] = counter >> 16; 
        premask[seedsize + 2] = counter >> 8; 
        premask[seedsize + 3] = counter;

        uint8_t* postmask = hashfunc(premask, seedsize + sizeof(uint32_t));
        mask = realloc(mask, (counter + 1) * hashsize);
        for (uint32_t i = 0; i < hashsize; i++)
        {
            mask[counter * hashsize + i] = postmask[i];
        }
        free(postmask);
    }
    free(premask);
    return mask;
}

/*this uses sha-256*/
static uint8_t* RSA_PadOAEP(uint16_t size, uint8_t *buffer, uint16_t mLen)
{
    uint32_t kLen = size / 8; //length of RSA modulus
    uint32_t hLen = 32; //length of hash output
    uint32_t mmLen = kLen - 2 * hLen - 2; //maximum message length
    uint32_t psLen = kLen - mLen - 2 * hLen - 2; //padding string length
    uint32_t dbLen = hLen + psLen + 1 + mLen; //datablock length
    if (mLen > mmLen)
    {
        return NULL;
    }

    //Build Seed
    uint8_t Seed[hLen];
    FILE* f = fopen(DEVICE, "r");
    fread(Seed, 1, hLen, f);
    fclose(f);

    //Build DB
    uint8_t* HashL = sha256(NULL, 0);
    uint8_t DB[dbLen];
    uint32_t pos = 0;
    for (uint32_t i = 0; i < hLen; i++) DB[pos++] = HashL[i];
    free(HashL);
    for (uint32_t i = 0; i < psLen; i++) DB[pos++] = 0x00;
    DB[pos++] = 0x01;
    for (uint32_t i = 0; i < mLen; i++) DB[pos++] = buffer[i];

    //Mask DB
    uint8_t* DBMask = RSA_MGF1(sha256, hLen, Seed, hLen, dbLen);
    for (uint32_t i = 0; i < dbLen; i++) DB[i] ^= DBMask[i];
    free(DBMask);

    //Mask Seed
    uint8_t* SeedMask = RSA_MGF1(sha256, hLen, DB, dbLen, hLen);
    for (uint32_t i = 0; i < hLen; i++) Seed[i] ^= SeedMask[i];
    free(SeedMask);
    
    //Finalize
    uint8_t* out = malloc(1 + hLen + dbLen);
    pos = 0;
    out[pos++] = 0x00;
    for (uint32_t i = 0; i < hLen; i++) out[pos++] = Seed[i];
    for (uint32_t i = 0; i < dbLen; i++) out[pos++] = DB[i];
    return out;
}

//Removes the OAEP padding scheme
static uint8_t* RSA_DeOAEP(uint16_t size, uint8_t *block, uint16_t *bufferSizeInBytes)
{
    if (block[0] != 0x00) return NULL;
    uint32_t kLen = size / 8; //length of RSA modulus
    uint32_t hLen = 32; //length of hash output
    uint32_t dbLen = kLen - hLen - 1; //datablock length

    //Grab the masks
    uint8_t MaskedSeed[hLen];
    for (uint32_t i = 0; i < hLen; i++) MaskedSeed[i] = block[i + 1];
    uint8_t MaskedDB[dbLen];
    for (uint32_t i = 0; i < dbLen; i++) MaskedDB[i] = block[i + 1 + hLen];

    //Recover the original Seed
    uint8_t* Seed = RSA_MGF1(sha256, hLen, MaskedDB, dbLen, hLen);
    for (uint32_t i = 0; i < hLen; i++) Seed[i] ^= MaskedSeed[i];

    //Recover the original DB
    uint8_t* SeedMask = RSA_MGF1(sha256, hLen, Seed, hLen, dbLen);
    for (uint32_t i = 0; i < dbLen; i++) MaskedDB[i] ^= SeedMask[i];
    free(Seed);
    free(SeedMask);

    //Verify the padding
    uint32_t pos = hLen;
    while (MaskedDB[pos] == 0)
        if ((++pos) == dbLen - 1) return NULL;
    if (MaskedDB[pos] != 0x01) return NULL;
    pos++;

    //Extract the data
    uint32_t outlen = dbLen - pos;
    uint8_t* out = malloc(outlen);
    for (uint32_t i = 0; i < outlen; i++)
    {
        out[i] = MaskedDB[pos++];
    }
    
    *bufferSizeInBytes = outlen;
    return out;
}



uint8_t* rsa_encrypt(rsakey_t key, uint8_t padding, uint8_t *buffer, uint16_t bufferSize)
{
    uint8_t* block;
    uint8_t* eblock;
    if (padding == RSA_ENCRYPTION)
    {
        block = RSA_Pad(key.bitWidth, buffer, bufferSize);
        eblock = RSA_Apply(key, block);
        free(block);
    }
    else if (padding == RSA_SIGNATURE)
    {
        block = RSA_PadSig(key.bitWidth, buffer, bufferSize);
        eblock = RSA_Apply(key, block);
        free(block);
    }
    else if (padding == RSA_OAEP)
    {
        block = RSA_PadOAEP(key.bitWidth, buffer, bufferSize);
        eblock = RSA_Apply(key, block);
        free(block);
    }
    else
    {
        eblock = RSA_Apply(key, buffer);
    }
    return eblock;
}

uint8_t* rsa_decrypt(rsakey_t key, uint8_t padding, uint8_t *eblock, uint16_t *bufferSize)
{
    uint8_t* block;
    uint8_t* buffer;
    if (padding == RSA_ENCRYPTION || padding == RSA_SIGNATURE)
    {
        block = RSA_Apply(key, eblock);
        buffer = RSA_DePad(key.bitWidth, block, bufferSize);
        free(block);
    }
    else if (padding == RSA_OAEP)
    {
        block = RSA_Apply(key, eblock);
        buffer = RSA_DeOAEP(key.bitWidth, block, bufferSize);
        free(block);
    }
    else
    {
        buffer = RSA_Apply(key, eblock);
    }
    return buffer;
}
#endif
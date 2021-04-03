#include "../inc/sha1.h"

uchar* sha1HexDigest(SHA1_CTX* sha1)
{
    uint len = DIGEST_SIZE * 2 + 1;
    uchar* digest = (uchar*)malloc( len * sizeof(uchar)); // for null
    memset(digest, 0, len);
    for(uint i = 0; i < H_SIZE; ++i)
        sprintf_s(digest + i * 8, 9, "%08x", sha1->H[i]);
    digest[DIGEST_SIZE * 2] = 0;
    return digest;
}
SHA1_CTX* sha1Init()
{
    SHA1_CTX* sha1 = (SHA1_CTX*)malloc(sizeof(SHA1_CTX));
    sha1->H[0] = 0x67452301U;
    sha1->H[1] = 0xEFCDAB89U;
    sha1->H[2] = 0x98BADCFEU;
    sha1->H[3] = 0x10325476U;
    sha1->H[4] = 0xC3D2E1F0U;

    memset(sha1->block, 0, BLOCK_SIZE * sizeof(uchar));
    memset(sha1->W, 0, W_SIZE * sizeof(uint));

    sha1->offset = 0;
    sha1->totalSize = 0;
}
void sha1ProcessBlock(SHA1_CTX* sha1)
{
    uint A = sha1->H[0];
    uint B = sha1->H[1];
    uint C = sha1->H[2];
    uint D = sha1->H[3];
    uint E = sha1->H[4];
    
    uint* W = sha1->W;
    uchar* block = sha1->block;
    
    uint i = 0;
    for(i = 0; i < 16; ++i)
        W[i] = toInt(&block[i * 4]);
    for(i; i < W_SIZE; ++i)
        W[i] = rol32( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);

    for(uint i = 0; i < W_SIZE; ++i)
    {
        uint temp = rol32(A, 5) + E + W[i];

        if(i < 20)
            temp += F_00_19(B, C, D) + K_00_19;
        else if(i < 40)
            temp += F_20_39(B, C, D) + K_20_39;
        else if(i < 60)
            temp += F_40_59(B, C, D) + K_40_59;
        else
            temp += F_60_79(B, C, D) + K_60_79;

        E = D;
        D = C;
        C = rol32(B, 30);
        B = A;
        A = temp;
    }
    memset(sha1->block, 0, BLOCK_SIZE);

    sha1->H[0] += A;
    sha1->H[1] += B;
    sha1->H[2] += C;
    sha1->H[3] += D;
    sha1->H[4] += E;
}
void sha1Append(SHA1_CTX* sha1, const void* data, uint len)
{
    uint n = 0;
    while(len > 0)
    {
        n = MIN(len, BLOCK_SIZE - sha1->offset);
        for(int i = 0; i < n; ++i)
            sha1->block[sha1->offset++] = ((uchar*)data)[i];
        sha1->totalSize += n * 8;
        data = (uchar*)data + n;
        len -= n;
        if(sha1->offset == 64)
        {
            sha1ProcessBlock(sha1);
            sha1->offset = 0;
        }
    }
}
void sha1Final(SHA1_CTX* sha1)
{
    sha1->block[sha1->offset++] = 128; // 1000000 in bin
    uint off = sha1->offset;
    if(sha1->offset < 55)
        memset(sha1->block + off, 0, (BLOCK_SIZE - 9 - off) * sizeof(uchar));
    else
    {
        memset(sha1->block + off, 0, (BLOCK_SIZE - off) * sizeof(uchar));
        sha1ProcessBlock(sha1);
        sha1->offset = 0;
        memset(sha1->block, 0, (BLOCK_SIZE - 9) * sizeof(uchar));
    }
    
    for(uint i = 1, shift = 0; i < 9; ++i, shift += 8)
        sha1->block[BLOCK_SIZE - i] = (sha1->totalSize >> shift) & 0xff;
    sha1ProcessBlock(sha1);
}
#include <mem.h>
#include <stdlib.h>
#include <stdio.h>

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long long uint64;

#define BLOCK_SIZE 64
#define DIGEST_SIZE 20
#define H_SIZE 5
#define W_SIZE 80

#define K_00_19 0x5A827999U
#define K_20_39 0x6ED9EBA1U
#define K_40_59 0x8F1BBCDCU
#define K_60_79 0xCA62C1D6U

#define toInt(bytes) (((bytes)[0])<<24)+(((bytes)[1])<<16)+(((bytes)[2])<<8)+((bytes)[3])

#define F_00_19(m, l, k) (((m)&(l)) | (~(m)&(k)))
#define F_20_39(m, l, k) ((m)^(l)^(k))
#define F_40_59(m, l, k) (((m)&(l))|((m)&(k))|((l)&(k)))
#define F_60_79(m, l, k) ((m)^(l)^(k))

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define rol32(a, n) _rotl((a), (n))

struct SHA1_CTX
{
    uchar block[BLOCK_SIZE];

    uint H[H_SIZE];
    uint W[W_SIZE];

    uint64 totalSize; // total size in bits
    uint64 offset;
};

typedef struct SHA1_CTX SHA1_CTX;

uchar* sha1HexDigest(SHA1_CTX* sha1);

SHA1_CTX* sha1Init();
void sha1Append(SHA1_CTX* sha1, const void* data, uint len);
void sha1Final(SHA1_CTX* sha1);
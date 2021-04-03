#include <stdio.h>
#include <stdlib.h>

#include "inc/sha1.h"

#define LEN 555

int main()
{
    unsigned char* a = (unsigned char*)malloc(LEN * sizeof(unsigned char));
    memset(a, 'a', LEN * sizeof(unsigned char));

    SHA1_CTX* sha = sha1Init();
    sha1Append(sha, a, LEN);
    sha1Final(sha);

    unsigned char* hex = sha1HexDigest(sha);
    printf("%s\n", hex);  // hex value: b5e8dd8c9c207648635a6c4084e2b6c4c68d1eff
    free(hex);
    
    free(sha);

    return 0;
}
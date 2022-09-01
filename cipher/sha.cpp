#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include "sha.h"

typedef 
unsigned char* (*SHA_PROC)(const unsigned char*, size_t, unsigned char*);

static 
SHA_PROC sha_proc_table[] = {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
};

static 
size_t sha_len_table[] = {
    SHA_DIGEST_LENGTH,
    SHA224_DIGEST_LENGTH,
    SHA256_DIGEST_LENGTH,
    SHA384_DIGEST_LENGTH,
    SHA512_DIGEST_LENGTH,
};

bool 
sha_crypt(const void* data, int size, std::string& digest, SecureHashAlgorithm agorithm, bool hex_or_binarys) noexcept {
    if (NULL == data || size < 1) {
        return false;
    }
    if (agorithm < SecureHashAlgorithm_Sha1 || agorithm > SecureHashAlgorithm_Sha512) {
        return false;
    }
    unsigned char digest_sz[SHA512_DIGEST_LENGTH];
    size_t digest_sz_len = sha_len_table[(int)agorithm];
    SHA_PROC sha_proc = sha_proc_table[(int)agorithm];
    sha_proc((unsigned char*)data, size, digest_sz);
    if (!hex_or_binarys) {
        digest = std::string((char*)digest_sz, digest_sz_len);
    } 
    else {
        char hex_sz[SHA512_DIGEST_LENGTH * 2];
        for (size_t i = 0; i < digest_sz_len; i++) {
            int ch = digest_sz[i];
            sprintf(hex_sz + (i * 2), "%02X", ch);
        }
        digest = std::string(hex_sz, digest_sz_len * 2);
    }
    return true;
}
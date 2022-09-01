#pragma once

#include <stdio.h>

#ifndef RC4_MAXBIT
#define RC4_MAXBIT 0xff
#endif

inline bool
rc4_sbox_impl(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen, bool ascending) noexcept {
    if (NULL == sbox || NULL == key || keylen < 1 || sboxlen < 1) {
        return false;
    }

    for (int i = 0; i < sboxlen; i++) {
        if (ascending) {
            sbox[i] = (unsigned char)i;
        }
        else {
            sbox[sboxlen - (i + 1)] = (unsigned char)i;
        }
    }

    for (int i = 0, j = 0; i < sboxlen; i++) {
        j = (j + sbox[i] + key[i % keylen]) % sboxlen;
        unsigned char b = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = b;
    }

    return true;
}

inline bool
rc4_sbox(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept {
    return rc4_sbox_impl(sbox, sboxlen, key, keylen, true);
}

inline bool
rc4_sbox_descending(unsigned char* sbox, int sboxlen, unsigned char* key, int keylen) noexcept {
    return rc4_sbox_impl(sbox, sboxlen, key, keylen, false);
}

inline bool
rc4_crypt_sbox(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept {
    if (NULL == key || keylen < 1 || NULL == data || datalen < 1 || NULL == sbox || sboxlen < 1) {
        return false;
    }

    unsigned char x = (unsigned char)(E ? subtract : -subtract);
    for (int i = 0, low = 0, high = 0, mid; i < datalen; i++) {
        low = low % sboxlen;
        high = (high + sbox[i % sboxlen]) % sboxlen;

        unsigned char b = sbox[low];
        sbox[low] = sbox[high];
        sbox[high] = b;

        mid = (sbox[low] + sbox[high]) % sboxlen;
        if (E) {
            data[i] = (unsigned char)((data[i] ^ sbox[mid]) - x);
        }
        else {
            data[i] = (unsigned char)((data[i] - x) ^ sbox[mid]);
        }
    }

    return true;
}

inline bool
rc4_crypt_sbox_c(unsigned char* key, int keylen, unsigned char* sbox, int sboxlen, unsigned char* data, int datalen, int subtract, int E) noexcept {
    if (NULL == key || keylen < 1 || NULL == data || datalen < 1 || NULL == sbox || sboxlen < 1) {
        return false;
    }

    unsigned char x = (unsigned char)(E ? subtract : -subtract);
    for (int i = 0, low = 0, high = 0, mid; i < datalen; i++) {
        low = (low + keylen) % sboxlen;
        high = (high + sbox[i % sboxlen]) % sboxlen;

        unsigned char b = sbox[low];
        sbox[low] = sbox[high];
        sbox[high] = b;

        mid = (sbox[low] + sbox[high]) % sboxlen;
        if (E) {
            data[i] = (unsigned char)((data[i] ^ sbox[mid]) - x);
        }
        else {
            data[i] = (unsigned char)((data[i] - x) ^ sbox[mid]);
        }
    }

    return true;
}

inline bool
rc4_crypt(unsigned char* key, int keylen, unsigned char* data, int datalen, int subtract, int E) noexcept {
    if (NULL == key || keylen < 1 || NULL == data || datalen < 1) {
        return false;
    }

    unsigned char sbox[RC4_MAXBIT];
    rc4_sbox(sbox, sizeof(sbox), key, keylen);

    return rc4_crypt_sbox(key, keylen, sbox, sizeof(sbox), data, datalen, subtract, E);
}
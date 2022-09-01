#include "Cipher.h"
#include "RC4.h"
#include "../cipher/rc4.h"
#include "../cipher/Encryptor.h"

RC4::RC4(const std::string& name, const std::string& key, const std::string& vk, Mode mode) noexcept
    : Cipher(name, key)
    , _vk(vk) 
    , _mode(mode) {
}

std::string RC4::SBox(const void* data, int datalen, Mode mode) noexcept {
    unsigned char sbox[RC4_MAXBIT];
    if (mode & Mode::Descending) {
        if (!rc4_sbox_descending(sbox, sizeof(sbox), (unsigned char*)data, datalen)) {
            return "";
        }
    }
    else {
        if (!rc4_sbox(sbox, sizeof(sbox), (unsigned char*)data, datalen)) {
            return "";
        }
    }
    return std::string((char*)sbox, sizeof(sbox));
}

std::shared_ptr<Byte> RC4::Encrypt(const void* data, int datalen, int& outlen) noexcept {
    outlen = 0;
    if (NULL == data || datalen < 1) {
        return NULL;
    }
    std::shared_ptr<Byte> buffer = make_shared_alloc<Byte>(datalen);
    memcpy(buffer.get(), data, datalen);

    std::shared_ptr<Byte> vk = make_shared_alloc<Byte>(this->_vk.size());
    memcpy(vk.get(), this->_vk.data(), this->_vk.size());
    struct {
        unsigned char*  key;
        int             keylen;
        unsigned char*  vk;
        int             vklen;
    } s;
    s.key               = (unsigned char*)this->Key.data();
    s.keylen            = this->Key.size();
    s.vk                = (unsigned char*)vk.get();
    s.vklen             = this->_vk.size();

    bool b;
    if (this->_mode & Mode::AlgorithmC) {
        b = rc4_crypt_sbox_c(s.key, s.keylen, s.vk, s.vklen, buffer.get(), datalen, 0, 0);
    }
    else {
        b = rc4_crypt_sbox(s.key, s.keylen, s.vk, s.vklen, buffer.get(), datalen, 0, 0);
    }
    if (!b) {
        return NULL;
    }
    else {
        outlen = datalen;
    }
    return buffer;
}

std::shared_ptr<Byte> RC4::Decrypt(const void* data, int datalen, int& outlen) noexcept {
    return this->Encrypt(data, datalen, outlen);
}

#define DEFINE_RC4_ALGORITHM_TYPE(DefineName, CipherName, Vk) \
DefineName::DefineName(const std::string& key, Mode mode) noexcept : RC4(CipherName, key, RC4::SBox(Vk, mode), mode) {}

DEFINE_RC4_ALGORITHM_TYPE(RC4MD5, "rc4-md5", ComputeMD5(key, true));
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA1, "rc4-sha1", ComputeSHA(key, SecureHashAlgorithm_Sha1));
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA224, "rc4-sha224", ComputeSHA(key, SecureHashAlgorithm_Sha224));
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA256, "rc4-sha256", ComputeSHA(key, SecureHashAlgorithm_Sha256));
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA386, "rc4-sha386", ComputeSHA(key, SecureHashAlgorithm_Sha386));
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA512, "rc4-sha512", ComputeSHA(key, SecureHashAlgorithm_Sha512));
#undef DEFINE_RC4_ALGORITHM_TYPE
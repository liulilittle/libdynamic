#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iostream>

#include "md5.h"
#include "sha.h"
#include "rc4.h"
#include "Encryptor.h"

Encryptor::Encryptor(const std::string& method, const std::string& password) noexcept
    : _cipher(NULL)
    , _method(method)
    , _password(password) {
    initKey(method, password);
    initCipher(_encryptCTX, 1);
    initCipher(_decryptCTX, 0);
}

void Encryptor::Initialize() noexcept {
    /* initialize OpenSSL */
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();
    ERR_load_EVP_strings();
    ERR_load_crypto_strings();
}

std::shared_ptr<Byte> Encryptor::Encrypt(Byte* data, int datalen, int& outlen) noexcept {
    outlen = 0;
    if (datalen < 0 || (NULL == data && datalen != 0)) {
        outlen = ~0;
        return NULL;
    }

    if (datalen == 0) {
        return NULL;
    }

    MutexScope scope(_encrypt_syncobj);
    if (NULL == _cipher) {
        return NULL;
    }

    // INIT-CTX
    if (EVP_CipherInit_ex(_encryptCTX.get(), _cipher, NULL, _key.get(), _iv.get(), 1) < 1) {
        return NULL;    
    }

    // ENCR-DATA
    int feedbacklen = datalen + EVP_CIPHER_block_size(_cipher);
    std::shared_ptr<Byte> cipherText = make_shared_alloc<Byte>(feedbacklen);  

    if (EVP_CipherUpdate(_encryptCTX.get(),
         cipherText.get(), &feedbacklen, data, datalen) < 1) {
        outlen = ~0;
        return NULL;
    }   

    outlen = feedbacklen;
    return cipherText;
}

std::shared_ptr<Byte> Encryptor::Decrypt(Byte* data, int datalen, int& outlen) noexcept {
    outlen = 0;
    if (datalen < 0 || (NULL == data && datalen != 0)) {
        outlen = ~0;
        return NULL;
    }

    if (datalen == 0) {
        return NULL;
    }

    MutexScope scope(_decrypt_syncobj);
    if (NULL == _cipher) {
        return NULL;
    }

    // INIT-CTX
    if (EVP_CipherInit_ex(_decryptCTX.get(), _cipher, NULL, _key.get(), _iv.get(), 0) < 1) {
        return NULL;    
    }

    // DECR-DATA
    int feedbacklen = datalen + EVP_CIPHER_block_size(_cipher);
    std::shared_ptr<Byte> cipherText = make_shared_alloc<Byte>(feedbacklen);
    
    if (EVP_CipherUpdate(_decryptCTX.get(), 
        cipherText.get(), &feedbacklen, data, datalen) < 1) {
        feedbacklen = ~0;
        return NULL;
    }
    
    outlen = feedbacklen;
    return cipherText;
}

void Encryptor::initCipher(std::shared_ptr<EVP_CIPHER_CTX>& context, int enc) {
    bool exception = false;
    do {
        if (NULL == context.get()) {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            context = std::shared_ptr<EVP_CIPHER_CTX>(ctx, [](EVP_CIPHER_CTX* context) noexcept {
                EVP_CIPHER_CTX_cleanup(context);
                EVP_CIPHER_CTX_free(context);
            });
            EVP_CIPHER_CTX_init(context.get());
            if ((exception = EVP_CipherInit_ex(context.get(), _cipher, NULL, NULL, NULL, enc) < 1)) {
                break;
            }
            if ((exception = EVP_CIPHER_CTX_set_key_length(context.get(), EVP_CIPHER_key_length(_cipher)) < 1)) {
                break;
            }
            if ((exception = EVP_CIPHER_CTX_set_padding(context.get(), 1) < 1)) {
                break;
            }
        }
    } while (0);
    if (exception) {
        context = NULL;
        throw std::runtime_error("There was a problem initializing the cipher that caused an exception to be thrown");
    }
}

bool Encryptor::Support(const std::string& method) noexcept {
    if (method.empty()) {
        return false;
    }
    return NULL != EVP_get_cipherbyname(method.data());
}

void Encryptor::initKey(const std::string& method, const std::string password) {
    _cipher = EVP_get_cipherbyname(method.data());
    if (NULL == _cipher) {
        throw std::runtime_error("Such encryption cipher methods are not supported");
    }

    std::shared_ptr<Byte> iv = make_shared_alloc<Byte>(EVP_CIPHER_iv_length(_cipher));

    _key = make_shared_alloc<Byte>(EVP_CIPHER_key_length(_cipher));
    if (EVP_BytesToKey(_cipher, EVP_md5(), NULL, (Byte*)password.data(), (int)password.length(),
        1, _key.get(), iv.get()) < 1) {
        iv = NULL;
        throw std::runtime_error("Bytes to key calculations cannot be performed using cipher with md5(md) key password iv key etc");
    }

    // INIT-IVV
    int ivLen = EVP_CIPHER_iv_length(_cipher);
    _iv = make_shared_alloc<Byte>(ivLen); // RAND_bytes(iv.get(), ivLen);

    std::stringstream ss; // MD5->RC4
    ss << "Ppp@";
    ss << method;
    ss << ".";
    ss << std::string((char*)_key.get(), EVP_CIPHER_key_length(_cipher));
    ss << ".";
    ss << password;

    ComputeMD5(ss.str(), _iv.get(), ivLen); // MD5::HEX
    rc4_crypt(_key.get(), EVP_CIPHER_key_length(_cipher), _iv.get(), ivLen, 0, 0);
}

std::string ComputeMD5(const std::string& s, bool toupper) noexcept {
    MD5 md5;
    md5.update(s);
    return md5.toString(toupper);
}

bool ComputeMD5(const std::string& s, const Byte* md5, int& md5len) noexcept {
    if (md5len < 1 || NULL == md5) {
        md5len = 0;
        return false;
    }
    else {
        md5len = md5len > (int)sizeof(MD5::HEX) ? (int)sizeof(MD5::HEX) : md5len;
    }
    MD5 m;
    m.update(s);
    memcpy((void*)md5, m.digest(), md5len);
    return true;
}

std::string ComputeSHA(const std::string& s, int algorithm) noexcept {
    std::string hash;
    if (!sha_crypt(s.data(), s.size(), hash, (SecureHashAlgorithm)algorithm, true)) {
        return "";
    }
    return hash;
}

bool ComputeSHA(const std::string& s, const Byte* digest, int& digestlen, int algorithm) noexcept {
    if (digestlen < 1 || NULL == digest) {
        digestlen = 0;
        return false;
    }
    else {
        digestlen = digestlen > (int)sizeof(MD5::HEX) ? (int)sizeof(MD5::HEX) : digestlen;
    }
    std::string hash;
    if (!sha_crypt(s.data(), s.size(), hash, (SecureHashAlgorithm)algorithm, false)) {
        digestlen = 0;
        return false;
    }
    int max = std::min<int>(hash.size(), digestlen);
    memcpy((void*)digest, (void*)hash.data(), max);
    return true;
}
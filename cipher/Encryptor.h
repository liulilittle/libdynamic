#pragma once

#include "../env.h"
#include "sha.h"
#include "md5.h"
    
class Encryptor : public std::enable_shared_from_this<Encryptor> {
public:
    typedef std::mutex                                  Mutex;
    typedef std::lock_guard<Mutex>                      MutexScope;

public:
    Encryptor(const std::string& method, const std::string& password) noexcept;

public:
    static void                                         Initialize() noexcept;
    static bool                                         Support(const std::string& method) noexcept;

public:
    std::shared_ptr<Byte>                               Encrypt(Byte* data, int datalen, int& outlen) noexcept;
    std::shared_ptr<Byte>                               Decrypt(Byte* data, int datalen, int& outlen) noexcept;
    inline std::shared_ptr<Encryptor>                   GetPtr() noexcept {
        return this->shared_from_this();
    }

private:
    void                                                initCipher(std::shared_ptr<EVP_CIPHER_CTX>& context, int enc);
    void                                                initKey(const std::string& method, const std::string password);

private:
    const EVP_CIPHER*                                   _cipher;
    std::shared_ptr<Byte>                               _key; // _cipher->key_len
    std::shared_ptr<Byte>                               _iv;
    std::string                                         _method;
    std::string                                         _password;
    std::shared_ptr<EVP_CIPHER_CTX>                     _encryptCTX;
    std::shared_ptr<EVP_CIPHER_CTX>                     _decryptCTX;
    Mutex                                               _encrypt_syncobj;
    Mutex                                               _decrypt_syncobj;
};

std::string                                             ComputeMD5(const std::string& s, bool toupper) noexcept;
bool                                                    ComputeMD5(const std::string& s, const Byte* md5, int& md5len) noexcept;
std::string                                             ComputeSHA(const std::string& s, int algorithm) noexcept;
bool                                                    ComputeSHA(const std::string& s, const Byte* digest, int& digestlen, int algorithm) noexcept;
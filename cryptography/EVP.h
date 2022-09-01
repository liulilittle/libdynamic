#pragma once 

#include "Cipher.h"
#include "../cipher/Encryptor.h"

class EVP : public Cipher {
public:
    EVP(const std::string& name, const std::string& key) noexcept;

public:
    static bool                                 Support(const std::string& name) noexcept;

public:
    virtual std::shared_ptr<Byte>               Encrypt(const void* data, int datalen, int& outlen) noexcept override;
    virtual std::shared_ptr<Byte>               Decrypt(const void* data, int datalen, int& outlen) noexcept override;

private:
    std::shared_ptr<Encryptor>                  _encryptor;
};
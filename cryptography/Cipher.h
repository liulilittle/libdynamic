#pragma once

#include "../env.h"

class Cipher {
protected:
    Cipher(const std::string& name, const std::string& key) noexcept;

public:
    virtual std::shared_ptr<Byte>   Encrypt(const void* data, int datalen, int& outlen) = 0;
    virtual std::shared_ptr<Byte>   Decrypt(const void* data, int datalen, int& outlen) = 0;
    static std::shared_ptr<Cipher>  Create(const std::string& name, const std::string& key);

public:
    const int                       Kf;
    const std::string               Name;
    const std::string               Key;
};
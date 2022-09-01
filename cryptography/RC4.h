#pragma once 

#include "Cipher.h"

class RC4 : public Cipher {
public:
    enum Mode {
        Default    = 0,
        Descending = 1,
        AlgorithmC = 2,
    };
    RC4(const std::string& name, const std::string& key, const std::string& vk, Mode mode) noexcept;

public:
    inline static std::string                   SBox(const std::string& s, Mode mode) noexcept {
        return SBox(s.data(), s.size(), mode);
    }
    static std::string                          SBox(const void* data, int datalen, Mode mode) noexcept;
    virtual std::shared_ptr<Byte>               Encrypt(const void* data, int datalen, int& outlen) noexcept override;
    virtual std::shared_ptr<Byte>               Decrypt(const void* data, int datalen, int& outlen) noexcept override;

private:
    std::string                                 _vk; // S-Box
    Mode                                        _mode;
};

#define DEFINE_RC4_ALGORITHM_TYPE(DefineName) \
class DefineName final : public RC4 { \
public: \
    DefineName(const std::string& key, Mode mode = (Mode)(Mode::Descending | Mode::AlgorithmC)) noexcept; \
}

DEFINE_RC4_ALGORITHM_TYPE(RC4MD5);
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA1);
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA224);
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA256);
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA386);
DEFINE_RC4_ALGORITHM_TYPE(RC4SHA512);
#undef DEFINE_RC4_ALGORITHM_TYPE
#pragma once

#include <string>

enum SecureHashAlgorithm {
    SecureHashAlgorithm_Sha1,
    SecureHashAlgorithm_Sha224,
    SecureHashAlgorithm_Sha256,
    SecureHashAlgorithm_Sha386,
    SecureHashAlgorithm_Sha512,
};

bool sha_crypt(const void* data, int size, std::string& digest, SecureHashAlgorithm agorithm, bool hex_or_binarys) noexcept;
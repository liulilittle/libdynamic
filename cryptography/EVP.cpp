#include "Cipher.h"
#include "EVP.h"

EVP::EVP(const std::string& name, const std::string& key)  noexcept
    : Cipher(name, key) {
    this->_encryptor = make_shared_object<Encryptor>(name, key);
}

std::shared_ptr<Byte> EVP::Encrypt(const void* data, int datalen, int& outlen) noexcept {
    return this->_encryptor->Encrypt((Byte*)data, datalen, outlen);
}

std::shared_ptr<Byte> EVP::Decrypt(const void* data, int datalen, int& outlen) noexcept {
    return this->_encryptor->Decrypt((Byte*)data, datalen, outlen);
}

bool EVP::Support(const std::string& name) noexcept {
    if (name.empty()) {
        return false;
    }
    return Encryptor::Support(name);
}
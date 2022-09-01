#include "Cipher.h"
#include "EVP.h"
#include "RC4.h"

Cipher::Cipher(const std::string& name, const std::string& key) noexcept
   : Kf(0)
   , Name(name)
   , Key(key) {
    constantof(this->Kf) = GetHashCode(name.data(), name.size()) + GetHashCode(key.data(), key.size());
}

std::shared_ptr<Cipher> Cipher::Create(const std::string& name, const std::string& key) {
   if (name.empty()) 
       throw std::runtime_error("name is null or empty.");
   if (key.empty()) 
       throw std::runtime_error("key is null or empty.");
   // RC4
   if (name == "rc4-md5")
       return make_shared_object<RC4MD5>(key);
   if (name == "rc4-sha1")
       return make_shared_object<RC4SHA1>(key);
   if (name == "rc4-sha224")
       return make_shared_object<RC4SHA224>(key);
   if (name == "rc4-sha256")
       return make_shared_object<RC4SHA256>(key);
   if (name == "rc4-sha386")
       return make_shared_object<RC4SHA386>(key);
   if (name == "rc4-sha512")
       return make_shared_object<RC4SHA512>(key);
   // EVP
   if (EVP::Support(name))
       return make_shared_object<EVP>(name, key);
   throw std::runtime_error("not supported name.");
}
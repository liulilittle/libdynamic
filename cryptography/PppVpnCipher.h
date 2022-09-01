#pragma once 

#include "Cipher.h"

struct PppVpnCipher {
public:
    const int                           Kf;
    const std::shared_ptr<Cipher>       Protocol;
    const std::shared_ptr<Cipher>       Transport;

public:
    inline ~PppVpnCipher() noexcept = default;
    inline PppVpnCipher(int key, std::shared_ptr<Cipher> protocol, std::shared_ptr<Cipher> transport)
        : Kf(key)
        , Protocol(protocol)
        , Transport(transport) {
        if (NULL == protocol) {
            throw std::runtime_error("Not allow the argument \"protocol\" is NULL references");
        }
        
        if (NULL == transport) {
            throw std::runtime_error("Not allow the argument \"transport\" is NULL references");
        }
    }
    inline PppVpnCipher(int key, const std::string& protocol, const std::string& protocolKey, const std::string& transport, const std::string& transportKey) noexcept
        : PppVpnCipher(key
            , Cipher::Create(protocol, protocolKey)
            , Cipher::Create(transport, transportKey)) {
        
    }
};
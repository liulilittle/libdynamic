#pragma once

#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <limits.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <condition_variable>
#include <mutex>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <functional>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#ifdef _WIN32
namespace boost { // boost::asio::posix::stream_descriptor
    namespace asio {
        namespace posix {
            typedef boost::asio::windows::stream_handle stream_descriptor;
        }
    }
}
#include <WinSock2.h>
#else
namespace boost {
    namespace asio {
        typedef io_service io_context;
    }
}
#endif

typedef unsigned char                                               Byte;
typedef signed char                                                 SByte;
typedef signed short int                                            Int16;
typedef signed int                                                  Int32;
typedef signed long long                                            Int64;
typedef unsigned short int                                          UInt16;
typedef unsigned int                                                UInt32;
typedef unsigned long long                                          UInt64;
typedef double                                                      Double;
typedef float                                                       Single;
typedef bool                                                        Boolean;
typedef signed char                                                 Char;

unsigned char                                                       libdynamic_random_byte() noexcept;
int                                                                 libdynamic_random(int min, int max) noexcept;
int                                                                 libdynamic_random_ascii() noexcept;
int                                                                 GetHashCode(const char* s, int len) noexcept;

template<typename T>
inline std::shared_ptr<T>                                           make_shared_alloc(int length) noexcept {
    static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

    // https://pkg.go.dev/github.com/google/agi/core/os/device
    // ARM64v8a: __ALIGN(8)
    // ARMv7a  : __ALIGN(4)
    // X86_64  : __ALIGN(8)
    // X64     : __ALIGN(4)
    if (length < 1) {
        return NULL;
    }

    T* p = (T*)::malloc(length * sizeof(T));
    return std::shared_ptr<T>(p, ::free);
}

template<typename T, typename... A>
inline std::shared_ptr<T>                                           make_shared_object(A&&... args) noexcept {
    return std::make_shared<T>(std::forward<A&&>(args)...);
}

#pragma pack(push, 1)
struct ip_hdr {
public:
    enum Flags {
        IP_RF = 0x8000,            /* reserved fragment flag */
        IP_DF = 0x4000,            /* dont fragment flag */
        IP_MF = 0x2000,            /* more fragments flag */
        IP_OFFMASK = 0x1fff,       /* mask for fragmenting bits */
    };

public:
    /* version / header length / type of service */
    unsigned char                                                v_hl;
    /* type of service */
    unsigned char                                                tos;
    /* total length */
    unsigned short                                               len;
    /* identification */
    unsigned short                                               id;
    /* fragment offset field */
    unsigned short                                               flags;
    /* time to live */
    unsigned char                                                ttl;
    /* protocol */
    unsigned char                                                proto;
    /* checksum */
    unsigned short                                               chksum;
    /* source and destination IP addresses */
    unsigned int                                                 src;
    unsigned int                                                 dest;

public:
    inline static int                                            IPH_V(struct ip_hdr* hdr) noexcept {
        return ((hdr)->v_hl >> 4);
    }
    inline static int                                            IPH_HL(struct ip_hdr* hdr) noexcept {
        return ((hdr)->v_hl & 0x0f);
    }
    inline static int                                            IPH_PROTO(struct ip_hdr* hdr) noexcept {
        return ((hdr)->proto & 0xff);
    }
    inline static int                                            IPH_OFFSET(struct ip_hdr* hdr) noexcept {
        return (hdr)->flags;
    }
    inline static int                                            IPH_TTL(struct ip_hdr* hdr) noexcept {
        return ((hdr)->ttl & 0xff);
    }

public:
    static struct ip_hdr*                                        Parse(const void* packet, int size) noexcept;
    static unsigned short                                        NewId() noexcept;

public:
    static const int                                             MTU = 1500;
    static const int                                             IP_HLEN;
    static const unsigned char                                   IP_VER = 4;
    static const unsigned int                                    IP_ADDR_ANY_VALUE = 0x00000000;
    static const unsigned int                                    IP_ADDR_BROADCAST_VALUE = 0xffffffff;
    static const int                                             TOS_ROUTIN_MODE = 0;
    static const unsigned char                                   IP_DFT_TTL = 64;
    static const unsigned char                                   IP_PROTO_IP = 0;
    static const unsigned char                                   IP_PROTO_ICMP = 1;
    static const unsigned char                                   IP_PROTO_UDP = 17;
    static const unsigned char                                   IP_PROTO_TCP = 6;
};
#pragma pack(pop)


#ifndef BOOST_ASIO_MOVE_CAST
#define BOOST_ASIO_MOVE_CAST(type) static_cast<type&&>
#endif

#ifndef BOOST_ASIO_MOVE_ARG
#define BOOST_ASIO_MOVE_ARG(type) type&&
#endif

template<typename T>
inline constexpr T*                                                 addressof(const T & v) noexcept {
    return (T*)&reinterpret_cast<const char&>(v);
}

template<typename T>
inline constexpr T*                                                 addressof(const T * v) noexcept {
    return const_cast<T*>(v);
}

template<typename T>
inline constexpr T&                                                 constantof(const T & v) noexcept {
    return const_cast<T&>(v);
}

template<typename T>                                                
inline constexpr T*                                                 constantof(const T * v) noexcept {
    return const_cast<T*>(v);
}

template<typename T>
inline constexpr T&&                                                constant0f(const T && v) noexcept {
    return const_cast<T&&>(v);
}

template<typename T>
inline constexpr T&&                                                forward0f(const T & v) noexcept {
    return std::forward<T>(constantof(v));
}
#pragma once

#include <stdint.h>

#if (ANDROID || PPX || LINUX)
#include <functional>

#ifndef LIBDYNAMIC_API
#define LIBDYNAMIC_API
#endif
#else
#ifndef LIBDYNAMIC_API
#ifdef __cplusplus 
#ifdef _WIN32
#ifdef _LIBDYNAMIC_EXPORTS
#define LIBDYNAMIC_API extern "C" __declspec(dllexport)
#else
#pragma comment(lib, "libdynamic.lib")

#define LIBDYNAMIC_API extern "C" __declspec(dllimport)
#endif
#else
#define LIBDYNAMIC_API extern "C" __attribute__((visibility("default")))
#endif
#else
#define LIBDYNAMIC_API
#endif
#endif

#define LIBDYNAMIC_INDEPENDENT 1
#endif

typedef void(*libdynamic_localhost_join_callback)(int64_t state);

#if LIBDYNAMIC_INDEPENDENT
typedef int(*libdynamic_localhost_protect_callback)(int);
#else
typedef std::function<bool(int)>                        libdynamic_localhost_protect_callback;
#endif

LIBDYNAMIC_API
uint64_t                                                libdynamic_localhost_now() noexcept;

LIBDYNAMIC_API                  
int                                                     libdynamic_localhost_port() noexcept;

LIBDYNAMIC_API                  
void                                                    libdynamic_localhost_join(int64_t state, libdynamic_localhost_join_callback callback) noexcept;

LIBDYNAMIC_API                  
int                                                     libdynamic_localhost_open(
    int*                                                listenPort,
    const char*                                         address,
    int                                                 port,
    int                                                 kf,
    const char*                                         protocol,
    const char*                                         protocolKey,
    const char*                                         transport,
    const char*                                         transportKey,
    int                                                 transparent) noexcept;

LIBDYNAMIC_API                  
int                                                     libdynamic_localhost_close() noexcept;

LIBDYNAMIC_API                  
void                                                    libdynamic_localhost_protect(libdynamic_localhost_protect_callback callback) noexcept;
#pragma once

#include "../env.h"
#include "IPEndPoint.h"

typedef ip_hdr::Flags                                       IPFlags;

class BufferSegment final {
public:
    std::shared_ptr<Byte>                                   Buffer;
    int                                                     Length;

public:
    inline BufferSegment() noexcept : Length(0) {}
    inline BufferSegment(const std::shared_ptr<Byte>& buffer, int length) noexcept
        : Buffer(buffer)
        , Length(buffer ? std::max<int>(0, length) : 0) {

    }
};

class IPFrame final {
public:
    typedef std::shared_ptr<IPFrame>                        IPFramePtr;

public:
    AddressFamily                                           AddressesFamily;
    UInt32                                                  Destination;
    UInt32                                                  Source;
    Byte                                                    Ttl;
    UInt16                                                  Id;
    Byte                                                    Tos;
    Byte                                                    ProtocolType;
    IPFlags                                                 Flags;
    std::shared_ptr<BufferSegment>                          Payload;
    std::shared_ptr<BufferSegment>                          Options;

public:
    inline IPFrame() noexcept
        : AddressesFamily(AddressFamily::InterNetwork)
        , Destination(0)
        , Source(IPFrame::DefaultTtl)
        , Ttl(64)
        , Id(0)
        , Tos(0)
        , ProtocolType(0)
        , Flags(IPFlags::IP_DF) {

    }
    inline int                                              GetFragmentOffset() noexcept {
        int offset = (UInt16)this->Flags;
        offset = ((UInt16)(offset << 3)) >> 3;
        offset <<= 3;
        return offset;
    }
    inline void                                             SetFragmentOffset(int value) noexcept {
        int flags = (int)this->Flags >> 13;
        flags = flags << 13 | value >> 3;
        this->Flags = (IPFlags)flags;
    }

public:
    inline static std::shared_ptr<BufferSegment>            ToArray(const IPFrame* packet) noexcept {
        if (NULL == packet) {
            return NULL;
        }
        return constantof(packet)->ToArray();
    }
    inline static UInt16                                    NewId() noexcept {
        return ip_hdr::NewId();
    }
    inline static int                                       SizeOf(const IPFrame* packet) noexcept {
        if (NULL == packet) {
            return ~0;
        }
        return constantof(packet)->SizeOf();
    }
    std::shared_ptr<BufferSegment>                          ToArray() noexcept;
    int                                                     SizeOf() noexcept;
    inline static std::shared_ptr<IPFrame>                  Parse(const void* packet, int size) noexcept {
        return IPFrame::Parse(packet, size, true);
    }
    static std::shared_ptr<IPFrame>                         Parse(const void* packet, int size, bool checksum) noexcept;
    static int                                              Subpackages(std::vector<IPFramePtr>& out, const IPFramePtr& packet) noexcept;

public:
    static const Byte                                       DefaultTtl = ip_hdr::IP_DFT_TTL;
};
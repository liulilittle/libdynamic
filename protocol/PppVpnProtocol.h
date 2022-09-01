#pragma once

#include "../env.h"
#include "../packet/Ipep.h"
#include "../packet/IPEndPoint.h"
#include "../io/SeekOrigin.h"
#include "../io/Stream.h"
#include "../io/MemoryStream.h"
#include "../io/BinaryReader.h"
#include "../cryptography/PppVpnCipher.h"

enum AddressType {
    None    = 0,
    IPv4    = 1,
    IPv6    = 2,
    Domain  = 3,
};

class AddressEndPoint {
public:
    AddressType                                 Type = AddressType::None;
    std::string                                 Host;
    int                                         Port = 0;
};

enum Error {
    Success,                                                            // 成功
    ReceiveIsDisconnectedOrTimeout,                                     // 接收超时或者断开链接
    ProvideTheKeysFrameIsIllegal,                                       // 提供关键帧无效
    TheAddressLengthOfIPv4IsIncorrect,                                  // IPv4地址簇长度无效
    UnableToDecryptEncryptedBinaryData,                                 // 无法解密加密的二进制数据
    DomainNameAddressLengthNotAllowLessOrEqualsZero,                    // 域名地址长度不允许小于或等于0
    DomainNameWithFullBlankOrEmptyStringAreNotAllowed,                  // 不允许提供全空白或者空字符串的域名
    DomainNameResolutionFailed,                                         // 解析域名时发生了故障
    ResolvedDnsSuccessfullyButNoAnyIPAddressWasFound,                   // 解析域名成功但是找不到任何IP地址
    AddressTypeIsNotSupported,                                          // 地址类型不支持
    DestinationServerAddressIsNotAllowedToBeAnyAddress,                 // 目的服务器地址不允许为任何地址(0.0.0.0)
    PortsAreNotAllowedToBeLessThanOrEqualTo0OrGreaterThan65535,         // 端口不允许小于或等于0或者大于65535
    UnableToCreateServerSocket,                                         // 无法创建服务器套接字对象
    UnableToInitiateConnectEstablishmentWithTheServer,                  // 无法发起与服务器之间的链接建立
    ManagedAndUnmanagedResourcesHeldbyObjectHaveBeenReleased,           // 对象持有的托管与非托管资源已被释放
    EstablishConnectTimeoutWithTheRemoteServer,                         // 与远程服务器之间建立链接超时
    ProblemOccurredWhileTheSynchronizationObjectWasWaitingForSignal,    // 同步对象在等待信号时发生了问题
    UnableToReadBytesNetworkStream,                                     // 无法读入网络字节流
    ProtocolTypeIsNotSupported,                                         // 协议类型不支持
    NoneTypeHeaderNotLessThanTwoBytes,                                  // None类型头不小于两个字节
    UnalbeToAllocateDatagramPort,                                       // 无法分配数据报端口
    ReferencesEndPointIsNullReferences,                                 // 引用的地址端点是空引用
    UnhandledExceptions,                                                // 未处理异常
    TimeoutSafeWaitHandleIsCloseOrIsInvalid,                            // 超时安全等待句柄已经关闭或者无效
    DenyAccessToTheServerFirewallRulesRestrictResources,                // 禁止访问服务器防火墙规则限制资源
};

struct DatagramPacket {
public:
    int                                         ProtocolType; // = 0
    IPEndPoint                                  Source;
    IPEndPoint                                  Destination;
    std::shared_ptr<Byte>                       Message;
    int                                         MessageSize; // = 0
    int                                         MessageOffset;

public:
    inline DatagramPacket() noexcept : ProtocolType(0), MessageSize(0), MessageOffset(0) {}
};

class PppVpnProtocol final {
public:
    static bool                                 PortNumberToBytes(
        Stream&                                 stream, 
        const std::shared_ptr<PppVpnCipher>&    cipher, 
        int                                     port) noexcept;
    static bool                                 WriteBytesTextAddress(
        Stream&                                 stream,
        const std::shared_ptr<PppVpnCipher>&    cipher,
        const std::string&                      host,
        AddressType                             addressType) noexcept;
    inline static Byte                          ProtocolTypeToByte(int protocol) noexcept {
        int r = 0;
        switch (protocol)
        {
        case ip_hdr::IP_PROTO_ICMP:
            r = 2;
            break;
        case ip_hdr::IP_PROTO_UDP:
            r = 1;
            break;
        case ip_hdr::IP_PROTO_TCP:
            r = 0;
            break;
        }
        r = (r << 6) | (PppVpnProtocol::RandKey() & 0x3F);
        return (Byte)r;
    }
    inline static int                           ByteToProtocolType(Byte b) noexcept {
        b >>= 6;
        switch (b)
        {
        case 2:
            return ip_hdr::IP_PROTO_ICMP;
        case 1:
            return ip_hdr::IP_PROTO_UDP;
        case 0:
            return ip_hdr::IP_PROTO_TCP;
        }
        return ip_hdr::IP_PROTO_IP;
    }

public:
    static bool                                 ReadAddressFromBytesText(
        BinaryReader&                           br, 
        const std::shared_ptr<PppVpnCipher>&    cipher,
        std::string&                            hostname,
        IPEndPoint&                             addressEP,
        AddressType&                            addressType) noexcept;
    static bool                                 BytesToPortNumber(
        BinaryReader&                           br, 
        const std::shared_ptr<PppVpnCipher>&    cipher,
        int&                                    port) noexcept;
    inline static bool                          ReadEndPointFromBytesText(
        BinaryReader&                           br, 
        const std::shared_ptr<PppVpnCipher>&    cipher,
        std::string&                            hostname,
        IPEndPoint&                             addressEP,
        AddressType&                            addressType) noexcept {
        if (!ReadAddressFromBytesText(br, cipher, hostname, addressEP, addressType)) {
            return false;
        }

        int port;
        if (!BytesToPortNumber(br, cipher, port)) {
            return false;
        }

        constantof(addressEP.Port) = (UInt16)port;
        return true;
    }

private:
    static bool                                 BuildDatagramPacket(
        Stream&                                 stream,
        const std::shared_ptr<PppVpnCipher>&    cipher,
        const std::string&                      address,
        int                                     addressPort,
        AddressType                             addressType,
        int                                     protocol,
        const void*                             buffer,
        int                                     buffer_size) noexcept;

public:
    inline static Byte                          RandKey() noexcept {
        return libdynamic_random(0x00, 0xff);
    }
    static bool                                 BuildHandshakePacket(
        Stream&                                 stream,
        const std::shared_ptr<PppVpnCipher>&    cipher,
        const std::string&                      host,
        int                                     port,
        AddressType                             addressType) noexcept;
    static bool                                 ReadDatagramPacket(
        Stream&                                 stream,
        const std::shared_ptr<PppVpnCipher>&    cipher,
        DatagramPacket&                         packet) noexcept;
    static bool                                 BuildDatagramPacket(
        Stream&                                 stream, 
        const std::shared_ptr<PppVpnCipher>&    cipher, 
        const DatagramPacket&                   packet) noexcept;
};
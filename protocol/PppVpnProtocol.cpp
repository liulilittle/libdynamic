#include "PppVpnProtocol.h"

bool PppVpnProtocol::PortNumberToBytes(
    Stream& stream,
    const std::shared_ptr<PppVpnCipher>& cipher,
    int port) noexcept {
    if (!stream.CanWrite()) {
        return false;
    }

    if (NULL == cipher) {
        return false;
    }

    if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
        port = IPEndPoint::MinPort;
    }

    Byte buf[] = {
        (Byte)(port >> 8),
        (Byte)port
    };

    int datalen;
    std::shared_ptr<Byte> data = cipher->Protocol->Encrypt(buf, sizeof(buf), datalen);
    if (datalen < 1 || NULL == data) {
        return false;
    }

    return stream.Write(data.get(), 0, datalen);
}

bool PppVpnProtocol::WriteBytesTextAddress(
    Stream& stream,
    const std::shared_ptr<PppVpnCipher>& cipher,
    const std::string& host,
    AddressType addressType) noexcept {
    if (!stream.CanWrite()) {
        return false;
    }

    if (NULL == cipher) {
        return false;
    }

    if (!stream.WriteByte(((int)addressType << 6) | (PppVpnProtocol::RandKey() & 0x3F))) { // ATYPE(Domain)
        return false;
    }

    int address_length;
    std::shared_ptr<Byte> address_data = cipher->Transport->Encrypt(host.data(), host.size(), address_length);
    if (address_length < 1 || NULL == address_data) {
        return false;
    }

    Byte address_length_bytes[] = { 
        (Byte)(address_length)
    };

    int address_size_length;
    std::shared_ptr<Byte> address_size_data = cipher->Protocol->Encrypt(
        address_length_bytes, sizeof(address_length_bytes), address_size_length);
    if (address_size_length < 1 || NULL == address_size_data) {
        return false;
    }

    return stream.Write(address_size_data.get(), 0, address_size_length) &&
        stream.Write(address_data.get(), 0, address_length);
}

bool PppVpnProtocol::BuildHandshakePacket(
    Stream& stream,
    const std::shared_ptr<PppVpnCipher>& cipher,
    const std::string& host,
    int port,
    AddressType addressType) noexcept {
    if (!stream.CanWrite()) {
        return false;
    }

    if (NULL == cipher) {
        return false;
    }

    if (!stream.WriteByte(PppVpnProtocol::RandKey())) {
        return false;
    }

    if (cipher->Kf != 0) {
        if (!stream.WriteByte(cipher->Kf)) {
            return false;
        }
    }

    bool b = false;
    switch (addressType)
    {
    case AddressType::Domain:
        b = PppVpnProtocol::WriteBytesTextAddress(stream, cipher, host, AddressType::Domain);
        break;
    case AddressType::IPv4:
        b = PppVpnProtocol::WriteBytesTextAddress(stream, cipher, host, AddressType::IPv4);
        break;
    case AddressType::IPv6:
        b = PppVpnProtocol::WriteBytesTextAddress(stream, cipher, host, AddressType::IPv6);
        break;
    default:
        return false;
    }
    if (!b) {
        return false;
    }
    return PppVpnProtocol::PortNumberToBytes(stream, cipher, port);
}

bool PppVpnProtocol::BuildDatagramPacket(
    Stream& stream,
    const std::shared_ptr<PppVpnCipher>& cipher,
    const std::string& address,
    int addressPort,
    AddressType addressType,
    int protocol,
    const void* buffer,
    int buffer_size) noexcept {
    if (NULL == buffer || buffer_size < 1) {
        return false;
    }

    if (!stream.CanWrite()) {
        return false;
    }

    if (NULL == cipher) {
        return false;
    }

    if (!stream.WriteByte(PppVpnProtocol::RandKey())) {
        return false;
    }

    if (cipher->Kf != 0) {
        if (!stream.WriteByte(cipher->Kf)) {
            return false;
        }
    }

    if (protocol == ip_hdr::IP_PROTO_ICMP ||
        protocol == ip_hdr::IP_PROTO_TCP) {
        if (!stream.WriteByte(((int)AddressType::None << 6) | (0x02 & 0x3F))) {
            return false;
        }

        if (!stream.WriteByte(PppVpnProtocol::ProtocolTypeToByte(protocol))) {
            return false;
        }

        if (!stream.WriteByte(((int)addressType << 6) | (PppVpnProtocol::RandKey() & 0x3F))) { // ATYPE(Domain)
            return false;
        }

        int len;
        std::shared_ptr<Byte> pkg = cipher->Transport->Encrypt(buffer, buffer_size, len);
        if (len < 1 || NULL == pkg) {
            return false;
        }

        return stream.Write(pkg.get(), 0, len);
    }
    elif(protocol == ip_hdr::IP_PROTO_UDP) {
        bool b = false;
        switch (addressType)
        {
        case AddressType::Domain:
            b = PppVpnProtocol::WriteBytesTextAddress(stream, cipher, address, AddressType::Domain);
            break;
        case AddressType::IPv4:
            b = PppVpnProtocol::WriteBytesTextAddress(stream, cipher, address, AddressType::IPv4);
            break;
        case AddressType::IPv6:
            b = PppVpnProtocol::WriteBytesTextAddress(stream, cipher, address, AddressType::IPv6);
            break;
        default:
            return false;
        }
        if (!b) {
            return false;
        }

        b = PppVpnProtocol::PortNumberToBytes(stream, cipher, addressPort);
        if (!b) {
            return false;
        }

        int len;
        std::shared_ptr<Byte> pkg = cipher->Transport->Encrypt(buffer, buffer_size, len);
        if (len < 1 || NULL == pkg) {
            return false;
        }

        return stream.Write(pkg.get(), 0, len);
    }
    else {
        return false;
    }
}

bool PppVpnProtocol::ReadDatagramPacket(
    Stream& stream,
    const std::shared_ptr<PppVpnCipher>& cipher,
    DatagramPacket& packet) noexcept {
    if (!stream.CanRead()) {
        return false;
    }

    if (NULL == cipher) {
        return false;
    }

    int n;
    int header_size = 3;
    Byte stack_buf[UINT16_MAX];

    BinaryReader br(stream);
    if (cipher->Kf != 0) {
        int l = stream.Read(stack_buf, 0, header_size);
        if (l != header_size) {
            return false;
        }

        n = stack_buf[1];
        if (n != cipher->Kf) {
            return false;
        }

        n = stack_buf[2];
    }
    else {
        header_size = 2;
        int l = stream.Read(stack_buf, 0, header_size);
        if (l != header_size) {
            return false;
        }

        n = stack_buf[1];
    }

    int addressLength = n & 0x3F;
    int port = 0;
    int protocolType = ip_hdr::IP_PROTO_UDP;
    AddressType addressType = (AddressType)(n >> 6);

    IPEndPoint dstAddressEP;
    AddressType dstAddressType = AddressType::None;

    switch (addressType) {
    case AddressType::None:
    {
        if (addressLength < 2) {
            return false;
        }
        std::shared_ptr<Byte> buffer = br.ReadBytes(addressLength);
        if (NULL == buffer) {
            return false;
        }
        Byte* p = buffer.get();
        protocolType = PppVpnProtocol::ByteToProtocolType(p[0]);
        if (protocolType != ip_hdr::IP_PROTO_ICMP) { // ip_hdr::IP_PROTO_TCP
            return false;
        }
        addressType = (AddressType)(p[1] >> 6);
        switch (addressType)
        {
        case AddressType::IPv4:
            break;
        case AddressType::IPv6:
            break;
        default:
            return false;
        }
        break;
    }
    case AddressType::IPv4:
    {
        std::string hostname;
        if (!ReadEndPointFromBytesText(br, cipher, hostname, dstAddressEP, dstAddressType)) {
            return false;
        }
        break;
    }
    case AddressType::IPv6:
    {
        std::string hostname;
        if (!ReadEndPointFromBytesText(br, cipher, hostname, dstAddressEP, dstAddressType)) {
            return false;
        }
        break;
    }
    case AddressType::Domain:
    {
        std::string hostname;
        if (!ReadEndPointFromBytesText(br, cipher, hostname, dstAddressEP, dstAddressType)) {
            return false;
        }
        break;
    }
    default:
        return false;
    }

    std::shared_ptr<Byte> messages = NULL;
    int headerSeekOf = stream.GetPosition();
    int messageSize = stream.GetLength() - headerSeekOf;
    if (messageSize < 1) {
        return false;
    }
    else {
        MemoryStream& ms = dynamic_cast<MemoryStream&>(stream);
        messages = cipher->Transport->Decrypt(ms.GetBuffer().get() + headerSeekOf, messageSize, messageSize);

        if (messageSize < 1 || NULL == messages) {
            return false;
        }
    }
    packet.ProtocolType = protocolType;
    packet.Destination = dstAddressEP;
    packet.Message = messages;
    packet.MessageOffset = 0;
    packet.MessageSize = messageSize;
    return true;
}

bool PppVpnProtocol::BytesToPortNumber(
    BinaryReader& br,
    const std::shared_ptr<PppVpnCipher>& cipher,
    int& port) noexcept {
    port = 0;
    if (NULL == cipher) {
        return false;
    }

    Stream& stream = br.GetStream();
    if (!stream.CanRead()) {
        return false;
    }

    Byte buf[sizeof(UInt16)];
    if (stream.Read(buf, 0, sizeof(buf)) != sizeof(buf)) {
        return false;
    }

    int len;
    std::shared_ptr<Byte> p = cipher->Protocol->Decrypt(buf, sizeof(buf), len);
    if (NULL == p || len < (int)sizeof(buf)) {
        return false;
    }

    Byte* b = p.get();
    port = b[0] << 8 | b[1];
    return true;
}

bool PppVpnProtocol::ReadAddressFromBytesText(
    BinaryReader& br,
    const std::shared_ptr<PppVpnCipher>& cipher,
    std::string& hostname,
    IPEndPoint& addressEP,
    AddressType& addressType) noexcept {
    addressType = AddressType::None;
    if (NULL == cipher) {
        return false;
    }

    Stream& stream = br.GetStream();
    if (!stream.CanRead()) {
        return false;
    }

    int addressLength = 0;
    {
        Byte b;
        if (!br.TryReadByte(b)) {
            return false;
        }

        int l;
        std::shared_ptr<Byte> p = cipher->Protocol->Decrypt(&b, 1, l);
        if (NULL == p) {
            return false;
        }

        addressLength = *p.get();
    }

    if (addressLength < 1) {
        return false;
    }

    std::shared_ptr<Byte> buffer = br.ReadBytes(addressLength);
    if (NULL == buffer) {
        return false;
    }

    int buffer_size;
    buffer = cipher->Transport->Decrypt(buffer.get(), addressLength, buffer_size);
    if (buffer_size < 1 || NULL == buffer) {
        return false;
    }

    hostname = std::string((char*)buffer.get(), addressLength);
    if (hostname.empty()) {
        return false;
    }
    else {
        addressEP = Ipep::GetEndPoint(hostname, 0);
    }

    AddressFamily addressFamily = addressEP.GetAddressFamily();
    if (addressFamily == AddressFamily::InterNetwork) {
        if (addressEP.IsNone()) {
            addressType = AddressType::Domain;
        }
        else {
            addressType = AddressType::IPv4;
        }
    }
    elif(addressFamily == AddressFamily::InterNetworkV6) {
        addressType = AddressType::IPv6;
    }
    else {
        return false;
    }

    return true;
}

bool PppVpnProtocol::BuildDatagramPacket(
    Stream& stream,
    const std::shared_ptr<PppVpnCipher>& cipher,
    const DatagramPacket& packet) noexcept {
    if (NULL == cipher ||
        !stream.CanWrite() ||
        packet.MessageSize < 1 ||
        packet.MessageOffset < 0 ||
        NULL == packet.Message) {
        return false;
    }

    std::string hostAddress;
    AddressType addressType = AddressType::None;
    const IPEndPoint& destinationEP = packet.Destination;
    do {
        int addressBytesSize;
        Byte* addressBytes = destinationEP.GetAddressBytes(addressBytesSize);
        if (NULL == addressBytes || addressBytesSize < 1) {
            return false;
        }

        AddressFamily af = destinationEP.GetAddressFamily();
        switch (af) {
        case AddressFamily::InterNetwork:
            addressType = AddressType::IPv4;
            break;
        case AddressFamily::InterNetworkV6:
            addressType = AddressType::IPv6;
            break;
        default:
            return false;
        };

        if (packet.ProtocolType == ip_hdr::IP_PROTO_UDP) {
            hostAddress = IPEndPoint::ToAddressString(af, addressBytes, addressBytesSize);
        }
    } while (0);
    Byte* message_data = packet.Message.get();
    if (NULL != message_data) {
        message_data += packet.MessageOffset;
    }
    return PppVpnProtocol::BuildDatagramPacket(
        stream,
        cipher,
        hostAddress,
        destinationEP.Port,
        addressType,
        packet.ProtocolType,
        message_data,
        packet.MessageSize);
}
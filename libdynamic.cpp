#include "libdynamic.h"
#include "env.h"
#ifdef LIBDYNAMIC_INDEPENDENT
#include "./cryptography/PppVpnCipher.h"
#include "./protocol/PppVpnProtocol.h"
#include "./packet/IPFrame.h"
#include "./packet/UdpFrame.h"
#include "./packet/IcmpFrame.h"
#else
using namespace Ppp;
#endif

class dynamic_localhost;

static boost::asio::io_context                          dynamic_context_;
static std::shared_ptr<dynamic_localhost>               dynamic_localhost_;
static uint64_t                                         dynamic_now_     = 0;
static libdynamic_localhost_protect_callback            dynamic_protect_ = NULL;

#pragma pack(push, 1)
struct dynamic_tcp_endpoint {
    char v4_or_v6;
    uint16_t port;
    uint32_t in4;
    char in6[16];
};
#pragma pack(pop)

int  libdynamic_initialize() noexcept;
int  libdynamic_random() noexcept;
int  libdynamic_random(int min, int max) noexcept;
int  libdynamic_random_ascii() noexcept;
Byte libdynamic_random_byte() noexcept;

template<class TProtocol>
static std::string
libdynamic_to_string(const boost::asio::ip::basic_endpoint<TProtocol>& endpoint) noexcept {
    std::string host = endpoint.address().to_string();
    std::string port = std::to_string(endpoint.port());
    return host + ":" + port;
}

class dynamic_tcp_channel : public std::enable_shared_from_this<dynamic_tcp_channel> {
    static const int CTCP_TSS_NO_MASK                                       = 2;
    static const int CTCP_TSS                                               = CTCP_TSS_NO_MASK + 1;
    static const int CTCP_MSS                                               = 65535;
    static const int CTCP_INACTIVE_TIME                                     = 72;
    static const int CTCP_CONNECT_TIMEOUT                                   = 10;

public:
    struct message {
        std::shared_ptr<Byte>                                               packet;
        int                                                                 packet_size;
    };
    typedef std::shared_ptr<message>                                        pmessage;
    typedef std::list<pmessage>                                             message_queue;

public:
    typedef std::shared_ptr<dynamic_tcp_channel>                            Ptr;
    typedef std::function<void(const Ptr&, void*, int)>                     ReadEventHandler;

public:
    std::shared_ptr<ReadEventHandler>                                       ReadEvent;

public:
    inline dynamic_tcp_channel(const std::shared_ptr<PppVpnCipher>& cipher, bool transparent) noexcept
        : socket_(dynamic_context_)
        , cipher_(cipher)
        , available_(-1)
        , transparent_(transparent)
        , writing_(false)
        , last_(libdynamic_localhost_now()) {

    }
    inline ~dynamic_tcp_channel() noexcept {
        close();
    }

public:
    inline bool                                                             available() noexcept {
        if (available_ > -1) {
            if (socket_.is_open()) {
                uint64_t now = libdynamic_localhost_now();
                uint64_t max = available_ > 0 ? CTCP_INACTIVE_TIME : CTCP_CONNECT_TIMEOUT;
                uint64_t diff = now - last_;
                if (max > diff) {
                    return true;
                }
            }
            close();
        }
        return false;
    }
    inline bool                                                             establish() noexcept {
        return available() && available_ > 0;
    }
    inline bool                                                             write(const void* data, int offset, int length) noexcept {
        if (!data || offset < 0 || length < 1 || length > CTCP_MSS || !establish()) {
            return false;
        }

        if (transparent_) {
            int packet_size_ = CTCP_TSS + length;
            std::shared_ptr<Byte> packet_ = make_shared_alloc<Byte>(packet_size_);

            Byte* p_ = packet_.get();
            p_[0] = (Byte)libdynamic_random(0x01, 0xff);
            p_[1] = (Byte)(length >> 8);
            p_[2] = (Byte)(length);

            memcpy(p_ + CTCP_TSS, (char*)data + offset, length);
            for (int i = 1; i < packet_size_; i++) {
                p_[i] ^= p_[0];
            }

            pmessage message_ = make_shared_object<message>();
            message_->packet = packet_;
            message_->packet_size = packet_size_;
            messages_.push_back(message_);
            return write_loopkout(false);
        }
        else {
            int payload_size_;
            std::shared_ptr<Byte> payload_bytes_ = cipher_->Transport->Encrypt((char*)data + offset, length, payload_size_);
            if (NULL == payload_bytes_ || payload_size_ < 1) {
                return false;
            }

            Byte sz_[CTCP_TSS_NO_MASK] = {
                (Byte)(payload_size_ >> 8),
                (Byte)(payload_size_),
            };

            int header_bytes_size_;
            std::shared_ptr<Byte> header_bytes_ = cipher_->Protocol->Encrypt(sz_, CTCP_TSS_NO_MASK, header_bytes_size_);
            if (NULL == header_bytes_ || header_bytes_size_ < 1) {
                return false;
            }

            int packet_header_size_ = header_bytes_size_ + 1;
            int packet_size_ = packet_header_size_ + payload_size_;
            std::shared_ptr<Byte> packet_ = make_shared_alloc<Byte>(packet_size_);

            Byte* p_ = packet_.get();
            p_[0] = (Byte)libdynamic_random(0x01, 0xff);

            Byte* b_ = header_bytes_.get();
            p_[1] = (Byte)(b_[0]);
            p_[2] = (Byte)(b_[1]);

            memcpy(p_ + packet_header_size_, payload_bytes_.get(), payload_size_);
            for (int i = 1; i < packet_size_; i++) {
                p_[i] ^= p_[0];
            }

            pmessage message_ = make_shared_object<message>();
            message_->packet = packet_;
            message_->packet_size = packet_size_;
            messages_.push_back(message_);
            return write_loopkout(false);
        }
    }
    inline void                                                             close() noexcept {
        if (socket_.is_open()) {
            boost::system::error_code ec_;
            try {
                socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec_);
            }
            catch (std::exception&) {}
            try {
                socket_.close(ec_);
            }
            catch (std::exception&) {}
        }

        messages_.clear();
        available_ = -1;
        last_ = libdynamic_localhost_now();
    }
    inline bool                                                             open(const dynamic_tcp_endpoint& endpoint) noexcept {
        if (socket_.is_open()) {
            return false;
        }

        boost::system::error_code ec_;
        if (endpoint.v4_or_v6) {
            socket_.open(boost::asio::ip::tcp::v4(), ec_);
        }
        else {
            socket_.open(boost::asio::ip::tcp::v6(), ec_);
        }
        if (ec_) {
            return false;
        }

        socket_.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec_);
        socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec_);
        if (ec_) {
            return false;
        }

        boost::asio::ip::tcp::endpoint remoteEP_;
        if (endpoint.v4_or_v6) {
            if (is_any(endpoint)) {
                remoteEP_ = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), endpoint.port);
            }
            else {
                remoteEP_ = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4(ntohl(endpoint.in4)), endpoint.port);
            }
        }
        else {
            if (is_any(endpoint)) {
                remoteEP_ = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::loopback(), endpoint.port);
            }
            else {
                boost::asio::ip::address_v6::bytes_type in6_;
                memcpy(in6_.data(), endpoint.in6, in6_.size());

                remoteEP_ = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6(in6_), endpoint.port);
            }
        }

        bool loopback = is_loopback(endpoint) || is_any(endpoint) || is_none(endpoint) || is_broadcast(endpoint);
        if (!loopback) {
            if (!protect(socket_.native_handle())) {
                return false;
            }
        }

        std::shared_ptr<dynamic_tcp_channel> self = shared_from_this();
        socket_.async_connect(remoteEP_,
            [self, this](const boost::system::error_code& ec_) noexcept {
                if (ec_ || !handshake()) {
                    close();
                    return;
                }
            });

        available_ = 0;
        last_ = libdynamic_localhost_now();
        return true;
    }

private:
    inline static bool                                                      is_broadcast(const dynamic_tcp_endpoint& endpoint) noexcept {
        if (endpoint.v4_or_v6) {
            return endpoint.in4 == htonl(INADDR_BROADCAST);
        }
        return is_any(endpoint);
    }
    inline static bool                                                      is_none(const dynamic_tcp_endpoint& endpoint) noexcept {
        if (endpoint.v4_or_v6) {
            return endpoint.in4 == htonl(INADDR_NONE);
        }
        return is_any(endpoint);
    }
    inline static bool                                                      is_any(const dynamic_tcp_endpoint& endpoint) noexcept {
        if (endpoint.v4_or_v6) {
            return endpoint.in4 == htonl(INADDR_ANY);
        }

        uint64_t* in6_ = (uint64_t*)endpoint.in6;
        return in6_[0] == 0 && in6_[1] == 0;
    }
    inline static bool                                                      is_loopback(const dynamic_tcp_endpoint& endpoint) noexcept {
        if (endpoint.v4_or_v6) {
            return endpoint.in4 == htonl(INADDR_LOOPBACK);
        }

        boost::asio::ip::address_v6 address_(*(boost::asio::ip::address_v6::bytes_type*)endpoint.in6);
        return address_.is_loopback(); // IN6_IS_ADDR_LOOPBACK
    }

protected:
    virtual bool                                                            protect(int sockfd_) noexcept {
        libdynamic_localhost_protect_callback protect_ = dynamic_protect_;
        if (NULL == protect_) {
            return true;
        }
        return protect_(sockfd_);
    }

private:
    inline bool                                                             handshake() noexcept {
        if (!socket_.is_open()) {
            return false;
        }

        std::shared_ptr<Byte> messages_ = make_shared_alloc<Byte>(256);
        Byte* packet_ = messages_.get();

        int offset_ = 0;
        packet_[offset_++] = libdynamic_random_byte();
        if (cipher_->Kf != 0) {
            packet_[offset_++] = cipher_->Kf;
        }

        int length_ = libdynamic_random(2, 0x40);
        packet_[offset_++] = 0 << 6 | length_;
        packet_[offset_++] = 1 << 6 | ((int)libdynamic_random_byte() & 0x3F);
        // Only-IPv4
        // V6 Else: 2 << 6
        packet_[offset_++] = 1 << 6 | ((int)libdynamic_random_byte() & 0x3F);

        for (int i = 2; i < length_; i++) {
            packet_[offset_++] = libdynamic_random_ascii();
        }

        std::shared_ptr<dynamic_tcp_channel> self = shared_from_this();
        socket_.async_send(boost::asio::buffer(packet_, offset_),
            [self, this, messages_](const boost::system::error_code& ec_, size_t sz_) noexcept {
                if (ec_) {
                    close();
                    return;
                }
            });
        boost::asio::async_read(socket_, boost::asio::buffer(buffer_, CTCP_TSS_NO_MASK),
            [self, this](const boost::system::error_code& ec_, size_t sz_) noexcept {
                int by_ = std::max<int>(-1, ec_ ? -1 : sz_);
                if (by_ != CTCP_TSS_NO_MASK) {
                    close();
                    return;
                }

                Error error_ = (Error)buffer_[1];
                if (error_ != Error::Success) {
                    close();
                    return;
                }

                bool success = read();
                if (!success) {
                    close();
                    return;
                }

                available_ = 1;
                last_ = libdynamic_localhost_now();
            });
        return true;
    }
    inline bool                                                             read() noexcept {
        if (!socket_.is_open()) {
            return false;
        }

        std::shared_ptr<dynamic_tcp_channel> self = shared_from_this();
        boost::asio::async_read(socket_, boost::asio::buffer(buffer_, CTCP_TSS),
            [self, this](const boost::system::error_code& ec_, size_t sz_) noexcept {
                int transferred_length_ = std::max<int>(-1, ec_ ? -1 : sz_);
                if (transferred_length_ < 1) {
                    close();
                    return;
                }

                int mask_ = buffer_[0];
                for (int i = 1; i < CTCP_TSS; i++) {
                    buffer_[i] ^= mask_;
                }

                int length_ = 0;
                if (transparent_) {
                    length_ = transform_length(buffer_ + 1, CTCP_TSS_NO_MASK);
                }
                else {
                    int outlen_;
                    std::shared_ptr<Byte> payload_ = cipher_->Protocol->Decrypt(buffer_ + 1, CTCP_TSS_NO_MASK, outlen_);
                    if (NULL == payload_) {
                        close();
                        return;
                    }
                    length_ = transform_length(payload_.get(), outlen_);
                }

                if (length_ < 1 || length_ > CTCP_MSS) {
                    close();
                    return;
                }

                boost::asio::async_read(socket_, boost::asio::buffer(buffer_, length_),
                    [self, this, mask_](const boost::system::error_code& ec_, size_t sz_) noexcept {
                        int length_ = std::max<int>(-1, ec_ ? -1 : sz_);
                        if (length_ < 1) {
                            close();
                            return;
                        }

                        for (int i = 0; i < length_; i++) {
                            buffer_[i] ^= mask_;
                        }

                        int payload_size_;
                        std::shared_ptr<Byte> payload_;

                        if (transparent_) {
                            payload_ = std::shared_ptr<Byte>(buffer_, [](void*) noexcept {});
                            payload_size_ = length_;
                        }
                        else {
                            int outlen_;
                            payload_ = cipher_->Transport->Decrypt(buffer_, length_, outlen_);
                            if (NULL == payload_) {
                                std::shared_ptr<ReadEventHandler> handler_ = ReadEvent;
                                if (handler_) {
                                    (*handler_)(self, NULL, -1);
                                }
                                close();
                                return;
                            }
                            payload_size_ = outlen_;
                        }

                        last_ = libdynamic_localhost_now();
                        if (payload_size_ > 0) {
                            std::shared_ptr<ReadEventHandler> handler_ = ReadEvent;
                            if (handler_) {
                                (*handler_)(self, payload_.get(), payload_size_);
                            }
                        }

                        if (!read()) {
                            close();
                        }
                    });
                last_ = libdynamic_localhost_now();
            });
        return true;
    }

private:
    inline bool                                                             write_loopkout(bool internal_) noexcept {
        if (!internal_) {
            if (writing_.exchange(true)) { // 正在队列写数据且不是内部调用则返回真
                return true;
            }
        }

        const message_queue::iterator tail = messages_.begin();
        const message_queue::iterator endl = messages_.end();
        if (tail == endl) { // 当前消息队列是空得
            writing_.exchange(false);
            return false;
        }

        const std::shared_ptr<dynamic_tcp_channel> self = shared_from_this();
        const pmessage message = std::move(*tail);

        messages_.erase(tail); // 从消息队列中删除这条消息
        boost::asio::async_write(socket_, boost::asio::buffer(message->packet.get(), message->packet_size),
            [self, this, message](const boost::system::error_code& ec, size_t sz) noexcept {
                bool success = false;
                if (ec) {
                    close();
                }
                else {
                    success = true;
                    last_ = libdynamic_localhost_now();
                }
                write_loopkout(true);
            });
        return true;
    }
    inline static int                                                       transform_length(const void* p, int l) noexcept {
        if (l > 1) {
            Byte* b = (Byte*)p;
            return b[0] << 8 | b[1];
        }
        elif(l > 0) {
            return *(Byte*)p;
        }
        return 0;
    }

private:
    boost::asio::ip::tcp::socket                                            socket_;
    std::shared_ptr<PppVpnCipher>                                           cipher_;
    int                                                                     available_;
    bool                                                                    transparent_;
    std::atomic<bool>                                                       writing_;
    uint64_t                                                                last_;
    message_queue                                                           messages_;
    Byte                                                                    buffer_[CTCP_MSS];
};

class dynamic_udp_channel : public std::enable_shared_from_this<dynamic_udp_channel> {
public:
    inline dynamic_udp_channel() noexcept
        : socket_(dynamic_context_) {

    }
    inline ~dynamic_udp_channel() noexcept {
        close();
    }

public:
    typedef std::shared_ptr<dynamic_udp_channel>                            Ptr;
    typedef boost::asio::ip::udp::endpoint                                  EndPoint;
    typedef std::function<void(const Ptr&, void*, int, const EndPoint&)>    ReadEventHandler;

public:
    std::shared_ptr<ReadEventHandler>                                       ReadEvent;

public:
    inline bool                                                             available() noexcept {
        return socket_.is_open();
    }
    inline int                                                              open(int listen_port) noexcept {
        boost::system::error_code ec_;
        boost::asio::ip::udp::endpoint bindEP_;
        if (socket_.is_open()) {
            bindEP_ = socket_.local_endpoint(ec_);
            if (ec_) {
                return IPEndPoint::MinPort;
            }
            return bindEP_.port();
        }

        if (listen_port < IPEndPoint::MinPort || listen_port > IPEndPoint::MaxPort) {
            listen_port = IPEndPoint::MinPort;
        }

        socket_.open(boost::asio::ip::udp::v4(), ec_);
        if (ec_) {
            return IPEndPoint::MinPort;
        }

        bool unbind = true;
        if (listen_port > IPEndPoint::MinPort) {
#if _DEBUG
            bindEP_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), listen_port);
#else
            bindEP_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), listen_port);
#endif
            socket_.bind(bindEP_, ec_);
            unbind = ec_ ? true : false;
        }

        if (unbind) {
#if _DEBUG
            bindEP_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), IPEndPoint::MinPort);
#else
            bindEP_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), IPEndPoint::MinPort);
#endif
            socket_.bind(bindEP_, ec_);
            if (ec_) {
                return IPEndPoint::MinPort;
            }
        }

        bindEP_ = socket_.local_endpoint(ec_);
        if (ec_) {
            return IPEndPoint::MinPort;
        }
        return read() ? bindEP_.port() : IPEndPoint::MinPort;
    }
    inline void                                                             close() noexcept {
        if (socket_.is_open()) {
            boost::system::error_code ec_;
            try {
                socket_.close(ec_);
            }
            catch (std::exception&) {}
        }
    }
    inline bool                                                             write(const void* data, int offset, int length, const EndPoint& destinationEP) noexcept {
        if (!data || offset < 0 || length < 1 || !socket_.is_open()) {
            return false;
        }

        boost::system::error_code ec_;
        socket_.send_to(boost::asio::buffer((char*)data + offset, length), destinationEP, 0, ec_);
        return ec_ ? false : true;
    }

private:
    inline bool                                                             read() noexcept {
        if (!socket_.is_open()) {
            return false;
        }

        std::shared_ptr<dynamic_udp_channel> self = shared_from_this();
        socket_.async_receive_from(boost::asio::buffer(buffer_, sizeof(buffer_)), remoteEP_,
            [self, this](const boost::system::error_code& ec_, size_t sz_) noexcept {
                int by_ = std::max<int>(-1, ec_ ? -1 : sz_);
                if (by_ < 0) {
                    close();
                    return;
                }

                if (by_ > 0) {
                    std::shared_ptr<ReadEventHandler> handler = ReadEvent;
                    if (handler) {
                        (*handler)(self, buffer_, by_, remoteEP_);
                    }
                }
                read();
            });
        return true;
    }

private:
    boost::asio::ip::udp::socket                                            socket_;
    boost::asio::ip::udp::endpoint                                          remoteEP_;
    Byte                                                                    buffer_[UINT16_MAX];
};

class dynamic_localhost : public std::enable_shared_from_this<dynamic_localhost> {
    typedef std::unordered_map<std::string, uint64_t>                       ehternet_link_map;

public:
    typedef std::shared_ptr<dynamic_localhost>                              Ptr;

public:
    inline dynamic_localhost(
        const dynamic_tcp_endpoint& host,
        int kf,
        const std::string& protocol,
        const std::string& protocolKey,
        const std::string& transport,
        const std::string& transportKey,
        bool transparent) noexcept
        : host_(host)
        , port_(IPEndPoint::MinPort)
        , transparent_(transparent)
        , kf_(kf)
        , protocol_(protocol)
        , protocolKey_(protocolKey)
        , transport_(transport)
        , transportKey_(transportKey) {

    }
    inline ~dynamic_localhost() noexcept {
        close();
    }

public:
    inline int                                                              port() noexcept {
        return port_;
    }
    inline void                                                             close() noexcept {
        dynamic_udp_channel::Ptr uchannel_ = std::move(owner_);
        if (NULL != uchannel_) {
            uchannel_->ReadEvent.reset();
            uchannel_->close();
        }

        dynamic_tcp_channel::Ptr tchannel_ = std::move(channel_);
        if (NULL != tchannel_) {
            tchannel_->ReadEvent.reset();
            tchannel_->close();
        }

        port_ = IPEndPoint::MinPort;
        owner_.reset();
        cipher_.reset();
        tchannel_.reset();
    }
    inline int                                                              open(int port) noexcept {
        if (NULL != owner_) {
            close();
        }

        if (protocol_.empty() || protocolKey_.empty() || transport_.empty() || transportKey_.empty()) {
            return IPEndPoint::MinPort;
        }

        cipher_ = make_shared_object<PppVpnCipher>(kf_, protocol_, protocolKey_, transport_, transportKey_);
        channel_ = create_tchannel();
        owner_ = create_uchannel(port);

        if (NULL == owner_ || NULL == channel_) {
            close();
            return IPEndPoint::MinPort;
        }

        if (port <= IPEndPoint::MinPort || port >= IPEndPoint::MaxPort) {
            close();
            return IPEndPoint::MinPort;
        }
        return (port_ = port);
    }
    inline bool                                                             available() noexcept {
        if (NULL == cipher_) {
            return false;
        }

        dynamic_tcp_channel::Ptr tchannel_ = channel_;
        dynamic_udp_channel::Ptr uchannel_ = owner_;
        if (NULL == tchannel_ || NULL == uchannel_) {
            return false;
        }
        return uchannel_->available() && tchannel_->available();
    }
    inline void                                                             timeout() noexcept {
        std::shared_ptr<PppVpnCipher> cipher = cipher_;
        if (NULL == cipher) {
            return;
        }

        int port = port_;
        if (port <= IPEndPoint::MinPort || port >= IPEndPoint::MaxPort) {
            return;
        }

        // TCP动态隧道断开
        do {
            dynamic_tcp_channel::Ptr& channel = channel_;
            if (NULL == channel) { // 连接已被断开
                break;
            }

            if (channel->available()) {
                break;
            }

            channel = create_tchannel();
        } while (0);

        // UDP动态隧道断开
        do {
            dynamic_udp_channel::Ptr& channel = owner_;
            if (NULL == channel) {
                break;
            }

            if (channel->available()) {
                break;
            }

            channel = create_uchannel(port);
            if (NULL != channel) {
                port_ = port;
            }
        } while (0);
    }

public:
    inline void                                                             input(void* data, int length, const dynamic_udp_channel::EndPoint& remoteEP) noexcept {
        if (NULL == data || length < 1) {
            return;
        }

        DatagramPacket packet_;
        MemoryStream messages_(std::shared_ptr<Byte>((Byte*)data, [](void*) noexcept {}), length);
        if (!PppVpnProtocol::ReadDatagramPacket(messages_, cipher_, packet_)) {
            return;
        }

        if (packet_.MessageSize < 1) {
            return;
        }

        if (packet_.ProtocolType != ip_hdr::IP_PROTO_UDP &&
            packet_.ProtocolType != ip_hdr::IP_PROTO_TCP &&
            packet_.ProtocolType != ip_hdr::IP_PROTO_ICMP) {
            return;
        }

        packet_.Source = IPEndPoint::ToEndPoint(remoteEP);
        lan2wan(packet_);
    }

private:
    inline dynamic_tcp_channel::Ptr                                         create_tchannel() noexcept {
        std::shared_ptr<PppVpnCipher> cipher = cipher_;
        if (NULL == cipher) {
            return NULL;
        }

        std::shared_ptr<dynamic_localhost> self = shared_from_this();
        dynamic_tcp_channel::Ptr channel = make_shared_object<dynamic_tcp_channel>(cipher, transparent_);
        channel->ReadEvent = make_shared_object<dynamic_tcp_channel::ReadEventHandler>(
            [self, this](const dynamic_tcp_channel::Ptr&, void* data, int length) noexcept {
                if (NULL == data || length < 1) {
                    return;
                }

                std::shared_ptr<IPFrame> packet_ = IPFrame::Parse(data, length);
                if (NULL == packet_) {
                    return;
                }

                if (packet_->ProtocolType != ip_hdr::IP_PROTO_UDP &&
                    packet_->ProtocolType != ip_hdr::IP_PROTO_TCP &&
                    packet_->ProtocolType != ip_hdr::IP_PROTO_ICMP) {
                    return;
                }

                wan2lan(packet_, data, length);
            });

        if (!channel->open(host_)) {
            channel->ReadEvent.reset();
            channel->close();
            channel.reset();
        }
        return channel;
    }
    inline dynamic_udp_channel::Ptr                                         create_uchannel(int& port) noexcept {
        std::shared_ptr<dynamic_localhost> self = shared_from_this();
        std::shared_ptr<dynamic_udp_channel> channel = make_shared_object<dynamic_udp_channel>();
        channel->ReadEvent = make_shared_object<dynamic_udp_channel::ReadEventHandler>(
            [self, this](const dynamic_udp_channel::Ptr&, void* data, int length, const dynamic_udp_channel::EndPoint& remoteEP) noexcept {
                this->input(data, length, remoteEP);
            });

        port = channel->open(port);
        if (port <= IPEndPoint::MinPort || port >= IPEndPoint::MaxPort) {
            channel->ReadEvent.reset();
            channel->close();
            channel.reset();
            port = IPEndPoint::MinPort;
        }
        return channel;
    }

protected:
    virtual bool                                                            lan2wan(DatagramPacket& packet_) noexcept {
        dynamic_tcp_channel::Ptr channel = channel_;
        if (NULL == channel) {
            return false;
        }

        if (packet_.ProtocolType == ip_hdr::IP_PROTO_UDP) {
            std::shared_ptr<Byte> payload = packet_.Message;
            if (NULL == payload) {
                return false;
            }

            std::shared_ptr<UdpFrame> frame = make_shared_object<UdpFrame>();
            frame->Source = packet_.Source;
            frame->Destination = packet_.Destination;
            frame->AddressesFamily = packet_.Source.GetAddressFamily();
            if (packet_.MessageOffset > 0) {
                payload = std::shared_ptr<Byte>(payload.get() + packet_.MessageOffset, [payload](void*) noexcept {});
            }
            frame->Payload = make_shared_object<BufferSegment>(payload, packet_.MessageSize);

            std::shared_ptr<BufferSegment> messages_ = frame->ToIp()->ToArray();
            return channel->write(messages_->Buffer.get(), 0, messages_->Length);
        }
        elif (packet_.ProtocolType == ip_hdr::IP_PROTO_ICMP) {
            ilink_ = packet_.Source;
        }
        elif (packet_.ProtocolType == ip_hdr::IP_PROTO_TCP) {
            tlink_ = packet_.Source;
        }
        else {
            return false;
        }
        return channel->write(packet_.Message.get(), packet_.MessageOffset, packet_.MessageSize);
    }
    virtual bool                                                            wan2lan(std::shared_ptr<IPFrame> packet_, void* raw_, int raw_size_) noexcept {
        dynamic_udp_channel::Ptr channel = owner_;
        if (NULL == channel) {
            return false;
        }

        std::shared_ptr<PppVpnCipher> cipher = cipher_;
        if (NULL == cipher) {
            return false;
        }

        IPEndPoint* iplink_ = NULL;
        DatagramPacket datagramPacket_;
        datagramPacket_.MessageOffset = 0;
        datagramPacket_.ProtocolType = packet_->ProtocolType;

        MemoryStream stream_;
        if (packet_->ProtocolType == ip_hdr::IP_PROTO_UDP) {
            std::shared_ptr<UdpFrame> frame_ = UdpFrame::Parse(packet_.get());
            if (NULL == frame_) {
                return false;
            }

            std::shared_ptr<BufferSegment> payload_ = frame_->Payload;
            datagramPacket_.Message = payload_->Buffer;
            datagramPacket_.MessageSize = payload_->Length;
            datagramPacket_.Source = frame_->Destination;
            datagramPacket_.Destination = frame_->Source;

            if (!PppVpnProtocol::BuildDatagramPacket(stream_, cipher, datagramPacket_)) {
                return false;
            }
            return this->output(channel, stream_.GetBuffer().get(), stream_.GetPosition(), frame_->Destination);
        }
        elif (packet_->ProtocolType == ip_hdr::IP_PROTO_ICMP) {
            iplink_ = std::addressof(ilink_);
        }
        elif (packet_->ProtocolType == ip_hdr::IP_PROTO_TCP) {
            iplink_ = std::addressof(tlink_);
        }
        else {
            return false;
        }

        if (NULL == iplink_ || IPEndPoint::IsInvalid(*iplink_)) {
            return false;
        }
        else {
            datagramPacket_.Message = std::shared_ptr<Byte>((Byte*)raw_, [](void*) noexcept {});
            datagramPacket_.MessageSize = raw_size_;
            datagramPacket_.Source = *iplink_;
            datagramPacket_.Destination = *iplink_;

            if (!PppVpnProtocol::BuildDatagramPacket(stream_, cipher, datagramPacket_)) {
                return false;
            }
            return this->output(channel, stream_.GetBuffer().get(), stream_.GetPosition(), *iplink_);
        }
    }
    virtual bool                                                            output(dynamic_udp_channel::Ptr& channel, void* packet, int length, const IPEndPoint& destinationEP) noexcept {
        return channel->write(packet, 0, length,
            IPEndPoint::ToEndPoint<boost::asio::ip::udp>(destinationEP));
    }

private:
    dynamic_udp_channel::Ptr                                                owner_;
    dynamic_tcp_channel::Ptr                                                channel_;
    dynamic_tcp_endpoint                                                    host_;
    int                                                                     port_;
    int                                                                     kf_;
    std::string                                                             protocol_;
    std::string                                                             protocolKey_;
    std::string                                                             transport_;
    std::string                                                             transportKey_;
    bool                                                                    transparent_;
    std::shared_ptr<PppVpnCipher>                                           cipher_;
    IPEndPoint                                                              tlink_;
    IPEndPoint                                                              ilink_;
};

static void libdynamic_localhost_join_(const std::function<void()>& callback) noexcept {
    libdynamic_initialize();

    if (callback) {
        std::condition_variable cv_;
        std::mutex cv_m_;
        std::unique_lock<std::mutex> lk_(cv_m_);

        int join_ = 0;
        dynamic_context_.post(
            [&join_, &cv_, callback] {
                callback();
                join_ = 1;
                cv_.notify_one();
            });
        cv_.wait(lk_, [&join_] { return join_ == 1; });
    }
}

void libdynamic_localhost_join(int64_t state, libdynamic_localhost_join_callback callback) noexcept {
    if (callback) {
        libdynamic_localhost_join_([state, callback] {
            callback(state);
        });
    }
}

uint64_t libdynamic_localhost_now() noexcept {
    return dynamic_now_;
}

int libdynamic_timeout() noexcept {
    dynamic_localhost::Ptr localhost = dynamic_localhost_;
    if (NULL != localhost) {
        localhost->timeout();
    }
    return 0;
}

int libdynamic_initialize() noexcept {
    static std::atomic<bool> initialized_ = ATOMIC_FLAG_INIT;
    if (initialized_.exchange(true)) {
        return 0;
    }

    auto dowork_ = []() noexcept {
#ifdef _WIN32
        SetThreadPriority(GetCurrentProcess(), THREAD_PRIORITY_TIME_CRITICAL);
#else
        /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
        struct sched_param param_;
        param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR
        pthread_setschedparam(pthread_self(), SCHED_FIFO, &param_);
#endif
        boost::system::error_code ec_;
        boost::asio::io_context::work work_(dynamic_context_);
        dynamic_context_.run(ec_);
    };
    std::thread(dowork_).detach();

    static std::shared_ptr<boost::asio::deadline_timer> timeout_ = make_shared_object<boost::asio::deadline_timer>(dynamic_context_);
    static void(*timeout_tick_)() = []() noexcept {
        timeout_->expires_from_now(boost::posix_time::seconds(1));
        timeout_->async_wait(
            [](const boost::system::error_code& ec) {
                if (ec) {
                    timeout_.reset();
                    return;
                }

                dynamic_now_++;
                libdynamic_timeout();
                timeout_tick_();
            });
    };
    timeout_tick_();
    return 1;
}

int libdynamic_random_r(unsigned int* seed) noexcept {
    unsigned int next = *seed;
    int result;

    next *= 1103515245;
    next += 12345;
    result = (unsigned int)(next / 65536) % 2048;

    next *= 1103515245;
    next += 12345;
    result <<= 10;
    result ^= (unsigned int)(next / 65536) % 1024;

    next *= 1103515245;
    next += 12345;
    result <<= 10;
    result ^= (unsigned int)(next / 65536) % 1024;

    *seed = next;
    return result;
}

int libdynamic_random(int min, int max) noexcept { // rand() % (max - min) + min
    static unsigned int seed = time(NULL);

    int v = libdynamic_random_r(&seed);
    return v % (max - min + 1) + min;
}

int libdynamic_random() noexcept {
    return libdynamic_random(0, INT_MAX);
}

int libdynamic_random_ascii() noexcept {
    static Byte x_[] = { 'a', 'A', '0' };
    static Byte y_[] = { 'z', 'Z', '9' };

    int i_ = libdynamic_random() % 3;
    return libdynamic_random(x_[i_], y_[i_]);
}

Byte libdynamic_random_byte() noexcept {
    return libdynamic_random(0x00, 0x100);
}

int libdynamic_localhost_port() noexcept {
    libdynamic_initialize();

    std::shared_ptr<dynamic_localhost> localhost = dynamic_localhost_;
    return NULL != localhost ? localhost->port() : IPEndPoint::MinPort;
}

int libdynamic_localhost_close() noexcept {
    int success = 0;
    libdynamic_localhost_join_([&] {
        std::shared_ptr<dynamic_localhost> localhost = std::move(dynamic_localhost_);
        if (NULL == localhost) {
            return;
        }
        localhost->close();
        localhost.reset();
        dynamic_localhost_.reset();
        success = 1;
    });
    return success;
}

static int libdynamic_localhost_open_(
    int*        listenPort,
    const char* address,
    int         port,
    int         kf,
    const char* protocol,
    const char* protocolKey,
    const char* transport,
    const char* transportKey,
    int         transparent) noexcept {
    if (NULL == address || NULL == protocol || NULL == protocolKey || NULL == transport || NULL == transportKey) {
        return IPEndPoint::MinPort;
    }

    if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
        return IPEndPoint::MinPort;
    }

    IPEndPoint ipep_ = IPEndPoint(address, port);
    if (IPEndPoint::IsInvalid(ipep_)) {
        return IPEndPoint::MinPort;
    }

    std::shared_ptr<dynamic_localhost> localhost = std::move(dynamic_localhost_);
    if (NULL != localhost) {
        localhost->close();
        localhost.reset();
        dynamic_localhost_.reset();
    }

    dynamic_tcp_endpoint endpoint_;
    memset(&endpoint_, 0, sizeof(endpoint_));

    endpoint_.v4_or_v6 = ipep_.GetAddressFamily() == AddressFamily::InterNetwork;
    endpoint_.port = ipep_.Port;
    if (endpoint_.v4_or_v6) {
        endpoint_.in4 = ipep_.GetAddress();
    }
    else {
        int address_size_;
        Byte* address_bytes_ = ipep_.GetAddressBytes(address_size_);
        memcpy(endpoint_.in6, address_bytes_, address_size_);
    }

    auto trimNull = [](const std::string& s) noexcept {
        if (s.empty()) {
            return std::string();
        }
        size_t sz = s.size();
        while (s[sz - 1] == '\x0') {
            sz--;
        }
        return std::string(s.data(), sz);
    };
    std::string protocol_ = trimNull(protocol);
    std::string protocolKey_ = trimNull(protocolKey);
    std::string transport_ = trimNull(transport);
    std::string transportKey_ = trimNull(transportKey);
    if (protocol_.empty() || protocolKey_.empty() || transport_.empty() || transportKey_.empty()) {
        return IPEndPoint::MinPort;
    }
    else {
        try {
            Cipher::Create(protocol_, protocolKey_);
        }
        catch (std::exception&) {
            return IPEndPoint::MinPort;
        }

        try {
            Cipher::Create(transport_, transportKey_);
        }
        catch (std::exception&) {
            return IPEndPoint::MinPort;
        }
    }

    localhost = make_shared_object<dynamic_localhost>(endpoint_, kf, protocol_, protocolKey_, transport_, transportKey_, transparent ? true : false);
    if (NULL == localhost) {
        return IPEndPoint::MinPort;
    }

    int localPort = 0;
    if (NULL == listenPort) {
        listenPort = &localPort;
    }

    *listenPort = localhost->open(*listenPort);
    if (*listenPort <= IPEndPoint::MinPort || *listenPort > IPEndPoint::MaxPort) {
        localhost->close();
        localhost.reset();
        return IPEndPoint::MinPort;
    }

    dynamic_localhost_ = localhost;
    return *listenPort;
}

int libdynamic_localhost_open(
    int* listenPort,
    const char* address,
    int         port,
    int         kf,
    const char* protocol,
    const char* protocolKey,
    const char* transport,
    const char* transportKey,
    int         transparent) noexcept {
    int result;
    auto callbackf = [&]() noexcept {
        result = libdynamic_localhost_open_(listenPort, address, port,
            kf, protocol, protocolKey, transport, transportKey, transparent);
    };
    libdynamic_localhost_join_(callbackf);
    return result;
}

void libdynamic_localhost_protect(libdynamic_localhost_protect_callback callback) noexcept {
    libdynamic_initialize();

    dynamic_context_.post([callback] {
        dynamic_protect_ = std::move(callback);
    });
}

int libdynamic_localhost_input(void* buffer, int length, uint32_t srcAddr, int srcPort) noexcept {
    libdynamic_initialize();

    if (NULL == buffer || srcAddr == INADDR_ANY || srcAddr == INADDR_NONE) {
        return -1;
    }

    if (srcPort <= IPEndPoint::MinPort || srcPort > IPEndPoint::MaxPort) {
        return -1;
    }

    std::shared_ptr<dynamic_localhost> localhost_ = dynamic_localhost_;
    if (NULL == localhost_) {
        return -1;
    }

    if (length == 0) {
        return 0;
    }

    std::shared_ptr<Byte> chunk_ = make_shared_alloc<Byte>(length);
    if (NULL == chunk_) {
        return -1;
    }

    memcpy(chunk_.get(), buffer, length);
    dynamic_context_.post([localhost_, chunk_, length, srcAddr, srcPort] {
        IPEndPoint destinationEP = IPEndPoint(srcAddr, srcPort);
        localhost_->input(chunk_.get(), length, IPEndPoint::ToEndPoint<boost::asio::ip::udp>(destinationEP));
    });
    return length;
}
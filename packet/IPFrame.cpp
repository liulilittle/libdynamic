#include "../env.h"
#include "./native/checksum.h"
#include "IPFrame.h"

int IPFrame::SizeOf() noexcept {
    std::shared_ptr<BufferSegment> payload_segment = this->Payload;
    std::shared_ptr<BufferSegment> options_segment = this->Options;
    int options_size = 0;
    if (NULL != options_segment) {
        options_size = options_segment->Length;
    }

    int payload_offset = sizeof(struct ip_hdr) + options_size;
    int payload_size = 0;
    if (NULL != payload_segment) {
        payload_size = payload_segment->Length;
    }

    int message_data_size = payload_offset + payload_size;
    return message_data_size;
}

std::shared_ptr<BufferSegment> IPFrame::ToArray() noexcept {
    std::shared_ptr<BufferSegment> payload_segment = this->Payload;
    std::shared_ptr<BufferSegment> options_segment = this->Options;
    int options_size = 0;
    if (NULL != options_segment) {
        options_size = options_segment->Length;
    }

    int payload_offset = sizeof(struct ip_hdr) + options_size;
    int payload_size = 0;
    if (NULL != payload_segment) {
        payload_size = payload_segment->Length;
    }

    int message_data_size = payload_offset + payload_size;
    std::shared_ptr<Byte> message_data = make_shared_alloc<Byte>(message_data_size);

    struct ip_hdr* iphdr = (struct ip_hdr*)message_data.get();
    iphdr->dest = this->Destination;
    iphdr->src = this->Source;
    iphdr->ttl = this->Ttl;
    iphdr->proto = this->ProtocolType;
    iphdr->v_hl = 4 << 4 | payload_offset >> 2;
    iphdr->tos = this->Tos; // Routine Mode
    iphdr->len = htons(message_data_size);
    iphdr->id = htons(this->Id);
    iphdr->flags = htons((UInt16)(this->Flags == 0 ? IPFlags::IP_DF : this->Flags));
    iphdr->chksum = 0;

    if (options_size > 0) {
        Byte* destination_options = message_data.get() + sizeof(struct ip_hdr);
        memcpy(destination_options, options_segment->Buffer.get(), options_size);
    }

    if (payload_size > 0) {
        memcpy(message_data.get() + payload_offset, payload_segment->Buffer.get(), payload_size);
    }

    iphdr->chksum = inet_chksum(message_data.get(), payload_offset);
    if (iphdr->chksum == 0) {
        iphdr->chksum = 0xffff;
    }

    return make_shared_object<BufferSegment>(message_data, message_data_size);
}

std::shared_ptr<IPFrame> IPFrame::Parse(const void* packet, int size, bool checksum) noexcept {
    struct ip_hdr* iphdr = checksum ? ip_hdr::Parse(packet, size) : (struct ip_hdr*)packet;
    if (NULL == iphdr) {
        return NULL;
    }

    std::shared_ptr<IPFrame> frame = make_shared_object<IPFrame>();
    frame->Destination = iphdr->dest;
    frame->Source = iphdr->src;
    frame->Tos = iphdr->tos;
    frame->Ttl = iphdr->ttl;
    frame->AddressesFamily = AddressFamily::InterNetwork;
    frame->ProtocolType = iphdr->proto;
    frame->Id = ntohl(iphdr->id);
    frame->Flags = (IPFlags)ntohs(iphdr->flags);

    int iphdr_hlen = ip_hdr::IPH_HL(iphdr) << 2;
    int options_size = (iphdr_hlen - sizeof(struct ip_hdr));
    if (options_size > 0) {
        std::shared_ptr<BufferSegment> options_ = make_shared_object<BufferSegment>();
        options_->Length = options_size;
        options_->Buffer = make_shared_alloc<Byte>(options_size);

        frame->Options = options_;
        memcpy(options_->Buffer.get(), (char*)iphdr + sizeof(struct ip_hdr), options_size);
    }

    int message_size_ = size - iphdr_hlen;
    if (message_size_ > 0) {
        std::shared_ptr<BufferSegment> messages_ = make_shared_object<BufferSegment>();
        messages_->Buffer = make_shared_alloc<Byte>(message_size_);
        messages_->Length = message_size_;

        frame->Payload = messages_;
        memcpy(messages_->Buffer.get(), (char*)iphdr + iphdr_hlen, message_size_);
    }
    return frame;
}

int IPFrame::Subpackages(std::vector<IPFramePtr>& out, const IPFramePtr& packet) noexcept {
    if (NULL == packet) {
        return 0;
    }

    if (packet->Flags & IPFlags::IP_MF) {
        out.push_back(packet);
        return 1;
    }

    std::shared_ptr<BufferSegment> messages = packet->Payload;
    std::shared_ptr<BufferSegment> options = packet->Options;
    if (NULL == messages) {
        out.push_back(packet);
        return 1;
    }

    int max = ip_hdr::MTU - sizeof(struct ip_hdr);
    if (NULL != options) {
        max -= options->Length;
    }

    int szz = messages->Length;
    max = (max >> 3) << 3;
    if (szz <= max) {
        out.push_back(packet);
        return 1;
    }

    std::shared_ptr<Byte> buffer = messages->Buffer;

    int ofs = 0;
    int fragmentl = 0;
    std::shared_ptr<IPFrame> fragment;
    while (szz > max) {
        fragment = make_shared_object<IPFrame>();
        fragment->ProtocolType = packet->ProtocolType;
        fragment->Source = packet->Source;
        fragment->Destination = packet->Destination;
        fragment->Flags = IPFlags::IP_MF;
        fragment->Id = packet->Id;
        fragment->Options = options;
        fragment->Ttl = packet->Ttl;
        fragment->Tos = packet->Tos;
        fragment->Payload = make_shared_object<BufferSegment>(
            std::shared_ptr<Byte>(buffer.get() + ofs, [buffer](const Byte*) noexcept {}), max);
        fragment->SetFragmentOffset(ofs);

        options = NULL;
        ofs += max;
        szz -= max;
        fragmentl++;
        out.push_back(fragment);
    }
    if (szz > 0) {
        fragment = make_shared_object<IPFrame>();
        fragment->ProtocolType = packet->ProtocolType;
        fragment->Source = packet->Source;
        fragment->Destination = packet->Destination;
        fragment->Flags = ofs < 1 ? packet->Flags : (IPFlags)0;
        fragment->Id = packet->Id;
        fragment->Options = options;
        fragment->Ttl = packet->Ttl;
        fragment->Tos = packet->Tos;
        fragment->Payload = make_shared_object<BufferSegment>(
            std::shared_ptr<Byte>(buffer.get() + ofs, [buffer](const Byte*) noexcept {}), szz);
        fragment->SetFragmentOffset(ofs);
        out.push_back(fragment);
    }
    return ++fragmentl;
}
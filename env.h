#pragma once

#include "libdynamic.h"

#if !LIBDYNAMIC_INDEPENDENT
#include <Ppp/Environment.h>
#include <Ppp/IO/Stream.h>
#include <Ppp/IO/MemoryStream.h>
#include <Ppp/Vpn/PppVpnCipher.h>
#include <Ppp/Vpn/Protocol/PppVpnProtocol.h>
#include <Ppp/Cryptography/Cipher.h>
#include <Ppp/Net/IPEndPoint.h>
#include <Ppp/Net/Native/ip.h>
#include <Ppp/Net/Packet/IPFrame.h>
#include <Ppp/Net/Packet/UdpFrame.h>
#include <Ppp/Net/Packet/IcmpFrame.h>

using Ppp::Byte;
using Ppp::SByte;
using Ppp::Int16;
using Ppp::Int32;
using Ppp::Int64;
using Ppp::UInt16;
using Ppp::UInt32;
using Ppp::UInt64;
using Ppp::Double;
using Ppp::Single;
using Ppp::Boolean;
using Ppp::Char;
using Ppp::Net::IPEndPoint;
using Ppp::Net::AddressFamily;
using Ppp::Net::Native::ip_hdr;
using Ppp::Net::Packet::IPFrame;
using Ppp::Net::Packet::UdpFrame;
using Ppp::Net::Packet::IcmpFrame;
using Ppp::Net::Packet::BufferSegment;
using Ppp::IO::MemoryStream;
using Ppp::Cryptography::Cipher;
using Ppp::Vpn::Error;
using Ppp::Vpn::PppVpnCipher;
using Ppp::Vpn::Protocol::DatagramPacket;
using Ppp::Vpn::Protocol::PppVpnProtocol;
#else
#include "custom.h"
#endif

#ifndef elif
#define elif else if
#endif
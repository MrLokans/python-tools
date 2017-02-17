from __future__ import print_function

import os
import struct
import socket
import ctypes


HOST = '192.168.100.54'


class IPV4Header(ctypes.Structure):
    # https://en.wikipedia.org/wiki/IPv4#Header
    _fields_ = (
        ("ihl",          ctypes.c_ubyte, 4),
        ("version",      ctypes.c_ubyte, 4),
        ("tos",          ctypes.c_ubyte),
        ("len",          ctypes.c_ushort),
        ("id",           ctypes.c_ushort),
        ("offset",       ctypes.c_ushort),
        ("ttl",          ctypes.c_ubyte),
        ("protocol_num", ctypes.c_ubyte),
        ("sum",          ctypes.c_ushort),
        ("src",          ctypes.c_uint32),
        ("dst",          ctypes.c_uint32)
    )

    PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, *args, **kwargs):
        pass

    @property
    def src_address(self):
        # unisigned int in native order.
        return socket.inet_ntoa(struct.pack("@I", self.src))

    @property
    def dst_address(self):
        return socket.inet_ntoa(struct.pack("@I", self.dst))

    @property
    def protocol(self):
        _protocol = self.PROTOCOL_MAP.get(self.protocol_num)
        if _protocol is None:
            _protocol = str(self.protocol_num)
        return _protocol


class ICMPPacket(ctypes.Structure):
    # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#ICMP_datagram_structure
    _fields_ = (
        ('type',         ctypes.c_ubyte),
        ('code',         ctypes.c_ubyte),
        ('checksum',     ctypes.c_ushort),
        ('unused',       ctypes.c_ushort),
        ('next_hop_mtu', ctypes.c_ushort)
    )

    def __new__(cls, socket_buffer):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socker_buffer):
        pass


ON_WINDOWS_SYSTEM = os.name == 'nt'

if ON_WINDOWS_SYSTEM:
    SOCKET_PROTOCOL = socket.IPPROTO_IP
else:
    SOCKET_PROTOCOL = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET,
                        socket.SOCK_RAW,
                        SOCKET_PROTOCOL)

sniffer.bind((HOST, 0))

# Include IP headers
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if ON_WINDOWS_SYSTEM:
    # Enables a socket to receive all IP packets on the network.
    # The socket handle passed to the WSAIoctl function must be of
    # AF_INET address family, SOCK_RAW socket type, and IPPROTO_IP protocol.
    # The socket also must be bound to an explicit local interface, which means
    # that you cannot bind to INADDR_ANY.
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


print("Started reading the data.")
try:
    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = IPV4Header(raw_buffer[:20])
        print("Protocol: {proto} {source} -> {dest}"
              .format(proto=ip_header.protocol,
                      source=ip_header.src_address,
                      dest=ip_header.dst_address))

        if ip_header.protocol == "ICMP":
            # Calculate where header ends
            icmp_offset = ip_header.ihl * 4
            buf = raw_buffer[icmp_offset:icmp_offset + ctypes.sizeof(ICMPPacket)]
            icmp_header = ICMPPacket(buf)
            print("ICMP -> Type: %d, Code: %d" % (icmp_header.type, icmp_header.code))

except Exception as e:
    print("Unknown error occurend: %s" % e)
finally:
    if ON_WINDOWS_SYSTEM:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

import os
import socket

HOST = '192.168.100.54'
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

print("Reading the data.")
print(sniffer.recvfrom(65565))

if ON_WINDOWS_SYSTEM:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

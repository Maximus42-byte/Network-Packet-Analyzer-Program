import socket, sys
from struct import *


def ethernet_address(address):
    res = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(address[0]), ord(address[1]), ord(address[2]),
                                             ord(address[3]), ord(address[4]), ord(address[5]))
    return res


def print_to_both(line):
    print(line)
    log_file.write(line + '\n')


# *************** main ***************

log_file = open('./log', 'w+')

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
    packet = s.recvfrom(65565)

    # packet string from tuple
    packet = packet[0]

    ethernet_length = 14

    ethernet_header = packet[:ethernet_length]
    ethernet = unpack('!6s6sH', ethernet_header)
    ethernet_protocol = socket.ntohs(ethernet[2])

    print_to_both('Ethernet: src mac ' + ethernet_address(packet[6:12]) + ', dst mac ' + ethernet_address(packet[0:6]))

    # IP Protocol number = 8
    if ethernet_protocol == 8:
        # Parse IP packets:
        ip_header_packed = packet[ethernet_length:20 + ethernet_length]

        ip_header = unpack('!BBHHHBBH4s4s', ip_header_packed)

        version_IHL = ip_header[0]
        version = version_IHL >> 4
        IHL = version_IHL & 0xF

        ip_header_length = IHL * 4

        Identification = ip_header[3]

        Flags_FragmentOffset = ip_header[4]
        FragmentOffset = Flags_FragmentOffset & 0B0000111111111111

        TTL = ip_header[5]
        protocol = ip_header[6]
        checksum = ip_header[7]
        s_address = socket.inet_ntoa(ip_header[8])
        d_address = socket.inet_ntoa(ip_header[9])

        print_to_both('IP: src ip ' + str(s_address) + ', dst ip ' + str(d_address) + ', header checksum '
                      + str(checksum) + ', protocol ' + str(protocol) + ', TTL ' + str(TTL) + ', id '
                      + str(Identification) + ', fragment offset ' + str(FragmentOffset))

        # TCP protocol
        if protocol == 6:
            start_point = ip_header_length + ethernet_length
            tcp_header_packed = packet[start_point:start_point + 20]

            tcp_header = unpack('!HHLLBBHHH', tcp_header_packed)

            source_port = tcp_header[0]
            dest_port = tcp_header[1]
            sequence = tcp_header[2]
            acknowledgement = tcp_header[3]
            dataOffset_reserved = tcp_header[4]
            tcp_header_length = dataOffset_reserved >> 4
            flags = tcp_header[5]
            win_size = tcp_header[6]
            checksum = tcp_header[7]

            print_to_both(
                'TCP:src port ' + str(source_port) + ', dst port ' + str(dest_port) + ', seq number ' + str(sequence)
                + ', ack number ' + str(acknowledgement) + ', window size ' + str(win_size) + ', checksum '
                + str(checksum)
                + ', syn flag ' + str((flags & (1 << 1)) >= 1) + ', fin flag ' + str((flags & (1 << 0)) >= 1)
                + ', urg flag ' + str((flags & (1 << 5)) >= 1) + ', ack flag ' + str((flags & (1 << 4)) >= 1)
                + ', rst flag ' + str((flags & (1 << 2)) >= 1) + ', data offset ' + str(tcp_header_length))

        # UDP packets
        elif protocol == 17:
            start_point = ip_header_length + ethernet_length
            udp_header_length = 8
            udp_header_packed = packet[start_point:start_point + 8]

            udp_header = unpack('!HHHH', udp_header_packed)

            source_port = udp_header[0]
            dest_port = udp_header[1]
            length = udp_header[2]
            checksum = udp_header[3]

            print_to_both(
                'UDP: src port ' + str(source_port) + ', dst port ' + str(dest_port) + ', checksum ' + str(checksum)
                + ', length ' + str(length))

        # ICMP Packets
        elif protocol == 1:
            start_point = ip_header_length + ethernet_length
            icmp_header_length = 4
            icmp_header_packed = packet[start_point:start_point + 4]

            icmp_header = unpack('!BBH', icmp_header_packed)

            icmp_type = icmp_header[0]
            code = icmp_header[1]
            checksum = icmp_header[2]

            print_to_both('ICMP: Type ' + str(icmp_type) + ', Code ' + str(code) + ', Checksum ' + str(checksum))

# ************* end main *************

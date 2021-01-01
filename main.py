import socket
import struct

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main():
    icmp_counter = 0
    udp_counter = 0
    tcp_counter = 0

    sender_packet_counter = {}

    packet_size = []

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)

            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame: ')
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

            # IPv4 --> 8
            if eth_proto == 8:
                packet_size.append(len(data))

                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                print(TAB_1 + 'IPv4 Packet: ')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(version, header_length, ttl))
                print(TAB_2 + 'Protocol: {}, Source: {}, Target: {},'.format(proto, src, target))

                if src in sender_packet_counter:
                    sender_packet_counter[src] += 1
                else:
                    sender_packet_counter[src] = 1

                # ICMP --> 1
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print(TAB_1 + 'ICMP Packet: ')
                    print(TAB_2 + "Type: {}, Code: {}, Checksum: {},".format(icmp_type, code, checksum))
                    icmp_counter += 1

                # TCP --> 6
                elif proto == 6:
                    (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                     flag_fin, data) = tcp_segment(data)
                    print(TAB_1 + 'TCP Segment: ')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {},'.format(src_port, dest_port))
                    print(TAB_2 + 'Sequence: {}, Acknowledgement: {},'.format(sequence, acknowledgement))
                    print(TAB_2 + 'Flags: ')
                    print(
                        TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack,
                                                                                              flag_psh,
                                                                                              flag_rst, flag_syn,
                                                                                              flag_fin))
                    tcp_counter += 1


                # UDP --> 17
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    print(TAB_1 + 'UDP Segment: ')
                    print(
                        TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                    udp_counter += 1

                # Other
                else:
                    print(TAB_1 + 'Other Protocol')

            else:
                print('It is not IPv4 packet')
    except KeyboardInterrupt:
        print("Done")


# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Return properly fromatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[
                                                                                                                       offset:]


# Unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


if __name__ == '__main__':
    main()

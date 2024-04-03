import socket
import struct
import errno

def get_mac_address(bytesString):
    bytesString = map("{:02x}".format, bytesString)
    return ":".join(bytesString)

def main():
    try:
        # Create a raw socket to capture packets
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind(('0.0.0.0', 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Enable promiscuous mode
    except socket.error as e:
        print("Socket creation error:", e)
        return

    try:
        while True:
            try:
                # Receive packet data
                raw_data, addr = s.recvfrom(65565)

                # Ensure received data is at least the size of an Ethernet frame header
                if len(raw_data) < 14:
                    print("Received data is too short for Ethernet frame header")
                    continue

                # Unpack Ethernet frame header
                destination_mac, source_mac, ethernet_protocol = struct.unpack("! 6s 6s H", raw_data[:14])
                destination_mac = get_mac_address(destination_mac)
                source_mac = get_mac_address(source_mac)
                ethernet_protocol = socket.htons(ethernet_protocol)
                data = raw_data[14:]  # Packet payload

                # Analyze IPv4 packets
                if ethernet_protocol == 0x0800:  # IPv4 protocol
                    version_header_length = data[0]
                    version = version_header_length >> 4
                    header_length = (version_header_length & 0xF) * 4
                    ttl, protocol, src, dst = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
                    src = '.'.join(map(str, src))
                    dst = '.'.join(map(str, dst))

                    # Print packet information
                    print('\nEthernet frame:')
                    print('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, source_mac, ethernet_protocol))
                    print('IPv4 packet:')
                    print('\tVersion: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
                    print('\tProtocol: {}, Source: {}, Target: {}'.format(protocol, src, dst))
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except socket.error as e:
                # Handle socket-related errors
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print("Socket error:", e)
                    break
            except Exception as e:
                # Handle other exceptions
                print("Packet handling error:", e)
    finally:
        # Close the socket when done
        s.close()

if __name__ == '__main__':
    main()

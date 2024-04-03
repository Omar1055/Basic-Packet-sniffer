import socket
import struct
import errno
import platform

def get_mac_address(bytesString):
    bytesString = map("{:02x}".format, bytesString)
    return ":".join(bytesString)

def main():
    print("Starting packet sniffer...")
    try:
        # Create a raw socket to capture packets
        if platform.system() == 'Windows':
            print("Creating raw socket on Windows...")
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            print("Socket created successfully.")
            s.bind(('0.0.0.0', 0))
            print("Socket bound successfully.")
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            print("Socket options set successfully.")
        else:
            print("Creating raw socket on non-Windows...")
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            print("Socket created successfully.")
    except socket.error as e:
        print("Socket creation error:", e)
        return

    try:
        print("Packet sniffer started. Listening for packets...")
        while True:
            try:
                # Receive packet data
                raw_data, addr = s.recvfrom(65565)
                print("Packet received.")

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
                    print("IPv4 packet detected.")
                    version_header_length = data[0]
                    version = version_header_length >> 4
                    header_length = (version_header_length & 0xF) * 4
                    ttl, protocol, src, dst = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
                    src = '.'.join(map(str, src))
                    dst = '.'.join(map(str, dst))

                    # Print packet information
                    print('\nEthernet frame:')
                    print('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, source_mac,
                                                                                        ethernet_protocol))
                    print('IPv4 packet:')
                    print('\tVersion: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
                    print('\tProtocol: {}, Source: {}, Target: {}'.format(protocol, src, dst))
                else:
                    print("Non-IPv4 packet detected. Skipping...")
                    print("Ethernet Protocol:", ethernet_protocol)
                    print("Raw Ethernet Header (Hexadecimal):", raw_data[:14].hex())



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
        print("Closing socket...")
        s.close()
        print("Socket closed.")

if __name__ == '__main__':
    main()

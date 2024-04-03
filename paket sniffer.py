import socket
import struct
import errno
import time

def get_mac_address(bytesString):
    bytesString = map("{:02x}".format, bytesString)
    return ":".join(bytesString)

def main():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket
        s.connect(('www.google.com', 80))  # Connect to a web server on port 80
        s.setblocking(0)  # Set the socket to non-blocking mode
    except socket.error as e:
        print("Socket creation error:", e)
        return

    try:
        while True:
            try:
                raw_data = s.recv(1024)  # Receive TCP packets
                if len(raw_data) == 0:
                    time.sleep(0.1)  # Sleep briefly to avoid busy-waiting
                    continue

                if len(raw_data) < 14:
                    print("Received data is too short for Ethernet frame header")
                    continue

                destination_mac, source_mac, ethernet_protocol = struct.unpack("! 6s 6s H", raw_data[:14])  # Ethernet frame header
                destination_mac = get_mac_address(destination_mac)
                source_mac = get_mac_address(source_mac)
                ethernet_protocol = socket.htons(ethernet_protocol)
                data = raw_data[14:]  # Packet payload

                if ethernet_protocol == 8:  # IPv4 protocol
                    version_header_length = data[0]
                    version = version_header_length >> 4  # Shifting 4 positions to the right to retrieve the IP version
                    header_length = (version_header_length & 0xF) * 4  # "&" operation extracts the first 4 bits,
                                                                      # Multiplying the result by 4 gives us the length of the IP header in bytes
                    ttl, protocol, src, dst = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
                    src = '.'.join(map(str, src))
                    dst = '.'.join(map(str, dst))

                    print('\nEthernet frame:')
                    print('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, source_mac, ethernet_protocol))
                    print('IPv4 packet:')
                    print('\tVersion: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
                    print('\tProtocol: {}, Source: {}, Target: {}'.format(protocol, src, dst))
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except socket.error as e:
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print("Socket error:", e)
                    break
            except Exception as e:
                print("Packet handling error:", e)
    finally:
        s.close()

if __name__ == '__main__':
    main()

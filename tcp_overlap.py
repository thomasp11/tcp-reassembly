#!/usr/bin/env python
# -*- coding: ascii -*-
from scapy.all import *
import argparse

cmd_desc = 'Send a stream of TCP packets overlapping one string with another'

parser = argparse.ArgumentParser(description = cmd_desc)
parser.add_argument("--first", help = "First string to send", 
                    type = str, nargs = '?', const = 1, default = "first")
parser.add_argument("--hidden", help = "String to hide with overlapping data", 
                    type = str, nargs = '?', const = 1, default = "hidden")
parser.add_argument("--overlap", help = "String to send overlapping hidden string", 
                    type = str, nargs = '?', const = 1, default = "overlap")
parser.add_argument('ip', help = 'Destination IP Address')
parser.add_argument('port', help = 'Destination TCP Port', type = int)
args = parser.parse_args()

# IP arguments
dst_ip = args.ip

# TCP arguments
dst_port = args.port
src_port = random.randint(1024,65535)
tcp_seq = random.randint(0,4294967295)

first_string = args.first
hidden_string = args.hidden
overlap_string = args.overlap

if len(overlap_string) <= len(hidden_string):
    sys.exit("error: the overlap string must be longer than the hidden string")

# IP header
ip = IP(dst = dst_ip)

# SYN packet
syn = TCP(sport = src_port, dport = dst_port, flags = 'S', seq = tcp_seq)
tcp_seq = tcp_seq + 1

# SYN-ACK response packet
syn_ack_resp = sr1(ip/syn)
tcp_ack = syn_ack_resp.seq

tcp_ack = tcp_ack + 1

# ACK packet
ack = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
send(ip/ack)

# Send TCP stream
first_packet = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
sr1(ip/first_packet/first_string/hidden_string)
tcp_seq = tcp_seq + len(first_string)

overlap_packet = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
sr1(ip/overlap_packet/overlap_string)
tcp_seq = tcp_seq + len(overlap_string)

# FIN packet
fin = TCP(sport = src_port, dport = dst_port, flags = 'FA', seq = tcp_seq, ack = tcp_ack)
fin_resp = sr1(ip/fin)

tcp_seq = tcp_seq + 1
tcp_ack = tcp_ack + 1
ack = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
send(ip/ack)

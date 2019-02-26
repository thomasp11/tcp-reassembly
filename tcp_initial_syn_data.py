#!/usr/bin/env python
# -*- coding: ascii -*-
from scapy.all import *
import argparse

cmd_desc = 'Template for sending data with scapy over TCP'

parser = argparse.ArgumentParser(description = cmd_desc)
parser.add_argument('ip', help = 'Destination IP Address')
parser.add_argument('port', help = 'Destination TCP Port', type = int)
args = parser.parse_args()

# IP arguments
dst_ip = args.ip

# TCP arguments
dst_port = args.port
src_port = random.randint(1024,65535)
tcp_seq = random.randint(0,4294967295)

initial_syn_data = "data sent with initial tcp packet"
data = "(this message is what the host will process by default)"

# IP header
ip = IP(dst = dst_ip)

# SYN packet
syn = TCP(sport = src_port, dport = dst_port, flags = 'S', seq = tcp_seq)
tcp_seq = tcp_seq + 1

# SYN-ACK response packet
syn_ack_resp = sr1(ip/syn/initial_syn_data)
tcp_ack = syn_ack_resp.seq

tcp_ack = tcp_ack + 1

# ACK packet
ack = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
send(ip/ack)

# Send stream
data_packet = TCP(sport = src_port, dport = dst_port, flags = 'FA', seq = tcp_seq, ack = tcp_ack)
sr1(ip/data_packet/data)
tcp_seq = tcp_seq + len(data)

# FIN packet
fin = TCP(sport = src_port, dport = dst_port, flags = 'FA', seq = tcp_seq, ack = tcp_ack)
fin_resp = sr1(ip/fin)

tcp_seq = tcp_seq + 1
tcp_ack = tcp_ack + 1
ack = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
send(ip/ack)

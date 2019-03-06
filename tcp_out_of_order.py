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

packets_str = "packets"
packets_seq = tcp_seq + 1
received_str = "received"
received_seq = packets_seq + len(packets_str)
out_str = "out"
out_seq = received_seq + len(received_str)
of_str = "of"
of_seq = out_seq + len(out_str)
order_str = "order"
order_seq = of_seq + len(of_str)

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

# Send stream
of_pkt = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = of_seq, ack = tcp_ack)
send(ip/of_pkt/of_str)

packets_pkt = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = packets_seq, ack = tcp_ack)
send(ip/packets_pkt/packets_str)

order_pkt = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = order_seq, ack = tcp_ack)
send(ip/order_pkt/order_str)

received_pkt = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = received_seq, ack = tcp_ack)
send(ip/received_pkt/received_str)

out_pkt = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = out_seq , ack = tcp_ack)
send(ip/out_pkt/out_str)

tcp_seq = order_seq + len(order_str)

# FIN packet
fin = TCP(sport = src_port, dport = dst_port, flags = 'FA', seq = tcp_seq, ack = tcp_ack)
fin_resp = sr1(ip/fin)

tcp_seq = tcp_seq + 1
tcp_ack = tcp_ack + 1
ack = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
send(ip/ack)

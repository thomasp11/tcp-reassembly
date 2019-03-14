#!/usr/bin/env python
# -*- coding: ascii -*-
from scapy.all import *
import argparse
import binascii

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

# IP header
ip = IP(dst = dst_ip)

# SYN packet
syn = TCP(sport = src_port, dport = dst_port, flags = 'S', seq = tcp_seq, options=[(34, "")])
tcp_seq = tcp_seq + 1

# SYN-ACK response packet
syn_ack_resp = sr1(ip/syn)
tcp_ack = syn_ack_resp.seq
tcp_options = syn_ack_resp[TCP].options

tcp_ack = tcp_ack + 1

# ACK packet
ack = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
send(ip/ack)

# Send stream

# FIN packet
fin = TCP(sport = src_port, dport = dst_port, flags = 'FA', seq = tcp_seq, ack = tcp_ack)
fin_resp = sr1(ip/fin)

tcp_seq = tcp_seq + 1
tcp_ack = tcp_ack + 1
ack = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
send(ip/ack)

tcp_options_dict = dict(syn_ack_resp['TCP'].options)
tfo_cookie = str(hex(tcp_options_dict["TFO"][0])[2:]) + str(hex(tcp_options_dict["TFO"][1])[2:])

print "TCP Fast Open Cookie: " + tfo_cookie

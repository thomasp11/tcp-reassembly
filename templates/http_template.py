#!/usr/bin/env python
# -*- coding: ascii -*-
from scapy.all import *
import argparse
import time

cmd_desc = 'Template for sending data with scapy over TCP'

parser = argparse.ArgumentParser(description = cmd_desc)
parser.add_argument("--url", help = "URL to GET | default = '/'", 
                    type = str, nargs = '?', const = 1, default = '/')
parser.add_argument("--host", help = "HTTP Host | default = 'www.example.com'", 
                    type = str, nargs = '?', const = 1, default = 'www.example.com')
parser.add_argument("--wait-time", help = "How long to wait before resetting connection | default = 0.5 sec",
                    type = float, nargs = '?', const = 1, default = 0.5)
parser.add_argument('ip', help = 'Destination IP Address')
parser.add_argument('port', help = 'Destination TCP Port | default = 80',
                    type = int, nargs = '?', const = 1, default = 80)
args = parser.parse_args()

# IP arguments
dst_ip = args.ip

# TCP arguments
dst_port = args.port
src_port = random.randint(1024,65535)
tcp_seq = random.randint(0,4294967295)
wait_time = args.wait_time

# HTTP arguments
http_url = args.url
http_host = args.host

# HTTP header
http_data = "GET " + http_url + " HTTP/1.1\r\nHost: " + http_host + "\r\n\r\n"

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
http_tcp = TCP(sport = src_port, dport = dst_port, flags = 'A', seq = tcp_seq, ack = tcp_ack)
send(ip/http_tcp/http_data)
tcp_seq = tcp_seq + len(http_data)

# Wait for response
time.sleep(wait_time)

# Close connection with TCP reset
reset = TCP(sport = src_port, dport = dst_port, flags = 'R', seq = tcp_seq, ack = 0)
send(ip/reset)

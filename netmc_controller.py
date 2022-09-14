#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.8/site-packages/tofino/'))
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.8/site-packages/tofino/bfrt_grpc'))
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.8/site-packages/'))
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.8/site-packages/tofinopd/'))
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.8/site-packages/tofino_pd_api/'))
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.8/site-packages/p4testutils'))
import time
import datetime
import grpc
import bfrt_grpc.bfruntime_pb2_grpc as bfruntime_pb2_grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2

import bfrt_grpc.client as gc
import port_mgr_pd_rpc as mr
from time import sleep
import socket, struct
import binascii

NUM_SERVER = 4

def hex2ip(hex_ip):
	addr_long = int(hex_ip,16)
	hex(addr_long)
	hex_ip = socket.inet_ntoa(struct.pack(">L", addr_long))
	return hex_ip

# Convert IP to bin
def ip2bin(ip):
	ip1 = ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])
	return ip1

# Convert IP to hex
def ip2hex(ip):
	ip1 = ''.join([hex(int(x)+256)[3:] for x in ip.split('.')])
	return ip1

def table_add(target, table, keys, action_name, action_data=[]):
	keys = [table.make_key([gc.KeyTuple(*f) for f in keys])]
	datas = [table.make_data([gc.DataTuple(*p) for p in action_data],
								  action_name)]
	table.entry_add(target, keys, datas)

def table_mod(target, table, keys, action_name, action_data=[]):
	keys = [table.make_key([gc.KeyTuple(*f) for f in keys])]
	datas = [table.make_data([gc.DataTuple(*p) for p in action_data],
								  action_name)]
	table.entry_mod(target, keys, datas)

def table_del(target, table, keys):
	table.entry_del(target, keys)

def get_port_status(target, table, keys):
	keys = [table.make_key([gc.KeyTuple(*f) for f in keys])]
	for data,key in table.entry_get(target,keys):
		key_fields = key.to_dict()
		data_fields = data.to_dict()
		return data_fields[b'$PORT_UP']

def table_clear(target, table):
	keys = []
	for data,key in table.entry_get(target):
		if key is not None:
			keys.append(key)
	if keys:
		table.entry_del(target, keys)
        
try:
	grpc_addr = "localhost:50052"
	client_id = 0
	device_id = 0
	pipe_id = 0xFFFF
	client = gc.ClientInterface(grpc_addr, client_id, device_id)
	target = gc.Target(device_id, pipe_id)
	client.bind_pipeline_config("netmc")

	ip_list = [
	    0x0A000165,
	    0x0A000166,
	    0x0A000167,
	    0x0A000168,
		0x0A000169,
		0x0A00016A,
		0x0A00016B,
		0x0A00016C,
		0x0A00016D
    ]

	port_list = [
	    396,
	    392,
	    444,
	    440,
		428,
		424,
		412,
		408,
		64
	]

    recirculate_port_list = [
        68, 
        69, 
        70, 
        71, 
        192, 
        193, 
        194, 
        195, 
        196, 
        197, 
        198, 
        199, 
        324, 
        325, 
        326, 
        327, 
        448, 
        449, 
        450, 
        451, 
        452, 
        453, 
        454, 
        455
    ]

    #print port_list
	port_table = client.bfrt_info_get().table_get("$PORT")

	# Configure lookup table for converting server ID to IP address
	get_dst_ip_table = client.bfrt_info_get().table_get("pipe.SwitchIngress.get_dst_ip_table")
	table_clear(target, get_dst_ip_table)
	for i in range(NUM_SERVER):
		table_add(target, get_dst_ip_table,[("hdr.keys.key", i)],"get_dst_ip_action",[("addr",small_ip_list[i]),("port",small_port_list[i])])

	ipv4_exact = client.bfrt_info_get().table_get("pipe.SwitchIngress.ipv4_exact")
	table_clear(target, ipv4_exact)
	for i in range(NUM_GRP_CTRL):
		table_add(target, ipv4_exact,[("hdr.ipv4.dstAddr", ip_list[i])],"ipv4_forward",[("port",port_list[i])]) # 101

	ipv4_exact_netmc = client.bfrt_info_get().table_get("pipe.SwitchIngress.ipv4_exact_netmc")
	table_clear(target, ipv4_exact_netmc)
	for i in range(NUM_GRP_CTRL):
		table_add(target, ipv4_exact_netmc,[("hdr.ipv4.dstAddr", ip_list[i])],"ipv4_forward",[("port",port_list[i])]) # 101

    mirror_fwd_table = client.bfrt_info_get().table_get("mirror_fwd_table")
    table_clear(target, mirror_fwd_table)
    table_add(target, mirror_fwd_table, [("", )], "", [()])

	print("10.0.1.101",  binascii.hexlify(socket.inet_aton('10.0.1.101')).upper())
	print("10.0.1.102",  binascii.hexlify(socket.inet_aton('10.0.1.102')).upper())
	print("10.0.1.103",  binascii.hexlify(socket.inet_aton('10.0.1.103')).upper())
	print("10.0.1.104",  binascii.hexlify(socket.inet_aton('10.0.1.104')).upper())
	print("10.0.1.105",  binascii.hexlify(socket.inet_aton('10.0.1.105')).upper())
	print("10.0.1.106",  binascii.hexlify(socket.inet_aton('10.0.1.106')).upper())
	print("10.0.1.107",  binascii.hexlify(socket.inet_aton('10.0.1.107')).upper())
	print("10.0.1.108",  binascii.hexlify(socket.inet_aton('10.0.1.108')).upper())
	print("10.0.1.109",  binascii.hexlify(socket.inet_aton('10.0.1.109')).upper())
	print("10.0.1.110",  binascii.hexlify(socket.inet_aton('10.0.1.110')).upper())
#except:
	#print("Controller could not lauhched!")
finally:
	#print("10.0.1.101",  binascii.hexlify(socket.inet_aton('10.0.1.101')).upper())
	client.tear_down_stream()

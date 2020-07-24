#!/usr/bin/env python3
# coding=utf-8
# Copyright HiSilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
import csv
import struct
import hashlib

def str_to_hex(s):
    return ' '.join([hex(ord(c)).replace('0x', '') for c in s])
number = 0
value_len = 0
buf = b''
# 用reader读取csv文件
with open('efuse.csv', 'r') as csvFile:
    reader = csv.reader(csvFile)
    for line in reader:
        if(line[0] == "1"):
            size = int(line[3])
            if (size <= 32):
                value_len = 4
            elif (size <= 64):
                value_len = 8
            else:
                value_len = size // 8
                print(value_len)
            result = struct.pack('BBHHH', 0, 8, int(line[2]), size, value_len)
            value_str = line[4]
            value_list = value_str.split(" ")
            value_struct = b''
            for i in range(value_len // 4):
                value = int(value_list[i], 16)
                value_struct = value_struct + struct.pack('I', value)
            print(value_struct)
            buf = buf + result + value_struct
            number = number + 1
header = struct.pack('BBHIII', 0, 48, number, len(buf) + 48, 0, 0)
data = header + buf
hash = hashlib.sha256(data).digest()
bin_data = hash + data
#print(bin_data)

with open("efuse_cfg.bin", 'wb') as f:
    f.write(bin_data)

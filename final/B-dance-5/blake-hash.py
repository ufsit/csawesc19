from binascii import hexlify
import struct

target_hash = [0]*8

target_hash[0] = 0x9848885e;
target_hash[1] = 0x710428da;
target_hash[2] = 0x6fe5d051;
target_hash[3] = 0x2729c68d;
target_hash[4] = 0xd3d6073;
target_hash[5] = 0xd6bdab6a;
target_hash[6] = 0x72ef112a;
target_hash[7] = 0xd842151d;

target = ""

for i in range(8):
    target += struct.pack("I", target_hash[i])

# 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
print("Hash: " + hexlify(target))
print("Value: password")

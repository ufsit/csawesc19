from binascii import hexlify
import struct

target_hash = [0]*8

target_hash[0] = 0x41a8140e;
target_hash[1] = 0x2f702427;
target_hash[2] = 0xc2b629f1;
target_hash[3] = 0x4b98e2d0;
target_hash[4] = 0xef3801ff;
target_hash[5] = 0xe7c0f149;
target_hash[6] = 0xef31cc1f;
target_hash[7] = 0x1fbe7f2c;

target = ""

for i in range(8):
    target += struct.pack("I", target_hash[i])

# 0e14a8412724702ff129b6c2d0e2984bff0138ef49f1c0e71fcc31ef2c7fbe1f
print("Hash: " + hexlify(target))
print("Value: ???")

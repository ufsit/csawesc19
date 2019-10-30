from binascii import hexlify
import struct

target_hash = [0]*8

target_hash[0] = 0xdeb0e78;
target_hash[1] = 0xb5e695dd;
target_hash[2] = 0xa0804f17;
target_hash[3] = 0x765a8d20;
target_hash[4] = 0x5e450137;
target_hash[5] = 0x9de78210;
target_hash[6] = 0x42d3dfe6;
target_hash[7] = 0x544049e0;

target = ""

for i in range(8):
    target += struct.pack("I", target_hash[i])

# 780eeb0ddd95e6b5174f80a0208d5a763701455e1082e79de6dfd342e0494054 13 characters, 'ht' -> hash table?
print("Hash: " + hexlify(target))
print("Value: ??")

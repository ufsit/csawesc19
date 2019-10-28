import struct
import hashlib

target = "242b461d0b97cca55e5d62372b770ab4"

assert len(target) == 32
for i in range(256):
    inp = "imjustrandomdatathathasnomeaningwhatsoever!" + struct.pack("B", i)
    res = hashlib.md5(inp).hexdigest()
    assert len(res) == len(target)
    if res == target:
        print(inp, i)
        break



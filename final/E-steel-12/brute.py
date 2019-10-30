import hashlib

target = "703224f765d313ee4ed0fadcf9d63a5e"

for i in range(256):
    obj = hashlib.md5()
    obj.update(chr(i))
    res = obj.hexdigest()
    if res == target:
        print("asdf")

    for i in range(9):
        if obj.hexdigest() == target:
            print("asdf")

        #obj.update(res)
        obj = hashlib.md5()
        obj.update(res)
        res = obj.hexdigest()
        if res == target:
            print("asdf")

    if res == target:
        print(res)

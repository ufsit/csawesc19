import serial
import hashlib
import sys
import glob

while True:
    devices = glob.glob('/dev/tty.usbmodem*')
    if len(devices) == 0:
        continue

    device = devices[0]

    try:
        ser = serial.Serial(device, 2000000)

        print("--------- CONNECTED TO %s-----------" % device)
        while True:
            sys.stdout.write(ser.read(10))

    except serial.serialutil.SerialException:
        print("--------- EXCEPTION -----------")

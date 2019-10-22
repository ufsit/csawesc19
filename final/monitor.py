import serial
import hashlib
import sys
import glob

ser = serial.Serial(glob.glob('/dev/tty.usbmodem*')[0], 2000000)

while True:
    sys.stdout.write(ser.read(1024))

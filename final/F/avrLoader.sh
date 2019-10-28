#! /bin/bash

PORT="/dev/ttyACM0"

./teensy_loader_cli -mmcu=mk20dx256 -v -s ArduinoISP.ino.hex
sleep 2
avrdude -v -c arduino -b 19200 -patmega1284 -P $PORT -U lfuse:w:0xc2:m -U hfuse:w:0xd9:m -U efuse:w:0xff:m
sleep 2
avrdude -v -patmega1284 -carduino -P $PORT -b 230400 -Uflash:w:AVRChallengeSetF.ino.hex:i
sleep 2
./teensy_loader_cli -mmcu=mk20dx256 -v -s TeensyChallengeSetF.ino.hex

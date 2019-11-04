for f in final/*/sender.py; do SET=$(echo $f | cut -d/ -f2 | cut -d- -f1); NAME=$(echo $f | cut -d- -f2); FN="sender$SET-$NAME.py"; echo $FN; cat "$f" | sed "s/tty.usbmodem\*/ttyACM\*/" > $FN; done

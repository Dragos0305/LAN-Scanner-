#!/bin/bash

USER=$(whoami)

if [ "$USER" != "root" ]
then
	
	echo "[-]Error! You must run this script with root privileges"
	exit 1

fi

echo "[+]Check if you have pip3 installed"
sleep 1
if ! pip3 > /dev/null
then

	echo "[+]Pip3 found"
	echo "[+]Installing modules for script"
	sleep 1
else

	echo "[-]Pip3 is not installed..."
	echo "[+]Install pip3..."
	sleep 1
	apt-get -y install python3-pip.

fi

echo "[+]Install matplotlib..."
sleep 1
pip3 install matplotlib

echo "[+]Install fpdf..."
sleep 1
pip3 install fpdf

echo "[+]Install nmap tool..."
sleep 1
apt install nmap

echo "[+]Install nmap module..."
sleep 1
pip3 install python-nmap

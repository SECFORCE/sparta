#!/bin/bash
# smbenum 0.3 - This script will enumerate SMB using every tool in the arsenal
# SECFORCE - Antonio Quina

IFACE="eth0"

if [ $# -eq 0 ]
	then
		echo "Usage: $0 <IP>"
		echo "eg: $0 10.10.10.10"
		exit
	else
		IP="$1"
fi

echo -e "\n########## Getting Netbios name ##########"
nbtscan -v -h $IP

echo -e "\n########## Checking for NULL sessions ##########"
output=`bash -c "echo 'srvinfo' | rpcclient $IP -U%"`
echo $output

echo -e "\n########## Enumerating domains ##########"
bash -c "echo 'enumdomains' | rpcclient $IP -U%"

echo -e "\n########## Enumerating users ##########"
nmap -Pn -T4 -sS -p139,445 --script=smb-enum-users $IP
bash -c "echo 'enumdomusers' | rpcclient $IP -U%"

echo -e "\n########## Enumerating Administrators ##########"
net rpc group members "Administrators" -I $IP -U%

echo -e "\n########## Enumerating Domain Admins ##########"
net rpc group members "Domain Admins" -I $IP -U%

echo -e "\n########## Enumerating groups ##########"
nmap -Pn -T4 -sS -p139,445 --script=smb-enum-groups $IP

echo -e "\n########## Enumerating shares ##########"
nmap -Pn -T4 -sS -p139,445 --script=smb-enum-shares $IP

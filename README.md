# Portscanner
ScapyPython portscanner

A port scanner using python and the scapy library.

-h for help
-p list the ports you want (ie 6-10 7 8 or 4 500 etc)
-v list the the first three values of the ip you want (192.168.0 or 185.201.253 NOT 192.168.0.2)
-t list the last value of the ip (ie 10-20 5 7 or 200-255 533 799 etc)
-k kind of scan you want (U is udp, T is TCP, and S is for a TCP stealth scan

Example usage:

python python_scapy.py -v 192.185.207 -t 10-20 55 -p 6-10 -k S

will scan 192.185.207.10-20 and 55 on ports 6-10 using a stealth TCP scan (more likely to get through firewalls)

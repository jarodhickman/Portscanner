#This is a basic udp/tcp port scanner created for a class project.
#Credit goes to the following sources:
#https://github.com/interference-security/Multiport/blob/master/multiport.py by interference-security (stealth and udp scan)
#https://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/ (scapy set-up and basic tcp)

#If I were to continue this project, I would clean up the scans and make better options for stealth and getting around firewalls.
#I would also add multithreading to speed up the process.

# import the necessary packages
import sys
import argparse
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
from datetime import datetime
from time import strftime
import struct
 

#class to create a new action for arg parse
class InflateRange(argparse.Action):
	def __call__(self, parser, namespace, values, option_string=None):
		# print('%r %r %r' % (namespace, values, option_string))
		lst = []
		for string in values:
			# print 'in string:',string
			if '-' in string:
				m = re.match(r'(\d+)(?:-(\d+))?$', string)
				if not m:
					raise ArgumentTypeError("'" + string + "' is not a range of number. Expected forms like '0-5' or '2'.")
				start = m.group(1)
				end = m.group(2) or start
				lst.extend(list(range(int(start,10), int(end,10)+1)))
			else:
				 lst.append(int(string))
			setattr(namespace, self.dest, lst)

# construct the argument parse and parse the arguments
ap = argparse.ArgumentParser()

ap.add_argument('-v', '--Value', required=True,
	help='first three hex values of the subnet you wish to scan. IE xxx.xxx.xxx')
ap.add_argument('-t', '--Target', action=InflateRange, nargs='*', required=True,
	help="last three digits of the ip of targets. IE xxx or xxx-xxx for more than one")
ap.add_argument("-k", "--Kind", nargs="*", required=False, default="X",
 	help="type of scan U=udp T=TCP S=Stealth TCP. All give a icmp scan")
ap.add_argument('-p', '--Ports', nargs="*", action=InflateRange, required=True,
	help="ports of target you wish to scan. #-# or # or any comobo of those two")
 
#debugging and declares address array
args = vars(ap.parse_args())
address = []
hexaddress = args['Value']
ports = []
#appends hex with the values in target
for value in args['Target']:
	address.append(hexaddress+'.'+str(value))
#
for port in args['Ports']:
	ports.append(port)

# declares variables that can be used in scapy
start_clock = datetime.now()
synack = 0x12
rstack = 0x14
TIMEOUT = 2
conf.verb = 0
Uhost = []

#definitions of functions for various scans as well as checking that the host is up
def checkhost(host):
	packet = IP(dst=host, ttl=20)/ICMP()
	reply = sr1(packet, timeout=TIMEOUT)
	if not (reply is None):
		print host+" is online"
		Uhost.append(host)
	else:
		print "Timeout waiting for %s" % packet[IP].dst

def tcpscan(port, host):
	srcport = RandShort()
	conf.verb = 0
	SYNACKpkt = sr1(IP(dst = host)/TCP(sport = srcport, dport = port, flags = "S"))
	pktflags = SYNACKpkt.getlayer(TCP).flags
	if pktflags == synack:
		return True
	else:
		return False
	RSTpkt = IP(dst = host)/TCP(sport = srcport, dport = port, flags = "R")
	send(RSTpkt)

def stealth_scan(dst_ip,dst_port,dst_timeout):
    src_port = RandShort()
    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
    if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
        return "Filtered"
    elif(stealth_scan_resp.haslayer(TCP)):
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=dst_timeout)
            return "Open"
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(stealth_scan_resp.haslayer(ICMP)):
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"

def udpscan(dst_ip,dst_port):
	packet = IP(dst=dst_ip)/UDP(dport=dst_port)
	response = sr1(packet, verbose=False, timeout=5)

	if response is None:
		print "Port "+str(dst_port)+": Open|Filtered"

	elif(response.haslayer(ICMP)):

		if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code)==3):
			print "Port "+str(dst_port)+": Closed"
		elif(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,9,10,13]):
			print "Port "+str(dst_port)+": Filtered"
	else:
		print "Port "+str(dst_port)+": HOWDY"

#Calling of functions

#Gets rid of hosts that can't be reached from the list
for host in address:
	checkhost(host)
#Performs a UDP scan
if 'U' in args['Kind']:
	for host in Uhost:
		print "Udp scan: "+host
		for port in ports:
			udpscan(host, port)
#Performs a TCP scan
if 'T' in args['Kind']:
	for host in Uhost:
		print "TCP scan: "+host
		for port in ports:
			if tcpscan(port, host) == True:
				print "Port "+str(port)+": Open"
			else:
				print "Port "+str(port)+": Closed"
#Performs a stealth version of the TCP scan
if 'S' in args['Kind']:
	for host in Uhost:
		print "Stealth TCP: "+host
		for port in ports:
			print "Port "+str(port)+": "+stealth_scan(host,port,10)
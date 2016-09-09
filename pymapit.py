#!/usr/bin/python

import sys
import os

__version__ = '0.1b'
__author__ = 'd3ad7rack, d3ad7rack@security-focused.com'
__doc__ = """
PyMap-IT http://www.security-focused.com

#TODO:
# Scan Types:
#  -e <interface> (Use specified interface) <- probably require another menu
#  --source-port <portnumber>; -g <portnumber> (Spoof source port number)
#  --data <hex string> (Append custom binary data to sent packets)
#  --data-string <string> (Append custom string to sent packets)
#  --data-length <number> (Append random data to sent packets)
#  --ttl <value> (Set IP time-to-live field)
#  --randomize-hosts (Randomize target host order)
#  --spoof-mac <MAC address, prefix, or vendor name> (Spoof MAC address)
#  --proxies <Comma-separated list of proxy URLs> (Relay TCP connections through a chain of proxies)
#  --badsum (Send packets with bogus TCP/UDP checksums)
#  --adler32 (Use deprecated Adler32 instead of CRC32C for SCTP checksums)
#
# Functions:
#  Exit()
#
# Done:
#  -D <decoy1>[,<decoy2>][,ME][,...] (Cloak a scan with decoys)
#  -S <IP_Address> (Spoof source address)


  by Will Frye, d3ad7rack
"""


# Guts of the program, for selected scan types
# def exit_out():



class evade_fw:
	def decoy_address(self):
		os.system('clear')
		print('What IP, IP-range (CIDR or range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan? ')
		ip = raw_input('IP, CIDR, Range, or Domain: ')
		print("Now going to run nmap scan -D RND:10,192.168.1.103,10.0.0.129,ME -sV -Pn and version detection options, saving output to decoy-" + ip + ".nmap and decoy-" + ip + ".xml for later parsing.")
		os.system('sudo nmap -D RND:10,192.168.1.103,10.0.0.129,ME -sV -Pn --stylesheet=nmap.xsl -oX decoy-' + ip + '.xml -oN decoy-' + ip + '.nmap ' + ip)
		os.system('clear')
		print("Scan ran against " + ip + " and saved to current directory under decoy-" + ip + ".nmap and decoy-" + ip + ".xml for your parsing pleasure!")
		print("")
		print("Scan against " + ip + " ran, now giving you the ports that were open and their services running on them...")
		print("Open ports tcp/udp with software versions are...")
		print("")
		os.system('cat decoy-' + ip + '.nmap | grep open | grep tcp||udp')
		print("")
		print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
		print("")
		raw_input("Press any key to continue...")

	def spoof_ip(self):
		os.system('clear')
		print('What IP, IP-range (CIDR or range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan? ')
		ip = raw_input('IP, CIDR, Range, or Domain: ')
		print('What ports are you wanting to scan against? Can be entered as xxx-yyy, x,y,z, or a single port')
		spoofed_ip = raw_input('Spoofed IP Address: ')
		print("Now going to run nmap scan with -Pn -sV -A -S " + spoofed_ip + " options, saving output to spoofed-" + ip + ".nmap and spoofed-" + ip + ".xml for later parsing.")
		os.system('sudo nmap -Pn -sV -A -S ' + spoofed_ip + ' --stylesheet=nmap.xsl -oX spoofed-' + ip + '.xml -oN spoofed-' + ip + '.nmap ' + ip)
		os.system('clear')
		print("Scan ran against " + ip + " and saved to current directory under spoofed-" + ip + ".nmap and spoofed-" + ip + ".xml for your parsing pleasure!")
		print("")
		print("Scan against " + ip + " ran, now giving you the ports that were open and their services running on them...")
		print("Open ports tcp/udp with software versions are...")
		print("")
		os.system('cat spoofed-' + ip + '.nmap | grep open | grep tcp||udp')
		print("")
		print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
		print("")
		raw_input("Press any key to continue...")

	def fragmented_scan(self):
		os.system('clear')
		print('What IP, IP-range (CIDR or range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan? ')
		ip = raw_input('IP, CIDR, Range, or Domain: ')
		print("Now going to run nmap scan with -f option, saving output to fragged-scan-" + ip + ".nmap and fragged-scan-" + ip + ".xml for later parsing.")
		os.system('sudo nmap -f --stylesheet=nmap.xsl -oX fragged-scan-' + ip + '.xml -oN fragged-scan-' + ip + '.nmap ' + ip)
		os.system('clear')
		print("Scan ran against " + ip + " and saved to current directory under fragged-scan-" + ip + ".nmap and fragged-scan-" + ip + ".xml for your parsing pleasure!")
		print("")
		print("Scan against " + ip + " ran, now giving you the ports that were open and their services running on them...")
		print("Open ports tcp/udp with software versions are...")
		print("")
		os.system('cat fragged-scan-' + ip + '.nmap | grep open | grep tcp||udp')
		print("")
		print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
		print("")
		raw_input("Press any key to continue...")

def xsl_file():
	print("When, if asked, please use your password for copying over the nmap.xsl stylesheet to your current directory, for saved xml files to work correctly")
	os.system('sudo cp /usr/local/share/nmap/nmap.xsl .')
	print("")
	print("All done, happy hacking!")
	print("")
	raw_input("Press any key to continue...")

def basic_loud_scan():
	os.system('clear')
	print('What IP, IP-range (CIDR or range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan? ')
	ip = raw_input('IP, CIDR, Range, or Domain: ')
	print('What ports are you wanting to scan against? Can be entered as xxx-yyy, x,y,z, or a single port')
	ports = raw_input('Ports: ')
	print("Now going to run nmap scan with -Pn -sV -A -T4 options, saving output to loud-scan-" + ip + ".nmap and loud-scan-" + ip + ".xml for later parsing.")
	os.system('sudo nmap -Pn -sV -A -T4 --stylesheet=nmap.xsl -oX loud-scan-' + ip + '.xml -oN loud-scan-' + ip + '.nmap ' + ip)
	os.system('clear')
	print("Scan ran against " + ip + " and saved to current directory under loud-scan-" + ip + ".nmap and loud-scan-" + ip + ".xml for your parsing pleasure!")
	print("")
	print("Scan against " + ip + " ran, now giving you the ports that were open and their services running on them...")
	print("Open ports tcp/udp with software versions are...")
	print("")
	os.system('cat loud-scan-' + ip + '.nmap | grep open | grep tcp||udp')
	print("")
	print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
	print("")
	raw_input("Press any key to continue...")


evade = evade_fw()

# Main program running dialogue
def main():  # menu goes here
	opt_list = [xsl_file,
				basic_loud_scan,
				fw_main
				#exit
				]

	while (True):
		os.system('clear')
		print("SELECT OPTION: ")
		print("1\tCopy nmap.xsl file to present directory for proper saving of xml files (Needs to be done)")
		print("2\tBasic, Loud Scan")
		print("3\tEvade Firewalls")
		print("X\tExit")
		opt_choice = int(raw_input("Selection: "))
		os.system('clear')
		opt_choice -= 1
		opt_list[opt_choice]()

	return


# Menu for evading firewall scans
def fw_main():  # menu goes here
	opt_list = [evade.fragmented_scan,
				evade.spoof_ip,
				evade.decoy_address,
				main
				]

	while (True):
		os.system('clear')
		print("SELECT OPTION: ")
		print("1\tScan with Fragmented Packets")
		print("2\tScan with Spoofed IP Address")
		print("3\tScan using Random Decoy Addresses")
		print("4\tMain Menu")
		opt_choice = int(raw_input("Selection: "))
		os.system('clear')
		opt_choice -= 1
		opt_list[opt_choice]()

	return


main()

if __name__ == '__main__':
	main()

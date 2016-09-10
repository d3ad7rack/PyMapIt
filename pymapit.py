#!/usr/bin/python

import sys
import os

__version__ = '0.1b'
__author__ = 'd3ad7rack, d3ad7rack@security-focused.com'
__doc__ = """
PyMap-IT http://www.security-focused.com

#TODO:
# Classes:
#  Class for vulnerability checking
#
# Scan Types:
#  --randomize-hosts (Randomize target host order)
#  --spoof-mac <MAC> address, prefix, or vendor name> (Spoof MAC address)
#  --proxies <Comma-separated list of proxy URLs> (Relay TCP connections through a chain of proxies)
#  --badsum (Send packets with bogus TCP/UDP checksums)
#  --adler32 (Use deprecated Adler32 instead of CRC32C for SCTP checksums)
#
# Done:
#  -D <decoy1>[,<decoy2>][,ME][,...] (Cloak a scan with decoys)
#  -S <IP_Address> (Spoof source address)
#  Working exit function


  by Will Frye, d3ad7rack
"""

#class vuln_check:

class evade_fw:
	def decoy_address(self):
		os.system('clear')
		print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain) would you like to scan? ')
		ip = raw_input('IP, Range, or Domain: ')
		print('')
		print("What ports would you like to scan? (If no ports are supplied, we are going to scan the default top 1000 ports)")
		print("Ports that you'd like to scan can be entered as a single port, comma-separated ports (x,y,z) or a range (xxx-yyy)")
		ports = str(raw_input('What ports would you like to scan? '))
		print('')
		if ports == "":
			print("Now going to run nmap scan -D RND:10,192.168.1.103,10.0.0.129,ME -sV -Pn options, saving output to decoy-" + ip + ".nmap and decoy-" + ip + ".xml for later parsing.")
			os.system('sudo nmap -D RND:10,192.168.1.103,10.0.0.129,ME -sV -Pn --stylesheet=nmap.xsl -oX decoy-' + ip + '.xml -oN decoy-' + ip + '.nmap ' + ip)
			os.system('clear')
		else:
			print("Now going to run nmap scan -D RND:10,192.168.1.103,10.0.0.129,ME -sV -Pn -p" + ports + " options, saving output to decoy-" + ip + ".nmap and decoy-" + ip + ".xml for later parsing.")
			os.system('sudo nmap -D RND:10,192.168.1.103,10.0.0.129,ME -sV -Pn -p' + ports + ' --stylesheet=nmap.xsl -oX decoy-' + ip + '.xml -oN decoy-' + ip + '.nmap ' + ip)
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
		print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan? ')
		ip = raw_input('IP, Range, or Domain: ')
		print('')
		spoofed_ip = raw_input('Spoofed IP Address: ')
		print('')
		print("What ports would you like to scan? (If no ports are supplied, we are going to scan the default top 1000 ports)")
		print("Ports that you'd like to scan can be entered as a single port, comma-separated ports (x,y,z) or a range (xxx-yyy)")
		ports = str(raw_input('What ports would you like to scan? '))
		print('')
		if ports == "":
			print("Now going to run nmap scan with -Pn -sV -S " + spoofed_ip + " options, saving output to spoofed-" + ip + ".nmap and spoofed-" + ip + ".xml for later parsing.")
			os.system('sudo nmap -Pn -sV -S ' + spoofed_ip + ' --stylesheet=nmap.xsl -oX spoofed-' + ip + '.xml -oN spoofed-' + ip + '.nmap ' + ip)
			os.system('clear')
		else:
			print("Now going to run nmap scan with -Pn -sV -S " + spoofed_ip + " -p" + ports + " options, saving output to spoofed-" + ip + ".nmap and spoofed-" + ip + ".xml for later parsing.")
			os.system('sudo nmap -Pn -sV -S ' + spoofed_ip + ' -p' + ports + ' --stylesheet=nmap.xsl -oX spoofed-' + ip + '.xml -oN spoofed-' + ip + '.nmap ' + ip)
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
		print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan? ')
		ip = raw_input('IP, Range, or Domain: ')
		print('')
		print("What ports would you like to scan? (If no ports are supplied, we are going to scan the default top 1000 ports)")
		print("Ports that you'd like to scan can be entered as a single port, comma-separated ports (x,y,z) or a range (xxx-yyy)")
		ports = str(raw_input('What ports would you like to scan? '))
		print('')
		if ports == "":
			print("Now going to run nmap scan with -f option, saving output to fragged-scan-" + ip + ".nmap and fragged-scan-" + ip + ".xml for later parsing.")
			os.system('sudo nmap -f --stylesheet=nmap.xsl -oX fragged-scan-' + ip + '.xml -oN fragged-scan-' + ip + '.nmap ' + ip)
			os.system('clear')
		else:
			print("Now going to run nmap scan with -f -p" + ports + " options, saving output to fragged-scan-" + ip + ".nmap and fragged-scan-" + ip + ".xml for later parsing.")
			os.system('sudo nmap -f -p' + ports + ' --stylesheet=nmap.xsl -oX fragged-scan-' + ip + '.xml -oN fragged-scan-' + ip + '.nmap ' + ip)
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

def no_options():
	os.system('clear')
	print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan? ')
	ip = raw_input('IP, Range, or Domain: ')
	print('')
	print("What ports would you like to scan? (If no ports are supplied, we are going to scan the default top 1000 ports)")
	print("Ports that you'd like to scan can be entered as a single port, comma-separated ports (x,y,z) or a range (xxx-yyy)")
	ports = str(raw_input('What ports would you like to scan? '))
	print('')
	if ports == "":
		print("Now going to run nmap scan with no options, saving output to no-options-" + ip + ".nmap and no-options-" + ip + ".xml for later parsing.")
		os.system('sudo nmap --stylesheet=nmap.xsl -oX no-options-' + ip + '.xml -oN no-options-' + ip + '.nmap ' + ip)
		os.system('clear')
	else:
		print("Now going to run nmap scan with -p" + ports + " options, saving output to no-options-" + ip + ".nmap and no-options-" + ip + ".xml for later parsing.")
		os.system('sudo nmap -p' + ports + ' --stylesheet=nmap.xsl -oX no-options-' + ip + '.xml -oN no-options-' + ip + '.nmap ' + ip)
		os.system('clear')
	print("Scan ran against " + ip + " and saved to current directory under no-options-" + ip + ".nmap and no-options-" + ip + ".xml for your parsing pleasure!")
	print("")
	print("Scan against " + ip + " ran, now giving you the ports that were open and their services running on them...")
	print("Open ports tcp/udp with software versions are...")
	print("")
	os.system('cat no-options-' + ip + '.nmap | grep open | grep tcp||udp')
	print("")
	print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
	print("")
	raw_input("Press any key to continue...")

def basic_loud_scan():
	os.system('clear')
	print('What IP, IP-range (CIDR or range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan? ')
	ip = raw_input('IP, CIDR, Range, or Domain: ')
	print('')
	print("What ports would you like to scan? (If no ports are supplied, we are going to scan the default top 1000 ports)")
	print("Ports that you'd like to scan can be entered as a single port, comma-separated ports (x,y,z) or a range (xxx-yyy)")
	ports = str(raw_input('What ports would you like to scan? '))
	print('')
	if ports == "":
		print("Now going to run nmap scan with -Pn -sV -A -T4 options, saving output to loud-scan-" + ip + ".nmap and loud-scan-" + ip + ".xml for later parsing.")
		os.system('sudo nmap -Pn -sV -A -T4 --stylesheet=nmap.xsl -oX loud-scan-' + ip + '.xml -oN loud-scan-' + ip + '.nmap ' + ip)
		os.system('clear')
	else:
		print("Now going to run nmap scan with -Pn -sV -p" + ports + " -T4 options, saving output to loud-scan-" + ip + ".nmap and loud-scan-" + ip + ".xml for later parsing.")
		os.system('sudo nmap -Pn -sV -p' + ports + ' -T4 --stylesheet=nmap.xsl -oX loud-scan-' + ip + '.xml -oN loud-scan-' + ip + '.nmap ' + ip)
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

def exit():
	sys.exit()


evade = evade_fw()
#safe = safe_vuln_check()
#unsafe = unsafe_vuln_check()

# Main program running dialogue
def main():  # menu goes here
	opt_list = [xsl_file,
				no_options,
				basic_loud_scan,
				fw_main,
				vuln_main,
				exit
				]

	while (True):
		os.system('clear')
		print("SELECT OPTION: ")
		print("1\tCopy nmap.xsl file to present directory for proper saving of xml files (Needs to be done)")
		print("2\tBasic Scan, No Options")
		print("3\tBasic, Loud Scan")
		print("4\tFirewall Evasion Techniques")
		print("5\tVulnerability Checking (Not working currently, Working on it)")
		print("6\tExit")
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

def vuln_main():  # menu goes here
	opt_list = [safe_vulns_main,
				unsafe_vulns_main,
				main
				]

	while (True):
		os.system('clear')
		print("SELECT OPTION: ")
		print("1\tSafe Vulnerability Checking")
		print("2\tUnsafe Vulnerability Checking")
		print("3\tMain Menu")
		opt_choice = int(raw_input("Selection: "))
		os.system('clear')
		opt_choice -= 1
		opt_list[opt_choice]()

	return

#def safe_vulns_main():  # menu goes here
#	opt_list = [safe.http,
#				safe.ssh,
#				main
#				]
#
#	while (True):
#		os.system('clear')
#		print("SELECT OPTION: ")
#		print("1\tHTTP(S) Vulnerabilties")
#		print("2\tSSH Vulnerabilities")
#		print("3\t")
#		print("4\t")
#		print("5\t")
#		opt_choice = int(raw_input("Selection: "))
#		os.system('clear')
#		opt_choice -= 1
#		opt_list[opt_choice]()
#
#	return

#def unsafe_vulns_main():  # menu goes here
#	opt_list = [unsafe.http,
#				unsafe.ssh,
#				main
#				]
#
#	while (True):
#		os.system('clear')
#		print("SELECT OPTION: ")
#		print("1\tHTTP(S) Vulnerabilties")
#		print("2\tSSH Vulnerabilties")
#		print("3\t")
#		print("4\t")
#		print("5\t")
#		opt_choice = int(raw_input("Selection: "))
#		os.system('clear')
#		opt_choice -= 1
#		opt_list[opt_choice]()
#
#	return


main()

if __name__ == '__main__':
	main()

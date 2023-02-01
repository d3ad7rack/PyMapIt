#!/usr/bin/python

import sys
import os

# __version__ = '1.0'
# __author__ = 'd3ad7rack, d3ad7rack@security-focused.com'
# __doc__ = """
# PyMap-IT http://www.security-focused.com

#TODO:
# Classes:
#  Class for vulnerability checking (Safe vulnerability / discovery done, Un-Safe vulnerability / discovery needs to be done yet)
#
# Scan Types:
#  --rfc [/h/toolbox/recon/rfc1918.txt](RFC scan while internal) [Completed Dec 1]
#  --proxies <Comma-separated list of proxy URLs> (Relay TCP connections through a chain of proxies)
#  --badsum (Send packets with bogus TCP/UDP checksums)
#  --adler32 (Use deprecated Adler32 instead of CRC32C for SCTP checksums)
#  --CME, to scan for SMBv1
#  --g (send from source port, to bypass UDP 53 Ruleset Bypass)
#  --parsing to get hosts and ports for reporting
#  --add option for users to input a list of pre-identified targtes / subnets
#
# Done:
#  -D <decoy1>[,<decoy2>][,ME][,...] (Cloak a scan with decoys)
#  -S <IP_Address> (Spoof source address)
#  --randomize-hosts (Randomize target host order)
#  --spoof-mac <MAC> address, prefix, or vendor name> (Spoof MAC address)
#  Working exit function

"""
by Will Frye, d3ad7rack
"""

class complete_scans:
    def complete_scan(self):
        os.system('clear')
        print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain) would you like to scan? ')
        ip = raw_input('IP, Range, or Domain: ')
        print('')
        print("What ports would you like to scan? (If no ports are supplied, we are going to scan all TCP ports 1-65535)")
        print("Ports that you'd like to scan can be entered as a single port, comma-separated ports (x,y,z) or a range (xxx-yyy)")
        ports = str(raw_input('What ports would you like to scan? '))
        print('')
        if ports == "":
            print("Now going to run nmap scan '-sS -Pn -p- -T4 --max-retries 2 -oA nmap-reg-scan', and will give a log-file in xml, nmap, grepable nmap formats")
            os.system('sudo nmap -sS -Pn -p- -T4 --max-retries 2 -oA nmap-reg-scan ' + ip)
            os.system('clear')
        else:
            print('Now going to run nmap scan -sS -Pn -p' + ports + ' -T4 --max-retries 2 -oA nmap-reg-scan, and will give a log-file in xml, nmap, grepable nmap formats')
            print('clear')
            print("Scan ran against " + ip + " and saved to current directory, under nmap-reg-scan.[xml|nmap|gnmap] for your parsing pleasure!")
            print('')
            print("Scan against " + ip + " ran, now giving you the ports that were open and their services running on them...")
            print("Open ports tcp ports are...")
            print("")
            os.system('cat nmap-reg-scan.nmap | grep open | grep tcp||udp')
            print("")
            print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
            print("")
            raw_input("Press 'Enter' key to continue...")

    def complete_versions(self):
        os.system('clear')
        print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain) would you like to scan? ')
        ip = raw_input('IP, Range, or Domain: ')
        print('')
        print("What ports would you like to scan? (If no ports are supplied, we are going to scan all TCP ports 1-65535)")
        print("Ports that you'd like to scan can be entered as a single port, comma-separated ports (x,y,z) or a range (xxx-yyy)")
        ports = str(raw_input('What ports would you like to scan? '))
        print('')
        if ports == "":
            print("Now going to run nmap scan '-sS -sV -Pn -p- -T4 --max-retries 2 -oA nmap-reg-versions', and will give a log-file in xml, nmap, grepable nmap formats")
            os.system('sudo nmap -sS -sV -Pn -p- -T4 --max-retries 2 -oA nmap-reg-versions ' + ip)
            os.system('clear')
        else:
            print('Now going to run nmap scan -sS -sV -Pn -p' + ports + ' -T4 --max-retries 2 -oA nmap-reg-versions, and will give a log-file in xml, nmap, grepable nmap formats')
            print('clear')
            print("Scan ran against " + ip + " and saved to current directory, under nmap-reg-scan.[xml|nmap|gnmap] for your parsing pleasure!")
            print("")
            print("Scan against " + ip + " ran, now giving you the ports that were open and their services running on them...")
            print("Open ports tcp ports and the services assumed to be running on said ports are...")
            print("")
            os.system('cat nmap-reg-scan.nmap | grep open | grep tcp||udp')
            print("")
            print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
            print("")
            raw_input("Press 'Enter' key to continue...")


class rfc_scan:
    def rfc_scanner(self):
        os.system('clear')
        print('Simple ping scan to find all RFC1918 addresses on the network')
        print('')
        print("Now goin to run 'nmap -sn -iL /h/toolbox/recon/rfc1918.txt -oA rfc-addresses-pinged', and will give a log-file in xml, nmap, gnmap formats")
        os.system('sudo nmap -sn -iL /h/toolbox/recon/rfc1918.txt -oA rfc-addresses-pinged')
        os.system('clear')
        print("")
        print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
        print("")
        raw_input("Press 'Enter' key to continue...")


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
            raw_input("Press 'Enter' key to continue...")

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
            raw_input("Press 'Enter' key to continue...")

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
            raw_input("Press 'Enter' key to continue...")

class safe_vuln_check:
    def http(self):
        os.system('clear')
        print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan for HTTP(S) discoveries / vulnerabilities? ')
        ip = raw_input('IP, Range, or Domain: ')
        print('')
        print('Now scanning ports 80 and 443 on ' + ip)
        os.system('sudo nmap -p80,443 -sV --script=http-cross-domain-policy,http-frontpage-login,http-git,http-internal-ip-disclosure,http-slowloris-check,http-trace,http-vmware-path-vuln,http-vuln-cve2010-0738,http-vuln-cve2011-3192,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-2129,http-vuln-cve2015-1635,ssl-ccs-injection -d --script-args http.domain-lookup=true --stylesheet nmap.xsl -oX http-safe-vuln-scan-' + ip + '.xml -oN http-safe-vuln-scan-' + ip + '.nmap ' + ip)
        os.system('clear')
        print("Scan ran against " + ip + " and saved to current directory under http-safe-vuln-scan-" + ip + ".xml and http-safe-vuln-scan-" + ip + ".nmap for your parsing pleasure!")
        print("")
        print("Safe discovery / vulnerability scan ran against " + ip + " now opening resulting xml report file in firefox for easy readability")
        os.system("firefox http-safe-vuln-scan-" + ip + ".xml")
        print("")
        print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
        print("")
        raw_input("Press 'Enter' key to continue...")

    def ssh(self):
        os.system('clear')
        print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan for SSH discoveries / vulnerabilities? ')
        ip = raw_input('IP, Range, or Domain: ')
        print('')
        print('Now scanning port 22 on ' + ip)
        os.system('sudo nmap -p22 -sV --script=ssh-hostkey,ssh2-enum-algos,sshv1 --script-args ssh_hostkey=full --stylesheet nmap.xsl -oX ssh-safe-vuln-scan-' + ip + '.xml -oN ssh-safe-vuln-scan-' + ip + '.nmap ' + ip)
        os.system('clear')
        print("Scan ran against " + ip + " and saved to current directory under ssh-safe-vuln-scan-" + ip + ".xml and ssh-safe-vuln-scan-" + ip + ".nmap for your parsing pleasure!")
        print("")
        print("Safe discovery / vulnerability scan ran against " + ip + " now opening resulting xml report file in firefox for easy readability")
        os.system("firefox ssh-safe-vuln-scan-" + ip + ".xml")
        print("")
        print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
        print("")
        raw_input("Press 'Enter' key to continue...")

    def ftp(self):
        os.system('clear')
        print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan for (S)FTP discoveries / vulnerabilities? ')
        ip = raw_input('IP, Range, or Domain: ')
        print('')
        print('Now scanning port 21 on ' + ip)
        os.system('sudo nmap -p21 -sV --script=ftp-anon,ftp-bounce --stylesheet nmap.xsl -oX ftp-safe-vuln-scan-' + ip + '.xml -oN ftp-safe-vuln-scan-' + ip + '.nmap ' + ip)
        os.system('clear')
        print("Scan ran against " + ip + " and saved to current directory under ftp-safe-vuln-scan-" + ip + ".xml and ftp-safe-vuln-scan-" + ip + ".nmap for your parsing pleasure!")
        print("")
        print("Safe discovery / vulnerability scan ran against " + ip + " now opening resulting xml report file in firefox for easy readability")
        os.system('firefox ftp-safe-vuln-scan-' + ip + '.xml')
        print("")
        print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
        print("")
        raw_input("Press 'Enter' key to continue...")

    def irc(self):
        os.system('clear')
        print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain wold you like to scan for IRC discoveries / vulnerabilities? ')
        ip = raw_input('IP, Range, or Domain: ')
        print('')
        print('Now scanning ports 6660-6669,7000, and 8001 on ' + ip)
        os.system('sudo nmap -p6660-6669,7000,8001 -sV --script=irc-botnet-channels,irc-info --stylesheet nmap.xsl -oX irc-safe-vuln-scan-' + ip + '.xml -oN irc-safe-vuln-scan-' + ip + '.nmap ' + ip)
        os.system('clear')
        print("Scan ran against " + ip + " and saved to current directory under irc-safe-vuln-scan-" + ip + ".xml and irc-safe-vuln-scan-" + ip + ".nmap for your parsing pleasure!")
        print("")
        print("Safe discovery / vulnerability scan ran against " + ip + " now opening resulting xml report file in firefox for easy readability")
        os.system('firefox irc-safe-vuln-scan-' + ip + '.xml')
        print("")
        print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
        print("")
        raw_input("Press 'Enter' key to continue...")

class unsafe_vuln_check:
    def http(self):
        os.system('clear')
        print('What IP, IP-range (range of xxx-xxx i.e. 192.168.1.1-254, or domain would you like to scan for HTTP(S) discoveries / vulnerabilities? ')
        ip = raw_input('IP, Range, or Domain: ')
        print('')
        print('Now scanning ports 80 and 443 on ' + ip)
        os.system('sudo nmap -p80,443 -sV --script= --stylesheet nmap.xsl -oX http-safe-vuln-scan-' + ip + '.xml -oN http-safe-vuln-scan-' + ip + '.nmap ' + ip)
        os.system('clear')
        print("Scan ran against " + ip + " and saved to current directory under http-safe-vuln-scan-" + ip + ".xml and http-safe-vuln-scan-" + ip + ".nmap for your parsing pleasure!")
        print("")
        print("Safe discovery / vulnerability scan ran against " + ip + " now opening resulting xml report file in firefox for easy readability")
        os.system("firefox http-safe-vuln-scan-" + ip + ".xml")
        print("")
        print("Thank you for using d3ad7rack's fast and easy nmap scan-selector python program!!")
        print("")
        raw_input("Press 'Enter' key to continue...")

    def ssh(self):
        print("Not done yet...")

    def ftp(self):
        print("Not done yet...")

    def irc(self):
        print("Not done yet...")

    def no_options(self):
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
            raw_input("Press 'Enter' key to continue...")

class loud_scans:
    def basic_loud_scan(self):
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
            raw_input("Press 'Enter' key to continue...")

class xsl_file_copy:
    def xsl_file(self):
        print("When, if asked, please use your password for copying over the nmap.xsl stylesheet to your current directory, for saved xml files to work correctly")
        os.system('sudo cp /usr/share/nmap/nmap.xsl .')
        print("")
        print("All done, happy hacking!")
        print("")
        raw_input("Press 'Enter' key to continue...")


def exit():
    sys.exit()


complete = complete_scans()
evade = evade_fw()
safe = safe_vuln_check()
unsafe = unsafe_vuln_check()
loudness = loud_scans()
rfc_scan_id = rfc_scan()
xsl_copy = xsl_file_copy()

# Main program running dialogue
# Need to put in complete scan menu, as well as add the aliases in as scan types
def main():  # menu goes here
    opt_list = [xsl_copy.xsl_file,
                rfc_scan_id.rfc_scanner,
                unsafe.no_options,
                comp_scans,
                loud_scans.basic_loud_scan,
                fw_main,
                vuln_main,
                exit
                ]

    while (True):
        os.system('clear')
        print("SELECT OPTION: ")
        print("1\tCopy nmap.xsl file to present directory for proper saving of xml files (Needs to be done)")
        print("2\tRFC scan")
        print("3\tBasic scans, no options")
        print("4\tComplete scans, with and without version detection")
        print("5\tBasic, Loud Scan")
        print("6\tFirewall evasion techniques")
        print("7\tVulnerability checking (Safe discovery / vulnerability is working, but unsafe discovery / vulnerabiltiy scanning is not...yet")
        print("8\tExit")
        opt_choice = int(raw_input("Selection: "))
        os.system('clear')
        opt_choice -= 1
        opt_list[opt_choice]()

        return


# Menu for complete scans
def comp_scans():  # menu goes here
    opt_list = [complete.complete_scan,
                complete.complete_versions,
                main
                ]

    while (True):
        os.system('clear')
        print("SELECT OPTION: ")
        print("1\tComplete Scan, without grabbing service versions")
        print("2\tComplete Scan with service versions")
        print("3\tMain Menu")
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

# Menu for safe or unsafe vulnerability scans
def vuln_main():  # menu goes here
    opt_list = [safe_vulns_main,
                unsafe_vulns_main,
                main
                ]

    while (True):
        os.system('clear')
        print("SELECT OPTION: ")
        print("1\tSafe Discovery / Vulnerability Checking")
        print("2\tUnsafe Vulnerability Checking (Not working, currently")
        print("3\tMain Menu")
        opt_choice = int(raw_input("Selection: "))
        os.system('clear')
        opt_choice -= 1
        opt_list[opt_choice]()

        return

# Menu for safe discovery / vulnerability scans
def safe_vulns_main():  # menu goes here
    opt_list = [safe.http,
                safe.ssh,
                safe.ftp,
                safe.irc,
                main
                ]

    while (True):
        os.system('clear')
        print("SELECT OPTION: ")
        print("1\tHTTP(S) Discovery / Vulnerabilties")
        print("2\tSSH Discovery / Vulnerabilities")
        print("3\t(S)FTP Discovery / Vulnerabilities")
        print("4\tIRC Discovery / Vulnerabilities")
        print("5\tMain Menu")
        opt_choice = int(raw_input("Selection: "))
        os.system('clear')
        opt_choice -= 1
        opt_list[opt_choice]()

        return

# Menu for unsafe discovery / vulnerability scans
def unsafe_vulns_main():  # menu goes here
    opt_list = [unsafe.http,
                unsafe.ssh,
                unsafe.ftp,
                unsafe.irc,
                main
                ]

    while (True):
        os.system('clear')
        print("SELECT OPTION: ")
        print("1\tHTTP(S) Vulnerabilties")
        print("2\tSSH Vulnerabilties")
        print("3\t(S)FTP Discovery / Vulnerabilities")
        print("4\tIRC Discovery / Vulnerabilities")
        print("5\tMain Menu")
        opt_choice = int(raw_input("Selection: "))
        os.system('clear')
        opt_choice -= 1
        opt_list[opt_choice]()

        return



main()

if __name__ == '__main__':
    main()

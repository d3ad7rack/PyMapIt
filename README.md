#   ****** PyMapIt *****

A simple program that I had made that basically does all the dirty work of
trying to figure out what options are needed for an nmap scan for those
just getting into network security and don't know what all the switches/options
of nmap are.

With that being said, it is required to have nmap already installed on your system.
If you don't have nmap already installed, you can install it by issuing
"sudo apt-get install nmap"

The program, as of right now, is in beta stage, so there are some kinks that need
to be worked out. Specifically the Exit option of the main menu. I'm still learning
about Python and how to do certain things, so this program is still a work in progress.

I'd love to hear what you think about it.



# ***** Usage *****

To use the program all you need to do is issue: python pymapit.py

The script will ask for your sudo password when it gets to that point in the script,
but you do not need to run the script as sudo.


# ***** Pre-reqs *****

The only thing that is needed to be installed for the script to work correctly is nmap

from colorama import Fore
from colorama import Fore,Back,Style


culoare_general_help = Fore.MAGENTA
culoare_info_comenzi = Fore.LIGHTGREEN_EX
culoare_info_evidentiere = Fore.RED+Style.BRIGHT
culoare_reset = Fore.RESET+Back.RESET+Style.RESET_ALL

def display_banner():
    banner_text =  ''' 
    .___  ___. .___________.    ___              _______.  ______     ___      .__   __. .__   __.  _______ .______      
    |   \/   | |           |   /   \            /       | /      |   /   \     |  \ |  | |  \ |  | |   ____||   _  \     
    |  \  /  | `---|  |----`  /  ^  \          |   (----`|  ,----'  /  ^  \    |   \|  | |   \|  | |  |__   |  |_)  |    
    |  |\/|  |     |  |      /  /_\  \          \   \    |  |      /  /_\  \   |  . `  | |  . `  | |   __|  |      /     
    |  |  |  |     |  |     /  _____  \     .----)   |   |  `----./  _____  \  |  |\   | |  |\   | |  |____ |  |\  \----.
    |__|  |__|     |__|    /__/     \__\    |_______/     \______/__/     \__\ |__| \__| |__| \__| |_______|| _| `._____|
    
    MTA SCANNER V1.0
    \N{COPYRIGHT SIGN} Developed by Stratulat Dragos & Negrea Stefan
    [!]PSO project BETA STAGE
    [?]Type help for more details                                                                                                                                                                                                                
    '''

    print (f"{Fore.LIGHTGREEN_EX}{banner_text}")


def general_help():
    print(Fore.MAGENTA + Style.BRIGHT + "\nWelcome to help menu. This is a list with available system commands:")
    print(culoare_general_help + "• \"run_simple_scan\"")
    print(culoare_general_help + "• \"show_open_ports\"")
    print(culoare_general_help + "• \"service\"")
    print(culoare_general_help + "• \"show_os\"")
    print(culoare_general_help + "• \"run_complex_scan\"")
    print(culoare_general_help + "• \"ping_scan\"")
    print(culoare_general_help + "• \"UDP_scan\"")
    print(culoare_general_help + "• \"exploit\"")
    print(culoare_general_help + "• \"quick_full_scan\"")
    print(culoare_general_help + "• \"scan_for_vuln\"")
    print(culoare_general_help + "• \"print_vuln\"")
    print(Fore.MAGENTA + Style.BRIGHT + "For more details type help " + Fore.RED + Style.BRIGHT + "command\n")


def run_simple_scan_help():
    print(culoare_info_comenzi + "\nCommand " + culoare_info_evidentiere + "run_simple_scan")
    print(culoare_info_comenzi + "• Is used for a fast and simple scan")
    print(culoare_info_comenzi + "• Example: " + culoare_reset + culoare_info_evidentiere + "run_simple_scan")
    print(
        culoare_info_comenzi + "• Nmap command used: " + culoare_info_evidentiere + "nmap -oX -p [port_range] -sV [address]")
    print(culoare_info_comenzi + "• Parameters used: ")
    print(
        culoare_info_evidentiere + "   -oX" + culoare_reset + culoare_info_comenzi + " Output scan in XML format to the given filename.")
    print(
        culoare_info_evidentiere + "   -sV" + culoare_reset + culoare_info_comenzi + " Version detection - can be used to help differentiate the truly open ports from the filtered ones.\n")


def show_open_ports_help():
    print(culoare_info_comenzi + "\nCommand " + culoare_info_evidentiere + "show_open_ports")
    print(culoare_info_comenzi + "• Is used to show the open ports of a host.")
    print(
        culoare_info_comenzi + "• Example: " + culoare_reset + culoare_info_evidentiere + "show_open_ports 192.168.209.129")
    print(
        culoare_info_comenzi + "• Output example: " + culoare_reset + culoare_info_evidentiere + "\n\nHost: 192.168.209.129\nState: up\n--------------------------------\nProtocol: tcp\nport ftp: 21     state: open\nport ssh: 22     state: open\nport telnet: 23     state: open\nport smtp: 25     state: open\nport domain: 53     state: open\nport http: 80     state: open\n")


def service_help():
    print(culoare_info_comenzi + "\nCommand " + culoare_info_evidentiere + "sevice")
    print(culoare_info_comenzi + "• Is used to show details about a particular service.")
    print(
        culoare_info_comenzi + "• Example: " + culoare_reset + culoare_info_evidentiere + "service ssh 192.168.209.129\n")


def show_os_help():
    print(culoare_info_comenzi + "\nCommand " + culoare_info_evidentiere + "show_os")
    print(culoare_info_comenzi + "• It shows the operating system running on target and some details about it.")
    print(culoare_info_comenzi + "• Example: " + culoare_reset + culoare_info_evidentiere + "show_os 192.168.209.129\n")


def run_complex_scan_help():
    print(culoare_info_comenzi + "\nCommand " + culoare_info_evidentiere + "run_complex_scan")
    print(
        culoare_info_comenzi + "• It makes a more complex scan in which you get more details about the target on which we perform the scan.")
    print(culoare_info_comenzi + "• Example: " + culoare_reset + culoare_info_evidentiere + "run_complex_scan")
    print(
        culoare_info_comenzi + "• Nmap command used: " + culoare_info_evidentiere + "nmap [host] -p [port-range] -sS -sV -sC -O")
    print(culoare_info_comenzi + "• Parameters used: ")
    print(
        culoare_info_evidentiere + "   -sS" + culoare_reset + culoare_info_comenzi + " TCP SYN scan. SYN scan is the default and most popular scan option for good\n       reasons. It can be performed quickly, scanning thousands of ports\n       per second on a fast network not hampered by restrictive firewalls.")
    print(
        culoare_info_evidentiere + "   -sC" + culoare_reset + culoare_info_comenzi + " equivalent to --script=default")
    print(
        culoare_info_evidentiere + "   -sV" + culoare_reset + culoare_info_comenzi + " Version detection - can be used to help differentiate the truly open ports from the filtered ones.")
    print(
        culoare_info_evidentiere + "   -O" + culoare_reset + culoare_info_comenzi + " Enable OS detection\n")

def udp_scan_help():
    print(culoare_info_comenzi + "\nCommand " + culoare_info_evidentiere + "udp_scan")
    print(culoare_info_comenzi + "• Is does a UDP scan")
    print(culoare_info_comenzi + "• Example: " + culoare_reset + culoare_info_evidentiere + "udp_scan 192.168.209.129 1-1024")
    print(
        culoare_info_comenzi + "• Nmap command used: " + culoare_info_evidentiere + "scan [host] [port-range] -n -sU --max-retries 2 -T4")
    print(culoare_info_comenzi + "• Parameters used: ")
    print(culoare_info_evidentiere + "   -n" + culoare_reset + culoare_info_comenzi + " Never do DNS resolution")
    print(
        culoare_info_evidentiere + "   --max-retries <tries>" + culoare_reset + culoare_info_comenzi + " Caps number of port scan probe retransmissions.")
    print(culoare_info_evidentiere + "   -T4" + culoare_reset + culoare_info_comenzi + " for faster execution")
    print(culoare_info_evidentiere + "   -sU" + culoare_reset + culoare_info_comenzi + " UDP Scan\n")


def exploit_help():
    print(culoare_info_comenzi + "\nCommand " + culoare_info_evidentiere + "exploit")
    print(culoare_info_comenzi + "• Is used to exploit the service from a specific port.")
    print(
        culoare_info_comenzi + "• Example: " + culoare_reset + culoare_info_evidentiere + "exploit 22 192.168.209.129\n")


def quick_full_scan_help():
    print(culoare_info_comenzi + "\nCommand " + culoare_info_evidentiere + "quick_full_scan")
    print(culoare_info_comenzi + "• It does a quick scan on all ports.")
    print(culoare_info_comenzi + "• Example: " + culoare_reset + culoare_info_evidentiere + "quick_full_scan\n")


def scan_for_vuln_help():
    print(culoare_info_comenzi + "\nCommand " + culoare_info_evidentiere + "scan_for_vuln")
    print(culoare_info_comenzi + "• It scans a service from a target for vulnerabilities")
    print(
        culoare_info_comenzi + "• Example: " + culoare_reset + culoare_info_evidentiere + "scan_for_vuln 192.168.209.129 22")
    print(
        culoare_info_comenzi + "• Nmap command used: " + culoare_info_evidentiere + "scan_for_vuln [address] [port_range] -sS -sV -A -T4 --script=vuln")
    print(culoare_info_comenzi + "• Parameters used: ")
    print(
        culoare_info_evidentiere + "   -sS" + culoare_reset + culoare_info_comenzi + " TCP SYN scan. SYN scan is the default and most popular scan option for good\n       reasons. It can be performed quickly, scanning thousands of ports\n       per second on a fast network not hampered by restrictive firewalls.")
    print(culoare_info_evidentiere + "   -T4" + culoare_reset + culoare_info_comenzi + " for faster execution")
    print(
        culoare_info_evidentiere + "   -A" + culoare_reset + culoare_info_comenzi + " to enable OS and version detection, script scanning, and traceroute")
    print(
        culoare_info_evidentiere + "   --script=vuln" + culoare_reset + culoare_info_comenzi + " Loads all scripts whose name starts with vuln")
    print(
        culoare_info_evidentiere + "   -sV" + culoare_reset + culoare_info_comenzi + " Version detection - can be used to help differentiate the truly open ports from the filtered ones.\n")


def help(command = ""):
    if (command == ""):
        general_help()
        return
    if (command == "run_simple_scan"):
        run_simple_scan_help()
        return
    if (command == "show_open_ports"):
        show_open_ports_help()
        return
    if (command == "service"):
        service_help()
        return
    if (command == "show_os"):
        show_os_help()
        return
    if (command == "run_complex_scan"):
        run_complex_scan_help()
        return
    if (command == "udp_scan"):
        udp_scan_help()
        return
    if (command == "exploit"):
        exploit_help()
        return
    if (command == "quick_full_scan"):
        quick_full_scan_help()
        return
    if (command == "scan_for_vuln"):
        scan_for_vuln_help()
        return
    else:
        print("Help command doesn't exist")




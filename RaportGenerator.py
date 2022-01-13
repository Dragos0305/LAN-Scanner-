import colorama
import nmap
from colorama import Fore
import subprocess
from fpdf import FPDF
import matplotlib.pyplot as plt
colorama.init(autoreset=True)


def show_scan_info(scanner):
    up_hosts = [host for host in scanner.all_hosts() if scanner[host].state() == "up"]
    if len(up_hosts) == 0:
        print(f"{Fore.RED}[-]{Fore.RESET} No host available in this network")
    else:
        print_message("success", "Scanning finished. Available Hosts are:")

        for index, host in enumerate(up_hosts):
            print(f"Host {index + 1}: {host}")


def print_message(_type, text):
    if _type == "success":
        print(f"{Fore.LIGHTGREEN_EX}[+]{Fore.RESET}{text}")
    elif _type == "error":
        print(f"{Fore.LIGHTRED_EX}[-]{Fore.RESET}{text}")
    elif _type == "info":
        print(f"{Fore.LIGHTBLUE_EX}[!]{Fore.RESET}{text}")


class RaportGenerator:

    # RaportGenerator class constructor
    def __init__(self, address, port_range='1-1000'):
        self.address = address
        self.port_range = port_range
        self.scanner = nmap.PortScanner()
        self.vuln_list = {}

    # Scanning method
    def run_simple_scan(self):

        print_message("info", "Starting simple scan...")
        print_message("info", f"Command used: nmap -oX -p {self.port_range} -sV {self.address}")
        self.scanner.scan(self.address, self.port_range, '-v')
        show_scan_info(self.scanner)

    def run_complex_scan(self):
        print(f"{Fore.LIGHTBLUE_EX}[+]{Fore.RESET} Starting complex scan...")
        print(f"{Fore.LIGHTBLUE_EX}[+]{Fore.RESET} Command used: ")

        self.scanner.scan(self.address, self.port_range, '-sS -sV -sC -O')
        show_scan_info(self.scanner)
        print(self.scanner)

    def service(self, service, host):

        protocols = self.scanner[host].all_protocols()

        for protocol in protocols:
            if int(service) in self.scanner[host][protocol].keys():
                service_information = self.scanner[host][protocol][int(service)]
                for info in service_information:
                    print(f"{info}: {service_information[info]}")
            else:
                print(f"{Fore.LIGHTRED_EX}[-]{Fore.RESET}This service is close. We don't have information about it")

    def show_open_ports(self, host):

        try:
            self.scanner.scaninfo()

        except:

            print(f"{Fore.LIGHTRED_EX}[-]{Fore.RESET}Try start a scan first")
            return

        if not self.scanner.has_host(host):
            print("You entered bad host")
            exit(1)

        print(f'Host: {host}')
        print(f'State: {self.scanner[host].state()}')

        for protocol in self.scanner[host].all_protocols():

            print('--------------------------------')
            print(f'Protocol: {protocol}')

            port_list = self.scanner[host][protocol]

            for port in port_list:
                print(f"port {port_list[port]['name']}: {port}\t state: {self.scanner[host][protocol][port]['state']}")

    def show_os(self, host):
        try:
            print("OS Details")
            print(f"Host: {host}")
            print(f"Name: {self.scanner[host]['osmatch'][0]['name']}")
        except:
            print_message("error", "Scanning method didn't find details about Operating System")

    def udp_scan(self, host, port_range='1-1024'):
        print_message("info", "Start UDP scan")
        self.scanner.scan(host, port_range, '-n -sU --max-retries 2 -T5')
        print_message("info", "UDP scan finished. For more details type show_open_ports")

    def scan_for_vuln(self, host, port_number):

        if self.scanner[host]['tcp'][int(port_number)]['state'] == 'open':
            vuln_scan = nmap.PortScanner()
            vuln_scan.scan(host, port_number, '-sS -sV -A -T4 --script=vuln')
            self.result = vuln_scan[host]['tcp'][int(port_number)]['script']
            if host not in self.vuln_list.keys():
                self.vuln_list[host] = []
                self.vuln_list[host].append(self.result)
            else:
                self.vuln_list[host].append(self.result)
        else:
            print_message("error", "Port closed...")
            return
        print_message("info", "Scan finished")

    def quick_full_scan(self):
        self.scanner.scan(self.address, '-', '-sS -T4 -n -O')

    def exploit(self, port_number, host):
        service_name = self.scanner[host]['tcp'][int(port_number)]['name']

        if service_name == "ssh":
            print_message("info", "Exploiti ssh service by bruteforce method...")
            command = f"hydra -f -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://{host} -t 4 "
            brute_force_process = subprocess.Popen(command.split())
            output, error = brute_force_process.communicate()
            print(output)

    def generate_report(self):
        # Create PDF OBJECT
        WIDTH = 210
        HEIGHT = 297

        print(f"{Fore.LIGHTBLUE_EX}[!]{Fore.RESET}Generate report Please wait...")
        pdf = FPDF('P', 'mm', 'A4')
        pdf.add_page()
        pdf.image(f"./CopertaV2.png", 0, 0, WIDTH, HEIGHT)
        pdf.add_page()
        pdf.set_font('Arial', 'B', 18)
        pdf.ln('8')

        pdf.write(5, "1.General Information\n")
        self.quick_full_scan()
        pdf.ln('20')

        # For every host in newtork print information in PDF
        for host in self.scanner.all_hosts():
            pdf.set_font('Times', size=12)

            if self.scanner[host]['status']['reason'] != "localhost-response":

                # Genral Information
                pdf.write(5, f"       Host: {self.scanner[host]['addresses']['ipv4']}\n")
                pdf.write(5, f"       Mac Address: {self.scanner[host]['addresses']['mac']}\n")
                pdf.write(5, f"       Vendor: {self.scanner[host]['vendor'][self.scanner[host]['addresses']['mac']]}\n")
                pdf.write(5, f"       Uptime: {self.scanner[host]['uptime']['seconds']} seconds\n")
                pdf.write(5, f"       Last boot: {self.scanner[host]['uptime']['lastboot']}\n")
                pdf.write(5, f"       OS Family: {self.scanner[host]['osmatch'][0]['name']} (accuracy: {self.scanner[host]['osmatch'][0]['accuracy']})\n")

                pdf.set_font('Arial', 'B', 18)
                pdf.ln('100')

                pdf.write(5, "2.Open Ports\n")
                pdf.ln('200')
                data = {}

                pdf.set_font('Arial', 'B', 12)
                pdf.write(5, "2.1 TCP protocols\n")
                pdf.ln('200')

                pdf.set_font('Times', size=12)

                demo_port_list = [22]

                for port in demo_port_list:

                    self.scan_for_vuln(host, str(port))
                    pdf.write(5, f"  Port number: {port}\n")
                    pdf.write(5, f"  State: {self.scanner[host]['tcp'][port]['state']}\n")
                    pdf.write(5, f"  Service Name: {self.scanner[host]['tcp'][port]['name']}\n")

                    pdf.write(5, f"  Vulnerabilities found: \n")
                    cvss_list = []
                    pdf.set_font('Times', size=9)
                    keys = self.result.keys()
                    for key in keys:
                        for vulns in self.result[key].split("\n"):
                            for index, token in enumerate(vulns.split("\t")):
                                if index == 0:
                                    pdf.write(5, f'{token}\n')
                                else:
                                    pdf.write(5, f'{token}  ')
                                    try:
                                        float(token)
                                        cvss_list.append(float(token))
                                    except:
                                        continue

                dict_chart = {"Low": 0, "Medium": 0, "High": 0}

                for cvss in cvss_list:
                    if cvss > 0.1 and cvss <= 3.9:
                            dict_chart["Low"] += 1
                    if cvss >= 4.0 and cvss <= 6.9:
                            dict_chart["Medium"] += 1
                    if cvss >= 7.0 and cvss <= 8.9:
                            dict_chart["High"] += 1

                plt.pie(list(dict_chart.values()), labels=list(dict_chart.keys()), autopct='%2.1f%%')
                plt.title("Vulnerabilities statistic")
                plt.savefig("vuln_statistics.png")

                pdf.add_page()
                pdf.image("vuln_statistics.png", 30, 15, w=150, h=110)
                print(f"{Fore.LIGHTBLUE_EX}[!]{Fore.RESET} Report was generated")
                pdf.output("example.pdf")
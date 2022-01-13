import RaportGenerator
from colorama import Fore
import subprocess
import utils

command_dictionary = {"run_simple_scan": ["Raport"],
                      "show_open_ports": ["Raport", "host"],
                      "service": ["Raport", "service", "host"],
                      "show_os": ["Raport", "host"],c
                       "run_complex_scan": ["Raport"],
                      "ping_scan": ["Raport"],
                      "udp_scan": ["Raport", "host", "port-range"],
                      "exploit": ["Raport", "port_number", "host"],
                      "quick_full_scan": ["Raport"],
                      "scan_for_vuln": ["Raport", "host", "port_number"],
                      "print_vuln": ["Raport","host"],
                      "generate_report": ["Raport"]}



def parse_command(command_argument):

    words = command_argument.split(" ")
    main_command = words[0]
    if main_command in command_dictionary.keys():

        number_of_parameters = len(words) - 1
        obiect = command_dictionary[main_command][0]
        return_command = obiect + "." + main_command
        parameteres = [element for index, element in enumerate(words) if index != 0]
        if number_of_parameters != len(command_dictionary[main_command]) - 1:
            print(f"{Fore.LIGHTRED_EX}[-]Invalid number of parameters. "
                  f"Command receive {len(command_dictionary[main_command])-1}. "
                  f"You give {number_of_parameters} arguments. Type command_name help for more details")
            return None, None
        return str(return_command), tuple(parameteres)
    else:
        return None, None




if __name__ == '__main__':

    print(f"{Fore.LIGHTBLUE_EX}[!]{Fore.RESET}Welcome to MTA Scanner.")
    utils.display_banner()
    print(f"{Fore.LIGHTBLUE_EX}[!]{Fore.RESET}Before start scannig we need some information")
    ip_address = input(f"{Fore.LIGHTBLUE_EX}[+]{Fore.RESET}Please type LAN address: ")
    port_range = input(f"{Fore.LIGHTBLUE_EX}[+]{Fore.RESET}Please enter port range (1-1000) by default: ")

    Raport = RaportGenerator.RaportGenerator(ip_address, port_range)
    while True:

        command = input("(mconsole) > ")
        help_sem = 0;
        if command == "exit":
            exit(0)

        if command.find("help") != -1 and len(command) != 0:
            args = command.split()
            if len(args) == 2:
                utils.help(args[1])
                help_sem = 1
            else:
                utils.help()
                help_sem = 1

        if len(command) and help_sem == 0:

            function, parameters = parse_command(command)

            if function is not None and parameters is not None:
                eval(function + str(parameters))
            else:
                try:
                    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
                    output, error = process.communicate()

                    if output is None:
                        print(error.decode())
                    else:
                        print(output.decode())
                except:
                    RaportGenerator.print_message("error", "Unknown command")


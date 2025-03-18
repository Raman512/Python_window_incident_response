import winrm
import logging
import time
from datetime import datetime
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Configure logging to log the output to a file
logging.basicConfig(filename=f"winrm_script_output_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log", 
                    level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Functions for each task with animation and styling

def print_header(text):
    print(f"{Fore.YELLOW}{Style.BRIGHT}{text}{Style.RESET_ALL}")

def wait_for_done():
    print(Fore.GREEN + "Done!" + Style.RESET_ALL)
    time.sleep(1)

def print_progress(text):
    print(f"{Fore.CYAN}Processing: {text}...{Style.RESET_ALL}")
    time.sleep(1)

def animate_menu_options():
    options = [
        "IP Configuration",
        "Users",
        "Active TCP & UDP Ports",
        "Firewall Configuration",
        "System Information",
        "CPU Usage",
        "Memory Usage (RAM)",
        "Disk Space",
        "Log Entries (Security Logs)",
        "Running Processes",
        "Scheduled Tasks Details",
        "Network Connections",
        "Ping Remote Host",
        "File Sharing",
        "Open Sessions",
        "Recent .exe Files",
        "Registry Control (Run Keys)",
        "Installed Software",
        "All-in-One (Run all tasks)",
        "Exit"
    ]
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}Select an option to run:{Style.RESET_ALL}")
    for i, option in enumerate(options, start=1):
        time.sleep(0.3)
        print(f"{Fore.GREEN}{i}. {option}")

def ip_config(winrm_session):
    print_header("IP Configuration:")
    print_progress("Retrieving IP configuration")
    result = winrm_session.run_cmd('ipconfig', ['/all'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("IP Configuration:\n" + output)
    wait_for_done()

def users(winrm_session):
    print_header("Users:")
    print_progress("Retrieving user list")
    result = winrm_session.run_cmd('net', ['user'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Users:\n" + output)
    wait_for_done()

def network_stats(winrm_session):
    print_header("Active TCP & UDP Ports:")
    print_progress("Fetching network stats")
    result = winrm_session.run_cmd('netstat', ['-ano'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Active TCP & UDP Ports:\n" + output)
    wait_for_done()

def firewall_config(winrm_session):
    print_header("Firewall Config:")
    print_progress("Retrieving firewall settings")
    result = winrm_session.run_cmd('netsh firewall show config')
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Firewall Config:\n" + output)
    wait_for_done()

def system_info(winrm_session):
    print_header("System Information:")
    print_progress("Getting system info")
    result = winrm_session.run_cmd('systeminfo')
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("System Information:\n" + output)
    wait_for_done()

def cpu_usage(winrm_session):
    print_header("CPU Usage:")
    print_progress("Fetching CPU usage")
    result = winrm_session.run_cmd('wmic', ['cpu', 'get', 'loadpercentage'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("CPU Usage:\n" + output)
    wait_for_done()

def memory_usage(winrm_session):
    print_header("Memory Usage (RAM):")
    print_progress("Fetching memory usage")
    result = winrm_session.run_cmd('wmic', ['memorychip', 'get', 'capacity,deviceLocator'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Memory Usage (RAM):\n" + output)
    wait_for_done()

def disk_space(winrm_session):
    print_header("Disk Space:")
    print_progress("Getting disk space details")
    result = winrm_session.run_cmd('wmic', ['logicaldisk', 'get', 'size,freespace,caption'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Disk Space:\n" + output)
    wait_for_done()

def log_entries(winrm_session):
    print_header("Log Entries (Security Logs):")
    print_progress("Fetching security logs")
    result = winrm_session.run_cmd('wevtutil qe security')
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Log Entries (Security Logs):\n" + output)
    wait_for_done()

def running_processes(winrm_session):
    print_header("Running Processes:")
    print_progress("Retrieving running processes")
    result = winrm_session.run_cmd('tasklist')
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Running Processes:\n" + output)
    wait_for_done()

def scheduled_tasks(winrm_session):
    print_header("Scheduled Tasks Details:")
    print_progress("Retrieving scheduled tasks")
    result = winrm_session.run_cmd('schtasks', ['/query', '/fo', 'LIST', '/v'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Scheduled Tasks Details:\n" + output)
    wait_for_done()

def network_connections(winrm_session):
    print_header("Network Connections:")
    print_progress("Getting network connections")
    result = winrm_session.run_cmd('netstat', ['-an'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Network Connections:\n" + output)
    wait_for_done()

def ping_remote_host(winrm_session):
    remote_host = input("Enter host to ping: ")
    print_header(f"Pinging remote host: {remote_host}")
    print_progress("Pinging remote host")
    result = winrm_session.run_cmd('ping', [remote_host])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info(f"Pinging remote host: {remote_host}:\n" + output)
    wait_for_done()

def file_sharing(winrm_session):
    print_header("File Sharing:")
    print_progress("Retrieving file sharing info")
    result = winrm_session.run_cmd('net', ['view'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("File Sharing:\n" + output)
    wait_for_done()

def open_sessions(winrm_session):
    print_header("Open Sessions:")
    print_progress("Retrieving open sessions")
    result = winrm_session.run_cmd('net session')
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Open Sessions:\n" + output)
    wait_for_done()

def recent_files(winrm_session):
    print_header("Files (recent .exe files):")
    print_progress("Retrieving recent .exe files")
    result = winrm_session.run_cmd('forfiles /D -10 /S /M *.exe /C "cmd /c echo @ext @fname @fdate"')
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Recent .exe Files:\n" + output)
    wait_for_done()

def registry_run(winrm_session):
    print_header("Registry Control (Run Keys):")
    print_progress("Retrieving registry run keys")
    result = winrm_session.run_cmd('reg', ['query', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Registry Control (Run Keys):\n" + output)
    wait_for_done()

def installed_software(winrm_session):
    print_header("Installed Software:")
    print_progress("Retrieving installed software list")
    result = winrm_session.run_cmd('reg', ['query', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'])
    output = result.std_out.decode('ascii')
    print(Fore.GREEN + output)
    logging.info("Installed Software:\n" + output)
    wait_for_done()

def all_in_one(winrm_session):
    print_header("Running All Tasks...")
    ip_config(winrm_session)
    users(winrm_session)
    network_stats(winrm_session)
    firewall_config(winrm_session)
    system_info(winrm_session)
    cpu_usage(winrm_session)
    memory_usage(winrm_session)
    disk_space(winrm_session)
    log_entries(winrm_session)
    running_processes(winrm_session)
    scheduled_tasks(winrm_session)
    network_connections(winrm_session)
    ping_remote_host(winrm_session)
    file_sharing(winrm_session)
    open_sessions(winrm_session)
    recent_files(winrm_session)
    registry_run(winrm_session)
    installed_software(winrm_session)

# Main menu to select the action
def menu():
    animate_menu_options()
    choice = input("\nEnter your choice (1-20): ")

    if choice == "1":
        return ip_config
    elif choice == "2":
        return users
    elif choice == "3":
        return network_stats
    elif choice == "4":
        return firewall_config
    elif choice == "5":
        return system_info
    elif choice == "6":
        return cpu_usage
    elif choice == "7":
        return memory_usage
    elif choice == "8":
        return disk_space
    elif choice == "9":
        return log_entries
    elif choice == "10":
        return running_processes
    elif choice == "11":
        return scheduled_tasks
    elif choice == "12":
        return network_connections
    elif choice == "13":
        return ping_remote_host
    elif choice == "14":
        return file_sharing
    elif choice == "15":
        return open_sessions
    elif choice == "16":
        return recent_files
    elif choice == "17":
        return registry_run
    elif choice == "18":
        return installed_software
    elif choice == "19":
        return all_in_one
    elif choice == "20":
        return None
    else:
        print(Fore.RED + "Invalid choice, please try again.")
        return menu()

# Main function to process the commands based on user selection
def main():
    # Read the credentials from the file
    with open('cred_list.txt', 'r') as f:
        lines = f.readlines()

    # Iterate through each line in the file and extract the credentials
    for line in lines:
        fields = line.strip().split("|")
        IP_address = fields[0]
        user = fields[1]
        passw = fields[2]

        logging.info(f"Attempting to connect to {IP_address} as {user}...")

        try:
            # Create a winrm session using the credentials
            winrm_session = winrm.Session(f'http://{IP_address}:5985', auth=(user, passw), transport='ntlm')

            while True:
                selected_function = menu()
                if selected_function:
                    selected_function(winrm_session)
                else:
                    logging.info("Exiting...")
                    break

        except Exception as e:
            logging.error(f"Failed to connect to {IP_address}. Error: {e}")

# Run the main function
if __name__ == "__main__":
    main()

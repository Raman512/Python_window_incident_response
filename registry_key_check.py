import winrm
import time
from colorama import Fore, init
import sys

# Initialize colorama for terminal styling
init(autoreset=True)

# Function to show the main menu
def show_menu():
    print(Fore.YELLOW + "\nSelect an option to run:")
    print("1. Registry Control (Startup Programs - All Users)")
    print("2. User Registry Control (User-Specific Startup Programs)")
    print("3. Windows Services")
    print("4. Security Settings")
    print("5. Installed Software (From Uninstall Registry Key)")
    print("6. Installed Software (32-bit on 64-bit systems)")
    print("7. Windows Firewall Settings")
    print("8. Run All Tasks")
    print("9. Exit")
    choice = input("\nEnter your choice (1-9): ")
    return choice

# Function to simulate a loading animation
def loading_animation():
    print(Fore.CYAN + "Processing", end="")
    for _ in range(3):
        time.sleep(0.5)
        print(".", end="")
        sys.stdout.flush()
    print()

# Task functions based on the user's choice
def registry_control(winrm_session):
    loading_animation()
    print("Registry Control (Startup Programs - All Users):")
    result = winrm_session.run_cmd('reg', ['query', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'])
    print(result.std_out.decode('ascii'))

def user_registry_control(winrm_session):
    loading_animation()
    print("User Registry Control (User-Specific Startup Programs):")
    result = winrm_session.run_cmd('reg', ['query', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'])
    print(result.std_out.decode('ascii'))

def windows_services(winrm_session):
    loading_animation()
    print("Windows Services:")
    result = winrm_session.run_cmd('reg', ['query', r'HKLM\SYSTEM\CurrentControlSet\Services'])
    print(result.std_out.decode('ascii'))

def security_settings(winrm_session):
    loading_animation()
    print("Security Settings:")
    result = winrm_session.run_cmd('reg', ['query', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Security'])
    print(result.std_out.decode('ascii'))

def installed_software(winrm_session):
    loading_animation()
    print("Installed Software (From Uninstall Registry Key):")
    result = winrm_session.run_cmd('reg', ['query', r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'])
    print(result.std_out.decode('ascii'))

def installed_software_32bit(winrm_session):
    loading_animation()
    print("Installed Software (32-bit on 64-bit):")
    result = winrm_session.run_cmd('reg', ['query', r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'])
    print(result.std_out.decode('ascii'))

def windows_firewall(winrm_session):
    loading_animation()
    print("Windows Firewall Settings:")
    result = winrm_session.run_cmd('reg', ['query', r'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'])
    print(result.std_out.decode('ascii'))

def run_all_tasks(winrm_session):
    print(Fore.CYAN + "Running all tasks...\n")
    registry_control(winrm_session)
    user_registry_control(winrm_session)
    windows_services(winrm_session)
    security_settings(winrm_session)
    installed_software(winrm_session)
    installed_software_32bit(winrm_session)
    windows_firewall(winrm_session)

# Main function that handles the interaction with WinRM and user input
def main():
    # Read the credentials from the file
    with open('cred_list.txt', 'r') as f:
        lines = f.readlines()

    for line in lines:
        fields = line.strip().split("|")
        IP_address = fields[0]
        user = fields[1]
        passw = fields[2]

        print(f"\nAttempting to connect to {IP_address} as {user}...")

        try:
            # Create a winrm session using the credentials
            winrm_session = winrm.Session(f'http://{IP_address}:5985', auth=(user, passw), transport='ntlm')

            while True:
                # Show the menu and get user choice
                choice = show_menu()

                if choice == "1":
                    registry_control(winrm_session)
                elif choice == "2":
                    user_registry_control(winrm_session)
                elif choice == "3":
                    windows_services(winrm_session)
                elif choice == "4":
                    security_settings(winrm_session)
                elif choice == "5":
                    installed_software(winrm_session)
                elif choice == "6":
                    installed_software_32bit(winrm_session)
                elif choice == "7":
                    windows_firewall(winrm_session)
                elif choice == "8":
                    run_all_tasks(winrm_session)
                elif choice == "9":
                    print(Fore.RED + "Exiting program.")
                    return  # Exit the loop and stop the program
                else:
                    print(Fore.RED + "Invalid choice, please try again.")

        except Exception as e:
            print(f"Failed to connect to {IP_address}. Error: {e}")

if __name__ == "__main__":
    main()

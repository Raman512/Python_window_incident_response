# WinRM Remote System Info Gathering Script

This project contains a Python script that connects to remote Windows machines via WinRM (Windows Remote Management) and retrieves system information such as:
IP Configuration,User Accounts,System Services and Processes,File Sharing and Open Sessions,Active Ports and Firewall Configuration, Event Logs

The script reads a list of credentials (IP address, username, and password) from a text file and runs various commands to gather information from each system.
Features:

Retrieves IP configuration using :ipconfig /all
    
Lists user accounts with  : net user
    
Lists local groups with : net localgroup
    
Shows running tasks with :tasklist /svc
    
Displays system services with : net start
    
Fetches scheduled tasks with : schtasks
    
Queries the Windows registry for autostart applications Shows active TCP/UDP connections with:  netstat -ano
    
Lists shared files using : net view
    
Queries recent executable files : forfiles
    
Retrieves firewall configuration with : netsh
    
Lists network sessions with : net use and net session
    
Retrieves security log entries with:  wevtutil

Prerequisites:
  Python 3.x
  winrm Python library (You can install it with pip install pywinrm)
  A valid cred_list.txt file with IP addresses, usernames, and passwords for the target machines.

# Installation:

    Clone the repository: git clone https://github.com/Raman512/Python_window_incident_response.git

Install required Python packages:

    pip install pywinrm

Create a cred_list.txt file with the following format:

    <IP_address>|<username>|<password>

Run the script:

    python name_of_your_script.py

Example of cred_list.txt file format:

    192.168.1.100|admin|password123
    192.168.1.101|user|mypassword456

# Usage:

Ensure that WinRM is enabled and accessible on the remote machines.
The script will loop through each line in cred_list.txt, establish a connection, and run the predefined commands.
 The results will be printed to the console.

This script is for educational purposes only. Use it responsibly and with permission. Unauthorized access to systems is illegal and unethical.

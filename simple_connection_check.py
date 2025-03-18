import winrm

# Read the credentials from the file
with open('cred_list.txt', 'r') as f:
    lines = f.readlines()


for line in lines:
    fields = line.strip().split("|")
    IP_address = fields[0]
    user = fields[1]
    passw = fields[2]
    
    # Print the details
    print(f"Attempting to connect to {IP_address} as {user}...")

    # Create winrm session using  credentials
    try:
        # Use 'http' for unencrypted connection or 'https' if SSL is set up
        winrm_session = winrm.Session(f'http://{IP_address}:5985', auth=(user, passw), transport='ntlm')

        #Get IP configuration using 'ipconfig /all'
        print("IP Configuration:")
        result = winrm_session.run_cmd('ipconfig', ['/all'])
        print(result.std_out.decode('ascii'))



        # Check the output and errors
        print("Standard Error:")
        print(result.std_err.decode('ascii'))

    except Exception as e:
        # If there is an error, print it
        print(f"Failed to connect to {IP_address}. Error: {e}")

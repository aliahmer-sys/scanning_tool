# nmap_module.py

import subprocess

from config import nmap_command  # Import the path to theHarvester from config.py
# Function to fetch subdomains using Nmap
def fetch_subdomains_nmap(domain, nmap_options):
    """Fetch subdomains using Nmap with a full list of options."""
    print(f"Fetching subdomains for {domain} using Nmap...")

    command = [nmap_command, '-p', '53', '--script', 'dns-brute', domain] + nmap_options  # DNS brute force script for subdomains

    try:
        # Run the Nmap command and capture the output
        output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode()
        subdomains = []

        # Parse the output and extract subdomains
        for line in output.split('\n'):
            if 'Nmap scan report for' in line:
                subdomain = line.split(' ')[-1]
                subdomains.append(subdomain)

        return subdomains
    except subprocess.CalledProcessError as e:
        print(f"Error fetching subdomains with Nmap: {e.output.decode()}")
        return []  # Return an empty list in case of error

# Function to perform a basic port scan using Nmap
def port_scan(target, nmap_options):
    """Scan ports for a target using Nmap with full list of options."""
    print(f"Scanning ports for {target} using Nmap...")
    nmap_command = '/opt/homebrew/bin/nmap'  # Adjust the Nmap path as needed

    # Default command for port scan
    command = [nmap_command] + nmap_options + [target]

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode()
        print("Port Scan Results:")
        print(output)  # Print the Nmap scan results
    except subprocess.CalledProcessError as e:
        print(f"Error during port scanning: {e.output.decode()}")

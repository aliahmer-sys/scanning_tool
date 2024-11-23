# main.py

import subprocess
from config import THEHARVESTER_PATH  # Import the path to theHarvester from config.py

# Function to fetch subdomains using theHarvester
def fetch_subdomains_theharvester(domain):
    """Fetch subdomains using theHarvester."""
    print(f"Fetching subdomains for {domain} using theHarvester...")

    # Now use the path from the config file
    command = ['python3', THEHARVESTER_PATH, '-d', domain, '-b', 'all']

    try:
        # Run the command and capture the output
        output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode()
        subdomains = []

        # Parse the output and extract subdomains
        for line in output.splitlines():
            if 'Subdomain' in line:
                subdomain = line.split(':')[-1].strip()
                subdomains.append(subdomain)

        return subdomains

    except subprocess.CalledProcessError as e:
        print(f"Error fetching subdomains with theHarvester: {e.output.decode()}")
        return []  # Return an empty list in case of error

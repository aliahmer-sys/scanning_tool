# main.py

import os
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
import re
from nmap_module import fetch_subdomains_nmap, port_scan  # Import from nmap_module
from theharvester_module import fetch_subdomains_theharvester  # Import from theharvester_module
# Function to fetch emails from the domain and its subdomains
def fetch_emails(domain, max_depth=2, max_workers=10):
    """Fetch emails by crawling the domain and its links."""
    print(f"Fetching emails from the main domain {domain}...")
    visited_urls = set()  # Keep track of visited URLs to avoid revisits
    emails = set()  # Set to store emails

    def crawl(url):
        """Crawl the URL and return a list of emails found."""
        if url in visited_urls:
            return []  # Skip if already visited
        visited_urls.add(url)

        try:
            response = requests.get(url, timeout=10)  # Timeout for requests
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'xml')  # Parse the page content with BeautifulSoup

            # Use regex to extract emails from the page content
            found_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
            return found_emails
        except requests.HTTPError as e:
            print(f"HTTP error fetching emails from {url}: {e}")
            return []
        except requests.RequestException as e:
            print(f"Error fetching emails from {url}: {e}")
            return []

    def extract_links(url):
        """Extract all valid HTTP(S) links from a URL."""
        links = []
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'xml')

            # Loop through all 'a' tags and extract valid URLs
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('/'):
                    href = f'https://{domain}{href}'  # Convert relative links to absolute links
                elif not href.startswith('http'):
                    continue  # Skip non-HTTP links

                # Avoid URLs related to login or signup pages
                if 'login' in href or 'signup' in href or 'signin' in href:
                    continue

                if domain in href:
                    links.append(href)

        except requests.RequestException as e:
            print(f"Error extracting links from {url}: {e}")

        return links

    # Start with the main domain and crawl links
    urls_to_crawl = [f'https://{domain}']
    emails_collected = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        while urls_to_crawl and max_depth > 0:
            current_urls = urls_to_crawl[:]
            urls_to_crawl = []

            # Use ThreadPoolExecutor to crawl multiple URLs concurrently
            futures = {executor.submit(crawl, url): url for url in current_urls}
            for future in as_completed(futures):
                collected_emails = future.result()
                emails_collected.extend(collected_emails)

                # Extract new links to crawl
                new_links = extract_links(futures[future])
                urls_to_crawl.extend(new_links)

            max_depth -= 1  # Decrement depth after each crawl round

    # Update the main email set with collected emails
    emails.update(emails_collected)

    if emails:
        print(f"Emails found: {', '.join(emails)}")
    else:
        print("No emails found on the site.")

    return list(emails)  # Return the collected emails


# Function to perform NS lookup for a domain (to find Name Servers)
def ns_lookup(domain):
    """Perform NS Lookup to retrieve Name Servers."""
    print(f"Performing NS Lookup for {domain}...")

    try:
        result = dns.resolver.resolve(domain, 'NS')  # Perform NS lookup
        print("Name Servers:")
        for ns in result:
            print(ns.to_text())  # Print each Name Server
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"No NS records found for {domain}")
    except dns.exception.DNSException as e:
        print(f"Error during NS Lookup: {e}")

    # Optionally try the parent domain if no results found
    if '.' in domain:
        parent_domain = domain.split('.', 1)[1]  # Get the parent domain (e.g., example.com)
        print(f"\nTrying parent domain: {parent_domain}...")
        try:
            result = dns.resolver.resolve(parent_domain, 'NS')
            print("Name Servers for parent domain:")
            for ns in result:
                print(ns.to_text())
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"No NS records found for {parent_domain}")
        except dns.exception.DNSException as e:
            print(f"Error during NS Lookup for {parent_domain}: {e}")


# Main function to handle user interaction and execute tasks
def main():
    while True:  # Infinite loop for user interaction
        # Display menu options
        print("\nSelect an option:")
        print("1. Network Scan")
        print("2. Email and Subdomain Harvesting with Nmap")
        print("3. Email and Subdomain Harvesting with theHarvester")
        print("5. Nslookup")
        print("6. Exit")

        choice = input("Enter your choice (1/2/3/5/6): ")

        # Handle Nmap options
        nmap_options = []

        if choice in ['1', '2']:  # Network Scan or Email/Subdomain Harvesting with Nmap
            print("\nSelect the type of Nmap scan:")
            print("1. SYN Scan (default) [-sS]")
            print("2. Version Detection [-sV]")
            print("3. OS Detection [-O]")
            print("4. Script Scan (e.g., dns-brute) [--script=dns-brute]")
            print("5. Top 100 Ports Scan [--top-ports 100]")
            print("6. Fast Scan [-T4 --top-ports 100]")

            scan_choice = input("Enter your choice (1/2/3/4/5/6): ")

            if scan_choice == '1':
                nmap_options = ['-sS']
            elif scan_choice == '2':
                nmap_options = ['-sV']
            elif scan_choice == '3':
                nmap_options = ['-O']
            elif scan_choice == '4':
                nmap_options = ['--script=dns-brute']
            elif scan_choice == '5':
                nmap_options = ['--top-ports', '100']
            elif scan_choice == '6':
                nmap_options = ['-T4', '--top-ports', '100']
            else:
                print("Invalid choice. Using default SYN scan.")
                nmap_options = ['-sS']

        # Handle user choice
        if choice == '1':
            domain = input("Enter the target domain (e.g., example.com): ")
            port_scan(domain, nmap_options)
        elif choice == '2':
            domain = input("Enter the target domain (e.g., example.com): ")
            subdomains = fetch_subdomains_nmap(domain, nmap_options)
            print("Subdomains found with Nmap:")
            for subdomain in subdomains:
                print(subdomain)
            emails = fetch_emails(domain)
            print("Emails found:")
            for email in emails:
                print(email)
        elif choice == '3':
            domain = input("Enter the target domain (e.g., example.com): ")
            subdomains = fetch_subdomains_theharvester(domain)
            print("Subdomains found with theHarvester:")
            for subdomain in subdomains:
                print(subdomain)
            emails = fetch_emails(domain)
            print("Emails found:")
            for email in emails:
                print(email)
        elif choice == '5':
            domain = input("Enter the target domain (e.g., example.com): ")
            ns_lookup(domain)
        elif choice == '6':
            print("Exiting the program.")
            break  # Exit the loop and end the program
        else:
            print("Invalid choice, please try again.")

        input("\nPress any key to continue or Ctrl+C to exit.")


# Main entry point of the program
if __name__ == "__main__":
    main()  # Run the main function when the script is executed

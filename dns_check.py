import subprocess
import re
import argparse
from termcolor import colored

def check_record(command, record_type, verbose):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout.strip()
        
        record_exists = any(re.search(pattern, output, re.IGNORECASE) for pattern in ["v=spf1", "v=DMARC1", "v=DKIM"])
        
        if record_exists:
            print(colored(f"{record_type} record exists!", "green"))
        else:
            print(colored(f"No {record_type} record found.", "red"))
        
        if verbose:
            print(output)
    except Exception as e:
        print(colored(f"Error checking {record_type} record: {str(e)}", "red"))

def load_domains(domain_source):
    try:
        with open(domain_source, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(colored(f"Error loading domain list: {str(e)}", "red"))
        return []

def main(domains, spf, dmarc, dkim, verbose):
    for domain in domains:
        print(f"Checking records for domain: {domain}")
        if spf:
            check_record(f"nslookup -type=txt {domain}", "SPF", verbose)
        if dmarc:
            check_record(f"nslookup -type=txt _dmarc.{domain}", "DMARC", verbose)
        if dkim:
            check_record(f"dig txt selector1._domainkey.{domain}", "DKIM", verbose)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS record checker for SPF, DMARC, and DKIM.")
    parser.add_argument("domains", nargs="*", help="Domain(s) to check")
    parser.add_argument("-f", "--file", help="File containing a list of domains to check")
    parser.add_argument("-s", "--spf", action="store_true", help="Check SPF records")
    parser.add_argument("-d", "--dmarc", action="store_true", help="Check DMARC records")
    parser.add_argument("-k", "--dkim", action="store_true", help="Check DKIM records")
    parser.add_argument("-V", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    domains = args.domains if args.domains else []
    
    if args.file:
        domains.extend(load_domains(args.file))
    
    if not domains:
        print(colored("No domains provided to check.", "red"))
    elif not (args.spf or args.dmarc or args.dkim):
        print(colored("No record types specified. Please select at least one record type to check (-s, -d, -k).", "red"))
    else:
        main(domains, args.spf, args.dmarc, args.dkim, args.verbose)

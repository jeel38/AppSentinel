import requests
import argparse
import sublist3r

def get_subdomains(domain):
    try:
        subdomains = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        return subdomains
    except Exception as e:
        print(f"Error fetching subdomains for {domain}: {e}")
        return []

def check_status(subdomains):
    status_codes = {}
    for subdomain in subdomains:
        for protocol in ['http', 'https']:
            url = f"{protocol}://{subdomain}"
            try:
                response = requests.get(url, timeout=5)
                status_codes[subdomain] = response.status_code
                break  # Exit the loop if the request is successful
            except requests.exceptions.RequestException:
                status_codes[subdomain] = 'Error'
    return status_codes

def main(domains):
    results = {}
    for domain in domains:
        print(f"Finding subdomains for: {domain}")
        subdomains = get_subdomains(domain)
        print(f"Checking status codes for subdomains of: {domain}")
        status_codes = check_status(subdomains)
        results[domain] = {sub: status for sub, status in status_codes.items() if status != 'Error'}
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find subdomains and check their status codes.')
    parser.add_argument('domains', metavar='D', type=str, nargs='+', help='a list of domains to check')
    args = parser.parse_args()
    
    results = main(args.domains)
    for domain, subdomains in results.items():
        print(f"Results for {domain}:")
        for subdomain, status in subdomains.items():
            print(f"  {subdomain}: {status}")

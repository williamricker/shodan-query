import os
import json
import urllib.request
import shodan
import sys
from dotenv import load_dotenv

def load_api_key():
    load_dotenv()
    return os.getenv('SHODAN_API_KEY')

def get_target_ip():
    return input("Enter Target IPv4 Address: ").strip()

def lookup_host(api, target_ip):
    try:
        return api.host(target_ip)
    except Exception as e:
        print(e)
        sys.exit(1)

def print_general_info(host):
    print("""
        IP: {}
        Organization: {}
        Host Names: {}
    """.format(host['ip_str'], host.get('org', 'n/a'), host.get('hostnames', 'n/a')))

def fetch_kev_data():
    json_url = urllib.request.urlopen("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    kev_data = json.loads(json_url.read())
    return kev_data.pop("vulnerabilities")

def create_vuln_dictionary(vulnerabilities):
    vuln_dictionary = {}
    for vuln in vulnerabilities:
        cve_id = vuln.get('cveID')
        vuln_dictionary.update({cve_id: vuln})
    return vuln_dictionary

def check_for_kev(host, vuln_dictionary):
    for item in host['vulns']:
        if item in vuln_dictionary:
            return True
    return False

def print_kev_info(host, vuln_dictionary):
    print("The host may be impacted by the following Known Exploited Vulnerabilities identified by CISA: ")
    print("")
    for item in host['vulns']:
        if item in vuln_dictionary:
            kev_item = vuln_dictionary.get(item)
            print(item)
            print("Vulnerability Name: " + kev_item.get('vulnerabilityName'))
            print("Description: " + kev_item.get('shortDescription'))
            print("")

def print_other_vulns(host):
    print("Host may still contain other vulnerabilities, including the following:\n")
    for item in host['vulns']:
        print(item)
    print("\nBest of luck!")

def main():
    shodan_key = load_api_key()
    api = shodan.Shodan(shodan_key)
    target_ip = get_target_ip()
    host = lookup_host(api, target_ip)
    
    print_general_info(host)

    if 'vulns' not in host or len(host['vulns']) == 0:
        print("No vulnerabilities have been identified on this host.")
        sys.exit(0)

    vulnerabilities = fetch_kev_data()
    vuln_dictionary = create_vuln_dictionary(vulnerabilities)

    if check_for_kev(host, vuln_dictionary):
        print_kev_info(host, vuln_dictionary)
    else:
        print("No 'Known Exploited Vulnerabilities' were identified on the host.")
    
    print_other_vulns(host)

if __name__ == "__main__":
    main()
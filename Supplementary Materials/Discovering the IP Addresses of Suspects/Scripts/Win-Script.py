import subprocess
import requests
import whois
import os
import msvcrt  # Microsoft Visual C++ Runtime, for Windows-specific operations

def get_char():
    return msvcrt.getch().decode()

def is_private_ip(ip):
    return ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.")

def fetch_ripe_info(ip):
    url = f"https://stat.ripe.net/data/whois/data.json?resource={ip}"
    try:
        print(f"Fetching RIPE data for IP: {ip}...")
        response = requests.get(url, timeout=5)
        data = response.json()
        records = data['data']['records'][0]
        result = "\n".join(f"{item['key'].title()}: {item['value']}" for item in records if item['key'] in ['inetnum', 'netname', 'descr', 'country', 'status', 'mnt-by', 'created'])
        return result if result.strip() else "No RIPE data available."
    except (requests.RequestException, KeyError, IndexError):
        return "No RIPE data available."

def fetch_whois_info(ip):
    try:
        w = whois.whois(ip)
        info = f"\nDomain: {w.domain_name}\nRegistrar: {w.registrar}\nUpdated Date: {w.updated_date}\nCreation Date: {w.creation_date}\nExpiration Date: {w.expiration_date}\nEmails: {w.emails}"
        return info.strip()
    except Exception as e:
        return "Failed to fetch data from Whois."

def analyze_traffic(interface):
    print("Starting live capture on interface " + interface)
    cmd = [
        'tshark', 
        '-i', interface, 
        '-a', 'duration:60', 
        '-Y', "(ip.dsfield.dscp == 46 && ip.flags.df == 1) || (stun && frame.len == 86 && stun.type == 0x0001)", 
        '-T', 'fields', 
        '-e', 'ip.src', 
        '-e', 'ip.dst'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    full_output = []

    if result.returncode == 0 and result.stdout:
        lines = result.stdout.strip().split('\n')
        ips = set(ip.strip() for line in lines for ip in line.replace(',', ' ').split() if ip)
        private_ips = {ip for ip in ips if is_private_ip(ip)}
        public_ips = ips - private_ips

        print("\nPrivate IP addresses found:")
        for ip in sorted(private_ips):
            print(ip)
        print("\nPublic IP addresses found:")
        for ip in sorted(public_ips):
            print(ip)

        user_input = input("\nFetch more information from RIPE/Whois databases? (Y/N): ")
        if user_input.lower() == 'y':
            for ip in sorted(public_ips):
                ripe_data = fetch_ripe_info(ip)
                if ripe_data:
                    print(f"\nFetching data for IP: {ip}\n{ripe_data}")
                    full_output.append(f"Data for IP: {ip}\n{ripe_data}")
                else:
                    whois_data = fetch_whois_info(ip)
                    print(f"\nFetching data for IP: {ip}\nNo data available from RIPE. Checking Whois...\n{whois_data}")
                    full_output.append(f"Data for IP: {ip}\nNo data available from RIPE. Checking Whois...\n{whois_data}")

        print("Do you want to save this data to a file? (Y/N): ", end='')
        save_input = input()
        if save_input.lower() == 'y':
            filepath = os.path.join(os.path.expanduser('~'), 'Downloads', 'Suspect_IP_analysis.txt')
            with open(filepath, "w") as file:
                file.write("\n".join(full_output))
            print(f"Data saved to '{filepath}'.")

    else:
        print("No data to process or an error occurred:", result.stderr)

if __name__ == "__main__":
    analyze_traffic('4')

#!/usr/bin/env python3

import subprocess
import requests
import whois
import os
import termios
import tty
import sys

def get_char():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

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
        return result if result.strip() else None
    except requests.RequestException:
        return None
    except KeyError:
        return None

def fetch_whois_info(ip):
    try:
        w = whois.whois(ip)
        info = f"\nDomain: {w.domain_name}\nRegistrar: {w.registrar}\nUpdated Date: {w.updated_date}\nCreation Date: {w.creation_date}\nExpiration Date: {w.expiration_date}\nEmails: {w.emails}"
        return info.strip()
    except Exception as e:
        return "Failed to fetch data from Whois."

def analyze_traffic():
    print("Starting the analysis...")
    cmd = ['tshark', '-r', 'traffictest.pcap', '-Y', "(ip.dsfield.dscp == 46 && ip.flags.df == 1) || (stun && frame.len == 86 && stun.type == 0x0001)", '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst']
    result = subprocess.run(cmd, capture_output=True, text=True)
    full_output = []

    if result.returncode == 0 and result.stdout:
        lines = result.stdout.strip().split('\n')
        ips = set(ip.strip() for line in lines for ip in line.replace(',', ' ').split())
        private_ips = {ip for ip in ips if is_private_ip(ip)}
        public_ips = ips - private_ips

        full_output.append("Private IP addresses found:")
        full_output.extend(sorted(private_ips))
        full_output.append("\nPublic IP addresses found:")
        full_output.extend(sorted(public_ips))

        print("\n".join(full_output))
        print("\nFetch more information from RIPE/Whois databases? (Y/N): ", end='', flush=True)
        user_input = get_char()
        print(user_input)

        if user_input.lower() == 'y':
            for ip in sorted(public_ips):
                ripe_data = fetch_ripe_info(ip)
                if ripe_data:
                    ip_info = f"\nFetching data for IP: {ip}\n{ripe_data}"
                else:
                    whois_data = fetch_whois_info(ip)
                    ip_info = f"\nFetching data for IP: {ip}\nNo data available from RIPE. Checking Whois...\n{whois_data}"
                print(ip_info)
                full_output.append(ip_info)

            print("Do you want to save this data to a file? (Y/N): ", end='', flush=True)
            save_input = get_char()
            print(save_input)
            if save_input.lower() == 'y':
                with open(os.path.expanduser("~/Desktop/Suspect_IP_analysis.txt"), "w") as file:
                    file.write("\n".join(full_output))
                print("Data saved to 'Suspect_IP_analysis.txt' on Desktop.")
    else:
        print("No data to process or an error occurred:", result.stderr)

if __name__ == "__main__":
    analyze_traffic()


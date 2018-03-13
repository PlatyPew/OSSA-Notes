# OSSA Notes by PlatyPew
Organizational Systems Security Analyst notes and assets

How to pass OSSA by nmap-ing & Ctrl-F'ing everything

USE 1337 HAXXXORZ SKILLZ 2 HAX INTO JAVASCRIPT SERVERS RUNNIN C++ IN PYTHON 6 USIN MALWARE CRACKIN WIFI

# Content Page
1. [What Is Information Security?](#what-is-information-security)
	- [Cybertacks](#cybertacks)
	- [Basic Security Concepts](#basic-security-concepts)
	- [The 8-Step Security Gameplan™](#the-8-step-security-gameplan)
2. [Defending Your Turf & Security Policy Formulation](#defending-your-turf--security-policy-formulation)
	- [Security Policy Formulation & Defending Your Turf](#security-policy-formulation--defending-your-turf)
	- [Defending Your Turf: This LANd is Mine](#defending-your-turf-this-land-is-mine)
3. [Network 101](#network-101)
	- [Networking Protocols From A Security Viewpoint](#networking-protocols-from-a-security-viewpoint)
	- [ARP: Tying Frames & IP Together](#arp-tying-frames--ip-together)
	- [Layer 4: TCP and UDP](#layer-4-tcp-and-udp)
	- [DNS: I can't remember your IP...](#dns-i-cant-remember-your-ip)
4. [Defensive Tools & Lockdown](#defensive-tools--lockdown)
	- [Firewalls](#firewalls)
	- [NIDS](#nids)
	- [HIDS & File-Integrity Checkers](#hids--file-integrity-checkers)
	- [Honeypots](#honeypots)
	- [Cryptography](#cryptography)
5. [The 5E Attacker Methodology](#the-5e-attacker-methodology-for-penestration-testing)
	- [Preparation & Tool Repositories](#preparation--tool-repositories)
	- [Exploration](#exploration)
	- [Enumeration](#enumeration)
	- [Exploitation](#exploitation)
	- [Embedding](#embedding)
	- [Egress](#egress)
6. [Wireless (In)security](#wireless-insecurity)
7. [Incident Response & Computer Forensics](#incident-response--computer-forensics)
	- [Incident Response Framework](#incident-response-framework)
	- [Computer Forensics Introduction](#computer-forensics-introduction)
	- [Forensics Analysis: Information Gathering From Other Sources](#forensics-analysis-information-gathering-from-other-sources)
8. [The Impact of Law](#the-impact-of-law)
	- [Why You Need To Know](#why-you-need-to-know)
	- [The State Of Cybercrime Law](#the-state-of-cybercrime-law)
	- [Issues with Enforcement](#issues-with-enforcement)
	- [When To Enforce](#when-to-enforce)

[**Command Cheatsheet**](#command-cheatsheet)

# What is Information Security?

## Cybertacks
**Origins**
1. The Curious
	- Found tool online and randomly picked IP address to test
2. The Malicious
	- Doesn't like a certain individual or organisation
3. The Criminal
	- Attacking others for money
4. The Competitor
	- Attacking other businesses competing with you in same industry
5. The Natural
	- Natural disasters may cause DoS
6. The Politically-charged
	- Governments don't like each other

**Security Myths**
- Non-Windows operating systems are more secure
- Hackers are needed to protect us
- Firewalls, anti-virus & other security technologies are enough
- More security spending = more secure
- Lock icon (HTTPS) means I am secure

## Basic Security Concepts
**IT-Security concept**
- Confidentiality
	- How to prevent others from finding out about it
	- Encryption
- Integrity
	- Keeping date and platforms in a state of "wholeness"
	- Checksum/Hash
- Availability
	- Notion of maintaining on-demand accessibility


**Defining Security**

In real world, IT-Security does not exist for IT-security's sake.
The SOB Troika applies for real world
- Security
- Operations
- Business

**Trust and verify, ask the Oracle**

Google Hacks:

- `site:` Limits results to particular site
- `filetype:` Limits results to a particular file type
- `intitle:` Limits results to searching for keywords in title of the page
- `allintext:` Limits results to searching for keywords in the title of the page
- `loc:` Limits results to particular geographical location
- `ip:` Limits results to particular IP address

## The 8-Step Security Gameplan™ 
A high-level summary framework to guide through general execution of a security implementation

1. Identify Centres of Gravity
	- What needs to be protected?
	- Baseline (The bare minimum to protect)
	- Consequences of threat (What happens if being attacked?)
2. Understand the Threats
	- Requires understanding of threats
	- Segregate threats
		- Internal/External
		- Natural/Man-made
	- Imagine being the hacker (How would **_I_** hack myself)
3. Gather Information from Stakeholders
	- Identify assets you wish to protect
	- Inform parties that changes may likely cause impact
	- On-going dialogue refines and develops plan
4. Develop Baselines
	- Conduct baselining sessions of normal operations
	- Makes detection of anomalies easier and more apparent
5. User and Corporate Education
	- Humans are weakest link
	- Explain rationale for proposals
	- Convince management
		- Security benefits
		- Cost-savings
		- Increase productivity
		- etc.
6. Establish Platform Defense
	- Setup defensive procedures and emplace defensive platforms
	- Understand how attackers may try to circumvent defensive mechanisms put in place
7. Establish Business Continuity and Disaster Recovery
8. Maintain Balance
	- Highlight evolving challenges and problems
	- Undertake applicability reviews (Are plans developed 2 years ago still relevant?)
	- Spot checks and surprise "blind" testing
	- Patch!
	- Does it comply with the law?

# Defending Your Turf & Security Policy Formulation

## Security Policy Formulation & Defending Your Turf
**The 4Ps of Defence**
- Policies
	- Define direction a company is going to achieve whatever goals it states in the policy
- Procedures
	- Setup to detail the steps, standards and workflow necessary to achieve milestones needed to ensure policy is compiled with
- Platforms
	- Technical hardware & software are deployed to support the delivery and fulfilment of procedures
- People
	- **People** operate **Platforms** dictated by **Procedures** to attain and be compliant to the **Policies**

## Defending Your Turf: This LANd is Mine
1. Vulnerability Identification
	- Identify both technical and non-technical issues in order to be able to identify areas which needs attention
2. Platform Lockdown
	- Principle of least privilege applies
	- Deploy Triple-A
		- Authentication
		- Authorisation
		- Accounting
3. Monitor the Setup
	- Implement Management Overlay to keep track of traffic, access, user numbers etc.
	- Check if network is protected
4. Damage Control
	- If breach is detected, implement containment procedures
	- Limit fallout and contain damage
	- Forensics afterwards

# Network 101

## Networking Protocols From A Security Viewpoint

**OSI 7-Layer model**

- Physical
- Data-link
- Network
- Transport
- Session
- Presentation
- Application

**Layer 2 Frames**

- An envelope containing a letter, it has an address and some content inside
- Holds MAC addresses of sending and receiving network adapter

Sniff traffic when wired network uses a switch

1. Flood switch's content addressable memory (CAM) with fake MAC address entries (Macof)
2. CAM has been crowded and switch is unable to determine legit MAC addresses
3. Switch forwards all frames out of every port in an attempt to get a frame to its destination
4. ARP poisoning also possible (Ettercap-ng)

**Layer 3 IP**

IP gets packet from point A to point B

No prior-established connection between sender and recipient. Relies on upper layer protocols to ensure delivery and re-assemble the IP packets in the right order to the correct destination

**IP TTL values identify OS stack**

- `TTL: 128` Windows
- `TTL: 64` Linux

**Private addresses to stem IPv4 address-exhaustion**

Private IP ranges allows for spoofed DoS attacks. (As long as there is NAT because it's not routable)

**IP Broadcast allows Amplification Attacks**

1. Spoof as victim's IP
2. Send a broadcast packet with a payload size of 32KB
3. Packet hits gateway router and is broadcast to everybody
4. Everybody replies with 32KB to victim IP
5. Victim is overwhelmed and thus amplification attack has occurred

## ARP: Tying Frames & IP Together

Used to find out which MAC address has which IP

Problems with ARP
- No way of telling if information contained in ARP reply is legit
- Therefore, attacker can send unsolicited ARP replies telling that the IP address for a particular host is held by the attacker's MAC address
- This populates the ARP cache, and poisons itself
- This can be used to "insert" oneself between the poisoned hosts (Man in the Middle Attack)

Routing
- Route a packet to the internet through the gateway
- Data sent from host-to-host, host-to-router router-to-router

**ICMP**

- Internet Control Message Protocol
- Contains
	- Time-exceeded
	- Destination-unreachable
	- Source-quench
	- Redirect

## Layer 4: TCP and UDP

**Layer 4 TCP**

3-way handshake (A is client and B is other device)
- `SYN` (A to B)
- `SYN/ACK` (B to A)
- `ACK` (A to B)
- Connection is established and data can be transferred
- Attacks
	- Exploit by never sending ACK to complete the handshake
	- Send more SYN packets so target keeps assigning more memory to hold open and incomplete handshakes
	- May run out of memory space

4-way termination (A is client and B is other device)
- `FIN/ACK` (B to A)
- `ACK` (A to B)
- `FIN/ACK` (A to B)
- `ACK` (B to A)
- Attacks
	- FIN-flagged packets can be used to bypass if firewall stops SYN-flagged
	- Default reaction to FIN packet is to terminate an existing connection using 4-way termination described above.
	- With no existing connection to FIN, host sends a RST packet
	- Firewalls may not be so strict on FIN packets as because it may presume that it is part of an already existing connection

**Layer 4 UDP**

- Unified Datagram Protocol (UDP)
- "Best effort" delivery
- Used where speed is required
	- Games
	- Video Streaming
	- Calls
- Target with no service residing behind UDP port that receives UDP packet will send back an ICMP Port Unreachable packet
- In all other scenarios, no reply will be give (Looks like it is being filtered by a firewall)

## DNS: I can't remember your IP...

People cannot remember IP addresses

Normal DNS query
- What is IP of secure.com? (Client to ISP's DNS server)
- If no cache, ask the .com root server who is Authoritative Name Server for secure.com (ISP's DNS to secure.com DNS)
- secure.com is at xxx.xxx.xxx.xxx (secure.com DNS to ISP's DNS)
- secure.com is at xxx.xxx.xxx.xxx (ISP's DNS to client)
- 3-way handshake to xxx.xxx.xxx.xxx (Client to secure.com)

DNS Poisoning
- Attacker sends link to victim with a domain controlled by him
- Victim machine queries ISP's DNS which queries attacker's DNS
- Attacker's DNS returns IP as well as fake IP of legitimate site
- This poisons the DNS cache as any users who want to access the site will be redirected to the fake IP
- Patched version
	- Launching a MITM at any point along the path of transmission of the DNS response from the ISP's DNS server to the client making the request and rewriting the contents of the response, attacker can still perform DNS poison

# Defensive Tools & Lockdown

## Firewalls

Can have multiple forms
- Appliance
	- Firmware code on dedicated hardware platform
- Software
	- Installed on server as point defence
- Personal
	- For workstations and individuals

**Firewall Type: Packet Filter**
- Sits between internal network and the rest of the world
- Packet filter compares the packet to a set of filter rules. Decides to forward or discard packet.
- Avoid sending messages by configuring firewall to silently drop all packets that does not match its permit rules
- Comparison involves
	- Source address
	- Source port
	- Destination address
	- Destination port

Characteristics
- Fast performance (No data checking required)
- Often "plug and play"
- Network Address Translation (NAT) and Network Address Port Translation act as security "feature" (Not intended to)
- Compatible to nearly all applications

**Firewall Type: Stateful Packet Inspection (SPI)**
- Stateful packet filters keep some state about each connection passing through hem
- Built-in knowledge about TCP/IP's rules for data flow
- Can detect incorrectly sequence-numbered packets and inconsistent IP protocol options
- Examples
	- Attackers can send packets from port 80 on the attacker's machine which would pass right through the firewall
	- SPI firewalls can reject these unsolicited packets
	- Mitigates DoS (SYN floods)
	- Tracks established connections and allows inbound packets based on the established state
	- Relatively fast

**Firewall Type: Application Proxy**
- Proxies break up the connection between the client and the server
- To the server, proxy pretends to be the client
- To the client, proxy pretends to be the server
- Masks IP stack and characteristics of the server it is protecting

Characteristics
- If attacker tries to work with fragmented packets or fields in the IP packet, internal server will never see it
- Can understand application-specific data in the protocol
- Can check the legality of traffic between client and server
	- Can check HTTP GET command before passing it on to the server
- It is application specific (Not compatible with other applications)

**Firewall Type: Proxy Firewall**
- Not only protects network stack, but can perform payload-level inspection
- Combines stateful inspection technology, proxying and application-protocol-awareness

Characteristics
- Still works like a proxy. Examines packets in between 2 connections
- Interrogate the behaviours and logic of what is requested and returned
	- Web-app firewall (WAF) protects against web attacks
		- SQL injection
		- XSS
		- etc.

**Firewall TCP and UDP replies**

TCP
- `ACK` Open: Host, Port & IP up
- `RST` Closed: Host up, Port & IP down
- `xxx` Filtered: Firewall up

UDP
- If payload does not match up, UDP will not reply
- If no UDP service, shows `ICMP port unreachable`

**Firewall Rules of Thumb**
- Block Inbound (Ingress): Obviously
- Block Outbound (Egress): Legal reasons
- Implicit Deny-All: Safety reasons

**Firewall Deployment**
- Internet to Firewall to DMZ (Filtering is the bare minimum)
- Internet to Firewall to LAN
- May cause rule confusion (Allow internet to access internal LAN)

## NIDS

- Monitors traffic on its network
- Capture all network traffic that crosses its network segment
- Involves looking at the packets
- Uses signatures
	- String signatures
		- Looks for text string that indicates a possible attack
	- Port signatures
		- Watches for connection attempts to well-know frequently attacked ports
	- Header condition signatures
		- Watches for dangerous or illogical combinations in packet headers
- Connect to the segment you want to be monitored
	- Hubs
	- Switch-port mirroring
	- Active taps
- Example
	- Snort

## HIDS & File-Integrity Checkers

- Can only monitor certain types of systems
- Does not have access to core communication functionality (Cannot fend off attacks against the protocol stack itself)
- Can only tell you after something has happened
- EXPEN$IVE
- Examples
	- Tripwire
	- OSSEC HIDS
	- AIDE
	- File Checksum Integrity Verifier (FCIV)

## Honeypots
- Set to detect or deflect unauthorised use of information systems
	- Sugarcane: Setup as an open proxy (Not common nowadays)
	- Entraps: Buys time for SysAdmin to respond
- Seems to contain information or resources valuable to the attacker

**Low-interaction honeypot**
- Advantages
	- Plug-and-play simplicity
	- Easy to deploy and maintain
	- Minimal risk
	- Mitigate risk by containing attacker's activity
- Disadvantage
	- Log only limited information (Can only capture known activity)
	- Easier for attackers to detect a low-interaction honeypot

**High-interaction honeypot**
- Advantages
	- Capture intensive amounts of information
- Disadvantages
	- Increase the risk of the honeypot as attackers can use these real operating system to attack non-honeypot systems
	- More complex to deploy and maintain

**Common Error in Deploying Honeypots**
- Creating a contiguous range of fake hosts which have exactly the same characteristics
	- Attacker needs to only scan entire target range to identify honeypot
- Make each honeypot host as unique as possible

## Cryptography

Used to ensure confidentiality

**Types of ciphers**
- Transposition
	- Changes one character from the plaintext to another
	- Railfence cipher
- Substitution
	- Plaintext substituted with ciphertext
- Block
	- Symmetric key cipher which operates on fixed-length group of bits
	- AES
	- 3DES
- Stream
	- Plaintext digits encrypted one at a time, transformation of successive digits varies during encryption
	- CryptMT

**Uses of Cryptography**
- Proving integrity by hashing
	- Produces fixed length after calculating checksum of input
- Sending data using symmetric key encryption
	- Used to encrypt and decrypt data
- Remote networking using virtual private networking
	- Use symmetric key encryption to encrypt communications between 2 end points
	- Modes
		- Transport
			- AH
				- Ensure integrity of packet
				- Incompatible with NAT
			- ESP
				- Ensure confidentiality of packet
				- Client-to-site VPN
		- Tunnel
			- AH
			- ESP
				- Site-to-site VPN
- Sending data using public-key cryptography
	- Public Key used to encrypt
	- Private Key used to decrypt
- Proving identity using digital signatures
	- Used to authenticate digital information
- Ransomware

**Trust Standards: Public Key Infrastructure (PKI)**
- Arrangement which provides for third-party to vouch for their identities
- Public keys are typically in certs
- Can bot refer to Certificate Authority (CA) and related arrangements
- Enables users to authenticate each other
- Consists of
	- Client software
	- Server software
	- Certificate authority
	- Hardware (Tokens/Smart Cards)

**Encryption Software: GnuPrivacy Guard (GPG)**

# The 5E Attacker Methodology™ for Penetration-Testing
**Anatomy of an attack**
- Attacker's preparation & tool repositories
- Exploration
- Enumeration
- Exploitation
- Embedding
- Egress

**5E Attacker Methodology™**
- Exploration and Enumeration will take 90% of the time spent
- Must know what defences are in play before launching any attacks
- Used to guide between Vulnerability Assessment (VA) and Penetration Testing (PT)

## Preparation & Tool Repositories
**Preparation: Sandboxing**
- Must not be connected to production systems or networks
- Must be tightly controlled
- Check authenticity of tools (Hashsum)

## Exploration
First phase in an attacker's attempt to understand more about the target he intends to launch an attack against

- Human-driven approach: Use physical human effort and geographic placement
	- Social Engineering
	- Dumpster Diving
	- Physical violation
- Computer-aided approach: Using the internet and other public technical resources to obtain the desired information
	- Scoping out
		- Forums
		- Technical Help postings
		- Electronic Bulletin Boards
	- Domain Registrars and WHOIS
	- DNS Servers
		- Zone transfers
		- Reverse lookup

## Enumeration
- Wardriving
	- Find any unsecured wireless access points
- Wardialing
	- Scanning for modems to bypass firewalls
- Portscanning
- OS discovery
- Tracerouting
- Vulnerability assessment
	- Are listening services vulnerable
- Web-based vulnerability

**Procedure**
- Port-scan each target for lists of open, closed and filtered ports
- Attempt to identify the type of service behind each open port
- Attempt to determine if the application is vulnerable
- Identify Operating System
- Try to identify the routes into and out of a network topology

**Enumeration Tools**
- NMAP
- Unicornscan
	- Checks UDP ports
- Nessus
	- Checks for vulnerability
	- Check [CVEDetails](http://cvedetails.com)
- OpenVAS
- HTTPrint [Download](http://net-square.com/httprint.html)
	- Determine web application's type and version
- AMAP [Download](http://www.thc.org/thc-amap)
	- Identifies applications listening on a port
- Online tests
	- http://alpha.hackerwhacker.com/freetools.php (Traceroute check for open port)
	- http://t1shopper.com/tools/port-scan (Allows lists of ports to scan)
	- http://serversniff.net (Webserver, namserver, etc.)
	- http://mxtoolbox.com (Mailserver checks)
	- http://subnetonline.com (Fun stuff?)
- Brain, Logic and Common Sense

## Exploitation
Try to gain control over the target via weakness found in enumeration
- Read-made tools
- Exploit-code compilation
- Techniques & Methods
- Self-crafted tools or 'sploits

**Exploitation: Spoofing & MITM**
- Assuming somebody's or something's identity
- Hide true identity
- Confuse incident handlers & investigators
- Insertion between an established connection or data flow
- Arp Poisoning
	- Attacker sends an ARP packet stating that the IP is the attacker's MAC address
	- Attacker arp poisons both victim and gateway
		- Target establishes SSL connection with Attacker
		- Attacker establishes SSL connection with actual server

**Exploitaiton: Denial of Service**
Attempting to disrupt the Availability component of the CIA Triad
- Send specially crafted packets to vulnerable applications
- Large amount of traffic consumes
	- CPU cycles
	- Network bandwidth
	- Memory
	- Storage

What makes DDoS Possible: Botnets and Zombies
- Launched from legions of compromised hosts
- 16 KB ICMP request multiply by 10000 hosts gets 1.28 Gbps traffic headed to single host
- Bot or zombie client is capable of performing a set of functions via commands issued from a zombie controller
- Bots or zombies may contain worm to spread itself
- Example
	- PhatBot

**Exploitation: Exploit Fundamentals**
- Buffer/Heap Overflows
	- Leads to execution of arbitrary code
- Shell Code
	- Assembly language used to launch programs
	- http://shell-storm.org/shellcode
- Format String Vulnerability
	- Sloppy programming
- Metasploit Framework (SKIDDE)

**Exploitation: Web Applications**
- Web-recon tools
	- Netcat
	- Stunnel (SSL)
	- HTTPrint
- Web-fuzzing tools
	- Spike Proxy
	- Webscarab
	- Crowbar
	- JBroFuzz
- Web-interception tools:
	- Achilles
	- Paros
	- Burp Proxy
	- SSLstrip
- Web-session management checking tools
	- CookieDigger

Web Server vs Web Applications
- Web Server
	- Network service that serves up content residing either on the web server or behind it
	- Examples
		- Apache
		- IIS
- Web Application
	- Customised content, modules or functionality
	- Examples
		- Intranet login portals
		- Search forms

OWASP Top 10
1. Unvalidated input
2. Broken access controls
3. Broken authentication & session management
4. Cross-site scripting
5. Buffer overflows
6. Injection flaws
7. Improper error handling
8. Insecure storage
9. Application denial of service
10. Insecure configuration management

**Exploitation: Password Cracking**
- Cracking Windows Passwords: SAM Database
	- Lan Manger
	- Windows NTLM

How to crack passwords
- Rainbow crack
	- Computes all possible plaintext-ciphertext pairs in advance and stores them in the rainbow table files
	- One-time pre-computation to generate rainbow tables
- OPHCrack
	- Makes use of any combination of uppercase, lowercase & numbers

## Embedding
Used to retain access in case of future need

- Backdoors
	- Accessing a computer system or application that ts maintainers or users are usually not aware of
	- Regular protocols used to evade detection (ICMP, P2P, HTTP)
- Trojans
	- Grants admin-level control to an attacker
	- Examples
		- Assassin
		- Lanfiltrator
		- Beast
- Rootkits
	- Buries itself into host's operating system
	- Categories
		- Traditional
			- Replace critical OS executables
		- Kernel
			- Controlled by the kernel
			- Calls a kernel syscall
			- Hide files, directories, processes, network connections without modifying and system binaries
	- Defence
		- Checksum (Cannot work against kernel rootkits)
		- System.map
		- kern_check.c: `kern_check /path_to/System.map`
		- CheckIDT
		- check-ps (Detects hidden processes)
		- Kstat
		- samhain

## Egress
Cleaning up evidence that could indicate that the attacker was there
- File hiding
	- Linux
		- Use prefix `.` for file and directory
		- Use `ls -a` to view hidden files
	- Windows
		- Hidden attribute
			- Use `attrib +s +h` to hide file or directory
			- Use `dir /a` to view
		- Alternate Data Stream (ADS)
			- Use `type path_to\file > path_to\file:hiddenfile` to hide
			- Use `expand path_to\file:hiddenfile hiddenfile` to extract
			- Use `wmic process call create path_to\file:hiddenfile` to run
			- Use `dir /r` to view
			- Use `LADS.exe` to view
		- Advanced and persistent ADS
			- Use `type path_to\file > \\?\"path_to\file"\CON:"hiddenfile"` to hide
			- Use `wmic process call create \\?\"path_to\file"\CON:"hiddenfile"` to run
- Log modification/removal
	- Linux
		- Syslog does most logs in `/var/log`
		- Current login log: `/var/run/utmp`
		- Past login log: `/var/log/wtmp`
	- Windows
		- Windows NT-based systems `%SystemRoot%\System32\Config\`
		- Only have 60 seconds to remove log because auto shutdown if EventLog service goes down
- Executable removal
	- Secure delete (Eraser)

# Wireless (In)security

**WLAN Basics**

Types of WLAN
- Personal/SOHO
	- Open
	- WEP
	- WPA-PSK/WPA2-PSK
- Enterprise-level
	- WPA/WPA2
	- VPNoL

- Open WLAN
	- Allows anyone to connect
	- Typically used in hotspots
	- Can be used as jump-off points for attacks or other nasty/illegal activities
- WEP-encrypted WLANs
	- Protected using Wired-Equivalent Privacy
	- Uses 40/64 or 104/128 bit keys as standard
	- Uses Cyclic Redundancy Check
	- Uses Encryption Algorithm called RC4
- WPA-PSK/WPA2-PSK-encrypted WLANs
	- Wireless frames protected by encryption schema called WiFi Protected Access - Pre-shared Key
	- Uses TKIP in place of WEP
	- SSN for WPA-PSK
	- RSN for WPA2-PSK
- VPNoL (Virtual Private Network over LAN)
	- Uses VPN architecture riding at layer 3 over theWLAN

Problems with WLAN encryptions
- WEP takes as little as 5 mins
	- Steady flow of traffic
	- ARP-replay injected frame
- WPA-PSK/WPA2-PSK
	- Passphrase is dictionary-guessable
	- First 2 frames of 4-way handshake captured

Terms
- WarChalking
	- Tells you whether there's a free 802.11 service in the area
- Looking for free WLAN access

**Typical WLAN Deficiencies**

Common mistakes
- Not enabling frame-level encryption such as WPA/WPA2
- Using dictionary-based WPA-PSK passphrases
- Not turning off SSID broadcasts in Beacon Frames
- Not using MAC or IP address filtering
- Not segmenting the WLAN as a DMZ
- Not turning off unneeded AP services
- Leaving AP settings defaulted
- SSID defaulted
- Not minimising the RF emanations

# Incident Response & Computer Forensics

Incident Response (IR) are needed for the following reasons
- Ability to respond to incidents in a consistent, systematic manner
- Minimize impact to business due to damage, theft or DoS
- To better prepare for handling future incidents and to provide feedback for enhancing current security practices
- Proper handling of legal issues that might stem from an incident

## Incident Response Framework
- Incident Response Policy
	- Dictates the management's commitment to the scope
	Procedures are based on policies
- Incident Response Team Structure & services
	- Team Model
		- Centralised incident response team
			- Single Campus
		- Distributed incident response team
			- Multi-site
	- Staffing Model
		- Employee/In-house IR Team
		- Fully-outsourced IR Team
		- Partially-outsourced IR Team

Factors to consider employee/in-house or outsourced team
	- Need for 24/7 availability
	- Cost
	- Time
	- Organisation structure
	- etc.

**Incident Response Phases**
- Preparation
	- Policies & Procedures
		- Develop incident scenarios, DRP and BCP plans
		- Establish chain of commands and "hot button" list
		- Determine escalation thresholds and procedure
		- Determine P.R. and legal involvement
	- Communications & Facilities
		- Encryption software
		- Incident reporting mechanism
		- Secure storage facility
		- Pagers/handphones
		- "War" room
		- Offsite recovery centres
	- IR Kit (Hardware & software)
- Detection & Analysis
	- Indication
		- NIDS/HIDS
		- Anti Virus Software
		- File Integrity checkers
		- Third party monitoring service
		- Logs from OS, services or applications
		- Network device logs
		- Honeypot logs
		- Information on new vulnerabilities & exploits
		- Information on incidents at other sites
		- People from within the organisation
		- People from outside of your organisation
	- Analysis
		- Profile your network & systems NOW before any incident happens
		- Understanding normal behaviours
		- Perform event correlation between your different defences such as Firewall, NIDS
	- Incident Documentation
		- Start recording all facts
		- Document/recordings need to be timestamp, data & signed
		- Maintain status of incident using application/database
	- Incident Prioritisation
		- Business impact of the incident
- Containment, Eradication & Recovery
	- Eradication
		- Limit undesirable from the target
	- Recovery
		- Rebuild from backup
- Post-Incident Activity

## Computer Forensics Introduction
Refers to the process digital evidence which is identified, preserved, analysed, interpreted and presented

Role of a Computer Forensics Investigator
- Protect seized evidence
- Recover deleted files
- Discover files contained in seized materials
- Discover swap, temp, file slack meta-data and artefacts
- Explore all unallocated space
- Conduct searches for key terms, special data - imagery
- Note any observed versus expected files, folders, binaries, www data, emails and file conditions
- Prepare a written report - archive data, finds
- Provide expert consultation and testimony, as necessary

Chain of custody
- Refers to handling of evidence in a certain manner
- Requires evidence collected to be stored in tamper-proof manner

Forensics Process
- Non-volatile data acquisition
	- Physical copy like `dd` command
	- Use write-blockers
	- Sanitise disk/storage where evidence is going to be written into
	- Types of copy
		- Physical copy
			- Contains deleted files
			- Unallocated space
			- File slack
		- Logical copy
	- Hashing to prove it is 1-to-1 exact match
- Volatile data acquisition
	- RAM
	- Swapfile/cache
	- Examples
		- Date & Time-stamp
		- Current network connections
		- Open network ports
		- Running services/processes
		- Routing tables
- Tools
	- Windows Forensic Toolchest
	- Forensic Server Project
	- Forensic Analysis & Digital Investigation
	- Hexadecimal analysis
	- Hex viewer/editor
	- Sleuth Kit & Autopsy
	- Filedisk
	- Disk Investigator

## Forensics Analysis: Information Gathering From Other Sources
- Web Browsing Investigation
	- Pasco
	- Galleta
- Email Header Analysis
	- Spam Filter Bypass Example
	- Find True Origin of Email
	- Show Email Defences in place
- Malicious Code & Infection Analysis
	- Locate & Identify
		1. Find strange connections with `netstat -an`
		2. Suspicious files
		3. Check registry
			- `%SYSTEMROOT%\Prefetch`
		4. Hiding places
			- `%SYSTEMROOT%` `%SYSTEMDIRECTORY`
			- `dir /o:d /t:c`: When file created
			- `dir /o:d /t:a`: When file accessed
			- `dir /o:d /t:w`: When file written to
		5. Have to start somewhere
			- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
			- `HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce`
		6. Check for any unauthentic code
		7. Check if "stuff" is hidden in binaries
		8. Google it
			- Google for ports relating to malware, trojans, backdoors, etc.
		9. The need to access something on my system
			- Process Monitor
			- Process Explorer
		10. See what they do inside
			- OllyDbg
			- IDA Pro
			- WinDbg
			- Decompiler
	- Examples
		- Trojan
		- Backdoor

# The Impact of Law

## Why You Need To Know
- Individual
- Corporate

- Permissible Actions
	- You cannot counter-hack
	- Established forensics & evidence gathering/handling procedures
	- Appropriate legal procedure
- Harmonisation

## The State Of Cybercrime Law
Singapore
- CMCA

## Issues with Enforcement

Key issues when it comes to prosecuting cyber-criminals
- Insufficient evidence
	- Insufficient logging
- Data corrupted
	- Improper handling
- Best evidence rule
	- Original piece of evidence is superior
- Circumstantial/Indirect evidence
	- Implies something occurred bu doesn't directly prove it

## When To Enforce
Singapore's Computer Misuse and Cybersecurity Act sections

# Command Cheatsheet
Welcome to the command cheatsheet! All you need to _attacc_ & _protecc_ is here!

IP addresses to remember!
- `172.30.3.X`: Linux Virtual Machines
- `10.50.0.X`: Firewall
- `10.50.X.1-3`: Server 1-3

**SSH Command**

- `ssh user@<ip address> -p <port number>`
- `scp -P <port number> from user@<ip address>:/to`

**VI Command Editor**

- `u`: Undo
- `CTRL-R`: Redo
- `CTRL-E`: Moves down by one line
- `CTRL-Y`: Moves up by one line
- `CTRL-F`: Page down
- `CTRL-B`: Page up
- `0`: Moves cursor to beginning of current line
- `$`: Moves cursor to end of current line
- `/pattern`: Search forwards
- `?pattern`: Search backwards
- `i`: Insert
- `dd`: Delete line
- `:wq`: Save and exit
- `:q!`: Exit without saving

**SFTP**
- `sftp user@<ip address>`
- `get`: Downloads file
- `bye`: Exits SFTP session

**dig command**
- `dig @<ip address> example.com axfr`: Information disclosure attack to internal host
- `dig example.com`: Finds IP address
- `dig example.com mx`: Finds mail exchanger records
- `dig example.com ns`: Finds name server records
- `dig example.com soa`: Finds start of authority of the domain and other information
- `dig @<authoritative nameserver> example.com`: Show additional information about name servers that are responsible for domain

**whois**
- `whois example.com`: Shows where the domain is being registered

**nmap**
- `nmap -sP -n <ip address>/<CIDR>`: Does ping sweep (Sends ICMP echo requests towards all hosts specified)
- `nmap -sS -n <ip address>`: Does SYN stealth scan
	- Sends SYN packets
	- If host replies with SYN/ACK, RST is sent to stop 3-way handshake from continuing. Reports as **open**
	- If host replies with RST, nmap reports as **closed**
	- If host no reply, nmap reports as **filtered**
- `nmap -sA <ip address>`: Used to determine if there is any firewall protecting the target
	- ACK packet is sent
	- RST packet is returned because session for ACK packet does not exist
- Tags
	- `-sV`: Version detection
	- `-Pn`: Disables ping
	- `-n`: Never do DNS resolution
	- `-p`: Specifies port
	- `-vv`: Very Verbose
	- `-O`: Enables OS detection
	- `-A`: Scan everything (Slows network)

**xprobe2**
- `xprobe2 <ip address>`: Determines OS of IP address

**Cheops**
- `cheops-agent -n`: Starts up cheops server
- `cheops-ng`: Starts cehops client
	- Add hostname, network, netmask and map everything

**Nessus**
- `nessus-mkcert`
- `nessus-adduser`
- `nessusd -D`: Starts up Nessusd server component
- `nessus`: Runs client
	- Add host, port, login, password and display server cert
	- Set Scan options
	- Select target

**httprint**
- `./httprint -h <website> -s <signature file>`: Determines webserver version
- `nikto.pl -host <ip address>`: Scan web server for potential web-related flaws and vulnerabilities

**iptables**
- `service iptables stop`: Stops service
- `iptables -F`: Flushes all entries in firewall
- `service iptables save`: Saves firewall configurations

**snort**
- `snort -c /etc/snort/snort.conf &`: Starts snort in daemon mode
- `tail -f /var/log/snort/alert`
- `more /var/log/snort/<filename>`

**tripwire**
- `tripwire-setup-keyfiles`
- `tripwire --init`
- `tripwire --check`: Check for any changes on system
- `twprint -m -r --twrfile /var/lib/tripwire/report/<filename-timestamp>.twr`: View tripwire report
- `tripwire --update-policy -Z low /etc/tripwire/twpol.txt`: Updates Tripwire database

**gpg**
- `gpg --gen-key`: Generates GPG key-pair
- `gpg --import <filename>`: Imports 3rd party public key
- `gpg --fingerprint`: View imported keys
- `gpg --sign-key <key id>`: Sign key shows that you've done verification
- `gpg --verify <filename1> <filename2>`: Verify authenticity of any package which was signed by private key counterpart

**Ettercap**
- `ettercap -G`: Runs graphical interface of Ettercap
1. Sniff -> Unified sniffing `Shift + U`
2. Host -> Scan for hosts `Ctrl + S`
3. Host -> Hosts lists `H`
4. Add targets
5. Targets -> Current Targets `T`
5. Start -> Start sniffing `Ctrl + W`
6. Mitm -> Arp poisoning
7. View -> Connections `Shift + C`
8. Mitm -> Stop mitm attack(s)

**Burpsuite**
1. Change interface from loopback only to anything else
2. Set SSL cert to generate CA-signed per-host certificates
3. Change proxy of browser to `127.0.0.1` and port to `8080`

**Metasploit** (Skidde tool)
- `msfconsole`: Starts metasploit console
- `show exploits`
- `use <exploit name>`: Sets exploit to use
- `show options`: Show options for particualr exploit
- `set <RHOST/RPORT/LHOST/LPORT> <host/port>`: Set listening/remote host/port
- `show targets`: Show which targets are vulnerable
- `show payloads`
- `set payload`: Sets the payload to use
- `exploits`: Haxxor like the script kiddie you are

**Netcat**
- `nc -lp <port number> -e path_to\cmd.exe`: Creates a remote shell as backdoor
- `nc <ip address> <port number>`: Connect to remote shell

**Alternate Data Stream (ADS)**
- `notepad path_to\file:hiddenfile`: Write to alternate data stream
- `wmic process call create path_to\file:hiddenfile`: Run hidden program
- `expand path_to\file:hiddenfile hiddenfile`: Extract hidden file from ADS
- `dir/r`: View all files including ADS files

**S-Tools**
- Right-click and reveal
- Enter passphrase and encryption algorithm

**Foremost**
- `foremost -T -i <.dd file>`: Extract all data from image

**Pasco**
- `pasco -d <index.dat_filename>`: View history of websites

**Galleta**
- `galleta <name_of_cookie>`: View cookie values

**dd command**
- `dd if=/source of=/destination`

# Extras
With that, you have unofficially completed the Organizational Systems Security Analyst! Now, go and do it for realz.

# Credits
**ThinkSecure™ Pte Ltd**

Take your certification here: http://securitystartshere.org/page-training-ossa.htm

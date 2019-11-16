# Sniffing - Evasion - Firewalls/IDS

### <u>Basic Knowledge</u>

 - Sniffing is capturing packets as they pass on the wire to review for interesting information
 - **MAC**  (Media Access Control) - physical or burned-in address - assigned to NIC for communications at the Data Link layer
    - 48 bits long
    - Displayed as 12 hex characters separated by colons
    - First half of address is the **organizationally unique identifier** - identifies manufacurer
    - Second half ensures no two cards on a subnet will have the same address
 - NICs normally only process signals meant for it
 - **Promiscuous mode** - NIC must be in this setting to look at all frames passing on the wire
 - **CSMA/CD** - Carrier Sense Multiple Access/Collision Detection - used over Ethernet to decide who can talk
 - **Collision Domains**
    - Traffic from your NIC (regardless of mode) can only be seen within the same collision domain
    - Hubs by default have one collision domain
    - Switches have a collision domain for each port

### <u>Protocols Susceptible</u>

- SMTP is sent in plain text and is viewable over the wire.  SMTP v3 limits the information you can get, but you can still see it.
- FTP sends user ID and password in clear text
- TFTP passes everything in clear text
- IMAP, POP3, NNTP and HTTP all  send over clear text data
- TCP shows sequence numbers (usable in session hijacking)
- TCP and UCP show open ports
- IP shows source and destination addresses

### <u>ARP</u>

- Stands for Address Resolution Protocol
- Resolves IP address to a MAC address
- Packets are ARP_REQUEST and ARP_REPLY
- Each computer maintains it's own ARP cache, which can be poisoned
- **Commands**
  - arp -a - displays current ARP cache
  - arp -d * - clears ARP cache
- Works on a broadcast basis - both requests and replies are broadcast to everyone
- **Gratuitous ARP** - special packet to update ARP cache even without a request
  - This is used to poison cache on other machines

### <u>IPv6</u>

- Uses 128-bit address
- Has eight groups of four hexadecimal digits
- Sections with all 0s can be shorted to nothing (just has start and end colons)
- Double colon can only be used once
- Loopback address is ::1

| IPv6 Address Type | Description                                           |
| ----------------- | ----------------------------------------------------- |
| Unicast           | Addressed and intended for one host interface         |
| Multicast         | Addressed for multiple host interfaces                |
| Anycast           | Large number of hosts can receive; nearest host opens |

| IPv6 Scopes | Description                                                  |
| ----------- | ------------------------------------------------------------ |
| Link local  | Applies only to hosts on the same subnet (Address block fe80::/10) |
| Site local  | Applies to hosts within the same organization (Address block FEC0::/10) |
| Global      | Includes everything                                          |

- Scope applies for multicast and anycast
- Traditional network scanning is **computationally less feasible**

### <u>Wiretapping</u>

- **Lawful interception** - legally intercepting communications between two parties
- **Active** - interjecting something into the communication
- **Passive** - only monitors and records the data
- **PRISM** - system used by NSA to wiretap external data coming into US

### <u>Active and Passive Sniffing</u>

- **Passive sniffing** - watching network traffic without interaction; only works for same collision domain
- **Active sniffing** - uses methods to make a switch send traffic to you even though it isn't destined for your machine
- **Span port** - switch configuration that makes the switch send a copy of all frames from other ports to a specific port
  - Not all switches have the ability to do this
  - Modern switches sometimes don't allow span ports to send data - you can only listen
- **Network tap** - special port on a switch that allows the connected device to see all traffic
- **Port mirroring** - another word for span port

### <u>MAC Flooding</u>

- Switches either flood or forward data
- If a switch doesn't know what MAC address is on a port, it will flood the data until it finds out
- **CAM Table** - the table on a switch that stores which MAC address is on which port
  - If table is empty or full, everything is sent  to all ports
- This works by sending so many MAC addresses to the CAM table that it can't keep up
- **Tools**
  - Etherflood
  - Macof
- **Switch port stealing** - tries to update information regarding a specific port in a race condition
- MAC Flooding will often destroy the switch before you get anything useful, doesn't last long and it will get you noticed.  Also, most modern switches protect against this.
- Countermeasures : Use sticky MAC and port security within cisco switches

### <u>ARP Poisioning</u>

- Also called ARP spoofing or gratuitous ARP
- This can trigger alerts because of the constant need to keep updating the ARP cache of machines
- Changes the cache of machines so that packets are sent to you instead of the intended target
- **Countermeasures**
  - Dynamic ARP Inspection using DHCP snooping
  - XArp can also watch for this
  - Default gateway MAC can also be added permanently into each machine's cache
- **Tools**
  - Cain and Abel
  - WinArpAttacker
  - Ufasoft
  - dsniff

### <u>DHCP Starvation</u>

- Attempt to exhaust all available addresses from the server
- Attacker sends so many requests that the address space allocated is exhausted
- DHCPv4 packets - DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, DHCPACK
- DHCPv6 packets - Solicit, Advertise, Request (Confirm/Renew), Reply
- **DHCP Steps**
  1. Client sends DHCPDISCOVER
  2. Server responds with DHCPOFFER
  3. Client sends request for IP with DHCPREQUEST
  4. Server sends address and config via DHCPACK
- **Tools**
  - Yersinia
  - DHCPstarv
- Mitigation is to configure DHCP snooping
- **Rogue DHCP Server** - setup to offer addresses instead of real server.  Can be combined with starvation to real server.

### <u>Spoofing</u>

- **MAC Spoofing** - changes your MAC address.  Benefit is CAM table uses most recent address.
- Port security can slow this down, but doesn't always stop it
- MAC Spoofing makes the switch send  all packets to your address instead of the intended one until the CAM table is updated with the real address again
- **IRDP Spoofing** - hacker sends ICMP Router Discovery Protocol messages advertising a malicious gateway
- **DNS Cache Poisioning** - changes where machines get their DNS info from, allowing attacker to redirect to malicious websites ( Implement DNSSEC ).

### <u>Sniffing Tools</u>

- Wireshark/Etherreal, Snort and TCPdump all use the **same packet capture utility** 
- **Wireshark**
  - Previously known as Ethereal
  - Can be used to follow streams of data
  - Can also filter the  packets so you can find  a specific type or specific source address
  - **Example filters**
    - ! (arp or icmp or dns) - filters out the "noise" from ARP, DNS and ICMP requests
    - http.request - displays HTTP GET requests
    - tcp contains string - displays TCP segments that contain the word "string"
    - ip.addr==172.17.15.12 && tcp.port==23 - displays telnet packets containing that IP
    - tcp.flags==0x16 - filters TCP requests with ACK flag set
    - wireshark –capture –local –masked 192.168.8.0 –range 24
- **tcpdump**
  - Recent version is WinDump (for Windows)
  - **Syntax**
    - tcpdump flag(s) interface
    - tcpdump -i eth1 - puts the interface in listening mode
- **tcptrace**
  - Analyzes files produced by packet capture programs such as Wireshark, tcpdump and Etherpeek
- **Netstumbler** - Wireless packet capture
- **Nmap** - used here for detection of promiscuous mode. Nmap’s NSE script allows you to check if a target on a local Ethernet has its network card in promiscuous mode
- **Other Tools**
  - **Ettercap** - also can be used for MITM attacks, ARP poisoning.  Has active and passive sniffing.
  - **Capsa Network Analyzer**
  - **Snort** - usually discussed as an Intrusion Detection application
  - **Sniff-O-Matic**
  - **EtherPeek**
  - **WinDump**
  - **WinSniffer**
  
  
 How to detect/avoid sniffing
 
- IP Source Guard : defense technique for MAC spoofing used in switches that restricts the IP traffic on untrusted Layer 2 ports by filtering traffic based on the DHCP snooping binding database
- ip dhcp snooping vlan 4,104 - Enable or disable DHCP snooping on one or more VLANs.
- switchport port-security mac-address sticky - Adds all secure MAC addresses that are dynamically learned to the running configuration
- switchport port-security - Enables port security on the interface to defend agains MAC spoofing
- switchport port-security maximum 1 vlan access - Sets the maximum number of secure MAC addresses for the interface. The range is 1 to 3072. The default is 1.
- Implement dynamic arp inspection (DAI) using the dynamic host configuration protocol (DHCP) snooping binding table to prevent the organization’s network against ARP poisoning
- Use SSH and SSL
- DNS Security (DNSSEC): Implement Domain Name System Security Extension (DNSSEC) to prevent DNS spoofing attacks.
- Use NMAP allows you to check if a target on a local Ethernet has its network card in promiscuous mode
  

### <u>Devices To Evade</u>

- **Intrusion Detection System** (IDS) - hardware or software devices that examine streams of packets for malicious behavior
  - **Signature based** - involves first creating models of possible intrusions and then comparing these models with incoming events to make a detection decision, most commercial IDSes generate signatures for **Network layer** and **Transport layer**
  - **Anomaly based** - makes decisions on alerts based on learned behavior and "normal" patterns
  - **False negative** - case where traffic was malicious, but the IDS did not pick it up
  - **HIDS** (Host-based intrusion detection system) - IDS that is host-based
  - **NIDS** (Network-based intrusion detection system) - IDS that scans network traffic
  - main advantage that a network-based IDS/IPS system has over a host-based solution They do not use host system resources.
  - Passive - Doesn't take an action
  - Active - Take action(IPS)
  
- **IDS/IPS** Tools
- **Snort** - a  widely deployed IDS that is open source
  - 3 Actions : Alert, Log, Pass
  - Includes a sniffer, traffic logger and a protocol analyzer
  - Runs in three different modes
    - **Sniffer** - watches packets in real time
    - **Packet logger** - saves packets to disk for review at a later time
    - **NIDS** - analyzes network traffic against various rule sets
  - Configuration is in /etc/snort on Linux and c:\snort\etc in Windows
  - **Rule syntax**
    - alert tcp !HOME_NET any -> $HOME_NET 31337 (msg : "BACKDOOR ATTEMPT-Backorifice")
      - This alerts about traffic coming not from an external network to the internal one on port 31337
  - **Example output**
    - 10/19-14:48:38.543734 0:48:542:2A:67 -> 0:10:B5:3C:34:C4 type:0x800 len:0x5EA
      **xxx -> xxx TCP TTL:64 TOS:0x0 ID:18112 IpLen:20 DgmLen:1500 DF**
    - Important info is bolded
    
- zIPS, Wifi Inspector, and Vangaurd Enforce are IDS tools  
    
- **Firewall**
  - An appliance within a network that protects internal resources from unauthorized access
  - Only uses rules that **implicitly denies** traffic unless it is allowed
  - Oftentimes uses **network address translation** (NAT) which can apply a one-to-one or one-to-many relationship between external and internal IP addresses
  - **Screened subnet** - hosts all public-facing servers and services( Between Internet, Intranet and DMZ)
  - **Bastion hosts** - hosts on the screened subnet designed to protect internal resources (2-ports Between Internet and Intranet)
  - **Private zone** - hosts internal hosts that only respond to requests from within that zone
  - **Multi-homed** - firewall that has two(Dual Homed) or more interfaces
  - **Dual-Firewall** - Two firewalls setup between Internet and DMZ , Another one between DMZ and Internal  
  - **Packet-filtering** - firewalls that only looked at headers and IP packets
  - **Stateful inspection** - firewalls that track the entire status of a connection
  - **Circuit-level gateway** - is only monitoring TCP handshaking of packets at the session layer of the OSI model , Or Layer 4 – TCP , prevents externally forged internet addresses.
  - **Application-level gateway** - firewall that works like a proxy, allowing specific services in and out, checks get/post
  - **dual-homed** - hardware requirement that either an IDS/IPS system or a proxy server must have in order to properly function
  
### <u>Evasion Techniques</u>

- **Slow down** - faster scanning such as using nmap's -T5 switch will get you caught.  Pros use -T1 switch to get better results
- **Flood the network** - trigger alerts that aren't your intended attack so that you confuse firewalls/IDS and network admins
- **Fragmentation** -  splits up packets so that the IDS can't detect the real intent
- **Unicode encoding** - works with web requests - using Unicode characters instead of ascii can sometimes get past
- **NOP instructions mutation** - Randomly replace the NOPs with functionally equivalent segments of the code (e.g.: x++; x-; ? NOP NOP) , used for writing buffer overflow exploits in order to avoid IDS and other filtering mechanisms.
- **Insertion Attack** - Uses TTL Field of TCP/IP to evade IDS/Firewall
- **Tools**
  - **Nessus** - also a vulnerability scanner
  - **ADMmutate** - creates scripts not recognizable by signature files
  - **NIDSbench** - older tool for fragmenting bits
  - **Inundator** - flooding tool

### <u>Firewall Evasion</u>


- TCP-over-DNS: The tcp-over-dns client will encrypt the data in a specific address and transfers that to the Internet Service Provider’s DNS server. The ISP’s DNS server then understands that it cannot answer the question, so it forwards it onto the TCP-over-DNS server. The TCP-over-DNS server decrypt the client’s data from the specified address and encodes the server’s data in the answer that is sent back to the client. In this way is a client-server tool utilized to evade firewall inspection as well.
- Encrypted traffic
- Obfuscating: Obfuscating is an IDS evasion technique used by attackers to encode the attack packet payload in such a way that the destination host can only decode the packet but not the IDS
- String concatination : 
  - “+” operator:  MS SQL database.
  - “||” operator:  Oracle database.
  - “concat(,)” operator: MySQL database.
  - “&” operator: MS Access database.
- Char encoding: uses char() function to replace common injection variables present in the SQL statement to evade the IDS.
- Hex encoding: uses hexadecimal encoding to replace common injection variables present in the SQL statement to evade the IDS.
- URL encoding: uses online URL encoding to encode SQL statement to bypass the IDS.
- Session splicing : It is a network-level evasion method used to bypass IDS where an attacker splits the attack traffic into many packets such that no single packet triggers the IDS. The attacker divides the data into the packets into small portions of bytes and while delivering the data evades the string match. Attackers use this technique to deliver the data into several small-sized packets. 
- Overlapping fragments and fragmentation attack evade IDS by using fragments of packet, whereas in unicode evasion is done by exploiting unicode characters.
- Unicode evasion
- Polymorphic shellcode: include multiple signatures, making it difficult to detect the signature. Attackers encode the payload using some technique and then place a decoder before the payload. As a result, the shellcode is completely rewritten each time it is sent for evading detection. Countermeasure,  Look for the nopopcode other than 0x90
- ASCII Shellcode - bypassed by commonly enforced character restrictions within string input code
- Bypassing firewall through content - sends an e-mail containing a malicious Microsoft office document to target WWW/FTP servers and embeds Trojan horse files as software installation files, mobile phone software, and so on to lure a user to access them.
- ICMP Type 3 Code 13 will show that  traffic is being blocked by firewall
- ICMP Type 3 Code 3 tells you the client itself has the port closed
- Firewall type can be discerned by banner grabbing
- IP address spoofing - hijacking technique where an attacker masquerades as a trusted host to conceal his identity, hijack browsers or websites, or gain unauthorized access to a network
- **Firewalking** - going through every port on a firewall to determine what is open
  - uses TTL values to determine gateway ACL filters
  - maps networks by analyzing IP packet response  
  - probes ACLs on packet filtering routers/firewalls using the same method as trace-routing
  - sends TCP or UDP packets into the firewall with TTL value is one hop greater than the targeted firewall
- **Tools**
  - Loki ICMP tunneling is used to execute commands of choice by tunneling them inside the payload of ICMP echo packets.
  - Super network tunnel - two-way HTTP tunneling software tool that allows HTTP, HTTPS, and SOCKS tunneling of any TCP communication between any client–server systems
  - Bitvise and Secure Pipes are SSH tunneling tools
    - Local Forwards - opens application communication ports to remote servers without opening those ports to public networks
  - CovertTCP
  - ICMP Shell
  - 007 Shell
- The best way around a firewall will always be a compromised internal machine

### <u>Honeypots</u>

- A system setup as a decoy to entice attackers
- Should not include too many open services or look too easy to attack
- **High interaction** - simulates all services and applications and is designed to be completely compromised
- **Low interaction** - simulates a number of services and cannot be completely compromised
- **Examples**
  - Specter
  - Honeyd
  - KFSensor

- Tar pits are the security entities similar to honeypots that are designed to respond slowly to the incoming requests. The layer 7 tar pits react slowly to the incoming SMTP commands by the attackers/spammers. Attackers can identify the presence of layer 7 tar pits by looking at the latency of the response from the service.

- Send-Safe Honeypot Hunter - honeypot detection tool has the following features:
  - Checks lists of HTTPS, SOCKS4, and SOCKS5 proxies with any ports
  - Checks several remote or local proxylists at once
  - Can upload “Valid proxies” and “All except honeypots” files to FTP
  - Can process proxylists automatically every specified period
  - May be used for usual proxylist validating as well


- Network Intrusions: General indications of network intrusions include:
  - Sudden increase in bandwidth consumption is an indication of intrusion
  - Repeated probes of the available services on your machines
  - Connection requests from IPs other than those in the network range, indicating that an unauthenticated user (intruder) is attempting to connect to the network
  - Repeated login attempts from remote hosts
  - A sudden influx of log data could indicate attempts at Denial-of-Service attacks, bandwidth consumption, and distributed Denial-of-Service attacks

- " Add any 10.7.2.155 5789 eq www permit any 10.7.2.158 5479 eq www permit" - Most granular ACL
- Netsh firewall show config - Shows windows FW rules
- Check Point’s FireWall-1 listens on TCP ports 256, 257, 258, and 259
- Microsoft’s Proxy Server usually listens on TCP ports 1080 and 1745.

- NetPatch firewall is a full-featured advanced android noroot firewall. 

- TippingPoint IPS  (From HP)
  - Gives an overview of current performance for all HP systems in the network, including launch capabilities into targeted management applications by using monitors
  - Pre-built, real-time reports that display big-picture analyses on traffic, top applications, and filtered attack events
  - Permits to see, control, and leverage the rules, shared services, and profiles of all the firewall devices throughout the network
  - Comprises of in-line, bump-in-the-wire intrusion prevention system with layer two fallback capabilities
  
- ZoneAlarm PRO FIREWALL 2018
  - Two-way firewall that monitors and blocks inbound as well as outbound traffic
  - Allows users to browse the web privately
  - Identity protection services help to prevent identity theft by guarding crucial data of the users. It also offers PC protection and data encryption
  - Through Do Not Track, it stops data-collecting companies from tracking the online users
  - Online Backup to backs up files and restores the data in the event of loss, theft, accidental deletion or disk failure


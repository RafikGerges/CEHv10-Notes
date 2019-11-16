# Reconnaissance

### <u>Footprinting</u>

- Looking for high-level information on a target
- Types
  - **Anonymous** - information gathering without revealing anything about yourself
  - **Pseudonymous** - making someone else take the blame for your actions

### <u>Four Main Focuses</u>

- Know the security posture
- Reduce the focus area
- Identify vulnerabilities
- Draw a network map

### <u>Types of Footprinting</u>

- **Active** - requires attacker to touch the device or network
  - Social engineering and other communication that requires interaction with target
- **Passive** - measures to collect information from publicly available sources
  - Websites, DNS records, business information databases

**Competitive Intelligence** - information gathered by businesses about competitors

**Alexa.com** - resource for statistics about websites

### <u>Methods and Tools</u>

**Search Engines**

- **NetCraft** - information about website and possibly OS info, can find Internal URLs
- **Sublitst3r** - python script designed to enumerate subdomains of websites using OSINT
- **Job Search Sites** - information about technologies can be gleaned from job postings
- **Google**
  - filetype:  - looks for file types
  - index of - directory listings
  - info: - contains Google's information about the page
  - intitle: - string in title
  - inurl: - string in url
  - link: - finds linked pages
  - related: - finds similar pages
  - site: - finds pages/websites specific in that given site/domain
  - site: target.com filetype:xls username password email - finds specific files within site/domain
  - site:target.com -site:Marketing.target.com accounting -  Results matching “accounting” in domain target.com but not on the site Marketing.target.com
  - SQL injection site:Wikipedia.org - find all Wikipedia pages that contain information about SQL, injection attacks, or SQL injection techniques
  - site:pastebin.com intext:*@*.com:* - mail lists dumped on pastebin.com
  - site: certifiedhacker.com filetype:xml | filetype:conf | filetype:cnf | filetype:reg | filetype:inf | filetype:rdp | filetype:cfg | filetype:txt | filetype:ora | filetype:ini - search for any files a target certifiedhacker.com may have
  - inurl:“NetworkConfiguration” cisco - VOIP footprinting to extract Cisco phone details
  -  inurl:“ccmuser/logon.asp” - Finds Cisco Call manager
  - “[main]” “enc_GroupPwd=” ext:txt - VPN Footprinting to find Cisco VPN client passwords



- **Metagoofil** - uses Google hacks to find information in meta tags

**Website Footprinting**

- **Web mirroring** - allows for discrete testing offline
  - HTTrack
  - Black Widow
  - Wget
  - WebRipper
  - Teleport Pro
  - Backstreet Browser
- **Archive.org** - provides cached websites from various dates which possibly have sensitive information that has been now removed

**Email Footprinting**

- **Email  header** - may show servers and where the location of those servers are
- **Email tracking** - services can track various bits of information including the IP address of where it was opened, where it went, etc.
- **Information gathered about the victim using email tracking tools:**

  - Recipient’s system IP address
  - Geolocation
  - Email received and Read
  - Read duration
  - Proxy detection
  - Links
  - Operating system and Browser information
  - Forward Email
  - Device Type

**DNS Footprinting**

- Ports

  - Name lookup - UDP 53
  - Zone transfer - TCP 53

- Zone transfer replicates all records

- **Name resolvers** answer requests

- **Authoritative Servers** hold all records for a namespace

- **DNS Record Types**

  

  - | Name  | Description        | Purpose                                        |
    | ----- | ------------------ | ---------------------------------------------- |
    | SRV   | Service            | Points to a specific service                   |
    | SOA   | Start of Authority | Indicates the authoritative NS for a namespace |
    | PTR   | Pointer            | Maps an IP to a hostname                       |
    | NS    | Nameserver         | Lists the nameservers for a namespace          |
    | MX    | Mail Exchange      | Lists email servers                            |
    | CNAME | Canonical Name     | Maps a name to an A reccord                    |
    | A     | Address            | Maps an hostname to an IP address              |
    | AAAA  | IPV6 Address       | Maps an hostname to an IPv6 address            |

- **DNS Poisoning** - changes cache on a machine to redirect requests to a malicious server

- **DNSSEC** - helps prevent DNS poisoning by encrypting records

- **SOA Record Fields**

  - **Source Host** - hostname of the primary DNS
  - **Contact Email** - email for the person responsible for the zone file
  - **Serial Number** - revision number that increments with each change
  - **Refresh Time** - time in which an update should occur
  - **Retry Time** - time that a NS should wait on a failure
  - **Expire Time** - time in which a zone transfer is allowed to complete
  - **TTL** - minimum TTL for records within the zone

- **IP Address Management**

  - **ARIN** - North America
  - **APNIC** - Asia Pacific
  - **RIPE** - Europe, Middle East
  - **LACNIC** - Latin America
  - **AfriNIC** - Africa

- **Whois** - obtains registration information for the domain

- **Nslookup** - performs DNS queries

  - nslookup [ - options ] [ hostname ]
  - interactive zone transfer
    - nslookup
    - server <IP Address>
    - set type = ns
    - ls -d domainname.com

- **Dig** - unix-based command like nslookup

  - dig @server name type

**Network Footprinting**

- IP address range can be obtained from regional registrar (ARIN here)
- Use traceroute to find intermediary servers
  - traceroute uses ICMP echo in Windows
- Windows command - tracert
- Linux Command - traceroute

**Other Tools**
- **Maltego** - tool allows analysts and pen testers to examine links between data/entities using graphs and link analysis
- **OSRFramework** - uses open source intelligence to get the collection of potentially actionable, overt, and publicly available information about target
- **Web Spiders** - obtain information from the website such as pages, etc.
- **Social Engineering Tools**
  - Social Engineering Framework (SEF)
- **Shodan** - search engine that shows devices connected to the Internet

**Computer Security Incident Response Team** (CSIRT) - point of contact for all incident response services for associates of the DHS

- "nc -l -p 2222 | nc 10.1.0.43 1234" - Netcat will listen on port 2222 and output anything received to a remote connection on 10.1.0.43 port 1234

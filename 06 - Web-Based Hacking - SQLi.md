# Web-Based Hacking - SQLi

### <u>Web Organizations</u>

- **Internet Engineering Task Force** (IETF) - creates engineering documents to help make the Internet work better
- **World Wide Web Consortium** (W3C) - a standards-developing community
- **Open Web Application Security Project** (OWASP) - organization focused on improving the security of software
- Automated patch management :  Detect -> assess -> acquire -> test -> deploy -> maintain
- Patch  - considered as a repair job to a programming problem .
- Hotfix - defined as a package that is used to address a critical defect in a live environment, and contains a fix for a single issue
- Service pack - Group of Hotfixes

### <u>OWASP Web Top 10</u>

- **A1 - Injection Flaws** - SQL, OS and LDAP injection
- **A2 - Broken Authentication and Session Management** - functions related to authentication and session management that aren't implemented correctly
- **A3 - Sensitive Data Exposure** - not properly protecting sensitive data (SSN, CC  numbers, etc.)
- **A4 - XML External  Entities (XXE)** - exploiting XML  processors by uploading hostile content in an XML document
- **A5 - Broken Access Control** - having improper controls on areas that should be protected
- **A6 - Security Misconfiguration** - across all parts of the server and application
- **A7 - Cross-Site Scripting (XSS)** - taking untrusted data and sending it without input validation
- **A8 - Insecure Deserialization** - improperly de-serializing data
- **A9 - Using Components with Known Vulnerabilities** - libraries and frameworks that have known security holes
- **A10 - Insufficient Logging and Monitoring** - not having enough logging to detect attacks

**WebGoat** - project maintained by OWASP which is an insecure web application meant to be tested

### <u>Web Server Attack Methodology</u>

- **Information Gathering** - Internet searches, whois, reviewing robots.txt
- **Web  Server Footprinting** - banner grabbing
  - **Tools**
    - Whois
    - Netcraft -  determines the OS of the queried host by looking in detail at the network characteristics of the HTTP response received from the website
    - HTTPRecon
    - ID Serve
    - HTTPrint
    - nmap
      - nmap --script -p80 http-trace localhost (detects vulnerable HTTP TRACE method)
      - nmap --script http-google-email <host> (lists email addresses)
      - nmap --script hostmap-* <host> (discovers virtual hosts on the IP address you are trying to footprint; * is replaced by online db such as  IP2Hosts)
      - nmap --script -p80 http-enum <host> (enumerates common web  apps)
      - nmap -p80 --script http-robots.txt <host> (grabs the robots.txt file)
      - nmap -p80 –script http-userdir -enum localhost (command is used to enumerate users)
  
    - telnet webserverAddress 80 HEAD / HTTP/1.0 - Can be used to fingerprint web server , will return the header of the victim server to the Telnet screen.

- **Website Mirroring** - brings the site to your own machine to examine structure, etc.
  - **Tools**
    - Wget
    - BlackWidow
    - HTTrack
    - WebCopier Pro
    - Web Ripper
    - SurfOffline
- **Vulnerability  Scanning**  - scans web server  for vulnerabilities
  - **Tools**
    - Nessus
    - Nikto - specifically suited for web servers; still very noisy like Nessus
    - GFI LanGuard - Only a Patch management software
    - Netscan Pro

- **Session Hijacking**
- **Web Server Password Cracking**
- **Netcat** is a networking utility that reads and writes data across network connections, using the TCP/IP protocol. It is a reliable “back-end” tool used directly or driven by other programs and scripts. It is also a network debugging and exploration tool.
- **UrlScan** - is a security tool that restricts the types of HTTP requests that IIS will process. By blocking specific HTTP requests, the UrlScan security tool helps to prevent potentially harmful requests from reaching applications on the server.
- **WebsiteCDS** - is a website change detection system that can detect hacking attempts on the web server. It is a script that goes through your entire web folder and detects any changes made to your code base and alerts you using email.



### <u>Web Server Architecture</u>

- **Most Popular Servers** - Apache, IIS and Nginx
- Apache runs configurations as a part of a module within special files (http.conf, etc.)
- IIS runs all applications in the context of LOCAL_SYSTEM
- IIS 5 had a ton of bugs - easy to get into
- **N-Tier  Architecture** - distributes processes across multiple servers; normally  as three-tier: Presentation (web), logic (application) and data (database)
- server type under an N-tier architecture is A group of servers with a unique role
- **Error Reporting** - should not be showing errors in production; easy to glean information
- **HTML** - markup language used to display web pages
- **HTTP Request Methods**
  - **GET** - retrieves whatever information is in the URL; sending data is done in URL
  - **HEAD** - identical to get except for no body return
  - **POST** - sends data via body - data not shown in URL or in history
  - **PUT** - requests data be stored at the URL
  - **DELETE** - requests origin server  delete resource
  - **TRACE** - requests application layer loopback of message
  - **CONNECT** - reserved for use with proxy
  - Both POST and GET can be manipulated by a web proxy
- **HTTP Error Messages**
  - **1xx: Informational** - request received, continuing
  - **2xx: Success** - action received, understood and accepted
  - **3xx: Redirection** - further action must be taken
  - **4xx: Client Error** - request contains bad syntax or cannot be fulfilled
  - **5xx: Server Error** - server failed to fulfill an apparently valid request
- Virtual document tree - component of the web server that provides storage on a different machine or a disk after the original disk is filled-up
- Server Root: It is the top-level root directory under the directory tree in which the server’s configuration and error, executable, and log files are stored. It consists of the code that implements the server.
- Document Root: Document root is one of the web server’s root file directories that stores critical HTML files related to the web pages of a domain name that will serve in response to the requests.
- Virtual Hosting: It is a technique of hosting multiple domains or websites on the same server. This allows sharing of resources between various servers. It is employed in large-scale companies where the company resources are intended to be accessed and managed globally.

### <u> Countermeasures </u>
- Machine.config is the mechanism of securing information by changing the machine level settings. This effect applies to all other applications. 
  - Machine.config file includes machine settings for the .Net framework that affects the security.
  - While implementing Machine.config, you must always ensure that tracing is disabled, that is, <trace enable=”false”/>in order to defend against web server attacks, and meanwhile you must also ensure that the debug compiles are turned off.
- Ensuring code access security, in order to avoid dictionary attacks on any web server, you have to configure the IIS to reject URLs with “../”, and install new patches and updates
- To defend web servers and provide security, you must remove unnecessary ISAPI filters from the web server, apply restricted ACLs, secure the SAM (stand-alone servers only), and block the remote registry administration.
- Choose an ICANN accredited registrar and encourage them to set registrar-lock on the domain name in order to avoid DNS Hijacking.
- UDP source port randomization - defend servers against blind response forgery
- defend against HTTP response-splitting and web cache poisoning:
  - Server Admin:
    - Use latest web server software
    - Regularly update/patch OS and web server
    - Run web vulnerability scanner
  
  - Application Developers:
    - Restrict web application access to unique IPs
    - Disallow carriage return (%0d or \r) and line feed (%0a or \n) characters
    - Comply to RFC 2616 specifications for HTTP/1.1

- To defend web server files and directories, you must eliminate unnecessary files within the .jar files, avoid mapping virtual directories between two different servers, or over a network, disable serving certain file types by creating a resource mapping, and also disable serving of directory listings.

### <u>Web Server Attacks</u>

- **DNS Amplification** - uses recursive DNS to DoS a target; amplifies DNS answers to target until it can't do anything
- **Directory Transversal** (../ or dot-dot-slash) - requests file that should not be accessible from web server
  - Example:  http://www.example.com/../../../../etc/password
  - Can use unicode to possibly evade IDS - %2e for dot and %sf for slash
- **Parameter Tampering** (URL Tampering) - manipulating parameters within URL to achieve escalation or other changes
- **Hidden Field Tampering** - modifying hidden form fields producing unintended results
- **Web Cache Poisoning** - replacing the cache on a box with a malicious version of it
- **WFETCH** - Microsoft tool that allows you to craft HTTP requests to see response data
- **Misconfiguration Attack** - same as before - improper configuration of a web server
- **Password Attack** - attempting to crack passwords related to web resources
- **Connection String Parameter Pollution** - injection attack that uses semicolons to take advantage of databases that use this separation method
- **Web Defacement** - simply modifying a web page to say something else
- **Tools**
  - **Brutus** - brute force web passwords of HTTP
  - **Hydra** - network login cracker
  - **Metasploit**
    - Basic working is Libraries use Interfaces and Modules to send attacks to services
    - **Exploits** hold the actual exploit
    - **Payload** contains the arbitrary code if exploit is successful
    - **Auxiliary** used for one-off actions (like a scan)
    - **NOPS** used for buffer-overflow type operations
- **Shellshock** - causes Bash to unintentionally execute commands when commands are concatenated on the end of function definitions
- Attackers use GET and CONNECT requests to use vulnerable web servers as Proxies
- **MSFvenom** - Used for Shellcode which is code that when run creates a reverse remote shell back to the creator. Attacks many platforms Win, Linux/Unix, FreedBSD, Android, OSX, Java,...etc.


### <u>Web Applications </u>

- Simple object access protocol (SOAP) is a lightweight and simple XML-based protocol designed to exchange structured and type information on the web
- 



### <u>Web Application Attacks</u>

- Most often hacked before of inherent weaknesses built into the program
- First step is to identify entry points (POST data, URL parameters, cookies, headers, etc.)
- **Tools for Identifying Entry Points**
  - DIG - DNS interrogation tool
  - Web spiders - automatically discover hidden content and functionality by parsing HTML form and client-side JavaScript requests and responses
  - WebScarab
  - HTTPPrint
  - BurpSuite
- **Web 2.0** - dynamic applications; have a larger attack surface due to simultaneous communication
- **connection stream parameter pollution (CSPP) attack** - Injecting parameters into a connection string using semicolons as a separator
- **File Injection** - attacker injects a pointer in a web form to an exploit hosted elsewhere
- **Command Injection** -involves injection of malicious html code through a web application, attacker gains shell access using **Java RMI** or similar.
- **Changing hidden form values** - authorization attack using hidden fields. When a user selects anything on an HTML page, it stores the selection as form field values and sends it to the application as an HTTP request (GET or POST)
- **Water hole attack** - attacker injects malicious script/code into the web application that can redirect the webpage and download the malware onto the victim’s machine
- **LDAP Injection** - exploits applications that construct LDAP statements
  - Format for LDAP injection includes )(&)
- **SOAP Injection** - inject query strings in order to bypass authentication
  - SOAP uses XML to format information
  - Messages are "one way" in nature
- **Buffer Overflow** (Smashing the stack) - attempts to write data into application's buffer area to overwrite adjacent memory, execute code or crash a system
  - Inputs more data than the buffer is allowed
  - Includes stack, heap, NOP sleds and more
  - **heap spraying attack** is a remote code execution exploit that allows the attacker to insert arbitrary code in the system's heap memory space
  - **Canaries** - systems can monitor these - if they are changed, they indicate a buffer overflow has occurred; placed between buffer and control data
- **XSS** (Cross-site scripting) - inputting javascript into a web form that alters what the page does
  - Can also be passed via URL (http://IPADDRESS/";!--"<XSS>=&{()}
  - Can be malicious by accessing cookies and sending them to a remote host
  - Can be mitigated by setting **HttpOnly** flag for cookies
  - **Stored XSS** (Persistent or Type-I) - stores the XSS in  a forum or like for multiple people to access
- **Cross-Site Request Forgery** (CSRF) - forces an end user to execute unwanted actions on an app they're already authenticated on
  - Inherits  identity and privileges of victim to perform an undesired function on victim's behalf
  - Captures the session and sends a request based off the logged in user's credentials
  - Can be mitigated by sending **random challenge tokens**
- **Session Fixation** - attacker logs into a legitimate site and pulls a session ID; sends link with session ID to victim.  Once vitcim logs in, attacker can now log in and run with uer's credentials
- **Cookies** - small text-based files stored that contains information like preferences, session details or shopping cart contents
  - Can be manipulated to change functionality (e.g. changing a cooking that says "ADMIN=no" to "yes")
  - Sometimes, but rarely, can also contain passwords
  
- XML denial of service issues - is a common service-oriented architecture (SOA) vulnerability.
- Sensitive data exposure - due to flaws such as insecure cryptographic storage and information leakage.
- Security misconfiguration - attacker exploits a web application by tampering with the form and parameter of the web application and he is successful in exploiting the web application and gaining access.
- Insufficient logging and monitoring - not recording the malicious event or ignores the important details about the event.
- Identify entry points for user input is how attacker starts to exploit a "Webpage"
  
  
- **Countermeasures**
  - Validate web content input for type, length, and range of input
  - set any cookie with a secure attribute - The client will send the cookie only over an HTTPS connection
  - Source code reviews are used to detect bugs and irregularities in the developed web applications
  - Fuzz testing -  is a black box testing method.
    - Mutation-based - current data samples create new test data and the new test data again mutates to generate further random data
    - Generation-based
    - Protocol-based - the protocol fuzzer sends forged packets to the target application that is to be tested
  - Set session cookies with HttpOnly flag - When a browser supports HttpOnly and detects a cookie containing the HttpOnly flag, the client side script tries to access the cookie then the browser returns back an empty string. Defends against XSS
  - use random tokens - to defend against CSRF attack.
  
  
### <u>SQL Injection</u>
  
- **SQL Injection** - injecting SQl commands into input fields to produce output
  - Data Handling - Definition (DDL), manipulation (DML) and control (DCL)
  - Example - input "' OR 1 = 1 --" into a login field - basically tells the server if 1 = 1 (always true) to allow the login.
  - Double dash (--) tells the server to ignore the rest of the query (in this example, the password check)
  - Basic test to see if SQL injection is possible is just inserting a single quote (') as first priority, then try double quote(") 
  - **Fuzzing** - inputting random data into a target to see what will happen
  - **Tautology** - using always true statements to test SQL (e.g. SELECT * FROM users WHERE name = ‘’ OR ‘1’=‘1′;)
  - **In-band SQL injection** - uses same communication channel to perform attack
    - Usually is when data pulled can fit into data exported (where data goes to a web table)
    - Best for using UNION queries
  - **Out-of-band SQL injection** - uses different communication channels (e.g. export results to file on web server)
  - **Blind/inferential SQLi** - time-intensive because the database should generate a new statement for each newly recovered bit , error messages and screen returns don't occur; use Timing delay and Boolean exploitation to know(example: WAITFOR DELAY '0:0:10'– and sleep() which doesn't consume processor resources).
  - **UNION SQL injection** - uses the UNION SQL operator to combine two or more malicious queries into a single statement. This allows the attacker to get a single result containing responses from all the malicious queries(ORDER BY 10–).
  
  In a Piggybacked SQL injection attack, an attacker injects an additional malicious query to the original query. The original query remains unmodified, and the attacker’s query is piggybacked on the original query. the attacker concatenates the delimiter (;) and malicious query to the original query as given below ( SELECT * FROM EMP WHERE EMP.EID = 1001 AND EMP.ENAME = ’Bob’; DROP TABLE DEPT;)
  
  Error-based SQL injection: In this attack, the attacker obtains information about the database by analyzing the error messages obtained from the underlying database.
  
   End-of-Line SQL injection, an attacker uses Line comments in specific SQL injection inputs.
   
   Alternate Encodings: In the alternate encodings technique, the tester modifies the SQL injection query by using alternate encoding, such as hexadecimal, ASCII, and Unicode.
   
   Stored Procedure Injection: Stored procedures are used at the back end of the web application to support its functionalities. In the stored procedure injection techniques, malicious SQL queries are executed within the stored procedure.
   
  "MS SQL" Server database use to store metadata in "sysobjects" table, Hackers can use this system table to acquire database schema information to further compromise the database
  
  
  
  - **Tools**
    - Sqlmap
    - sqlninja
    - Havij
    - SQLBrute
    - Pangolin
    - SQLExec
    - Absinthe
    - BobCat
    - DataThief - automate SQL injections and exploit a database by forcing a given web application to connect to another database controlled by a hacker
    - Marathon Tool - is a POC for using heavy queries to perform a Time-Based Blind SQL Injection attack

SQLiX: SQLiX is an SQL Injection scanner coded in Perl. It is able to crawl, detect SQL injection vectors, identify the back-end database, and grab function call/UDF results (even execute system commands for MS-SQL). (Source: https://www.owasp.org/index.php/Category:OASP_SQLiX_Project)

SQLDict: SQLDict is a basic single-IP brute-force S SQL Server password utility that can carry out a dictionary attack against a named SQL account. Specify the IP address to attack, and the user account, and then load an appropriate word list to try. (Source: http://ntsecurity.nu)

WebCruiser: WebCruiser is a Web Vulnerability and web pen testing tool used for auditing website security. It supports scanning a website as well as POC (Proof of concept) for web vulnerabilities like SQL Injection, Cross Site Scripting, XPath Injection, etc. (Source: http://sec4app.com)
    
- **HTTP Response Splitting**  - adds header response data to an input field so server splits the response
  - Can be used to redirect a user to a malicious site
  - Is not an attack in and of itself - must be combined with another attack
- **Countermeasures** - input scrubbing for injection, SQL parameterization for SQL injection, keeping patched servers, turning off unnecessary services, ports and protocols
  - Invoking the stored procedure xp_cmdshell to spawn a Windows command shell.
- Avoid constructing dynamic SQL with concatenated input values.
- Ensure that the Web configuration files for each application do not contain sensitive information.
- Use the most restrictive SQL account types for applications.
- Use Network, host, and application intrusion detection systems to monitor injection attacks.
- Perform automated black box injection testing, static source code analysis, and manual penetration testing to probe for vulnerabilities.
 
 
 IBM Security AppScan enhances web and mobile application security, improves application security, and strengthens regulatory compliance. By scanning web and mobile applications prior to deployment, AppScan identifies security vulnerabilities, generates reports, and makes recommendations to apply fixes.
 
 Acunetix Web Vulnerability Scanner provides automated web application security testing with innovative technologies including DeepScan and AcuSensor Technology. It rigorously tests for thousands of web application vulnerabilities including SQL injection and XSS.
 
Snort SQLi Rule
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:""SQL Injection attempt on Finance Dept. webserver""; flow:stateless; ack:0; flags:S; ttl:>220; reference:arachnids,439; classtype:attempted-recon; sid:613; rev:6;)"

/(\%27)|(\’)|(\-\-)|(\%23)|(#)/ix

/exec(\s|\+)+(s|x)p\w+/ix

/((\%27)|(\’))union/ix

/\w*((\%27)|(\’))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix

alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:”SQL Injection – Paranoid”; flow:to_server,established;uricontent:”.pl”;pcre:”/(\%27)|(\’)|(\-\-)|(%23)|(#)/i”; classtype:Web-application-attack; sid:9099; rev:5

- **SELECT @@VERSION** - The string “SELECT” can be represented by the hexadecimal number 0x73656c656374, which most likely will not be detected by a signature protection mechanism. The DBMS is Microsoft SQL Server and the correct SQL statement to retrieve the SQL server database version is SELECT @@VERSION

- **char()** a "MySQL" function converts hexadecimal and decimal values into characters to avoid detection.
 Oracle ASCIISTR function takes a string and returns an ASCII
 Oracle CHR() function returns the ASCII character that corresponds to the value passed to it.


Snort is an open-source, free and lightweight network intrusion detection system (NIDS) software for Linux and Windows to detect emerging threats

the following is a query in Oracle that takes a huge amount of time to execute:
SELECT * FROM products WHERE id=1 AND 1 < SELECT count(*) FROM all_users A, all_users B, all_users C



# Mobile Communications and IoT

### <u>Mobile Platform Hacking</u>

- **Three Main Avenues of Attack**
  - **Device Attacks** - browser based, SMS, application attacks, rooted/jailbroken devices
  - **Network Attacks** - DNS cache poisoning, rogue APs, packet sniffing
  - **Data Center (Cloud) Attacks** - databases, photos, etc.

- **OWASP Top 10 Mobile Risks**
  - **M1 - Improper Platform Usage** - misuse of features or security controls (Android intents, TouchID, Keychain)
  - **M2 - Insecure Data Storage** - improperly stored data and data leakage
  - **M3 - Insecure Communication** - poor handshaking, incorrect SSL, clear-text communication
  - **M4 - Insecure Authentication** - authenticating end user or bad session management
  - **M5 - Insufficient Cryptography** - code that applies cryptography to an asset, but is insufficient (does NOT include SSL/TLS)
  - **M6 - Insecure Authorization** - failures in authroization (access rights)
  - **M7 - Client Code Quality** - catchall for code-level implementation problems
  - **M8 - Code Tampering** - binary patching, resource modification, dynamic memory modification
  - **M9 - Reverse Engineering** - reversing core binaries to find problems and exploits
  - **M10 - Extraneous Functionality** - catchall for backdoors that were inadvertently placed by coders

### <u>Mobile Platforms</u>

- **Android** - platform built by Google
  - **Rooting** - name given to the ability to have root access on an Android device
    - **Tools**
      - KingoRoot
      - TunesGo
      - MTK Droid
      - Unrevoked
      - OneClickRoot - Low importance

- **iOS** - platform built by Apple
  - **Jailbreaking** - different levels of rooting an iOS device
    - **Tools**
      - Yalu
      - Velonzy
      - Yaig
      - Pangu
      - Cydia
      - evasi0n7 - Low importance
      - GeekSn0w - Low importance
      - Redsn0w - Low importance
      - Absinthe - Low importance
   
    - **Techniques**
      - **Untethered** - kernel remains patched after reboot, with or without a system connection, can start-up normally
      - **Semi-Tethered** - reboot no longer retains patch; must use installed jailbreak software to re-jailbreak, can start-up normally
      - **Tethered** - reboot removes all jailbreaking patches; phone may geet in boot loop requiring USB to repair, , cannot start-up  without PC connection.
    - **Types**
      - **Userland exploit** - found in the system itself; gains root access; does not provide admin; can be patched by Apple
      - **iBoot exploit** - found in bootloader called iBoot; uses vulnerability to turn codesign off; semi-tethered; can be patched
      - **BootROM exploit** - allows access to file system, iBoot and custom boot logos; found in device's first bootloader; cannot be patched
- **App Store attacks** - since some App stores are not vetted, malicious apps can be placed there
- **Phishing attacks** - mobile phones have more data to be stolen and are just as vulnerable as desktops
- **Android Device Administration API** - alows for security-aware apps that may help
- **Bring Your Own Device** (BYOD) - dangerous for organizations because not all phones can be locked down by default
- **Mobile Device Management** - like group policy on Windows; helps enforce security and deploy apps from enterprise
  - MDM solutions include Citrix XenMobile, IBM MaaS360, AirWatch and MobiControl
- **Bluetooth attacks** - if a mobile device can be connected to easily, it can fall prey to Bluetooth attacks
  - **Discovery mode** - how the device reacts to inquiries from other devices
    - **Discoverable** - answers all inquiries
    - **Limited Discoverable** - restricts the action
    - **Nondiscoverable** - ignores all inquiries
  - **Pairing mode** - how the device deals with pairing requests
    - **Pairable** - accepts all requests
    - **Nonpairable** - rejects all connection requests
 - **Android Vulnerability Scanning** - X-Ray  
 - **Sandbox** - helps protect mobile system users by limiting the resources that mobile app can access in the mobile platform. 

### <u>Mobile Attacks</u>

- **SMS Phishing(Smishing)** - sending texts with malicious links
  - People tend to trust these more because they happen less
  - **Trojans Available to Send**
    - Obad
    - Fakedefender
    - TRAMPS
    - ZitMo
  - **Spyware**
    - Mobile Spy
    - Spyera
    
- Harden Browser permission rules - protect employees from clickjacking attacks
- Block Text from the internet - feature from provider that helps protect users from phishing
- Mobile platform features such as Find my iPhone, Android device tracking and the like can be hacked to find devices, etc.
- **Mobile Attack Platforms** - tools that allow you to attack from your phone
  - Network Spoofer
  - DroidSheep - Android tool for web session hijacking using lincap and arpspoof
  - Nmap
  - LOIC (Low Orbit Ion Cannon) - Dos/DDoS runs from mobile app also.
  - Netcut - is an android app that allows attacker to identify target devices and block their access to WIFI
- **Bluetooth Attacks**
  - **Bluesmacking** - denial of service against device
  - **Bluejacking** - sending unsolicited messages
  - **Bluesniffing** - attempt to discover Bluetooth devices
  - **Bluebugging** - remotely using a device's features
  - **Bluesnarfing** - theft of data from a device
  - **Blueprinting** - colecting device information over Bluetooth
- **Bluetooth Attack Tools**
  - **BlueScanner** - finds devices around you
  - **BT Browser** - another tool for finding and enumerating devices
  - **Bluesniff** and **btCrawler** - sniffing programs with GUI
  - **Bloover** - can perform Bluebugging
  - **PhoneSnoop** - good spyware option for Blackberry
  - **Super Bluetooth Hack** - all-in-one package that allows you to do almost anything
  - **HackRF One** - Attackers use HackRF One to perform attacks such as BlueBorne or AirBorne attacks such as replay, fuzzing, jamming, etc. HackRF One is an advanced hardware and software defined radio with the range of 1MHz to 6GHz. It transmits and receives radio waves in half-duplex mode, so it is easy for attackers to perform attacks using this device.
  - **RFcrack** - More towards Rolling code attacks and can jam as well
  
### <u>IoT Architecture</u>

- **Definition** - a collection of devices using sensors, software, storage and electronics to collect, analyze, store and share data
- **Three Basic Components**
  - Sensing Technology
  - IoT gateways : Gateways are used to bridge the gap between the IoT device (internal network) and the end user (external network) and thus allowing them to connect and communicate with each other. The data collected by the sensors in IoT devices send the collected data to the concerned user or cloud through the gateway.
  - The cloud/storage : The collected data after travelling through the gateway arrives at the cloud, where it is stored and undergoes data analysis. The processed data is then transmitted to the user where he/she takes certain action based on the information received by him/her.
- **Operating Systems**
  - **RIOT OS** - embedded systems, actuator boards, sensors; is energy efficient
  - **ARM mbed OS** - mostly used on wearables and other low-powered devices
  - **RealSense OS X** - Intel's depth sensing version; mostly found in cameras and other sensors
  - **Nucleus RTOS** - used in aerospace, medical and industrial applications
  - **Brillo** - Android-based OS; generally found in thermostats
  - **Contiki** - OS made for low-power devices; found mostly in street lighting and sound monitoring
  - **Zephyr** - option for low-power devices and devices without many resources
  - **Ubuntu Core** - used in robots and drones; known as "snappy"
  - **Integrity RTOS** - found in aerospace, medical, defense, industrial and automotive sensors
  - **Apache Mynewt** - used in devices using Bluetooth Low Energy Protocol
- **Methods of Communicating**
  - **Device to Device** - communicates directly with other IoT devices
  - **Device to Cloud** - communicates directly to a cloud service
  - **Device to Gateway** - communicates with a gateway before sending to the cloud
  - **Back-End Data Sharing** - like device to cloud but adds abilities for 3rd parties to collect and use the data
- **Architecture Levels**
  - **Edge Technology Layer** - consists of sensors, RFID tags, readers and the devices
  - **Access Gateway Layer** - first data handling, message identification and routing
  - **Internet Layer** - crucial layer which serves as main component to allow communication between two end points such as device-to-device, device-to-cloud, device-to-gateway, and back-end data-sharing
  - **Middleware Layer** - sits between application and hardware; handles data and device management, data analysis and aggregation
  - **Application Layer** - responsible for delivery of services and data to the user

### <u>IoT Vulnerabilities and Attacks</u>

- **I1 - Insecure Web Interface** - problems such as account enumeration, weak credentials, and no account lockout
- **I2 - Insufficient Authentication/Authorization** - assumes interfaces will only be exposed on internal networks and thus is a flaw, insecure or weak password which offers poor security, thus allowing a hacker to gain access to the user account, and causing loss of data, loss of accountability and denying user to access the account.
- **I3 - Insecure Network Services** - may be succeptible to buffer overflow or DoS attacks
- **I4 - Lack of Transport Encryption/Integrity Verification** - data transported without encryption
- **I5 - Privacy Concerns** - due to collection of personal data
- **I6 - Insecure Cloud Interface** - easy-to-guess credentials make enumeration easy
- **I7 - Insecure Mobile Interface** - easy-to-guess credentials on mobile interface
- **I8 - Insufficient Security Configurability** - cannot change security which causes default passwords and configuration
- **I9 - Insecure Software/Firmware** - lack of a device to be updated or devices that do not check for updates
- **I10 - Poor Physical Security** - because of the nature of devices, these can easily be stolen


### <u>IoT Vulnerabilities &	Solutions</u>

- **1.Insecure Web Interface **
  - Enable default credentials to be changed
  - Enable account lockout mechanism
  - Conduct periodic assessment of web applications

- **2.Insufficient Authentication / Authorization**
  - Implement secure password recovery mechanisms
  - Use strong and complex passwords
  - Enable two-factor authentication

- **3.Insecure Network Services**	
  - Close open network ports
  - Disable UPnP
  - Review network services for vulnerabilities

- **4.Lack of Transport Encryption / Integrity Verification**
  - Encrypt communication between endpoints
  - Maintain SSL/TLS implementations
  - Not to use proprietary encryption solutions

### <u>IoT Attacks</u>

- **Sybil Attack** - uses multiple forged identifies to create the illusion of high traffic
- **Side Channel Attack** - Attackers perform side channel attacks by extracting information about encryption keys by observing the emission of signals i.e. “side channels” from IoT devices.
- **HVAC Attacks** - attacks on HVAC systems
- **Rolling Code** - the ability to jam a key fob's communications, steal the code and then create a subsequent code
- **BlueBorne Attack** - attacks against Bluetooth devices
- **Exploit Kits** - attacker use a malicious script to exploit poorly patched vulnerabilities in an IoT device
- **DoS Attack** - army of botnets to target a single online service or system
- **Jamming Attack** - ( Example RFCrack.py -j -F 314000000)

- Other attacks already enumerated in other sections still apply such as MITM, ransomware, side channel

### <u>IoT Hacking Methodology</u>

- **Steps**
  - **Information Gathering** - gathering information about the devices; 
    - **Shodan** - gather information such as IP address, hostname, ISP, device’s location, and the banner of the target IoT device (Googles for IoT devices connected to Internet)
    - **Foren6** - uses sniffers to capture 6LoWPAN traffic and renders the network state in a graphical user interface. It detects routing problems. The Routing Protocol for 6LoWPAN Networks, RPL, is an emerging IETF standard
    - **MultiPing** - An attacker can use the MultiPing tool to find IP address of any IoT device in the target network. After obtaining the IP address of an IoT device
  - **Vulnerability Scanning** - same as normal methodology - looks for vulnerabilities
    - **Tools**
      - Nmap (nmap -6 to identify IPv6 capability)
      - RIoT Vulnerability Scanner: Retina IoT vulnerability scanner identify at-risk IoT devices, such as IP cameras, DVRs, printers, routers, etc. This tool gives you an attacker’s view of all the IoT devices and their associated vulnerabilities
      - beSTORM -  Smart fuzzer and Discovers buffer overflow through black-box testing
      - Rapid7 Metasploit
      - IoTsploit
      - IoT Inspector
      - IoT Seeker
      
  - **Launching Attacks**
    - **Tools**
      - Firmalyzer : enables device vendors to perform automated security assessment on IoT firmware, for config and application vulnerabilities, assess firmware compliance, cryptographic issues, and uses advanced queries.
      - KillerBee
      - JTAGulator
      - Attify
      - Firmeware Mod Kit : reconstruct malicious firmware from legitimate firmware in order to maintain access to the victim device
      - HackRF One: Attackers use HackRF One to perform attacks such as BlueBorne or AirBorne attacks such as replay, fuzzing, jamming, etc. HackRF One is an advanced hardware and software defined radio with the range of 1MHz to 6GHz. It transmits and receives radio waves in half-duplex mode, so it is easy for attackers to perform attacks using this device.
      
  - **Gaining Access** - same objectives as normal methodology
  - **Maintaining Access** - same objectives as normal methodology
  
  - **DigiCert IoT security solution** : can be used to protect private data and home networks while preventing unauthorized access using PKI-based security solutions for IoT devices
  
  - **SeaCat.io** - security-first SaaS technology to operate IoT products in a reliable, scalable and secure manner. It provides protection to end users, business, and data.
  
  
- **Zigbee Framework** - Attify ZigBee framework consists of a set of tools used to perform ZigBee penetration testing. ZigBee protocol makes use of 16 different channels for all communications. Attackers use Zbstumbler from Attify Zigbee framework to identify the channel used by the target device.



### <u>IoT Ideal Framework </u>
- **Mobile** - An ideal framework for the mobile interface should include proper authentication mechanism for the user, account lockout mechanism after a certain number of failed attempts, local storage security, encrypted communication channels and the security of the data transmitted over the channel.

- **Gateway** - An ideal framework for the gateway should incorporate strong encryption techniques for secure communications between endpoints. Also, the authentication mechanism for the edge components should be as strong as any other component in the framework. Where ever possible the gateway should be designed in such a way that it authenticates multi-directionally to carry out trusted communication between the edge and the cloud. Automatic updates should also be provided to the device for countering vulnerabilities.

- **Cloud Platform** - A secure framework for the cloud component should include encrypted communications, strong authentication credentials, secure web interface, encrypted storage, automatic updates and so on.

- **Edge** - Framework consideration for edge would be proper communications and storage encryption, no default credentials, strong passwords, use latest up to date components and so on.

### <u>IoT devices manufacturing basic security measures </u>
 
- SSL/TLS should be used for communication purpose
- There should be a mutual check on SSL certificates and the certificate revocation list
- Use of strong passwords should be encouraged
- The device’s update process should be simple, secured with a chain of trust
- Implementing account lockout mechanisms after certain wrong login attempts to prevent brute force attacks
- Lock the devices down whenever and wherever possible to prevent them from attacks
- Periodically checking the device for unused tools and using whitelisting to allow only trusted tools or applications to run
- Use secure boot chain to verify all software that is executed on the device

### <u>Appendix </u>

- Port 48101: TCP/UDP port 48101 is used by the infected devices to spread malicious files to the other devices in the network. Monitor traffic on port 48101 as the infected devices attempt to spread the malicious file using port 48101

- Attackers use the following Nmap commands to scan a particular IP address:
  - nmap -n -Pn -sS -pT:0-65535 -v -A -oX <Name><IP>

- To perform a complete scan of the IoT device that checks for both TCP and UDP services and ports:
  - nmap -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX <Name><IP>

- To identify the IPv6 capabilities of a device:
  - nmap -6 -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX <Name><IP>
 
 
  
- **Rolling code attack:**

  - **Live Replay:**
    - python RFCrack.py -i

  - **Rolling Code:**
    - python RFCrack.py -r -M MOD_2FSK -F 314350000

  - **Adjust RSSI Range:**
    - python RFCrack.py -r -U “-75” -L “-5” -M MOD_2FSK -F 314350000

  - **Jamming:**
    - python RFCrack.py -j -F 314000000

# Wireless Network Hacking

### <u>Wireless Basics</u>

- **802.11 Series** - defines the standards for wireless networks
- **802.15.1** - Bluetooth
- **802.15.4** - Zigbee - low power, low data rate, close proximity ad-hoc networks
- **802.16** - WiMAX - broadband wireless metropolitan area networks

| Wireless Standard | Operating Speed (Mbps) | Frequency (GHz) | Modulation Type |
|-------------------|------------------------|-----------------|-----------------|
| 802.11a           | 54                     | 5               | OFDM            |
| 802.11b           | 11                     | 2.4             | DSSS            |
| 802.11d           | Variation of a & b     | Global use      |                 |
| 802.11e           | QoS Initiative         | Data and voice  |                 |
| 802.11g           | 54                     | 2.4             | OFDM and DSSS   |
| **802.11i**           | improved encryption WPA/WPA2 Encryption spec|                 |                 |
| 802.11n           | 100+                   | 2.4-5           | OFDM            |
| 802.11ac          | 1000                   | 5               | QAM             |

- **Orthogonal Frequency-Division Multiplexing** (OFDM) - carries waves in various phases orthogonal to eachother.
- **Direct-Sequence Spread Spectrum** (DSSS) - Multiplies the data with psuedo-noise
- **Frequency-hopping spread spectrum** (FHSS) - transmitting  signals by rapidly switching a carrier among many frequency channels,
- **Basic Service Set** (BSS) - communication between a single AP and its clients
- **Basic Service Set Identifier** (BSSID) - MAC address of the wireless access point
- **Spectrum Analyzer** - verifies wireless quality, detects rogue access points and detects attacks

- **Directional antenna** - signals in one direction; Yagi antenna is a type
- **Omnidirectional antenna** - signals in all directions 360 degree
- **Parabolic antenna** - Can reach Longest distances or coverage with very narrow beam, Directional
- **Yagi antenna** - frequency band of 10 MHz to VHF and UHF , Directional

- **Service Set Identifier** (SSID) - a text word (<= 32 char) that identifies network; provides no security
- **Three Types of Authentication**
  - **Open System** - no authentication
  - **Shared Key Authentication** - authentication through a shared key (password)
  - **Centralized Authentication** - authentication through something like RADIUS
- **Association** is the act of connecting; **authentication** is the act of identifying the client

### <u>Wireless Encryption</u>

- **Wired Equivalent Privacy** (WEP)
  - does not provide cryptographic integrity protection
  - Uses RC4 for encryption and a 32-bit CRC-32 for integrity check
  - Original intent was to give wireless the same level of protection of an Ethernet hub
  - **Initialization Vector** (IV) - 24 bits IV
  	- IVs are generally small and are frequently reused
  	- Sent in clear text as a part of the header
  	- This combined with RC4 makes it easy to decrypt the WEP key
  	- An attacker can send disassociate requests to the AP to generate a lot of these
  - 64-Bit uses 40-bit key
  - 128-Bit uses 104-bit key
  - 256-Bit uses 232-bit key
- **Wi-Fi Protected Access** (WPA or WPA2)
  - WPA uses TKIP with a 128-bit key
  - WPA changes the key every 10,000 packets
  - WPA transfers keys back and forth during an **Extensible Authentication Protocol** (EAP)
  - **WPA2 Enterprise** - can tie an EAP or RADIUS server into the authentication
  - **WPA2 Personal** - uses a pre-shared key to authenticate
  - WPA2 uses AES for encryption
  - WPA2 ensures FIPS 140-2 compliance
  - WPA2 uses CCMP instead of TKIP
  - **Message Integrity Codes** (MIC) - hashes for CCMP to protect integrity
  - **Cipher Block Chaining Message Authentication Code** (CBC-MAC) - integrity process of WPA2

| Wireless Standard | Encryption | IV Size (Bits) | Key Length (Bits) | Integrity Check |
|-------------------|------------|----------------|-------------------|-----------------|
| WEP               | RC4        | 24             | 40/104            | CRC-32          |
| WPA               | TKIP 	 | 48             | 128               | Michael/CRC-32  |
| WPA2              | AES-CCMP   | 48             | 128               | CBC-MAC (CCMP)  |


- Protected Extensible Authentication Protocol(PEAP)/Protected EAP : encapsulates the Extensible Authentication Protocol (EAP) within an encrypted and authenticated Transport Layer Security (TLS) tunnel.
- Lightweight EAP (LEAP): Cisco Proprietery verion of protected EAP, it changes the WEP keys dynamically upon several authentications during the session.

### <u>Wireless Hacking</u>

- **Threats**
  - Access Control Attacks
  - Integrity Attacks
  - Confidentiality Attacks
  - Availability Attacks
  - Authentication Attacks
- **Network Discovery**
  - Wardriving(WiFiFoFum), warflying, warwalking, warchalking etc.
   - with tools such as WiFiExplorer, WiFiFoFum, OpenSignalMaps, WiFinder
  - **Netcut** - is an android app that allows attacker to identify target devices and block their access to WIFI
  - **WIGLE** - map for wireless networks
  - **NetStumbler** - windows tool to find networks , can't monitor **802.11n**
  - **Kismet** - passive wireless packet analyzer/sniffer that can be used for discovery - windows/linux
  	- Works without sending any packets (passively)
  	- Can detects access points that have not been configured
  	- Works by channel hopping
  	- Can discover networks not sending beacon frames
  	- Ability to sniff packets and save them to  a log file (readable by Wireshark/tcpdump)
  - **NetSurveyor** - tool for Windows that does similar features to NetStumbler and Kismet
  	- Doesn't require special drivers
- **WiFi Adapter**
  - AirPcap is mentioned for Windows, but isn't made anymore
  - **pcap** - driver library for Windows
  - **libpcap** - drivery library for Linux

- SSID Cloaking - Keep certain default wireless messages from broadcasting the ID to everyone.
- Disable SSID Broadcast

### <u>Wireless Attacks</u>

- **Rogue Access Point** - places an access point controlled by an attacker
  - Detected through RF scanning or using network management software(Wired Side Input)
  - Wired Side Inputs: Network management software uses this technique to detect rogue APs. This software detects devices connected in the LAN, including Telnet, SNMP, CDP (Cisco discovery protocol) using multiple protocols.
  
- **Evil Twin** - a rogue AP with a SSID similar to the name of a popular network
  - Posing as an authorized AP by beaconing the WLAN’s service set identifier (SSID) to lure user
  - Also known as a mis-association attack
- **Honeyspot** - faking a well-known hotspot with a rogue AP
- **Ad Hoc Connection Attack** - connecting directly to another phone via ad-hoc network
  - Not very successful as the other user has to accept connection
- **DoS Attack** - 
  - availability attacks involve exploiting the CSMA/CA Clear Channel Assessment (CCA) mechanism to make a channel appear busy.
  - either sends de-auth packets to the AP or jam the wireless signal
  - With a de-auth, you can have the users conect to your AP instead if it has the same name
  - Jammers are very dangerous as they are illegal
- **MAC Filter** - only allows certain MAC addresses on a network
  - Easily broken because you can sniff out MAC addresses already connected and spoof it
  - Tools for spoofing include **SMAC** and **TMAC**
- **Rolling code Attack**
  - sniffing and replaying the RF code used to open a car using RFcrack
- **Jamming Attack**
  - Jamming wireless signal RFcrack -j
- **Beacon Flood** - Generating thousands of counterfeit 802.11 beacons to make it hard for clients to find a legitimate AP.
  
  
- **HackRF One** - Attackers use HackRF One to perform attacks such as BlueBorne or AirBorne attacks such as replay, fuzzing, jamming, etc. HackRF One is an advanced hardware and software defined radio with the range of 1MHz to 6GHz. It transmits and receives radio waves in half-duplex mode, so it is easy for attackers to perform attacks using this device.
- **RFcrack** - More towards Rolling code attacks and can jam as well
- **AirSnarf** - Linux Denial-of-service attacks against APs on the network
- **Ettercap** - can be used in wirless MITM to inject html codes
  
### <u>Wireless Encryption Attacks</u>

- **WEP Cracking**
  - Easy to do because of weak IVs
  - **Process**
    1. Start a compatible adapter with injection and sniffing capabilities
    2. Start a sniffer to capture packets
    3. Force the creation of thousands of packets (generally with de-auth)
    4. Analyze captured packets
  - **Tools**
        - **CommView for WiFi** - CommView for Wi-Fi is a wireless network monitor and analyzer for 802.11 a/b/g/n networks
  	- **Aircrack-ng** - sniffer, detector, traffic analysis tool and a password cracker
  	  - Uses dictionary attacks for WPA and WPA 2.  Other attacks are  for WEP only
	  - Airmon This script can be used to enable monitor mode on wireless interfaces
	  - Airodump  is used for packet capturing of raw 802.11 frames and is particularly suitable for collecting WEP IVs (Initialization Vector) for the intent of using them with aircrack-ng. If you have a GPS receiver connected to the computer, airodump-ng is capable of logging the coordinates of the found access points.
	    - airodump-ng -c 9 –bssid 00:14:6C:7E:40:80 -w output ath0
	  - Aircrack is an 802.11 WEP and WPA/WPA2-PSK key cracking program
	  - Aireplay is used to inject frames.There are different attacks which can cause deauthentications for the purpose of capturing WPA handshake data, fake authentications, Interactive packet replay, hand-crafted ARP request injection and ARP-request reinjection. With the packetforge-ng tool it's possible to create arbitrary frames.
	    - aireplay-ng -9 -e teddy -a 00:14:6C:7E:40:80  ath0
	    
	- **Cain and Abel** - sniffs packets and cracks passwords (may take longer)
      - Relies on statistical measures and the PTW technique to break WEP
	- **KisMAC** - MacOS tool to brute force WEP or WPA passwords
	- **WEPAttack**
	- **WEPCrack**
	- **Portable Penetrator**
	- **Elcomsoft's Wireless Security Auditor**
  - Methods to crack include **PTW**, **FMS**, and **Korek** technique
- **WPA Cracking**
  - Much more difficult than WEP
  - Uses a constantly changing temporal key and user-defined password
  - **Key Reinstallation Attack** (KRACK) - replay attack that uses third handshake of another device's session
  - Most other attacks are simply brute-forcing the password

### <u>Wireless Sniffing</u>

- Very similar to sniffing a wired network
- **Tools**
  - **NetStumbler**
  - **Kismet**
  - **OmniPeek** - provides data like Wireshark in addition to network activity and monitoring
  - **AirMagnet WiFi Analyzer Pro** - sniffer, traffic analyzer and network-auditing suite
  - **WiFi Pilot**

### <u> Bluetooth attacks </u>

- BlueBorne : Security vulnerability helps the attacker get full control of the device
- BlueJacking : sends an unsolicitated vCard over bluetooth contains command in the name field uses OBEX protocol
- BlueSmacking : DoS attack like ping of death.
- BlueSnarfing : Access to data like photos and contacts
- BlueBugging : access the device without the owner knowing
- BluePrinting : Capture make, model and OS details

### <u> Bluetooth Countermeasures </u>

- Use non-regular patterns as PIN keys while pairing a device. Use those key combinations that are non-sequential on the keypad.
- Keep BT in the disabled state, enable it only when needed and disable immediately after the intended task is completed.
- Keep the device in non-discoverable (hidden) mode.
- DO NOT accept any unknown and unexpected request for pairing your device.
- Keep a check of all paired devices in the past from time to time and delete any paired device that you are not sure about.
- Always enable encryption when establishing BT connection to your PC.
- Set Bluetooth-enabled device network range to the lowest and perform pairing only in a secure area.
- Install antivirus that supports host-based security software on Bluetooth-enabled devices.

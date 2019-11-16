# Cryptography - Steganography

### <u>Cryptograph Basics</u>

- **Cryptography** - science or study of protecting information whether in transit or at rest
  - Renders the information unusable to anyone who can't decrypt it
  - Takes plain text, applies cryptographic method, turn it into cipher text
- **Crypanalysis** - study and methods used to crack cipher text
- **Linear Cryptanalysis** - works best on block ciphers
- **Differential Cryptanalysis** - applies to symmetric key algorithms
  - Compares differences in the inputs to how each one affects the outcome
- **Integral cryptanalysis** - input vs output comparison same as differential; however, runs multiple computations of the same block size input
- Plain text doesn't necessarily mean ASCII format - it simply means unencrypted data
- **Nonrepudiation** - means by which a recipient can ensure the identity of the sender and neither party can deny sending
- **GAK** - Government access to key
- **Irreversibility** - is a cryptographic process that transforms data deterministically to a form from which the original data cannot be recovered, even by those who have full knowledge of the method of encryption, even if an attacker obtains the victim’s public key he cannot discover the victim’s private key that is required to crack the message.

### <u>Encryption Algorithms and Techniques</u>

- **Algorithm** - step-by-step method of solving a problem
- **Classic Cipher**
  - **Substitution** - bits are replaced by other bits
  - **Transposition** - doesn't replace;  simply changes order
- **Modern ciphers** - The user can calculate the Modern ciphers with the help of a one-way mathematical function that is capable of factoring large prime numbers.
- **Encryption Algorithms** - methmatical formulas used to encrypt and decrypt data
- **Based on the key type:** - Private(symmetric) ciphering and Public(Asymmetric) ciphering
- **Based on the input:**
- **Stream Cipher** - readable bits are encrypted one at a time in a continuous stream
  - Usually done by an XOR operation
  - Work at a high rate of speed
- **Block Cipher** - data bits are split up into blocks and fed into the cipher
  - Each block of data (usually 64 bits) encrypted with key and algorithm
  - Are simpler and slower than stream ciphers
- **XOR** - exclusive or; if inputs are the same (0,0 or 1,1), function returns 0; if inputs are not the same (0,1 or 1,0), function returns 1
- Key chosen for cipher must have a length larger than the data; if not, it is vulnerable to frequency attacks

### <u>Symmetric Encryption</u>

- **Symmetric Encryption** - known as single key or shared key
  - One key is used to encrypt and decrypt the data
  - Problems include key distribution and management
  - Suitable for large amounts of data
  - Harder for groups of people because more keys are needed as group increases
  - Does nothing for nonrepudiation; only performs confidentiality
- **Algorithms**
  - **DES** - block cipher; 56 bit key; quickly outdated and now considered not very secure
  - **3DES** - block cipher; 168 bit key; more effective than DES but much slower
  - **AES** (Advanced Encryption Standard) - Bulk/block cipher; 128, 192 or 256 bit key; replaces DES; much faster than DES and 3DES
  - **IDEA** (International Data Encryption Algorithm) - block cipher; 128 bit key; originally used in PGP 2.0
  - **Twofish** - block cipher 128-bit; up to 256 bit key ,Fiestel Cipher,  replaces DES for US government 
  - **Blowfish** - fast block cipher; to replace IDEA and DES,  replaced by AES; 64 bit block size; 32 to 448 bit key; considered public domain
  - **RC** (Rivest Cipher) - RC2 to RC6; block cipher; bariable key length up to 2040 bits; RC6 (lastest version) uses 128 bit blocks and 4 bit working registers; RC5 uses variable block sizes and 2 bit working registers
  - **RC4** - variable key symmetric, stream cipher, with byte-oriented operation and uses random premutation, Optimal for Voice/Video
  - **RC5** - variable key , Variable block size, parameterized algorithm , uses 2-bit working registeries.
  - **RC6** - parameterized algorithm , using integer multiplication and 4-bit working registeries

### <u>Asymmetric Encryption</u>

- Uses two types of keys for encryption and decryption
- **Public Key** - generally used for encryption; can be sent to anyone
- **Private Key** - kept secret; used for decryption
- Comes down to what one key encrypts, the other decrypts
- The private key is used to digitally sign a message
- **Algorithms**
  - **Diffie-Hellman** - developed as a key exchange protocol; used in SSL and IPSec; if digital signatures are waived, vulnerable to MITM attacks
    - Diffie-Hellman group 1—768 bit group
    - Diffie-Hellman group 2 —1024 bit group
    - Diffie-Hellman group 5—1536 bit group
    - Diffie-Hellman group 14—2048 bit group
    - Diffie-Hellman group 19—256 bit elliptic curve
    - Diffie-Hellman group 20—384 bit elliptic curve group
  - **Elliptic Curve Cryptosystem** (ECC) - uses points on elliptical curve along with logarithmic problems; uses less processing power; good for mobile devices
  - **El Gamal** - not based on prime number factoring; uses solving of discrete logarithm problems
  - **RSA** - achieves strong encryption through the use of two large prime numbers; factoring thse create key sizes up to 4096 bits; modern de facto standard
- Only downside is it's slower than symmetric especially on bulk encryption and processing power

### <u>Hash Algorithms</u>

- **Hash** - one-way mathematical function that produces a fix-length string (hash) based on the arrangement of data bits in the input
- **Algorithms**
  - **MD5** (Message Digest algorithm) - produces 128 bit hash expressed as 32 digit hexadecimal number; has serious flaws like collisions; still used for file download verification, file integrity checks, storing passwords. Use SHA-2/3
  - **SHA-1** - developed by NSA; 160-bit value output
  - **SHA-2** - four separate hash functions; produce outputs of 224, 256, 384 and 512 bits; not widely used
  - **SHA-3** - uses sponge construction with XOR and premutation
  - **RIPEMD-#** - 160-bit works through 80 stages, executing 5 blocks, excuted 16 times each; twice using modulo 32 addition, RIPEMD-128/256/320 available
  - **HMAC** - Used for message authentication. uses crypto key with hash function(MD5/SHA-1) executred twice to preven from length extension attack 
   - **CHAP** - challange/response with PPP servers, more secure than PAP
   - **EAP** -  Authentication used as alternative to CHAP/PAP
  
- **Collision** - occurs when two or more files create the same output
  - Can happen and can be used an attack; rare, though
- **DHUK Attack** (Don't Use Hard-Coded Keys) - allows attackers to access keys in certain VPN implementations; affects devices using ANSI X9.31 with a hard-coded seed key
- **Rainbow Tables** - contain precomputed hashes to try and find out passwords
- **Salt** - used with a hash to obscure the hash; collection of random bits
- **Things to Remember**
  - Hashes are used for integrity
  - Hashes are one-way functions
- **Tools**
  - HashCalc
  - MD5 Calculator
  - HashMyFiles
  - HashDroid ( for mobile)
  - Secret Space Encryptor: Mobile encryption
  - Advanced Encyrption Package 2017 : file transefer encryption, batch file encryption, backup encryption, ...etc,
  - BCTTextEncoder: text encryption

### <u>Steganography</u>

- **Steganography** - "security through obscurity", practice of concealing a message inside another medium so that only the sender and recipient know of it's existence
- **Ways to Identify**
  - Text - character positions are key - blank spaces, text patterns
  - Image - file larger in size; some may have color palete faults
  - Audio & Video - require statistical analysis
- **Methods**
  - Substitution - Least significant bit insertion, changes least meaningful bit
  - Masking and filtering (grayscale images) - like watermarking
  - Algorithmic transformation - hides in mathematical functions used in image compression
  - Transform domain techniques - Hid in cover image parts , cropping, compression,  frequency domain of a signal
  - Spread Spectrum  -  embed secret message in more space than it should
  - STatistical
  - Distortion 
  - Linguistics- Semagrams(signs/symbols), Open codes,
  - White space - adding white spaces at the end of of the lines - uses SNOW
  - Audio - hide in noise signal or inaudible range of frequencies
  - Microdots - reduce image/data to a single dot

  
- **Tools**
  - QuickStego
  - gifshuffle
  - SNOW
  - Steganography Studio
  - OpenStego

- **Steganalysis** - Finding the hidden message


### <u>PKI System</u>

- **Public Key Infrastructure** (PKI) - structure designed to verify and authenticate the identity of individuals
- **Registration Authority** - verifies user identity
- **Certificate Authority** - third party to the organization; creates and issues digital certificates
- **Certificate Revocation List** (CRL) - used to track which certificates have problems and which have been revoked
- **Validation Authority** - stores certificates and used to validate certificates via Online Certificate Status Protocol (OCSP)
- **Trust Model** - how entities within an enterprise deal with keys, signatures and certificates
- **Cross-Certification** - allows a CA to trust another CS in a completely different PKI; allows both CAs to validate certificates from either side
- **Single-authority system** - CA at the top
- **Hierarchial trust system** - CA at the top (root CA); makes use of one or more RAs (subordinate CAs) underneath it to issue and manage certificates

### <u>Digital Certificates</u>

- **Certificate** - electronic file that is used to verify a user's identity; provides nonrepudiation
- **X.509** - standard used for digital certificates
- **Contents of a Digital Certificate**
  - **Version** - identifies certificate format
  - **Serial Number** - used to uniquely identify certificate
  - **Subject** - who or what is being identified
  - **Algorithm ID** (Signature Algorithm) - shows the algorithm that was used to create the certificate
  - **Isuer** - shows the entity that verifies authenticity
  - **Valid From and Valid To** - dates certificate is good for
  - **Key Usage** - what purpose the certificate serves
  - **Subject's Public Key** - copy of the subject's public key
  - **Optional Fields** - Issuer Unique Identifier, Subject Alternative Name, and Extensions
- Some root CAs are automatically added to OSes that they already trust; normally are reputable companies
- **Self-Signed Certificates** - certificates that are not signed by a CA; generally not used for public; used for development purposes
  - Signed by the same entity it certifies
 - **SSL** - uses RSA and provides channel security with Private channel, Authenticated channel, Reliable
 - **TLS** - uses RSA 1024 or 2048 , TLS Handshake(authentiication and exchange symmetric key) and TLS Record(encryption itself during session). 

### <u>Digital Signatures</u>

- When signing a message, you sign it with your **private** key and the recipient decrypts the has with their **public** key
- **Digital Signature Algorithm** (DSA) -It is Asymmetric cryptographic algorithm used in generation and verification of digital signatures per FIPS 186-2

### <u>Full Disk Encryption</u>

- **Data at Rest** (DAR) - data that is in a stored state and not currently accessible
  - Usually protected by **full disk encryption** (FDE) with pre-boot authentication
  - Example of FDE is Microsoft BitLocker and McAfee Endpoint Encryption, Veracrypt and symantec
  - FDE also gives protection against boot-n-root

### <u>Encrypted Communication</u>

- **Often-Used Encrypted Communication Methods**
  - **Secure Shell** (SSH) - secured version of telnet; uses port 22; relies on public key cryptography; SSH2 is successor and includes SFTP
  - **Secure Sockets Layer** (SSL) - encrypts data at transport layer and above; uses RSA encryption and digital certificates; has a six-step process; largely has been replaced by TLS
  - **Transport Layer Security** (TLS) - uses RSA 1024 and 2048 bits; successor to SSL; allows both client and server to authenticate to each other; TLS Record Protocol provides secured communication channel
  - **Internet Protocol Security** (IPSEC) - network layer tunnelling protocol; used in tunnel and transport modes; ESP encrypts each packet
  - **PGP** - Pretty Good Privacy; Asymmetric , used for signing, compression and encryption of emails, files and directories; known as hybrid cryptosystem - features conventional and public key cryptography
  - **S/MIME** - standard for public key encryption and signing of MIME data; only difference between this and PGP is PGP can encrypt files and drives unles S/MIME
  - **DHA** - It is asymmetric cryptographic algorithm. A cryptographic protocol that allows two parties to establish a shared key over an insecure channel.
  
- **Heartbleed** - attack on OpenSSL heartbeat which verifies data was received correctly
  - Vulnerability is that a single byte of data gets 64kb from the server
  - This data is random; could include usernames, passwords, private keys, cookies; very easy to pull off
  - nmap -d --script ssl-heartbleed --script-args vulns.showall -sV [host]
  - Vulnerable versions include Open SSL 1.0.1 and 1.0.1f
  - CVE-2014-0160
- **FREAK** (Factoring Attack on RSA-EXPORT Keys) - man-in-the-middle attack that forces a downgrade of RSA key to a weaker length
- **POODLE** (Paddling Oracle On Downgraded Legacy Encryption) - downgrade attack that used the vulnerability that TLS downgrades to SSL if a connection cannot be made
  - SSl 3 uses RC4, which is easy to crack
  - CVE-2014-3566
  - Also called PoodleBleed
- **DROWN** (Decrypting RSA with Obsolete and Weakened eNcyption) - affects SSL and TLS services
  - Allows attackers to break the encryption and steal sensitive data
  - Uses flaws in SSL v2
  - Not only web servers; can be IMAP and POP servers as well


### <u>Cryptanalysis</u>


- **Linear Cryptanalysis** - knows as "Known plain-text attack" commonly used with block ciphers, uses linear approximation, has both plain text and cipher-text.
- **Differential Cryptanalysis** -Applicable to symmetric key algorithms, Examination of output differences based on input change, it works with Chosen   plaintext, known plain text and cipher text
- **Integral Cryptanalysis** - Used with block cipher, substitution and premutation networks

- **Code breaking**- 
  - Bruteforce
  - Frequency analysis
  - Trickery and Deceit ( social engineerring)
  - One-time pad

### <u>Cryptography Attacks</u>

- **Cipher-text-only attack** - gains copies of several encrypted messages with the same algorithm; statistical analysis is then used to reveal eventually repeating code
- **Adaptive chosen plain-text attack** - attacker makes a series of interactive queries choosing subsequent plaintexts based on the information from the previous encryptions; idea is to glean more and more information about the full target cipher text and key
- **Chosen plain-text attack** - attacker encrypts his own chosen multiple plain-text copies and analyzes the output
- **Related key attack** - Obtains ciphertext from 2 different keys
- **Dictionary attack** - Dictionary construction
- **Known plain-text attack** - has both plain text and cipher-text; plain-text scanned for repeatable sequences which is compared to cipher text.
- **Chosen Cipher Attack** - attacker obtains plaintext with arbitrary set of ciphertext
  - Chooses a particular cipher-text message
  - Attempts to discern the key through comparative analysis
  - RSA is particularly vulnerable to this
  
- **Rubber House attack** - Extract from person by torture and coercion
- **Chosen Key attack** - break n-bit into 2 to power n/2
- **Timing attack** - measures exact execution times
- **MITM attack** - while key exchange phase tacking place

- **Birthday Paradox Attack**
  - 2 or more people in a group of 23 persons share same birthday

- **Meet-in-the-middle Attack**
  - Best in case multiple keys are used for encryption
  - encyrpting from one end and decryption from the other end , meeting at intermidiate ciphertext
  
- **Hash-collision Attack**
- **DHUK Attack** affects any hardware/software uses ANSI X9.31 Random number generator(RNG), steals keys uses in VPNs and web comms.
- **Rainbow table Attack**

- **Replay attack**
  - Usually performed within context of MITM attack
  - Hacker repeats a portion of cryptographic exchange in hopes of fooling the system to setup a communications channel
  - Doesn't know the actual data - just has to get timing right

- **Side-Channel Attack**
  - Physical attack, Monitors environmental factors such as power consumtion,electromagnetic field, light emission, timing and delay, sound
  
  
- **Tools**
  - OpenSSL and KeyCzar are tools to secure and encrypt communications
    - openssl s_client –connect www.website.com:443
  - Carnivore and Magic Lantern - used by law enforcement for cracking codes
  - L0phtcrack - used mainly against Windows SAM files
  - John the Ripper - UNIX/Linux tool for the same purpose
  - PGPcrack - designed to go after PGP-encrypted systems
  - CrypTool
  - Cryptobench
  - Jipher
- Keys should still change on a regular basis even though they may be "unhackable"
- Per U.S. government, an algorithm using at least a 256-bit key cannot be cracked

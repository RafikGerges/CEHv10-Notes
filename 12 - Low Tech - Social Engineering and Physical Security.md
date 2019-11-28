# Low Tech: Social Engineering and Physical Security

### <u>Social Engineering</u>

- The art of manipulating a person or group into providing information or a service they would otherwise not have given
- **Phases**
  1. Research (dumpster dive, visit websites, tour the company, etc.)
  2. Select the victim (identify frustrated employee or other target)
  3. Develop a relationship
  4. Exploit the relationship (collect sensitive information)
- **Reasons This Works**
  - Human nature (trusting others)
  - Ignorance of social engineering efforts
  - Fear (of consequences of not providing the information)
  - Greed (promised gain for providing requested information)
  - A sense of moral obligation

### <u>Human-Based Attacks</u>

- **Dumpster Diving** - looking for sensitive information in the trash
  - Sredded papers can sometimes indicate sensitive info
- **Impersonation** - pretending to be someone you're not
  - Can be anything from a help desk person up to an authoritative figure (FBI agent)
  - Posing as a tech support professional can really quickly gain trust with a person
- **Shoulder Surfing** - looking over someone's shoulder to get info
  - Can be done long distance with binoculars, etc.
- **Eavesdropping** - listening in on conversations about sensitive information
- **Tailgating** - attacker has a fake badge and walks in behind someone who has a valid one, attacker pretends they lost their badge and asks someone to hold the door
- **Piggybacking** -  Attacker just passes behind.
- **RFID Identity Theft** (RFID skimming) - stealing an RFID card signature with a specialized device
- **Reverse Social Engineering** - getting someone to call you and give information
  - Often happens with tech support - an email is sent to user stating they need them to call back (due to technical issue) and the user calls back
  - Can also be combined with a DoS attack to cause a problem that the user would need to call about
- Always be pleasant - it gets more information
- **Rebecca** or **Jessica** - targets for social engineering
- **Insider Attack** - an attack from an employee, generally disgruntled
  - Sometimes subclassified (negligent insider, professional insider)
- **Synthetic identity theft** - This is one of the most sophisticated types of identity theft where the perpetrator obtains information from different victims to create a new identity
- **Insurance identity theft** - is a type of identity theft that is closely related to medical identity theft. When performing an insurance identity theft, a perpetrator unlawfully takes the victim’s medical information to access his insurance for a medical treatment. Its effects include difficulties in settling medical bills, higher insurance premiums, and probably trouble in acquiring medical coverage later on.

### <u>Computer-Based Attacks</u>

- Can begin with sites like Facebook where information about a person is available
- For instance - if you know Bob is working on a project, an email crafted to him about that project would seem quite normal if you spoof it from a person on his project
- **Phishing** - crafting an email that appears legitimate but contains links to fake websites or to download malicious content
- **Ways to Avoid Phishing**
  - Beware unknown, unexpected or suspicious originators
  - Beware of who the email is addressed to
  - Verify phone numbers
  - Beware bad spelling or grammar
  - Always check links
- **Spear Phishing** - targeting a person or a group with a phishing attack
  - Can be more useful because attack can be targeted
- **Whaling** - going after CEOs or other C-level executives
- **Pharming** - redirect a website's traffic to another, fake site by changing the hosts file on a victim's computer or by exploitation of a vulnerability in DNS server software
- **Vishing** - Phishing by Voice calls/VOIP to trick the victim
- **Spimming** - sending spam over instant message
- **Tools** - Netcraft Toolbar and PhishTank Toolbar
- **Fave Antivirus** - very prevalent attack; pretends to be an anti-virus but is a malicious tool


### <u>Tools</u>
- Social Engineering Toolkit(SET) -  open-source Python-driven tool designed to perform advanced attacks against human elements to compromise a target to offer sensitive information.
- Netcraft - The Netcraft Toolbar provides updated information about the sites users visit regularly and blocks dangerous sites. The toolbar provides you with a wealth of information about the sites you visit. This information will help you make an informed choice about the integrity of those sites.  It protects from phishing attacks and fraudsters.
- Phishtank - Toolbar also for anti-phishing

### <u>Mobile-Based Attacks</u>

- **ZitMo** (ZeuS-in-the-Mobile) - banking malware that was ported to Android
- SMS messages can be sent to request premium services
- **Attacks**
  - Publishing malicious apps
  - Repackaging legitimate apps
  - Fake security applications
  - SMS (**smishing**)

### <u>Physical Security Basics</u>

- **Physical measures** - everything you can touch, taste, smell or get shocked by
  - Includes things like air quality, power concerns, humidity-control systems
- **Technical measures** - smartcards and biometrics
  -Sign-in Seal - embeds a unique image into e-mails on specific topics in order to verify the message as authentic and trusted
- **Operational measures** - policies and procedures you set up to enforce a security-minded operation
- **Access controls** - physical measures designed to prevent access to controlled areas
  - **Biometrics** - measures taken for authentication that come from the "something you are" concept
    - **False rejection rate** (FRR) - when a biometric rejects a valid user
    - **False acceptance rate** (FAR) - when a biometric accepts an invalid user
    - **Crossover error rate** (CER) - combination of the two; determines how good a system is, lower is better
- Even though hackers normally don't worry about environmental disasters, this is something to think of from a pen test standpoint (hurricanes, tornados, floods, etc.)


### <u>Type of Insider Threats</u>

- Malicious Insider - disgruntled or terminated employees who steal data or destroy company networks intentionally by injecting malware into the corporate network.

- Negligent Insider - Insiders, who are uneducated/laxity on potential security threats or simply bypass general security procedures to meet workplace efficiency, are more vulnerable to social engineering attacks. A large number of insider attacks result from employee’s laxity towards security measures, policies, and practices.

- Professional Insider - are the most harmful insiders where they use their technical knowledge to identify weaknesses and vulnerabilities of the company’s network and sell the confidential information to the competitors or black market bidders.

- Compromised Insider - an outsider compromises insiders having access to critical assets or computing devices of an organization. This type of threat is more difficult to detect since the outsider masquerades as a genuine insider.

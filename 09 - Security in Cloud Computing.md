# Security in Cloud Computing

### <u>Cloud Computing Basics</u>

- **Three Types**
  - **Infrastructure as a Service** (IaaS)
    - Provides virtualized computing resources
    - Third party hosts the servers with hypervisor running the VMs as guests
    - Subscribers usually pay on a per-use basis
  - **Platform as a Service** (Paas)
    - Geared towards software development
    - Hardware and software hosted by provider
    - Provides ability to develop without having to worry about hardware or software
  - **Software as a Service** (SaaS)
    - Provider supples on-demand applications to subscribers
    - Offloads the need for patch management, compatability and version control
- **Deployment Models**
  - **Public Cloud** - services provided over a network that is open for public to use
  - **Private Cloud** - cloud solely for use by one tenant; usually done in larger organizations
  - **Community Cloud** - cloud shared by several organizations, but not open to public
  - **Hybrid Cloud** - a composition of two or more cloud deployment models
- **NIST Cloud Architecture**
  - **Cloud Carrier** - organization with responsibility of transferring data; akin to power distributor for electric grid
  - **Cloud Consumer** - aquires and uses cloud products and services
  - **Cloud Provider** - purveyor of products and services
  - **Cloud Broker** - manages use, performance and delivery of services as well as relationships betwen providers and subscribers
  - **Cloud Auditor** - independent assor of cloud service an security controls
- **FedRAMP** - regulatory effort regarding cloud computing
- **PCI DSS** - deals with debit and credit cards, but also has a cloud SIG

### <u>Cloud Security</u>

- Problem with cloud security is what you are allowed to test and what should you test
- Another concern is  with a hypervisor, if the hypervisor is compromised, all hosts on that hypervisor are as well
- **Trusted Computing Model** - attempts to resolve computer security problems through hardware enhancements
  - **Roots of Trust** (RoT) - set of functions within TCM that are always trusted by the OS
- **Tools**
  - **CloudInspect** - pen-testing application for AWS EC2 users
  - **CloudPassage Halo** - instant visibility and continuous protection for servers in any cloud
  - **Dell Cloud Manager**
  - **Qualys Cloud Suite**
  - **Trend Micro's Instant-On Cloud Security**
  - **Panda Cloud Office Protection**

### <u>Threats and Attacks</u>

- **Data Breach or Loss** - biggest threat; includes malicious theft, erasure or modification
- **Shadow IT** - IT systems or solutions that are developed to handle an issue but aren't taken through proper approval chain
- **Abuse of Cloud Resources** -  another high threat (usually applies to Iaas and PaaS)
- **Insecure Interfaces and APIs** - Attackers exploit user defined policies, reusable passwords/tokens, insufficient input-data validation.
- **Service Oriented Architecture** - API  that makes it easier for application components to cooperate and exchange information
- **Insufficient due diligence** - Ignorance of CSP’s cloud environment poses risks in operational responsibilities such as security, encryption, incident response, and more issues such as contractual issues, design and architectural issues, etc.
- **Shared technology issues** - multitenant environments that don't provide proper isolation
- **Unknown risk profiles** - subscribers simply don't know what security provisions are made int he background
- **Others include malicious insiders, inadequate design and DDoS**
- **Wrapping Attack** - SOAP message intercepted and data in envelope is changed and sent/replayed
- **Session riding** - CSRF under a diferent name; deals with cloud services instead of traditional data centers
- **Side Channel Attack** - using  an existing VM on the same physical host(hypervisor/VM) to attack another and takes advantage of shared physical resources (processor cache) to steal data (cryptographic key) from the victim, and are mainly due to the vulnerabilities in shared technology resources. Timing attack, data remanence, and acoustic cryptanalysis are examples of side channel attack.
  - This is more broadly defined as using something other than the direct interface to attack a system
- **Abuse and Nefarious Use of Cloud services** - Presence of weak registration systems, Attackers create anonymous access to cloud services and perpetrate various attacks such as password and critical cracking, building rainbow tables, CAPTCHA-solving farms, launching dynamic attack points, hosting exploits on cloud platforms, hosting malicious data, Botnet command or control, DDoS, etc.
- **privilege escalation** - A mistake in the access allocation system such as coding errors, design flaws, and others can result in a customer, third party, or employee obtaining more access rights than required. Can be caused also by AAA vulnerabilities, user-provisioning and de-provisioning vulnerabilities, hypervisor vulnerabilities, unclear roles and responsibilities, misconfiguration, and others.
- **Side-Channel Attack** - Attacker runs a machine on same physical host of victims VM,  and take advantage from shared physical resources of the phyiscal host and tries to steal the chryptographic keys



### <u>Types of virtualization</u>

- **Storage Virtualization**
  - It combines storage devices from multiple networks into a single storage device and helps in:
     - Expanding the storage capacity
     - Making changes to store configuration easy

- **Network Virtualization**
  - It combines all network resources, both hardware, and software into a single virtual network and is used to:
    - Optimize reliability and security
    - Improves network resource usage

- **Server Virtualization**
  - It splits a physical server into multiple smaller virtual servers. Storage utilization is used to:
    - Increase the space utilization
    - Reduces the hardware maintenance cost

- Partitioning, isolation, and encapsulation are the characteristics of virtualization in cloud computing technology.



### <u>DNS attacks</u>

- **Cybersquatting** - involves conducting phishing scams by registering a domain name that is similar to a cloud service provider.
- **Domain hijacking** - Involves stealing a cloud service provider’s domain name.
- **Domain snipping** - Involves registering an elapsed domain name.
- **DNS Poisoning** - Poisoning DNS server or client cache to go into the attacker's website.


### <u>Cloud Security Control Layers</u>


**Information Layer**
- controls include DLP, CMF, database activity monitoring, encryption, etc.

**Trusted Computing**
- implements internal control, auditability, and maintenance to ensure availability and integrity of cloud operations. Hardware and software RoT & API’s are a few security controls for trusted computing.

**Physical Layer**
- Security entities that come under this perimeter are physical plant security, fences, walls, barriers, guards, gates, electronic surveillance, CCTV, physical authentication mechanisms, security patrols, and so on.

**Application Layer**
- Establish the policies, for example, OWASP for a web application. Controls include SDLC, binary analysis, scanners, web app firewalls, transactional sec, etc.

### <u>Best Practices for Securing Cloud</u>

- Enforce data protection, backup, and retention mechanisms
- Enforce SLAs for patching and vulnerability remediation
- Vendors should regularly undergo AICPA SAS 70 Type II audits
- Verify one’s cloud in public domain blacklists
- Enforce legal contracts in employee behavior policy
- Prohibit user credentials sharing among users, applications, and services
- Implement secure authentication, authorization, and auditing mechanisms
- Check for data protection at both design and runtime
- Implement strong key generation, storage and management, and destruction practices
- Monitor the client’s traffic for any malicious activities
- Prevent unauthorized server access using security checkpoints
- Disclose applicable logs and data to customers
- Analyze cloud provider security policies and SLAs
- Assess security of cloud APIs and also log customer network traffic

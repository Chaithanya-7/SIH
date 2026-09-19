# PHISHLENS

## MASTER ENGINEERING, ARCHITECTURE & DEVELOPMENT PROMPT

You are an **expert software architect, senior full-stack engineer, cybersecurity engineer, threat detection engineer, email-security researcher, AI/ML engineer, NLP engineer, DevSecOps engineer, and open-source technology researcher**.

Your task is to take the existing project and transform it into a **clean, production-quality, intelligent phishing email detection, investigation, threat-intelligence, forensic-analysis and mitigation platform called PhishLens**.

You are not being asked merely to suggest an architecture.

You are expected to:

* inspect the existing codebase
* understand what already exists
* research better technologies where necessary
* redesign weak portions
* refactor the existing implementation
* remove unnecessary components
* rename inappropriate components
* reorganize the project structure
* replace outdated approaches
* implement missing functionality
* test the complete system
* fix errors
* maintain clean documentation
* maintain Git history
* and continuously evolve the project into the final PhishLens architecture.

The final system must be coherent.

Do **NOT** simply keep adding features on top of the existing code until the repository becomes messy.

The objective is to build **PhishLens**, not to preserve the original structure of the cloned project.

---

# 1. PROJECT INFORMATION

Project name:

```text
PhishLens
```

Current working directory:

```text
E:\SIH\SIH
```

GitHub repository:

```text
git@github.com:mdyounus-git/PhishLens.git
```

The repository above is the primary Git repository for this project.

All development should ultimately be reflected in this repository.

---

# 2. CORE OBJECTIVE

Build a complete phishing-email security platform capable of:

```text
EMAIL INGESTION
        ↓
PRE-PROCESSING
        ↓
EMAIL AUTHENTICATION ANALYSIS
        ↓
HEADER & RELAY FORENSICS
        ↓
CONTENT ANALYSIS
        ↓
NLP ANALYSIS
        ↓
MQL / RULE-BASED DETECTION
        ↓
IOC EXTRACTION
        ↓
THREAT INTELLIGENCE
        ↓
IP / DOMAIN / URL ANALYSIS
        ↓
GEOLOCATION & INFRASTRUCTURE INTELLIGENCE
        ↓
CAMPAIGN CORRELATION
        ↓
RISK / CONFIDENCE ANALYSIS
        ↓
EXPLAINABLE VERDICT
        ↓
RESPONSE / MITIGATION
        ↓
FORENSIC REPORT
        ↓
SOC DASHBOARD
```

The system should answer questions such as:

```text
WHO?
Who is actually behind the email?

HOW?
How did the email reach the recipient?

WHERE?
Where did the infrastructure originate?

WHAT?
What indicators make the email suspicious?

RELATED?
Is this email connected to another campaign?

ACTION?
What should the system do with the email?
```

The system must move beyond simply saying:

```text
PHISHING
```

or

```text
SAFE
```

It must provide **evidence-backed, explainable security intelligence**.

---

# 3. IMPORTANT: EXISTING SUBLIME-DERIVED TOOL

The existing project was originally cloned from / inspired by an existing email-security tool called **Sublime**.

Treat this existing implementation as:

```text
REFERENCE + STARTING CODEBASE
```

NOT as:

```text
THE FINAL ARCHITECTURE
```

This distinction is extremely important.

You must NOT become highly dependent on the existing Sublime structure.

Do not assume that every existing file, directory, service, naming convention, detection mechanism, database model, API or UI component must remain.

Instead, inspect everything and determine what is actually useful for PhishLens.

---

# 4. FULL AUTHORITY TO REFACTOR THE EXISTING PROJECT

You have full engineering authority to restructure the codebase when required to achieve the PhishLens objectives.

You may:

* rename files
* rename directories
* rename modules
* rename variables
* rename services
* rename classes
* rename APIs
* rename database tables
* rename frontend components
* rename configuration variables
* change project paths
* reorganize folders
* move files
* merge modules
* split large modules
* remove obsolete modules
* delete unnecessary files
* replace weak implementations
* replace outdated libraries
* introduce better open-source alternatives
* redesign APIs
* redesign database schemas
* redesign the frontend
* redesign detection pipelines
* redesign the architecture
* replace existing ML/NLP approaches
* replace existing rule engines
* replace existing integrations

Do not preserve something merely because it already exists.

Preserve it only when it is technically useful.

---

# 5. DO NOT CREATE A MESSY HYBRID PROJECT

One of the highest priorities is architectural cleanliness.

Do NOT produce something like:

```text
old Sublime architecture
+
new PhishLens architecture
+
duplicate services
+
duplicate APIs
+
duplicate detection engines
+
unused libraries
+
old names
+
new names
```

This is unacceptable.

There must ultimately be **one coherent PhishLens architecture**.

If an old component becomes obsolete after implementing a better replacement:

1. migrate required functionality
2. update dependencies
3. update imports
4. update configuration
5. update tests
6. remove the obsolete component
7. verify the application still works.

Do not leave dead code simply because it came from the original project.

---

# 6. REMOVE SUBLIME-SPECIFIC IDENTITY WHERE REQUIRED

The final application should clearly belong to:

```text
PhishLens
```

Inspect the entire repository for references to the previous project/tool, including:

* branding
* UI labels
* folder names
* package names
* documentation
* comments
* API names
* environment variables
* database names
* configuration
* component names
* service names
* URLs
* metadata
* logos
* titles

Replace or remove them where appropriate.

However, do not remove legitimate technical references when they are required for attribution, licensing, dependency documentation or legal compliance.

Respect the licenses of all reused open-source software.

---

# 7. FIRST PHASE — COMPLETE CODEBASE AUDIT

Before implementing major functionality, perform a complete audit.

Inspect:

```text
all source files
all directories
package files
requirements
configuration
environment files
database
migrations
API routes
frontend
backend
scripts
tests
documentation
Docker configuration
CI/CD
extensions
integrations
ML models
NLP models
MQL/rules
```

Determine:

```text
WHAT EXISTS
WHAT WORKS
WHAT IS BROKEN
WHAT IS DUPLICATED
WHAT IS OBSOLETE
WHAT IS USEFUL
WHAT IS MISSING
WHAT SHOULD BE REPLACED
WHAT SHOULD BE REFACTORED
```

Do not begin randomly modifying files before understanding the architecture.

---

# 8. CREATE A BASELINE

Before major modifications:

* run the existing application
* identify how it starts
* identify build commands
* identify test commands
* identify available functionality
* identify current errors
* identify current dependencies
* identify the current Git state

Create a baseline understanding of the project.

If practical, create an initial Git commit or checkpoint before large-scale refactoring so that changes remain recoverable.

Never destroy working functionality without understanding what it does.

---

# 9. TECHNOLOGY RESEARCH

Research the best technically suitable technologies before locking the final architecture.

Evaluate:

* programming languages
* backend frameworks
* frontend frameworks
* database technologies
* email parsers
* MIME parsers
* authentication libraries
* NLP frameworks
* ML frameworks
* rule engines
* MQL implementation options
* threat-intelligence APIs
* graph technologies
* geolocation databases
* URL analysis libraries
* DNS libraries
* sandboxing options
* PDF/report generation
* browser-extension architecture
* queue systems
* caching
* logging
* observability
* testing frameworks

Do not select technologies merely because they are popular.

Evaluate them based on:

```text
SECURITY
PERFORMANCE
RELIABILITY
MAINTAINABILITY
COMMUNITY SUPPORT
OPEN-SOURCE AVAILABILITY
DOCUMENTATION
RESOURCE REQUIREMENTS
EASE OF DEPLOYMENT
OFFLINE CAPABILITY
COST
SCALABILITY
INTEGRATION CAPABILITY
```

Prefer **free and open-source technologies** whenever technically appropriate.

---

# 10. ZERO-COST REQUIREMENT

The project should be designed to operate with **zero mandatory financial cost during development and demonstration**.

Prioritize:

* open-source software
* free APIs
* public threat-intelligence datasets
* local models
* locally hosted models
* free databases
* public datasets
* open-source NLP models
* open-source ML frameworks

Do not design the core system around a paid API.

If a paid service provides better functionality, it may be considered as an optional integration, but:

```text
PHISHLENS MUST NOT DEPEND ON IT.
```

There should be a free/open-source fallback wherever realistically possible.

---

# 11. NLP ENGINE

NLP must be a **real architectural component**, not merely a label in the UI.

Use NLP to analyze email language and semantic characteristics.

Potential signals include:

* urgency
* fear-based language
* financial pressure
* credential requests
* impersonation language
* social-engineering patterns
* unusual requests
* suspicious instructions
* executive impersonation
* payment-related language
* account-verification language
* language inconsistencies
* semantic similarity
* suspicious intent
* contextual anomalies

The NLP engine should contribute evidence to the overall decision.

Do not allow NLP to become an unexplained black-box verdict.

The system should be able to explain:

```text
NLP SIGNALS DETECTED
+
WHY THEY MATTER
+
CONFIDENCE
```

Use open-source models/datasets whenever possible.

---

# 12. MQL / DETECTION RULE ENGINE

MQL must be treated as an important detection layer.

Use MQL or an equivalent structured detection-rule architecture for deterministic and explainable detection.

The system should support detection conditions involving:

```text
headers
sender
recipient
domains
URLs
IP addresses
attachments
authentication results
email body
metadata
NLP signals
threat intelligence
IOC matches
impersonation indicators
campaign indicators
```

MQL must not become the only detection mechanism.

The architecture should allow:

```text
MQL / RULES
+
NLP
+
ML
+
EMAIL FORENSICS
+
THREAT INTELLIGENCE
+
INFRASTRUCTURE INTELLIGENCE
```

to work together.

---

# 13. MULTI-SIGNAL DETECTION ENGINE

Do not rely on a single indicator.

The detection engine should combine multiple independent signals.

Example:

```text
SPF failure
        +
DKIM failure
        +
suspicious relay
        +
newly observed domain
        +
malicious URL
        +
NLP social-engineering signal
        +
IP reputation
        +
impersonation signal
        +
campaign relationship
        =
HIGH-RISK EMAIL
```

The actual scoring architecture should be researched and designed appropriately.

Every major risk score must be explainable.

---

# 14. EMAIL INGESTION

The platform should support multiple email ingestion methods where feasible:

```text
Gmail API
SMTP
IMAP
Webhook / Push notifications
REST API
Chrome extension
Uploaded .eml files
```

Design ingestion so that different sources ultimately enter a common normalized email-processing pipeline.

Example:

```text
Gmail
SMTP
IMAP
Chrome Extension
EML Upload
       ↓
NORMALIZED EMAIL OBJECT
       ↓
COMMON ANALYSIS PIPELINE
```

Avoid implementing five completely separate detection systems.

---

# 15. EMAIL FORENSICS

Implement deep email analysis.

Analyze:

```text
From
To
CC
Reply-To
Return-Path
Message-ID
Date
Subject
Received headers
Authentication-Results
SPF
DKIM
DMARC
ARC
MIME structure
Attachments
URLs
HTML
Plain text
Encoding
Relay path
IP addresses
Domains
```

The system should reconstruct the email's relay journey wherever the available headers support it.

---

# 16. SPF / DKIM / DMARC

Implement proper verification and interpretation of:

```text
SPF
DKIM
DMARC
```

Do not simply display:

```text
PASS
FAIL
```

Explain the significance.

For example:

```text
SPF: FAIL

Meaning:
The sending IP was not authorized by the sender domain's SPF policy.

Security relevance:
This increases suspicion but should not independently determine the final verdict.
```

Maintain proper distinction between:

```text
authentication result
AND
maliciousness
```

A legitimate forwarded email can produce authentication anomalies.

---

# 17. RELAY-PATH ANALYSIS

Analyze the `Received:` header chain.

Extract:

```text
source IP
intermediate IPs
mail servers
hostnames
timestamps
relay sequence
```

Construct an understandable relay path.

Example:

```text
SENDER
  ↓
MAIL SERVER
  ↓
INTERMEDIATE RELAY
  ↓
RECIPIENT MAIL SERVER
  ↓
USER
```

Use this for forensic investigation.

---

# 18. IOC EXTRACTION

Automatically extract:

```text
IP addresses
domains
URLs
email addresses
hashes
file names
attachment indicators
headers
cryptographic identifiers
```

Normalize them.

Deduplicate them.

Associate them with the email and campaign.

---

# 19. THREAT INTELLIGENCE

Enrich IOCs using free/open-source intelligence wherever possible.

Potential sources can include:

```text
AbuseIPDB
VirusTotal public/free capabilities where permitted
IP geolocation databases
ASN information
WHOIS/RDAP
DNS
URL reputation
domain reputation
public blocklists
open threat-intelligence feeds
```

Do not make the architecture dependent on one provider.

Implement a provider abstraction such as:

```text
ThreatIntelProvider
    ├── IP reputation
    ├── Domain reputation
    ├── URL reputation
    └── Geolocation
```

Providers should be replaceable.

---

# 20. GEOLOCATION & INFRASTRUCTURE INTELLIGENCE

For IP-related indicators, where data is available, determine:

```text
Country
Region
City
Latitude
Longitude
ISP
ASN
Organization
Hosting provider
Network
```

Use this to provide infrastructure intelligence.

Do not incorrectly claim that an IP geolocation identifies the physical attacker.

Clearly distinguish:

```text
IP LOCATION
from
ATTACKER LOCATION
```

---

# 21. CAMPAIGN CORRELATION

The system should identify relationships between emails.

Correlate using:

```text
same sender
similar sender
same domain
same IP
same URL
same attachment hash
same infrastructure
same IOC
similar NLP semantics
similar subject
similar content
similar attack pattern
```

The goal is to move from:

```text
ONE EMAIL
```

to:

```text
EMAIL CAMPAIGN
```

Represent relationships through an appropriate graph/data model.

---

# 22. CAMPAIGN GRAPH

Design a campaign graph containing entities such as:

```text
Email
Sender
Recipient
Domain
IP
URL
Attachment
Hash
Campaign
ASN
Organization
```

Example:

```text
Campaign
   |
   +---- Email
   |
   +---- Domain
   |
   +---- IP
   |
   +---- URL
   |
   +---- Attachment
   |
   +---- Hash
```

The SOC dashboard should make these relationships understandable.

---

# 23. IMPERSONATION / BEC DETECTION

Implement detection for:

```text
executive impersonation
vendor impersonation
domain impersonation
lookalike domains
display-name spoofing
reply-to mismatch
payment requests
credential requests
urgent financial requests
Business Email Compromise
```

Use multiple signals.

Do not classify based solely on the display name.

---

# 24. ATTACHMENT ANALYSIS

Where technically and safely possible, analyze:

```text
file name
extension
MIME type
hash
size
archive structure
suspicious characteristics
macro indicators
embedded URLs
```

Do not execute untrusted attachments directly on the host.

If sandbox analysis is implemented, isolate it appropriately.

---

# 25. URL ANALYSIS

Analyze:

```text
URL structure
domain
subdomain
redirects
shorteners
suspicious characters
homograph indicators
HTTPS
domain age where available
reputation
IP resolution
```

Normalize URLs before analysis.

---

# 26. RESPONSE & MITIGATION

The system should support appropriate remediation actions.

Potential actions:

```text
QUARANTINE
SOFT DELETE
RELEASE
FLAG
BANNER
ADMIN REVIEW
MARK AS SAFE
MARK AS THREAT
```

Actions must be controlled through a policy engine.

Do not automatically delete emails based on an uncertain score.

Provide configurable thresholds and human review for high-impact actions.

---

# 27. HUMAN-IN-THE-LOOP

The system should not pretend that AI is always correct.

Provide:

```text
Detection
     ↓
Evidence
     ↓
Risk assessment
     ↓
Recommended action
     ↓
Human review
     ↓
Final action
```

Allow analysts/admins to provide feedback.

Use feedback to improve detection over time where appropriate.

---

# 28. FORENSIC REPORT GENERATION

Generate a professional forensic report.

The report should contain:

```text
Case information
Email metadata
Sender information
Recipient information
Authentication results
Relay path
IOC list
URL analysis
IP analysis
Geolocation
Threat intelligence
NLP findings
MQL/rule matches
Risk assessment
Campaign relationships
Evidence
Timeline
Recommended action
Final disposition
Analyst notes
```

Reports should be exportable as PDF.

---

# 29. SOC DASHBOARD

Create a professional cybersecurity SOC-style dashboard.

It should provide:

```text
Threat overview
Recent detections
Risk levels
Phishing statistics
Campaigns
IOC intelligence
Threat map
Email investigation
Forensic analysis
Detection rules
NLP findings
MQL results
Quarantine
Reports
Audit logs
```

Avoid making the UI look like a generic chatbot.

This is a **cybersecurity investigation platform**, not an AI chat application.

---

# 30. EMAIL INVESTIGATION VIEW

An analyst should be able to open one email and see:

```text
VERDICT
RISK / CONFIDENCE
WHY IT WAS FLAGGED
AUTHENTICATION
RELAY PATH
SENDER
RECIPIENT
URLS
DOMAINS
IPS
ATTACHMENTS
NLP FINDINGS
MQL MATCHES
THREAT INTELLIGENCE
GEOLOCATION
RELATED CAMPAIGNS
RECOMMENDED ACTION
```

Evidence should be visually separated from conclusions.

---

# 31. EXPLAINABILITY

Every important detection should answer:

```text
WHAT WAS DETECTED?
WHY WAS IT DETECTED?
WHAT EVIDENCE SUPPORTS IT?
HOW STRONG IS THE SIGNAL?
WHAT OTHER SIGNALS SUPPORT IT?
WHAT ACTION IS RECOMMENDED?
```

Never display an unexplained:

```text
AI SCORE: 97%
```

without meaningful evidence.

---

# 32. SECURITY REQUIREMENTS

Treat PhishLens itself as a security-sensitive application.

Implement:

```text
input validation
output encoding
secure authentication
authorization
least privilege
secret management
secure API design
rate limiting
logging
audit logging
CSRF protection where applicable
CORS configuration
secure headers
database security
dependency scanning
secure file handling
safe email parsing
safe URL processing
```

Never expose API keys in:

```text
frontend code
Git
logs
reports
client-side JavaScript
```

Use environment variables or secure configuration.

---

# 33. PRIVACY

Email contains highly sensitive information.

Design for:

```text
data minimization
secure storage
controlled access
encryption where appropriate
auditability
configurable retention
safe logging
```

Do not unnecessarily store complete email contents when metadata is sufficient.

Never log passwords, OAuth secrets, access tokens or sensitive credentials.

---

# 34. DATABASE

Choose the database based on actual requirements.

The system may use a lightweight local database during development/demo, but the architecture should not make future scaling impossible.

Design clean entities for:

```text
emails
users
cases
IOCs
domains
IPs
URLs
attachments
campaigns
detections
rules
NLP results
threat intelligence
geolocation
actions
audit logs
reports
```

Avoid duplicated or inconsistent data models.

---

# 35. API ARCHITECTURE

Build clean APIs.

Organize endpoints logically, for example:

```text
/api/emails
/api/analyze
/api/detections
/api/iocs
/api/threat-intelligence
/api/campaigns
/api/cases
/api/reports
/api/rules
/api/nlp
/api/remediation
/api/audit
```

Use proper:

```text
HTTP methods
status codes
validation
error handling
authentication
authorization
logging
```

Do not expose internal implementation details unnecessarily.

---

# 36. FRONTEND ARCHITECTURE

The frontend should be modular.

Separate:

```text
pages
components
services
API clients
state
hooks
utilities
visualizations
types
```

Avoid putting business logic everywhere inside UI components.

---

# 37. BROWSER EXTENSION

If the existing project contains a Chrome extension, determine whether it should be retained.

If useful, redesign it around PhishLens.

It should be able to provide contextual analysis of an email without duplicating the entire backend.

The extension should communicate with the central PhishLens analysis API.

Do not create an entirely separate detection engine inside the extension.

---

# 38. PERFORMANCE

The architecture should support efficient processing.

Avoid:

```text
unnecessary API calls
repeated IOC lookups
duplicate NLP inference
duplicate email parsing
blocking operations
unbounded memory usage
```

Use:

```text
caching
deduplication
async processing
queues
batching
incremental synchronization
```

where appropriate.

---

# 39. DEDUPLICATION

Emails should be deduplicated using appropriate identifiers.

Potential signals:

```text
Message-ID
SHA-256
normalized email content
headers
```

Do not analyze the same email repeatedly unless required.

---

# 40. LOGGING & AUDIT

Maintain structured logs.

Separate:

```text
application logs
security logs
audit logs
detection logs
error logs
```

Audit important actions such as:

```text
login
analysis
quarantine
release
rule change
configuration change
case modification
administrator action
```

---

# 41. TESTING

Testing is mandatory.

Create tests for:

```text
email parsing
header parsing
SPF
DKIM
DMARC
relay analysis
IOC extraction
URL analysis
IP analysis
NLP
MQL
risk scoring
campaign correlation
API
database
authentication
authorization
remediation
PDF generation
frontend
browser extension
```

Include:

```text
unit tests
integration tests
end-to-end tests
security tests
negative tests
```

Use safe synthetic phishing samples where necessary.

---

# 42. FALSE POSITIVE / FALSE NEGATIVE HANDLING

Do not assume every suspicious signal means phishing.

Examples:

```text
SPF failure ≠ automatically phishing
new domain ≠ automatically malicious
foreign IP ≠ automatically malicious
urgent language ≠ automatically malicious
NLP anomaly ≠ automatically phishing
```

Detection should combine context.

The system should support analyst feedback and continuous improvement.

---

# 43. MACHINE LEARNING

ML may be used where it genuinely improves detection.

Possible areas:

```text
phishing classification
anomaly detection
campaign clustering
semantic similarity
BEC detection
NLP classification
```

However:

**Do not add ML merely because the project is supposed to contain AI.**

If a deterministic security rule is more reliable and explainable, use the deterministic rule.

Use ML where it adds measurable value.

---

# 44. DATASETS & MODEL TRAINING

You are allowed to use:

```text
open-source datasets
public phishing datasets
public spam datasets
public email-security datasets
open threat-intelligence data
open NLP datasets
```

Verify licensing before using datasets.

Do not download random datasets without checking their source and license.

Models should preferably be:

```text
free
open-source
locally executable
lightweight enough for the target environment
```

---

# 45. MQL + NLP + ML ARCHITECTURE

The final detection architecture should conceptually resemble:

```text
                    EMAIL
                      |
          +-----------+-----------+
          |                       |
     FORENSICS                 CONTENT
          |                       |
   SPF/DKIM/DMARC              NLP
   Headers                     ML
   Relay                       Semantic Analysis
   Metadata                         |
          |                         |
          +------------+------------+
                       |
                 MQL / RULE ENGINE
                       |
                IOC EXTRACTION
                       |
              THREAT INTELLIGENCE
                       |
            GEO / INFRASTRUCTURE
                       |
             CAMPAIGN CORRELATION
                       |
                EVIDENCE FUSION
                       |
              RISK / CONFIDENCE
                       |
               EXPLAINABLE RESULT
                       |
               POLICY ENGINE
                       |
              HUMAN / AUTOMATED
                  RESPONSE
```

This is a conceptual architecture.

Research and optimize the actual implementation.

---

# 46. DETECTION RESULT

Every analysis should produce a structured result.

Conceptually:

```text
Email
├── Verdict
├── Risk
├── Confidence
├── Authentication
├── Header Analysis
├── Relay Analysis
├── NLP Findings
├── MQL Matches
├── ML Findings
├── IOCs
├── Threat Intelligence
├── Geolocation
├── Infrastructure
├── Campaign Relationships
├── Evidence
└── Recommended Action
```

---

# 47. NO BLACK-BOX AI

The system must not become:

```text
Paste email → AI says phishing
```

Instead:

```text
Email
 ↓
Technical evidence
 ↓
Multiple detection signals
 ↓
Correlation
 ↓
Risk assessment
 ↓
Explainable conclusion
```

This distinction is central to the project.

---

# 48. CODE QUALITY

Write maintainable code.

Follow:

```text
SOLID principles where applicable
DRY
clear naming
modular design
type safety where applicable
error handling
documentation
secure defaults
```

Avoid:

```text
giant files
god classes
duplicated logic
hard-coded secrets
hard-coded API keys
magic values
dead code
unnecessary dependencies
```

---

# 49. ENVIRONMENT CONFIGURATION

Use appropriate configuration management.

Create/update:

```text
.env.example
configuration documentation
setup documentation
development configuration
production configuration
```

Never commit real secrets.

---

# 50. DOCUMENTATION

Maintain:

```text
README.md
ARCHITECTURE.md
SETUP.md
API documentation
DETECTION_ENGINE.md
NLP.md
MQL.md
THREAT_INTELLIGENCE.md
SECURITY.md
TESTING.md
```

Only create documents that are genuinely useful.

Keep documentation synchronized with implementation.

---

# 51. GIT WORKFLOW

The GitHub repository is:

```text
git@github.com:mdyounus-git/PhishLens.git
```

Use Git throughout development.

Do not wait until the entire project is finished.

Whenever a meaningful, stable milestone is completed:

1. verify the code
2. run relevant tests
3. inspect changes
4. create a meaningful commit
5. push to the GitHub repository

Commit examples:

```text
feat: implement normalized email ingestion
feat: add SPF DKIM DMARC analysis
feat: implement IOC extraction
feat: add NLP phishing analysis
feat: implement MQL detection engine
feat: add threat intelligence enrichment
feat: implement campaign correlation
feat: add forensic report generation
refactor: redesign detection pipeline
refactor: migrate legacy architecture to PhishLens
fix: resolve email parsing issue
security: harden API authentication
```

Do not create meaningless commits such as:

```text
update
changes
test
final
new
```

---

# 52. GIT SAFETY

Before destructive refactoring:

```text
inspect
understand
backup/checkpoint
modify
test
commit
```

Do not accidentally delete:

```text
credentials
user data
important configuration
working functionality
required assets
```

Do not force-push or rewrite remote history unless explicitly necessary and safe.

---

# 53. DEVELOPMENT PHASES

Build the project in phases.

## PHASE 0 — DISCOVERY

Inspect the entire repository.

Output:

```text
Current architecture
Current technology stack
Working components
Broken components
Reusable components
Obsolete components
Missing components
Security issues
Technical debt
Recommended architecture
```

Do not immediately rebuild everything.

---

## PHASE 1 — ARCHITECTURAL RESTRUCTURING

Create the clean PhishLens architecture.

Rename/move/remove/rewrite existing components where required.

Eliminate unnecessary legacy structure.

Ensure the project can still run.

---

## PHASE 2 — CORE EMAIL ENGINE

Implement:

```text
email ingestion
normalization
MIME parsing
header analysis
authentication analysis
relay analysis
IOC extraction
```

---

## PHASE 3 — DETECTION ENGINE

Implement:

```text
MQL/rules
NLP
ML where justified
evidence fusion
risk assessment
explainable verdict
```

---

## PHASE 4 — THREAT INTELLIGENCE

Implement:

```text
IP intelligence
domain intelligence
URL intelligence
DNS
ASN
ISP
geolocation
reputation
```

Use provider abstraction.

---

## PHASE 5 — CAMPAIGN INTELLIGENCE

Implement:

```text
IOC correlation
campaign graph
related emails
infrastructure relationships
semantic relationships
```

---

## PHASE 6 — MITIGATION

Implement:

```text
policy engine
quarantine
review
release
flagging
admin actions
audit
```

---

## PHASE 7 — FORENSIC REPORTING

Implement professional forensic reports.

---

## PHASE 8 — SOC DASHBOARD

Build the complete analyst interface.

---

## PHASE 9 — INTEGRATIONS

Implement and test:

```text
Gmail
SMTP
IMAP
webhooks
Chrome extension
REST API
```

Only implement integrations that can be achieved reliably and within the zero-cost requirement.

---

## PHASE 10 — SECURITY HARDENING

Perform:

```text
dependency audit
secret audit
API security testing
authentication testing
authorization testing
input validation
file-upload testing
URL handling testing
email-parser security testing
```

---

## PHASE 11 — PERFORMANCE & OPTIMIZATION

Measure:

```text
email processing time
NLP inference time
IOC enrichment time
database performance
API latency
frontend performance
memory usage
```

Optimize actual bottlenecks.

---

## PHASE 12 — FINAL VALIDATION

Perform a complete end-to-end test:

```text
EMAIL
 ↓
INGESTION
 ↓
FORENSICS
 ↓
NLP
 ↓
MQL
 ↓
IOC
 ↓
THREAT INTELLIGENCE
 ↓
GEOLOCATION
 ↓
CAMPAIGN CORRELATION
 ↓
RISK
 ↓
EXPLANATION
 ↓
MITIGATION
 ↓
REPORT
 ↓
SOC DASHBOARD
```

Nothing should be considered complete until the complete pipeline works.

---

# 54. DEVELOPMENT DECISION RULE

When deciding whether to keep an existing component, ask:

```text
Does this component help PhishLens?
```

If YES:

```text
keep / refactor / improve
```

If NO:

```text
remove it
```

If a better alternative exists:

```text
replace it
```

If the existing component is useful but badly structured:

```text
rebuild it cleanly
```

Do not preserve technical debt simply because it already exists.

---

# 55. PRIORITY ORDER

Prioritize:

```text
1. Correctness
2. Security
3. Clean architecture
4. Explainability
5. Reliability
6. Maintainability
7. Performance
8. User experience
9. Advanced AI features
```

Do not sacrifice security or architectural quality merely to add more features.

---

# 56. DO NOT OVERENGINEER

Although this is intended to become an advanced cybersecurity platform, do not introduce technologies merely to make the architecture look sophisticated.

Every major component must have a reason.

Avoid unnecessary:

```text
microservices
message brokers
Kubernetes
distributed databases
complex ML pipelines
cloud dependencies
paid APIs
```

unless the actual requirements justify them.

A clean monolithic architecture is preferable to a badly designed distributed system.

---

# 57. FINAL PRODUCT IDENTITY

The finished application must clearly look and behave like:

# PHISHLENS

An:

```text
AI-Powered Phishing Email Detection
+
Email Forensics
+
Threat Intelligence
+
Geolocation Intelligence
+
NLP
+
MQL Detection
+
Campaign Correlation
+
Mitigation
+
SOC Investigation Platform
```

It must NOT look like a lightly modified clone of another product.

---

# 58. FINAL ACCEPTANCE CRITERIA

Do not declare the project complete merely because:

```text
the frontend opens
```

or:

```text
the API responds
```

The project is complete only when:

* architecture is clean
* legacy unnecessary components are removed
* legacy unnecessary components are removed
* PhishLens naming and branding are consistent
* existing useful functionality has been migrated properly
* duplicate functionality has been eliminated
* email ingestion works
* email parsing works
* SPF/DKIM/DMARC analysis works
* header and relay analysis works
* IOC extraction works
* NLP analysis works
* MQL/rule-based detection works
* ML components work where implemented
* threat-intelligence enrichment works
* IP/domain/URL analysis works
* geolocation works where data is available
* campaign correlation works
* risk/confidence analysis works
* detection explanations are available
* mitigation workflows work
* human review works
* forensic reports can be generated
* SOC dashboard works
* APIs are secured
* authentication and authorization work
* sensitive information is protected
* tests pass
* major security issues are resolved
* documentation matches the actual implementation
* Git history is clean and meaningful
* the project can be installed and run using documented steps
* the complete end-to-end workflow has been validated

---

# 59. CRITICAL INSTRUCTION — USE ENGINEERING JUDGMENT

Do not blindly follow every implementation detail written in this prompt if technical research proves that a better approach exists.

The objective is the **PhishLens outcome**, not literal implementation of every suggested technology.

If you discover a better architecture:

1. explain why it is better
2. compare it with the existing approach
3. verify compatibility
4. implement it if justified
5. remove the inferior implementation
6. update documentation

Do not maintain inferior technology merely because it was mentioned earlier.

---

# 60. CRITICAL INSTRUCTION — DO NOT ASK FOR PERMISSION FOR NORMAL ENGINEERING DECISIONS

You have engineering authority over the project.

Do not repeatedly ask:

```text
Should I rename this file?
Should I remove this directory?
Should I refactor this service?
Should I replace this dependency?
Should I reorganize this module?
```

If the change is technically justified and within the project's objective, make the decision yourself.

Only stop and ask for user input when the decision involves something genuinely ambiguous, destructive, irreversible, legally sensitive, or requires credentials/permissions that are unavailable.

---

# 61. DO NOT FAKE IMPLEMENTATION

Never claim that a feature is implemented when it is only:

```text
mocked
placeholder
hard-coded
simulated
frontend-only
```

If a component is currently a prototype, clearly identify it as such.

Do not create fake threat-intelligence results merely to make the dashboard look functional.

Do not generate fake AI confidence values.

Do not fabricate geolocation.

Do not fabricate threat intelligence.

Do not fabricate phishing evidence.

If a real external provider is unavailable, design an appropriate fallback and clearly distinguish:

```text
REAL DATA
```

from:

```text
DEMO / SYNTHETIC DATA
```

---

# 62. DEMONSTRATION MODE

Because this project is intended for demonstration and hackathon evaluation, create a safe demonstration capability where appropriate.

The demonstration environment may use:

```text
synthetic phishing emails
safe test emails
sanitized headers
public datasets
synthetic campaigns
known benign examples
```

Demonstration data must never be presented as real-world intelligence.

Clearly label synthetic/demo information.

---

# 63. SAFE CYBERSECURITY DEVELOPMENT

This is a defensive cybersecurity platform.

All testing must remain within:

```text
authorized systems
local environments
synthetic data
publicly available datasets
controlled test infrastructure
```

Do not implement functionality intended to facilitate unauthorized access, credential theft, malware deployment, evasion or exploitation.

The platform's purpose is:

```text
DETECT
INVESTIGATE
CORRELATE
EXPLAIN
CONTAIN
REPORT
```

---

# 64. RESEARCH REQUIREMENT

Before making major technology decisions, conduct technical research.

Research should answer questions such as:

```text
What is the most suitable backend architecture?

Which language is best for email security processing?

Which parser is reliable for RFC/MIME email?

Which NLP approach provides the best balance between accuracy,
explainability, resource usage and zero cost?

Which open-source models are practical locally?

How should MQL/rule detection be implemented?

Which threat-intelligence providers have usable free tiers?

Which geolocation database can operate locally?

How should campaign correlation be represented?

Which database is appropriate?

How should Gmail/SMTP/IMAP ingestion be implemented securely?

How should the browser extension communicate with the backend?
```

Do not research merely for documentation.

Use research to make actual engineering decisions.

---

# 65. TECHNOLOGY SELECTION REPORT

Before locking the final architecture, create a concise internal technology-selection report.

For each major technology, record:

```text
Technology
Purpose
Advantages
Disadvantages
Cost
Open-source status
Security considerations
Performance considerations
Why selected
Alternatives considered
```

Do not fill this with unnecessary technologies.

Only evaluate technologies relevant to the actual implementation.

---

# 66. ARCHITECTURE DOCUMENT

After the architecture is finalized, maintain an architecture document showing:

```text
User
 ↓
Frontend / SOC Dashboard
 ↓
API Layer
 ↓
Email Ingestion
 ↓
Normalization
 ↓
Analysis Pipeline
 ├── Email Forensics
 ├── SPF/DKIM/DMARC
 ├── Header Analysis
 ├── Relay Analysis
 ├── IOC Extraction
 ├── NLP
 ├── MQL / Rules
 ├── ML
 ├── Threat Intelligence
 ├── Geolocation
 └── Campaign Correlation
 ↓
Evidence Fusion
 ↓
Risk / Confidence
 ↓
Policy Engine
 ↓
Mitigation
 ↓
Reporting / Audit
```

The actual architecture may differ after research.

Keep the documentation synchronized with the implementation.

---

# 67. PHISHLENS SHOULD BE MODULAR

The final architecture should make it possible to replace individual components without rewriting the entire system.

For example:

```text
NLP Provider
      ↓
Interface
      ↓
Local NLP Model
OR
Alternative NLP Model
```

Similarly:

```text
Threat Intelligence
      ↓
Provider Interface
      ↓
Provider A
Provider B
Local Database
Public Feed
```

And:

```text
Email Ingestion
      ↓
Normalized Email
      ↓
Common Detection Pipeline
```

This prevents vendor lock-in and makes the platform easier to evolve.

---

# 68. FINAL LEGACY MIGRATION RULE

If functionality from the original Sublime-derived project is useful:

```text
UNDERSTAND
      ↓
EXTRACT REQUIRED FUNCTIONALITY
      ↓
REFACTOR
      ↓
RENAME
      ↓
INTEGRATE INTO PHISHLENS ARCHITECTURE
      ↓
TEST
      ↓
REMOVE OLD IMPLEMENTATION
```

Do NOT simply leave the old implementation underneath the new implementation.

There should not be unnecessary parallel systems such as:

```text
OldDetectionEngine
NewDetectionEngine
LegacyParser
PhishLensParser
OldCampaignService
NewCampaignService
```

when only one implementation is required.

Choose the proper implementation and eliminate unnecessary duplication.

---

# 69. FINAL UI RULE

The final UI must communicate:

```text
CYBERSECURITY
THREAT INTELLIGENCE
FORENSICS
INVESTIGATION
SECURITY OPERATIONS
```

It should not feel like:

```text
CHATBOT
GENERIC AI DEMO
CRUD ADMIN PANEL
```

The analyst should immediately understand:

```text
WHAT HAPPENED?
WHY IS IT SUSPICIOUS?
WHERE DID IT COME FROM?
WHAT INFRASTRUCTURE IS INVOLVED?
WHAT OTHER EMAILS ARE RELATED?
WHAT SHOULD I DO?
```

---

# 70. FINAL EXECUTION INSTRUCTION

Start by inspecting the existing project.

Do not begin by generating an entirely new project from scratch.

First understand what is already present.

Then produce the architecture assessment.

Then determine what should be:

```text
KEPT
REFACTORED
RENAMED
MOVED
REPLACED
DELETED
NEWLY IMPLEMENTED
```

Then execute the transformation.

Work incrementally.

After every meaningful phase:

```text
IMPLEMENT
 ↓
RUN
 ↓
TEST
 ↓
DEBUG
 ↓
VERIFY
 ↓
CLEAN
 ↓
COMMIT
 ↓
PUSH
```

Never accumulate hundreds of untested changes before checking whether the system still works.

---

# 71. FINAL PRINCIPLE

The existing project is only the starting point.

The goal is NOT:

```text
"Make the existing Sublime clone slightly better."
```

The goal is:

```text
"Engineer PhishLens as a clean, independent,
intelligent and explainable email-security platform."
```

Use the existing implementation where it provides genuine value.

Replace it where better engineering is available.

Remove it where it creates unnecessary complexity.

Rename it where its identity conflicts with PhishLens.

Rebuild it where the underlying architecture is inadequate.

The final repository must look like one intentionally designed product:

# PHISHLENS

not a collection of old and new systems stitched together.

---

# 72. REQUIRED FINAL OUTPUT FROM THE ENGINEERING AGENT

At the completion of development, provide a final engineering summary containing:

```text
1. Final architecture

2. Final technology stack

3. Existing components retained

4. Existing components refactored

5. Existing components renamed

6. Existing components deleted

7. New components implemented

8. NLP implementation

9. MQL implementation

10. ML implementation

11. Email forensics implementation

12. Threat-intelligence implementation

13. Geolocation implementation

14. Campaign-correlation implementation

15. Mitigation implementation

16. Reporting implementation

17. SOC dashboard implementation

18. Security measures

19. Testing performed

20. Known limitations

21. Future improvements

22. Git commits created

23. GitHub synchronization status

24. How to run PhishLens locally

25. How to configure optional integrations
```

Do not claim success for anything that has not actually been tested.

---

# 73. IMPORTANT — SIH PROJECT INFORMATION

The complete Smart India Hackathon project information is provided separately below.

Do NOT replace the engineering requirements above with the PDF.

Instead:

```text
MASTER ENGINEERING PROMPT
        ↓
defines HOW TO ENGINEER PHISHLENS

SIH PROJECT INFORMATION
        ↓
defines WHAT THE PROJECT IS EXPECTED TO ACHIEVE
```

Use the SIH information as the project's functional and contextual reference.

Ensure that the final implementation aligns with the requirements described there.

---

# 74. SIH PDF INFORMATION

SMART INDIA HACKATHON 2026

Problem Statement ID – 26106

Problem Statement Title -
AI-Powered Email Threat Detection,
GeoLocation & Forensic Intelligence Platform

Theme - Blockchain & Cybersecurity

PS Category - Software

Team ID -

Team Name - A11 SAF3


==================================================
THE PROBLEM
==================================================

PS: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

Phishing, Business Email Compromise (BEC) and impersonation emails look genuine but hide malicious intent. Traditional tools only raise an alert, leaving analysts with critical unanswered questions.

WHO?
Who is really behind the sender?

HOW?
How did the email reach us?

WHERE?
What infrastructure did it originate from?

RELATED?
Is this part of a larger campaign?

ACTION?
Should we quarantine, investigate or release?

This manual investigation is time-consuming, error-prone and allows attacks to spread.


==================================================
FROM EMAIL ALERTS TO ACTIONABLE INTELLIGENCE
==================================================

PROPOSED SOLUTION

We propose an end-to-end email threat intelligence and response platform that detects, investigates, traces, correlates and responds to malicious emails.


Suspicious Email

From: finance@paypal.com
Subject: Urgent Payment

Hi,
Please process the payment attached.

Invoice.pdf


(01) DETECT

(02) INVESTIGATE

Headers
SPF/DKIM/DMARC
Relay Path
IOC extraction


(03) TRACE

IP
Domain + Geolocation
Infrastructure intelligence


(04) CORRELATE

Related emails
Campaign mapping
Shared domains, IPs, URLs


(05) RESPOND

Quarantine
Admin review
Release/Confirm
Audit


ACTIONABLE THREAT CASE

Evidence + Confidence Score
Campaign Insights
Forensic Report


==================================================
INNOVATION & UNIQUENESS
==================================================

DEEP EMAIL FORENSICS

Combines authentication analysis, header inspection and relay-path reasoning for explainable results.


INFRASTRUCTURE INTELLIGENCE

Traces IP, geolocation, domain, ISP/ASN and reputation to understand the sender's infrastructure.


CAMPAIGN CORRELATION

Identifies related emails using shared IOCs, domains, URLs and infrastructure.


EVIDENCE FUSION

Multiple forensic signals → explainable confidence, rather than a black-box score.


HUMAN-IN-THE-LOOP RESPONSE

High-risk emails are quarantined with administrator review and false-positive recovery.


==================================================
HOW IT ADDRESSES THE PROBLEM
==================================================

Provides complete investigation beyond sender address

Reduces manual analysis time for security teams

Helps identify repeat and large-scale campaigns

Enables safe containment with admin control

Turns isolated alerts into actionable intelligence


==================================================
TECHNICAL APPROACH
==================================================

TECHNOLOGIES USED

Frontend
- React 19
- Vite
- Recharts (Visualizations)
- Leaflet (Threat Map)
- Lucide React (Icons)

Backend (Core Engine)
- Node.js (v18+/v20+)
- Express.js
- SQLite3 (Campaign Graph)
- PDFKit (Report Generation)
- Nodemailer (Alerts)
- SMTP Server
- IMAP
- Crypto
- DNS
- Dotenv
- CORS

Detection & Analysis
- Email Header & Relay Analysis
- SPF/DKIM/DMARC Verification

Email Integration
- Gmail API + OAuth 2.0
- Pub/Sub (Push Webhooks)
- SMTP (Port 2525)
- IMAP (Mailbox Polling)

Threat Intelligence / External APIs
- IP-API Risk scoring
- AbuseIPDB
- VPNAPI/IPQS

Client
- Chrome Extension (Manifest V3)
- Real-time email analysis


==================================================
SYSTEM ARCHITECTURE & FLOW
==================================================

1. MULTI-VECTOR EMAIL INGESTION

Gmail API
SMTP Gateway
IMAP
Webhooks
Chrome Extension
REST API

Gmail API:
Push + History Sync

SMTP Gateway:
Port 2525

IMAP:
Inbox Poller

Webhooks:
Pub/Sub

Chrome Extension:
Manifest V3

REST API:
/api/analyze


↓

2. DEDUPLICATION & PRE-PROCESSING

RFC Message-ID
SHA-256
Normalization


↓

3. THREAT DETECTION

Identify malicious / suspicious emails


↓

4. FORENSIC ANALYSIS

Email headers
Relay path analysis
Authentication analysis


↓

5. IOC EXTRACTION

URLs
IPs
Domains
Hashes


↓

6. INFRASTRUCTURE INTELLIGENCE

ASN / ISP
Geolocation
FCIDNS
Reputation checks


↓

7. CAMPAIGN GRAPH / CORRELATION

Nodes
Edges
Related emails
Campaign mapping
Shared infrastructure


↓

8. MULTI-SIGNAL ANALYSIS

Threat clustering
Evidence scoring


↓

9. EXECUTIVE GUARD

VIP impersonation detection
BEC protection


↓

10. POLICY ENGINE & REMEDIATION

Risk scoring
Apply rules
Quarantine
Soft-Delete
Banner


↓

11. STORAGE & AUDIT

SQLite DB
Audit Logger


↓

FORENSIC REPORT

Generate PDF
PDFKit


==================================================
ADDITIONAL ARCHITECTURAL COMPONENT
==================================================

SUPPLY CHAIN SECURITY
MQL
NLP

NLP is added at this stage to support Natural Language Processing-based analysis of email content, language patterns, semantic indicators and suspicious communication characteristics.


==================================================
SOC DASHBOARD
==================================================

SOC Dashboard
React 19 + Vite

Threat Map
Leaflet

Campaign Graph

Forensic Report
PDFKit

Chrome Extension
Manifest V3

GitHub Repository

https://github.com/Chaithanya-7/SIH


==================================================
IMPLEMENTATION METHODOLOGY
==================================================

1. REQUIREMENT ANALYSIS

- Understand problem statement
- Define features and scope
- Identify constraints and resources


2. SYSTEM DESIGN

- Design architecture and data flow
- Select technologies and tools
- Design database schema (SQLite)


3. DEVELOPMENT

- Implement backend APIs
- Build SOC dashboard and modules
- Develop Chrome extension


4. INTEGRATION & TESTING

- Integrate Gmail API, SMTP/IMAP
- Test with real/simulated emails
- Validate detection and analysis pipeline


5. DEPLOYMENT

- Deploy working prototype
- Perform end-to-end testing
- Prepare for demonstration


6. ITERATION & IMPROVEMENT

- Refine based on testing and feedback
- Optimize performance and accuracy
- Plan future enhancements


==================================================
FEASIBILITY AND VIABILITY
==================================================

FEASIBILITY ANALYSIS

Technically achievable with available tools and resources


TECHNOLOGICAL FEASIBILITY

Built using widely available, stable and open-source technologies
(React, Node.js, SQLite, Gmail API, etc.)


OPERATIONAL FEASIBILITY

Can be deployed on standard cloud infrastructure or on-premise servers with moderate resource requirements.


ECONOMIC FEASIBILITY

Uses open-source tools and free tiers (Gmail API, threat intel APIs), keeping development and operational cost low.


TEAM FEASIBILITY

Leverages our team’s existing skills in full-stack development, cybersecurity and AI/ML, proven through previous projects and hackathons.


==================================================
POTENTIAL CHALLENGES AND RISKS
==================================================

Key hurdles in development and deployment

Gmail API Limitations
- Rate limits
- Quota restrictions
- Strict OAuth verification process

False Positives / Negatives
- Risk of misclassification affecting user trust

Data Privacy & Security
- Handling sensitive email data requires strong security and compliance

Scalability & Performance
- Large email volumes may impact processing speed

User Adoption
- Convincing non-technical users to trust and use the system


==================================================
VIABILITY ANALYSIS
==================================================

High potential for real-world adoption and long-term impact


SOCIETAL IMPACT

Helps individuals, institutions and government organizations prevent phishing, fraud and data breaches, improving digital safety.


SCALABILITY

Modular architecture allows easy scaling from individual users to enterprises and government departments.


SUSTAINABILITY

Can be maintained and enhanced with community support and integration with additional threat intelligence sources.


ALIGNMENT WITH NATIONAL GOALS

Supports Digital India, Cyber Surakshit Bharat and secure governance by strengthening email security and citizen awareness.


==================================================
STRATEGIES FOR OVERCOMING CHALLENGES
==================================================

Practical solutions and mitigation plans


OPTIMIZED API USAGE

Implement efficient caching, incremental sync and fallback to IMAP/SMTP.


CONTINUOUS MODEL IMPROVEMENT

Use feedback loop, threat intelligence enrichment and human review for better accuracy.


STRONG SECURITY MEASURES

Encrypt data, follow least-privilege access and comply with data protection guidelines.


SCALABLE ARCHITECTURE

Modular microservice design with queue-based processing for high volumes.


USER-FRIENDLY INTERFACE & AWARENESS

Simple dashboard, clear alerts and awareness messages to build trust and adoption.


CONCLUSION

The solution is technically feasible, economically viable and socially impactful, with clear strategies to address risks, making it ready for real-world deployment and long-term sustainability.


==================================================
IMPACT AND BENEFITS
==================================================

IMPACT ON TARGET AUDIENCE

Protecting individuals, organisations and public services


INDIVIDUALS

- Reduces risk of phishing, fraud and identity theft.
- Increases digital safety and awareness.


EDUCATIONAL INSTITUTIONS

- Protects students and staff from malicious emails and impersonation attacks.
- Improves productivity and trust in digital services.


GOVERNMENT ORGANISATIONS

- Strengthens email security for public services and sensitive communications.


ENTERPRISES & SMEs

- Helps prevent Business Email Compromise (BEC) and financial losses.


NEW USERS

- Provides automated protection without requiring technical expertise.


==================================================
BENEFITS OF THE SOLUTION
==================================================

Social, economic, environmental and strategic value


SOCIAL BENEFITS

- Safer digital communication for all
- Reduces cyber fraud and financial exploitation
- Builds awareness and cyber hygiene


ECONOMIC BENEFITS

- Prevents monetary losses due to phishing/BEC
- Reduces manual investigation time and operational cost
- Improves productivity and trust in digital services


ENVIRONMENTAL BENEFITS

- Digital solution reduces need for physical processes
- Cloud-ready and low resource footprint
- Supports greener and more efficient operations


STRATEGIC BENEFITS

- Scalable for large-scale adoption across sectors
- Aligns with Digital India and Cyber Surakshit Bharat
- Strengthens national cybersecurity infrastructure


OVERALL IMPACT

A more secure, aware and resilient digital ecosystem, enabling individuals, institutions and the nation to stay one step ahead of evolving email-based threats.


==================================================
RESEARCH AND REFERENCES
==================================================

Core protocols used for email authentication and analysis


EMAIL SECURITY STANDARDS (RFCs)

RFC 5322 - Internet Message Format

www.rfc-editor.org/rfc/rfc5322


RFC 7208 - Sender Policy Framework (SPF)

www.rfc-editor.org/rfc/rfc7208


RFC 6376 - DomainKeys Identified Mail (DKIM)

www.rfc-editor.org/rfc/rfc6376


RFC 7489 - Domain-based Message Authentication, Reporting, and Conformance (DMARC)

www.rfc-editor.org/rfc/rfc7489


==================================================
APIs AND TECHNOLOGIES
==================================================

Official documentation for the tools and services used


Gmail API

developers.google.com/workspace/gmail/api/auth/scopes


Gmail Push Notifications (Pub/Sub)

developers.google.com/workspace/gmail/api/auth/scopes


==================================================
RELATED RESEARCH
==================================================

Academic work on phishing detection and email security


Phishing Detection Using Machine Learning (IEEE)

ieeexplore.ieee.org/document/9304691


A Survey on Email Spam and Phishing

arxiv.org/abs/2107.04508


Graph-based Analysis for Email Threat Campaigns

arxiv.org/abs/2107.04508


==================================================
THREAT LANDSCAPE & RESEARCH REPORTS
==================================================

Real-world data and studies that highlight the problem


FBI IC3 - Business Email Compromise: The $55 Billion Scam

www.ic3.gov/PSA/2024/PSA240911


Verizon Data Breach Investigations Report (DBIR) 2024


==================================================
BEST PRACTICES & GUIDELINES
==================================================

Recommended frameworks for secure email systems


CISA - Email Security Best Practices


OWASP - Email Security

owasp.org/www-project-email-security/


NIST Cybersecurity Framework

www.nist.gov/cyberframework


==================================================
PROJECT REPOSITORY
==================================================

Source code, documentation and implementation details


A11 SAF3 - SecureMail AI (GitHub Repository)

https://github.com/Chaithanya-7/SIH.git


Scan to Open
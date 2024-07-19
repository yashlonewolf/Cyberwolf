# Wolfyash Bug Bounty Oneliner

Automated Recon and Vulnerability Scanning Script

Description
This repository contains a powerful and comprehensive Bash script designed for automated reconnaissance and vulnerability scanning of target domains. The script integrates several popular tools to enumerate subdomains, resolve live subdomains, collect endpoints, and check for common vulnerabilities.

The script features:

Subdomain Enumeration: Uses subfinder, assetfinder, and amass to discover subdomains of the target domain.
Live Subdomain Resolution: Uses httpx to identify live subdomains and gather additional information like titles, status codes, content length, and web servers.
Endpoint Collection: Gathers endpoints from Wayback Machine and gau (GetAllUrls).
Parameter Enumeration: Uses paramspider to enumerate parameters in the collected endpoints.
Vulnerability Checks: Utilizes gf patterns to check for vulnerabilities such as XSS, SQLi, LFI, Redirect, RCE, and SSTI.
Payload Replacement: Uses qsreplace to inject payloads into parameters for further testing.
Keyword Search: Searches for sensitive keywords in the collected endpoints.
Features
Error Handling and Retry Mechanism: Ensures reliable data fetching with retry logic.
Real-time Display: All results are displayed directly in the terminal for immediate visibility.
ASCII Art: Displays a wolf face logo at the start of the script for a cool aesthetic touch.
Tools Used
subfinder: Fast subdomain enumeration tool.
assetfinder: Another subdomain enumeration tool.
amass: In-depth subdomain enumeration tool.
httpx: Fast and multi-functional HTTP toolkit.
gau: Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl.
paramspider: Parameter discovery tool.
gf: GoodFuzz patterns to identify potential vulnerabilities.
qsreplace: Query string replacer for payload injection.

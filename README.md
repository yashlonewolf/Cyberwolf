Here's the updated description for your GitHub repository:

---

# Wolfyash: Automated Recon and Vulnerability Scanning Script

![Wolf Logo]![image](https://github.com/user-attachments/assets/7db81ae5-6a4b-42f2-b4eb-5342b529c42a)


## Description

This repository contains a powerful and comprehensive Bash script designed for automated reconnaissance and vulnerability scanning of target domains. The script integrates several popular tools to enumerate subdomains, resolve live subdomains, collect endpoints, and check for common vulnerabilities.

The script features:

- **Subdomain Enumeration**: Uses `subfinder`, `assetfinder`, and `amass` to discover subdomains of the target domain.
- **Live Subdomain Resolution**: Uses `httpx` to identify live subdomains and gather additional information like titles, status codes, content length, and web servers.
- **Endpoint Collection**: Gathers endpoints from Wayback Machine and `gau` (GetAllUrls).
- **Parameter Enumeration**: Uses `paramspider` to enumerate parameters in the collected endpoints.
- **Vulnerability Checks**: Utilizes `gf` patterns to check for vulnerabilities such as XSS, SQLi, LFI, Redirect, RCE, and SSTI.
- **Payload Replacement**: Uses `qsreplace` to inject payloads into parameters for further testing.
- **Keyword Search**: Searches for sensitive keywords in the collected endpoints.

## Features

- **Error Handling and Retry Mechanism**: Ensures reliable data fetching with retry logic.
- **Real-time Display**: All results are displayed directly in the terminal for immediate visibility.
- **ASCII Art**: Displays a wolf face logo at the start of the script for a cool aesthetic touch.
Features:
Local File Inclusion (LFI) Detection: Scans for potential LFI vulnerabilities using gf and qsreplace.
Open Redirect Detection: Checks for open redirect vulnerabilities.
Gospider and Dalfox Integration: Uses gospider and dalfox for in-depth vulnerability scanning.
Subdomain Enumeration and Prototype Pollution Check: Enumerates subdomains and checks for prototype pollution.
JavaScript Variable and XSS Payload Check: Identifies potential XSS payloads in JavaScript variables.
CORS Vulnerability Detection: Detects potential CORS vulnerabilities.
Wayback URLs and XSS Check: Uses wayback URLs to check for XSS vulnerabilities.
Full Subdomain Scan: Performs subdomain enumeration, DNS resolution, port scanning, and HTTP probing.
Directory and File Enumeration: Uses dirsearch for thorough directory and file enumeration.
SQL Injection Detection: Checks for potential SQL injection vulnerabilities.
## Tools Used

- `subfinder`: Fast subdomain enumeration tool.
- `assetfinder`: Another subdomain enumeration tool.
- `amass`: In-depth subdomain enumeration tool.
- `httpx`: Fast and multi-functional HTTP toolkit.
- `gau`: Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl.
- `paramspider`: Parameter discovery tool.
- `gf`: GoodFuzz patterns to identify potential vulnerabilities.
- `qsreplace`: Query string replacer for payload injection.
Tools Utilized:
curl
grep
awk
sed
amass
assetfinder
subfinder
httpx
waybackurls
gau
paramspider
gf
qsreplace
dalfox
shuffledns
dnsx
naabu
katana
nuclei
dirsearch
## Usage

1. Clone the repository:
   ```sh
   git clone https://github.com/yashlonewolf/Wolfyash.git
   cd Wolfyash
   ```

2. Make the script executable:
   ```sh
   chmod +x Wyas.sh
   ```

3. Run the script with the target domain:
   ```sh

 LHOST="http://evil.com" ./Wyas.sh example.com
   ```

   Replace `<target>` with the domain you want to scan.



## Contributing

Contributions are welcome! Please fork this repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

If you have any questions or suggestions, feel free to open an issue or contact me directly.

--- https://chat.whatsapp.com/HsavjRTQTcj8rHtGffoBWM

This description provides a comprehensive overview of the script, its features, tools used, and usage instructions, making it easy for others to understand and use your project.

THANK YOU ALL

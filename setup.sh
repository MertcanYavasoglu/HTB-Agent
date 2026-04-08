#!/bin/bash
set -e

echo "[*] Setting up HTB Agent environment..."

# 1. Create Virtual Environment
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[*] Activating virtual environment..."
source venv/bin/activate

# 2. Install dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt

# 3. Install Playwright Browsers
echo "[*] Installing Playwright Chromium..."
playwright install chromium --with-deps

# 4. Prompt for .env configuration
if [ ! -f ".env" ]; then
    echo "[*] Creating .env config..."
    read -p "Enter Gemini API Key: " api_key
    read -p "Enter Nmap default args [-sV -sC -p-]: " nmap_args
    nmap_args=${nmap_args:-"-sV -sC -p-"}

    read -p "Enter path to Directory Wordlist [/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt]: " dir_wordlist
    dir_wordlist=${dir_wordlist:-"/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"}

    read -p "Enter path to Subdomain Wordlist [/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt]: " sub_wordlist
    sub_wordlist=${sub_wordlist:-"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"}

    cat <<EOF > .env
GEMINI_API_KEY="$api_key"
NMAP_DEFAULT_ARGS="$nmap_args"
WORDLIST_DIRS="$dir_wordlist"
WORDLIST_SUBDOMAINS="$sub_wordlist"
EOF
    echo "[+] .env file created successfully."
else
    echo "[+] .env file already exists. Skipping config prompt."
fi

echo "[+] Setup complete!"
echo "[*] Run the agent using: source venv/bin/activate && python3 -m htb_agent.main start --help"

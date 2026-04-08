#!/bin/bash
set -e

echo "[*] Setting up HTB Agent environment..."

# 0. OS Detection and System Dependencies
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_LIKE=$ID_LIKE
else
    echo "[!] Cannot determine OS. Skipping system dependencies installation."
    OS="unknown"
    OS_LIKE="unknown"
fi

echo "[*] Detected OS: $OS"

install_deps_apt() {
    echo "[*] Installing dependencies via apt..."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv nmap ffuf gobuster seclists
}

install_deps_dnf() {
    echo "[*] Installing dependencies via dnf..."
    sudo dnf install -y python3 python3-pip nmap ffuf gobuster
    # Note: seclists might not be in default repos, suggesting manual install if missing
}

install_deps_pacman() {
    echo "[*] Installing dependencies via pacman..."
    sudo pacman -Sy --needed --noconfirm python python-pip nmap ffuf gobuster
    # Note: seclists is usually available in blackarch or AUR, not default repos
}

case "$OS" in
    ubuntu|debian|kali|parrot|linuxmint|pop)
        install_deps_apt
        ;;
    fedora|centos|rhel|almalinux|rocky)
        install_deps_dnf
        ;;
    arch|manjaro|artix|endeavouros)
        install_deps_pacman
        ;;
    *)
        if echo "$OS_LIKE" | grep -q "debian"; then
            install_deps_apt
        elif echo "$OS_LIKE" | grep -q "fedora\|rhel\|centos"; then
            install_deps_dnf
        elif echo "$OS_LIKE" | grep -q "arch"; then
            install_deps_pacman
        else
            echo "[!] Unsupported OS for automatic system package installation."
            echo "[!] Please ensure nmap, ffuf, gobuster, python3, and python3-venv are installed manually."
        fi
        ;;
esac

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
if [ -x "$(command -v apt-get)" ]; then
    playwright install chromium --with-deps
else
    echo "[!] Non-Debian OS detected. Installing Playwright without --with-deps (you may need to install browser dependencies manually if Playwright fails to launch)."
    playwright install chromium
fi

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

#!/usr/bin/env bash
# install_all_tools.sh — Master installer for all hackingtool sub-tools
# Designed for Ubuntu 22.04+ / Debian 12+ / Kali Linux VPS
# Run as root: sudo bash install_all_tools.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; }

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo bash $0)"
    exit 1
fi

# --- Configuration ---
TOOLS_DIR="${TOOLS_DIR:-/opt/hackingtool-arsenal}"
LOG_FILE="/var/log/hackingtool_install.log"
FAILED_TOOLS=()

mkdir -p "$TOOLS_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1
cd "$TOOLS_DIR"

# =============================================================================
# PHASE 1: System packages
# =============================================================================
log "=== Phase 1: System packages ==="

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y \
    git curl wget python3 python3-pip python3-venv python3-dev \
    build-essential gcc g++ make cmake \
    php php-curl php-mbstring php-bz2 \
    figlet boxes lolcat \
    nmap sqlmap nikto dirb \
    steghide wireshark-common tshark \
    libssl-dev libffi-dev libgd-perl libimage-exiftool-perl \
    libstring-crc32-perl \
    sshpass netcat-openbsd \
    golang-go ruby ruby-dev \
    tilix xdotool \
    autopsy \
    jq unzip \
    whois dnsutils sslscan whatweb wafw00f hydra \
    masscan gobuster wpscan john hashcat enum4linux \
    theharvester recon-ng amass \
    2>/dev/null || warn "Some system packages failed (non-fatal)"

# Ruby gems
gem install XSpear 2>/dev/null || warn "XSpear gem install failed"

# Go tools
export GOPATH="$TOOLS_DIR/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
mkdir -p "$GOPATH"

# Python global tools
pip3 install --break-system-packages \
    slowloris androguard stegcracker socialscan shodan \
    howmanypeoplearearound requests flask rich \
    python-whois censys holehe phoneinfoga \
    2>/dev/null || warn "Some pip packages failed"

# =============================================================================
# PHASE 2: Clone & install all tools
# =============================================================================
log "=== Phase 2: Cloning and installing tools ==="

install_tool() {
    local name="$1"
    local repo="$2"
    local dir="$3"
    local post_install="${4:-}"

    if [[ -d "$TOOLS_DIR/$dir" ]]; then
        warn "$name already installed, skipping"
        return 0
    fi

    log "Installing $name..."
    if git clone --depth 1 "$repo" "$TOOLS_DIR/$dir" 2>/dev/null; then
        if [[ -n "$post_install" ]]; then
            (cd "$TOOLS_DIR/$dir" && eval "$post_install" 2>/dev/null) || warn "$name post-install had issues"
        fi
        log "$name installed OK"
    else
        fail "$name clone failed"
        FAILED_TOOLS+=("$name")
    fi
}

# --- Anonymity ---
log "--- Category: Anonymity ---"
install_tool "Anonsurf" "https://github.com/Und3rf10w/kali-anonsurf.git" "kali-anonsurf"
install_tool "Multitor" "https://github.com/trimstray/multitor.git" "multitor"

# --- Information Gathering ---
log "--- Category: Information Gathering ---"
install_tool "Dracnmap" "https://github.com/Screetsec/Dracnmap.git" "Dracnmap" \
    "chmod +x dracnmap-v2.2-dracOs.sh dracnmap-v2.2.sh"
install_tool "XeroSploit" "https://github.com/LionSec/xerosploit.git" "xerosploit"
install_tool "RED_HAWK" "https://github.com/Tuhinshubhra/RED_HAWK.git" "RED_HAWK"
install_tool "ReconSpider" "https://github.com/bhavsec/reconspider.git" "reconspider" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null; python3 setup.py install 2>/dev/null"
install_tool "Infoga" "https://github.com/m4ll0k/Infoga.git" "Infoga" \
    "python3 setup.py install 2>/dev/null"
install_tool "ReconDog" "https://github.com/s0md3v/ReconDog.git" "ReconDog"
install_tool "Striker" "https://github.com/s0md3v/Striker.git" "Striker" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "SecretFinder" "https://github.com/m4ll0k/SecretFinder.git" "secretfinder" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "Shodanfy" "https://github.com/m4ll0k/Shodanfy.py.git" "Shodanfy.py"
install_tool "Rang3r" "https://github.com/floriankunushevci/rang3r.git" "rang3r" \
    "pip3 install --break-system-packages termcolor 2>/dev/null"
install_tool "Breacher" "https://github.com/s0md3v/Breacher.git" "Breacher"

# --- Wordlist Generators ---
log "--- Category: Wordlist Generators ---"
install_tool "CUPP" "https://github.com/Mebus/cupp.git" "cupp"
install_tool "WlCreator" "https://github.com/Z4nzu/wlcreator.git" "wlcreator" \
    "gcc -o wlcreator wlcreator.c 2>/dev/null"
install_tool "GoblinWordGenerator" "https://github.com/UndeadSec/GoblinWordGenerator.git" "GoblinWordGenerator"
install_tool "SMWYG" "https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got.git" "SMWYG-Show-Me-What-You-Got" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"

# --- SQL Injection ---
log "--- Category: SQL Injection ---"
install_tool "sqlmap-dev" "https://github.com/sqlmapproject/sqlmap.git" "sqlmap-dev"
install_tool "NoSQLMap" "https://github.com/codingo/NoSQLMap.git" "NoSQLMap" \
    "python3 setup.py install 2>/dev/null"
install_tool "DSSS" "https://github.com/stamparm/DSSS.git" "DSSS"
install_tool "Explo" "https://github.com/dtag-dev-sec/explo.git" "explo" \
    "python3 setup.py install 2>/dev/null"
install_tool "Blisqy" "https://github.com/JohnTroony/Blisqy.git" "Blisqy"
install_tool "Leviathan" "https://github.com/leviathan-framework/leviathan.git" "leviathan" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"

# --- Web Attack ---
log "--- Category: Web Attack ---"
install_tool "Sublist3r" "https://github.com/aboul3la/Sublist3r.git" "Sublist3r" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "checkURL" "https://github.com/UndeadSec/checkURL.git" "checkURL"
install_tool "Blazy" "https://github.com/UltimateHackers/Blazy.git" "Blazy"
install_tool "takeover" "https://github.com/edoardottt/takeover.git" "takeover" \
    "python3 setup.py install 2>/dev/null"
install_tool "Dirb" "https://gitlab.com/kalilinux/packages/dirb.git" "dirb" \
    "bash configure 2>/dev/null && make 2>/dev/null"
install_tool "Web2Attack" "https://github.com/santatic/web2attack.git" "web2attack"

# --- XSS Attack ---
log "--- Category: XSS Attack ---"
install_tool "DalFox" "https://github.com/hahwul/dalfox.git" "dalfox" \
    "go install 2>/dev/null"
install_tool "XSS-LOADER" "https://github.com/capture0x/XSS-LOADER.git" "XSS-LOADER" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "extended-xss-search" "https://github.com/Damian89/extended-xss-search.git" "extended-xss-search"
install_tool "XSS-Freak" "https://github.com/PR0PH3CY33/XSS-Freak.git" "XSS-Freak" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "XSSCon" "https://github.com/menkrep1337/XSSCon.git" "XSSCon" \
    "chmod 755 -R ."
install_tool "XanXSS" "https://github.com/Ekultek/XanXSS.git" "XanXSS"
install_tool "XSStrike" "https://github.com/UltimateHackers/XSStrike.git" "XSStrike" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "RVuln" "https://github.com/iinc0gnit0/RVuln.git" "RVuln"

# --- Exploit Frameworks ---
log "--- Category: Exploit Frameworks ---"
install_tool "RouterSploit" "https://github.com/threat9/routersploit.git" "routersploit" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "Commix" "https://github.com/commixproject/commix.git" "commix"

# --- Phishing ---
log "--- Category: Phishing ---"
install_tool "autophisher" "https://github.com/CodingRanjith/autophisher.git" "autophisher"
install_tool "PyPhisher" "https://github.com/KasRoudra/PyPhisher.git" "PyPhisher" \
    "cd files 2>/dev/null && pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "SocialFish" "https://github.com/UndeadSec/SocialFish.git" "SocialFish" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "dnstwist" "https://github.com/elceef/dnstwist.git" "dnstwist"
install_tool "ShellPhish" "https://github.com/An0nUD4Y/shellphish.git" "shellphish"

# --- Payload Creators ---
log "--- Category: Payload Creators ---"
install_tool "TheFatRat" "https://github.com/Screetsec/TheFatRat.git" "TheFatRat" \
    "chmod +x setup.sh"
install_tool "Brutal" "https://github.com/Screetsec/Brutal.git" "Brutal" \
    "chmod +x Brutal.sh"
install_tool "MSFpc" "https://github.com/g0tmi1k/msfpc.git" "msfpc" \
    "chmod +x msfpc.sh"
install_tool "Venom" "https://github.com/r00t-3xp10it/venom.git" "venom" \
    "chmod -R 775 ."
install_tool "Enigma" "https://github.com/UndeadSec/Enigma.git" "Enigma"

# --- Post Exploitation ---
log "--- Category: Post Exploitation ---"
install_tool "Vegile" "https://github.com/Screetsec/Vegile.git" "Vegile" \
    "chmod +x Vegile"
install_tool "HeraKeylogger" "https://github.com/UndeadSec/HeraKeylogger.git" "HeraKeylogger" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"

# --- Remote Admin ---
log "--- Category: Remote Administration ---"
install_tool "Stitch" "https://github.com/nathanlopez/Stitch.git" "Stitch" \
    "pip3 install --break-system-packages -r lnx_requirements.txt 2>/dev/null"
install_tool "Pyshell" "https://github.com/knassar702/Pyshell.git" "Pyshell"

# --- Reverse Engineering ---
log "--- Category: Reverse Engineering ---"
install_tool "apk2gold" "https://github.com/lxdvs/apk2gold.git" "apk2gold"
install_tool "jadx" "https://github.com/skylot/jadx.git" "jadx"

# --- Steganography ---
log "--- Category: Steganography ---"
install_tool "StegoCracker" "https://github.com/W1LDN16H7/StegoCracker.git" "StegoCracker" \
    "chmod -R 755 ."
install_tool "snow10" "https://github.com/beardog108/snow10.git" "snow10" \
    "chmod -R 755 ."

# --- Wireless ---
log "--- Category: Wireless ---"
install_tool "Fluxion" "https://github.com/FluxionNetwork/fluxion.git" "fluxion" \
    "chmod +x fluxion.sh"
install_tool "Wifite2" "https://github.com/derv82/wifite2.git" "wifite2" \
    "python3 setup.py install 2>/dev/null"
install_tool "EvilTwin" "https://github.com/Z4nzu/fakeap.git" "fakeap"
install_tool "Fastssh" "https://github.com/Z4nzu/fastssh.git" "fastssh" \
    "chmod +x fastssh.sh"

# --- DDoS ---
log "--- Category: DDoS ---"
install_tool "ddos" "https://github.com/the-deepnet/ddos.git" "ddos" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "aSYNcrone" "https://github.com/fatih4842/aSYNcrone.git" "aSYNcrone" \
    "gcc aSYNcrone.c -o aSYNcrone -lpthread 2>/dev/null"
install_tool "UFONet" "https://github.com/epsylon/ufonet.git" "ufonet"
install_tool "GoldenEye" "https://github.com/jseidl/GoldenEye.git" "GoldenEye" \
    "chmod -R 755 ."

# --- Others ---
log "--- Category: Other Tools ---"
install_tool "HatCloud" "https://github.com/HatBashBR/HatCloud.git" "HatCloud"
install_tool "Hash-Buster" "https://github.com/s0md3v/Hash-Buster.git" "Hash-Buster"
install_tool "EvilURL" "https://github.com/UndeadSec/EvilURL.git" "EvilURL"
install_tool "KnockMail" "https://github.com/heywoodlh/KnockMail.git" "KnockMail" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "Sherlock" "https://github.com/sherlock-project/sherlock.git" "sherlock" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "FindUser" "https://github.com/xHak9x/finduser.git" "finduser" \
    "chmod +x finduser.sh"
install_tool "Crivo" "https://github.com/GMDSantana/crivo.git" "crivo" \
    "pip3 install --break-system-packages -r requirements.txt 2>/dev/null"
install_tool "Debinject" "https://github.com/UndeadSec/Debinject.git" "Debinject"
install_tool "Pixload" "https://github.com/chinarulezzz/pixload.git" "pixload"

# --- Android ---
log "--- Category: Android ---"
install_tool "Keydroid" "https://github.com/F4dl0/keydroid.git" "keydroid"
install_tool "LockPhish" "https://github.com/JasonJerry/lockphish.git" "lockphish"

# =============================================================================
# PHASE 3: Install hackingtool itself
# =============================================================================
log "=== Phase 3: Setting up hackingtool launcher ==="

HACKINGTOOL_DIR="/usr/share/hackingtool"
if [[ ! -d "$HACKINGTOOL_DIR" ]]; then
    cp -r /home/user/hackingtool "$HACKINGTOOL_DIR" 2>/dev/null || \
    cp -r "$(dirname "$(readlink -f "$0")")" "$HACKINGTOOL_DIR" 2>/dev/null || \
    warn "Could not copy hackingtool to $HACKINGTOOL_DIR — run from source directory"
fi

pip3 install --break-system-packages flask requests rich 2>/dev/null

# Create launcher
cat > /usr/local/bin/hackingtool << 'LAUNCHER'
#!/bin/bash
export TOOLS_DIR="/opt/hackingtool-arsenal"
export PATH="$PATH:$TOOLS_DIR/go/bin"
cd /usr/share/hackingtool 2>/dev/null || cd "$(dirname "$0")/../share/hackingtool"
python3 hackingtool.py "$@"
LAUNCHER
chmod +x /usr/local/bin/hackingtool

# =============================================================================
# Summary
# =============================================================================
echo ""
log "========================================="
log "  Installation Complete!"
log "========================================="
log "Tools directory: $TOOLS_DIR"
log "Log file: $LOG_FILE"

if [[ ${#FAILED_TOOLS[@]} -gt 0 ]]; then
    warn "The following tools had issues:"
    for t in "${FAILED_TOOLS[@]}"; do
        fail "  - $t"
    done
fi

echo ""
log "Run 'hackingtool' to start the menu"
log "Tools are in: $TOOLS_DIR"
echo ""

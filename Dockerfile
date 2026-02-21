# HackingTool v.5 — Full Red Team Platform
# Build:  docker build -t hackingtool .
# Run:    docker run -it -p 5000:5000 hackingtool
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    TOOLS_DIR=/opt/hackingtool-arsenal \
    GOPATH=/opt/hackingtool-arsenal/go \
    PATH="/opt/hackingtool-arsenal/go/bin:/usr/local/go/bin:${PATH}"

# ── Phase 1: System packages ────────────────────────────────────────────────
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    git curl wget python3 python3-pip python3-dev \
    build-essential gcc g++ make cmake \
    php php-curl php-mbstring \
    figlet boxes \
    nmap sqlmap nikto dirb \
    steghide \
    libssl-dev libffi-dev \
    sshpass netcat-openbsd \
    golang-go ruby ruby-dev \
    jq unzip \
    whois dnsutils sslscan whatweb wafw00f hydra \
    masscan gobuster wpscan john hashcat enum4linux \
    theharvester recon-ng amass \
    nbtscan smbclient crackmapexec \
    dnsenum fierce dnsrecon \
    wfuzz ffuf \
    medusa ncrack \
    tcpdump ettercap-text-only \
    hping3 arping fping \
    wordlists seclists \
    exiftool binwalk foremost \
    metasploit-framework \
    2>/dev/null; \
    rm -rf /var/lib/apt/lists/*

# Ruby gems
RUN gem install XSpear 2>/dev/null || true

# Python packages
RUN pip3 install --break-system-packages --no-cache-dir \
    flask requests rich urllib3 \
    slowloris shodan \
    python-whois censys holehe \
    dnstwist python-nmap termcolor \
    2>/dev/null || true

# ── Phase 2: Clone essential attack tools ────────────────────────────────────
RUN mkdir -p "$TOOLS_DIR" "$GOPATH"

WORKDIR /opt/hackingtool-arsenal

# Info gathering
RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r.git Sublist3r 2>/dev/null; \
    cd Sublist3r && pip3 install --break-system-packages -r requirements.txt 2>/dev/null || true
RUN git clone --depth 1 https://github.com/sherlock-project/sherlock.git sherlock 2>/dev/null; \
    cd sherlock && pip3 install --break-system-packages -r requirements.txt 2>/dev/null || true
RUN git clone --depth 1 https://github.com/s0md3v/ReconDog.git ReconDog 2>/dev/null || true
RUN git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git secretfinder 2>/dev/null; \
    cd secretfinder && pip3 install --break-system-packages -r requirements.txt 2>/dev/null || true

# SQL Injection
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev 2>/dev/null || true
RUN git clone --depth 1 https://github.com/codingo/NoSQLMap.git NoSQLMap 2>/dev/null || true

# XSS
RUN git clone --depth 1 https://github.com/UltimateHackers/XSStrike.git XSStrike 2>/dev/null; \
    cd XSStrike && pip3 install --break-system-packages -r requirements.txt 2>/dev/null || true
RUN git clone --depth 1 https://github.com/hahwul/dalfox.git dalfox 2>/dev/null || true

# Exploit frameworks
RUN git clone --depth 1 https://github.com/commixproject/commix.git commix 2>/dev/null || true
RUN git clone --depth 1 https://github.com/threat9/routersploit.git routersploit 2>/dev/null; \
    cd routersploit && pip3 install --break-system-packages -r requirements.txt 2>/dev/null || true

# Web attack
RUN git clone --depth 1 https://github.com/UltimateHackers/Blazy.git Blazy 2>/dev/null || true
RUN git clone --depth 1 https://github.com/Mebus/cupp.git cupp 2>/dev/null || true

# Phishing
RUN git clone --depth 1 https://github.com/KasRoudra/PyPhisher.git PyPhisher 2>/dev/null || true
RUN git clone --depth 1 https://github.com/thelinuxchoice/blackeye.git blackeye 2>/dev/null || true

# DDoS
RUN git clone --depth 1 https://github.com/jseidl/GoldenEye.git GoldenEye 2>/dev/null || true

# Other
RUN git clone --depth 1 https://github.com/s0md3v/Hash-Buster.git Hash-Buster 2>/dev/null || true

# ── Phase 3: Install HackingTool webapp ──────────────────────────────────────
WORKDIR /root/hackingtool
COPY requirements.txt ./
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt
COPY . .

# Initialize Metasploit DB (if available)
RUN msfdb init 2>/dev/null || true

EXPOSE 5000

# Default: start the web UI
CMD ["python3", "webapp.py"]

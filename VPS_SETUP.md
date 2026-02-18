# Hackingtool VPS Setup Guide

## Option 1: AWS EC2 (Recommended)

### Launch Instance

1. Go to **AWS Console > EC2 > Launch Instance**
2. Settings:
   - **AMI**: Ubuntu 22.04 LTS (or Kali Linux from AWS Marketplace)
   - **Instance type**: `t3.medium` (2 vCPU, 4GB RAM) minimum
   - **Storage**: 30GB+ GP3
   - **Security Group**: Allow SSH (port 22) from your IP only
3. Create/select a key pair and launch

### Connect & Install

```bash
# SSH into your instance
ssh -i your-key.pem ubuntu@<your-ec2-public-ip>

# Clone the repo
git clone https://github.com/Z4nzu/hackingtool.git
cd hackingtool

# Run the master installer (installs ALL 100+ tools)
sudo bash install_all_tools.sh

# Launch
hackingtool
```

### Estimated Costs

| Instance   | vCPU | RAM  | Monthly (on-demand) |
|-----------|------|------|---------------------|
| t3.medium | 2    | 4GB  | ~$30                |
| t3.large  | 2    | 8GB  | ~$60                |
| t3.xlarge | 4    | 16GB | ~$120               |

Use **spot instances** for 60-90% savings if you only need it for short engagements.

---

## Option 2: DigitalOcean / Linode / Vultr

```bash
# Create a $24/mo droplet (4GB RAM, 2 vCPU, Ubuntu 22.04)
# SSH in, then:
git clone https://github.com/Z4nzu/hackingtool.git
cd hackingtool
sudo bash install_all_tools.sh
hackingtool
```

---

## Option 3: Kali on AWS Marketplace

AWS Marketplace has official Kali Linux AMIs with many tools pre-installed:

1. Search "Kali Linux" in EC2 AMI marketplace
2. Launch a `t3.medium` or larger
3. SSH in and run the installer for the remaining tools

---

## Security Hardening for Your VPS

```bash
# Change default SSH port
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Enable UFW firewall
sudo ufw allow 2222/tcp
sudo ufw enable

# Disable password auth (key-only)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

---

## What the Installer Does

`install_all_tools.sh` performs three phases:

1. **System packages**: apt installs nmap, sqlmap, nikto, golang, ruby, php, steghide, wireshark, etc.
2. **Tool cloning**: Clones 80+ GitHub repos into `/opt/hackingtool-arsenal/` with their dependencies
3. **Launcher setup**: Creates the `hackingtool` command at `/usr/local/bin/hackingtool`

All tools are installed to `/opt/hackingtool-arsenal/`. A log is written to `/var/log/hackingtool_install.log`.

# Comprehensive Linux Server Hardening Guide

A complete guide to securing and hardening a Linux server with practical commands and configurations.

## Table of Contents
- [Initial Setup](#initial-setup)
- [System Updates](#system-updates)
- [User Management](#user-management)
- [SSH Hardening](#ssh-hardening)
- [Firewall Configuration (UFW)](#firewall-configuration-ufw)
- [Fail2Ban - Intrusion Prevention](#fail2ban---intrusion-prevention)
- [Apache Web Server Security](#apache-web-server-security)
- [DDoS Protection](#ddos-protection)
- [Mail Server Security](#mail-server-security)
- [Additional Security Measures](#additional-security-measures)
- [Monitoring and Logging](#monitoring-and-logging)

---

# Installation

Follow the guide below.

- If you are willing to risk it run: `minimal-priming.sh` for minimal installation.
- Or when daring: `advanced-priming.sh` for complete from the ground up installation and hardening.

Copy a script to a locaton on your server (usually: /usr/local/bin/ or /root/) and then make it executable:

  `chmod +x yourscript.sh`
  
Check the scripts, some things might break if you are not careful. Enter all details in both .sh scripts before running it. No warranty is given. **Things might break.**
Always test configurations in a staging environment before applying to production servers. Keep backups before making significant changes. Also, be sure to generate proper SSH keys before running the scripts.

It is always better to do all of this *manually*, but sometimes .sh files can be useful for whatever reason.

> Along the way, in a terminal window if you need to copy important information: `Ctrl+Shift+C` this will not kill a running command nor the terminal window, instead of just `Ctrl+C`.

## Initial Setup

### Update Package Lists
```bash
sudo apt update
sudo apt upgrade -y
sudo apt dist-upgrade -y
sudo apt autoremove -y
```

### Set Hostname
```bash
sudo hostnamectl set-hostname your-server-name
echo "127.0.0.1 your-server-name" | sudo tee -a /etc/hosts
```

---

## System Updates

### Enable Automatic Security Updates
```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

### Configure Automatic Updates
```bash
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

Add or verify these lines:
```conf
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
```

---

## User Management

### Create Non-Root User with Sudo Privileges
```bash
# Create new user
sudo adduser deployuser

# Add to sudo group
sudo usermod -aG sudo deployuser

# Switch to new user
su - deployuser
```

### Disable Root Login
```bash
sudo passwd -l root
```

### Set Strong Password Policy
```bash
sudo apt install libpam-pwquality -y
sudo nano /etc/security/pwquality.conf
```

Configure password requirements:
```conf
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
```

---

## SSH Hardening

### Install and Configure SSH
```bash
sudo apt install openssh-server -y
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
sudo nano /etc/ssh/sshd_config
```

### Generate and Deploy SSH Keys

On your local machine:
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
ssh-copy-id -i ~/.ssh/id_ed25519.pub deployuser@your_server_ip -p 2222
```

Or manually:
```bash
# On server
mkdir -p ~/.ssh
chmod 700 ~/.ssh
nano ~/.ssh/authorized_keys
# Paste your public key
chmod 600 ~/.ssh/authorized_keys
```


### Recommended SSH Configuration
```conf
# Change default port (choose something between 1024-65535)
Port 2222

# Disable root login
PermitRootLogin no

# Use SSH Protocol 2 only
Protocol 2

# Limit authentication attempts
MaxAuthTries 3
MaxSessions 2

# Disable password authentication (IMPORTANT: ! after setting up SSH keys !)
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no

# Disable X11 forwarding
X11Forwarding no

# Set login grace time
LoginGraceTime 30

# Allow specific users only
AllowUsers deployuser

# Disable host-based authentication
HostbasedAuthentication no

# Client timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable tunneling
PermitTunnel no
AllowTcpForwarding no
```

### Restart SSH Service
```bash
sudo systemctl restart sshd
sudo systemctl enable sshd
```

---

## Firewall Configuration (UFW)

> TIP: By restricting SSH access only to your home or work IP you greatly reduce unauthorized access. Redundancy: If you have a dynamic IP, but own a fixed VPN, also set the fixed VPN IP to allow the SSH port to be accesible. In this way, you always have access without locking yourself out permanently.

### Install and Configure UFW
```bash
sudo apt install ufw -y

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# IMPORTANT: Allow SSH from specific IP/range ONLY (prevents lockout)
# Replace with your actual IP address or range
sudo ufw allow from 777.7.777.7/24 to any port 2222 proto tcp comment 'YOUR IP: 777.7.777.7 SSH from office'
# OR for a single IP:
sudo ufw allow from 777.7.777.7 to any port 2222 proto tcp comment 'YOUR IP: 777.7.777.7 SSH from admin'
# OR for standard port 22:
sudo ufw allow from 777.7.777.7 to any port 22 proto tcp comment 'YOUR IP: 777.7.777.7 SSH from admin'

# Allow HTTP and HTTPS (publicly accessible)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow mail server ports (if needed)
sudo ufw allow 25/tcp    # SMTP
sudo ufw allow 587/tcp   # Submission
sudo ufw allow 993/tcp   # IMAPS
sudo ufw allow 995/tcp   # POP3S

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
sudo ufw status numbered  # Shows rule numbers
```

### Advanced UFW Rules
```bash
# Deny specific IP from accessing anything
sudo ufw deny from 192.0.2.100

# Allow specific IP to specific port only
sudo ufw allow from 777.7.777.7 to any port 3306 proto tcp comment 'MySQL from app server'

# Log denied connections (useful for monitoring)
sudo ufw logging on
sudo ufw logging medium  # or 'high' for more detail
```

### UFW Rate Limiting (DDoS Protection)
```bash
# Limit SSH connections
sudo ufw limit 2222/tcp

# For web servers
sudo ufw limit 80/tcp
sudo ufw limit 443/tcp
```

---

## Fail2Ban - Intrusion Prevention

### Install Fail2Ban
```bash
sudo apt install fail2ban -y
```

### Configure Fail2Ban
```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

### Basic Fail2Ban Configuration
```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = your-email@example.com
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = 2222
logpath = /var/log/auth.log
maxretry = 3

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache*/*access.log
maxretry = 2

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true

[apache-nohome]
enabled = true

[apache-botsearch]
enabled = true
```

### Start Fail2Ban
```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
sudo fail2ban-client status
```

---

## Apache Web Server Security

### Install Apache
```bash
sudo apt install apache2 -y
```

### Hide Apache Version
```bash
sudo nano /etc/apache2/conf-available/security.conf
```

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

### Enable Security Modules
```bash
sudo a2enmod headers
sudo a2enmod ssl
sudo a2enmod rewrite
sudo systemctl restart apache2
```

### Security Headers Configuration
```bash
sudo nano /etc/apache2/conf-available/security-headers.conf
```

```apache
<IfModule mod_headers.c>
    # Prevent clickjacking
    Header always set X-Frame-Options "SAMEORIGIN"
    
    # XSS Protection
    Header always set X-XSS-Protection "1; mode=block"
    
    # Prevent MIME type sniffing
    Header always set X-Content-Type-Options "nosniff"
    
    # Referrer Policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Content Security Policy
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    
    # HSTS (enable after testing)
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>
```

```bash
sudo a2enconf security-headers
sudo systemctl restart apache2
```

### Disable Directory Listing
```bash
sudo nano /etc/apache2/apache2.conf
```

```apache
<Directory /var/www/>
    Options -Indexes +FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
```

### Install ModSecurity (Web Application Firewall)
```bash
sudo apt install libapache2-mod-security2 -y
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo nano /etc/modsecurity/modsecurity.conf
```

Change:
```
SecRuleEngine On
```

### Install OWASP Core Rule Set
```bash
cd /tmp
wget https://github.com/coreruleset/coreruleset/archive/v3.3.0.tar.gz
tar -xvzf v3.3.0.tar.gz
sudo mv coreruleset-3.3.0 /etc/modsecurity/crs
sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
```

```bash
sudo nano /etc/apache2/mods-enabled/security2.conf
```

Add:
```apache
IncludeOptional /etc/modsecurity/crs/crs-setup.conf
IncludeOptional /etc/modsecurity/crs/rules/*.conf
```

```bash
sudo systemctl restart apache2
```

---

## DDoS Protection

### Install and Configure ModEvasive (Apache DDoS Protection)
```bash
sudo apt install libapache2-mod-evasive -y
sudo mkdir -p /var/log/mod_evasive
sudo chown -R www-data:www-data /var/log/mod_evasive
```

```bash
sudo nano /etc/apache2/mods-available/evasive.conf
```

```apache
<IfModule mod_evasive20.c>
    # Hash table size (increase for busy servers)
    DOSHashTableSize 3097
    
    # Maximum requests from same IP to same page within interval
    DOSPageCount 5
    DOSPageInterval 1
    
    # Maximum requests from same IP to entire site within interval
    DOSSiteCount 100
    DOSSiteInterval 1
    
    # How long to block offending IPs (seconds)
    DOSBlockingPeriod 60
    
    # Email notifications
    DOSEmailNotify your-email@example.com
    
    # Log directory
    DOSLogDir /var/log/mod_evasive
    
    # Whitelist IPs (optional - add trusted IPs)
    # DOSWhitelist 127.0.0.1
    # DOSWhitelist 192.168.1.*
    
    # System command to run when IP is blocked (optional)
    # DOSSystemCommand "sudo /usr/local/bin/ban_ip.sh %s"
</IfModule>
```

```bash
sudo a2enmod evasive
sudo systemctl restart apache2
```

### Test ModEvasive
```bash
# Install testing tool
sudo apt install apache2-utils -y

# Test (this should trigger blocking after several requests)
for i in {1..100}; do curl -I http://localhost/ ; done

# Check logs
sudo tail -f /var/log/mod_evasive/dos-*.log
```

### Kernel Parameter Tuning for DDoS Protection
```bash
sudo nano /etc/sysctl.conf
```

Add:
```conf
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Increase system file descriptor limit
fs.file-max = 65535

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
```

Apply changes:
```bash
sudo sysctl -p
```

---

## Mail Server Security

### Install Postfix and Dovecot
```bash
sudo apt install postfix dovecot-core dovecot-imapd dovecot-pop3d -y
```

### Configure Postfix Security
```bash
sudo nano /etc/postfix/main.cf
```

```conf
# Basic settings
myhostname = mail.yourdomain.com
mydomain = yourdomain.com
myorigin = $mydomain
inet_interfaces = all
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain

# TLS settings
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls = yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# Authentication
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname
broken_sasl_auth_clients = yes

# Restrictions
smtpd_recipient_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_non_fqdn_hostname,
    reject_non_fqdn_sender,
    reject_non_fqdn_recipient,
    reject_unknown_sender_domain,
    reject_unknown_recipient_domain,
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net,
    permit

smtpd_helo_restrictions = 
    permit_mynetworks,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname,
    reject_unknown_helo_hostname

# Rate limiting
smtpd_client_connection_rate_limit = 10
smtpd_client_message_rate_limit = 20
```

### Configure Dovecot Security
```bash
sudo nano /etc/dovecot/conf.d/10-auth.conf
```

```conf
disable_plaintext_auth = yes
auth_mechanisms = plain login
```

```bash
sudo nano /etc/dovecot/conf.d/10-ssl.conf
```

```conf
ssl = required
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
ssl_min_protocol = TLSv1.2
ssl_cipher_list = HIGH:!aNULL:!MD5
ssl_prefer_server_ciphers = yes
```

### Install SpamAssassin
```bash
sudo apt install spamassassin spamc -y
sudo systemctl enable spamassassin
sudo systemctl start spamassassin
```

### Restart Services
```bash
sudo systemctl restart postfix
sudo systemctl restart dovecot
```

---

## Additional Security Measures

### Install and Configure AppArmor
```bash
sudo apt install apparmor apparmor-utils -y
sudo systemctl enable apparmor
sudo systemctl start apparmor
sudo aa-status
```

### Install AIDE (File Integrity Monitoring)
```bash
sudo apt install aide -y
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

Run checks:
```bash
sudo aide --check

or:

sudo aide --config /etc/aide/aide.conf --check
```

### Install Rootkit Hunter
```bash
sudo apt install rkhunter -y
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter --check
```

### Install ClamAV Antivirus
```bash
sudo apt install clamav clamav-daemon -y
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
sudo systemctl enable clamav-daemon
```

Scan system:
```bash
sudo clamscan -r -i /home
```

### Lynis

Lynis can audit your system far better than we can possibly elaborate in this document. It is recommended!

```sudo apt install lynis```

Run a full audit:

```sudo lynis audit system```

### Disable Unnecessary Services
```bash
# List all services
systemctl list-unit-files --type=service

# Disable unnecessary ones
sudo systemctl disable avahi-daemon
sudo systemctl disable cups
sudo systemctl disable bluetooth
```

### Secure Shared Memory
```bash
sudo nano /etc/fstab
```

Add:
```
tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0
```

---

## Monitoring and Logging

### Install Logwatch
```bash
sudo apt install logwatch -y
```

Configure daily reports:
```bash
sudo nano /etc/cron.daily/00logwatch
```

```bash
#!/bin/bash
/usr/sbin/logwatch --output mail --mailto your-email@example.com --detail high
```

Make executable:
```bash
sudo chmod +x /etc/cron.daily/00logwatch
```

### Configure Auditd
```bash
sudo apt install auditd -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

Add audit rules:
```bash
sudo nano /etc/audit/rules.d/audit.rules
```

```bash
# Monitor changes to passwd and group files
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes

# Monitor sudo usage
-w /usr/bin/sudo -p x -k sudo_usage

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor crontab
-w /etc/crontab -p wa -k crontab_changes
```

Restart auditd:
```bash
sudo service auditd restart
```

---

## Final Checklist

- [ ] System fully updated
- [ ] Non-root user created with sudo privileges
- [ ] Root login disabled
- [ ] SSH hardened with key-based authentication
- [ ] Firewall configured and enabled
- [ ] Fail2Ban installed and running
- [ ] Apache secured with ModSecurity
- [ ] DDoS protection measures in place
- [ ] Mail server configured with TLS
- [ ] Automatic security updates enabled
- [ ] File integrity monitoring set up
- [ ] Rootkit scanner installed
- [ ] Antivirus installed
- [ ] Logging and monitoring configured
- [ ] Regular backups scheduled

---

## Regular Maintenance Tasks

### Daily
- Review fail2ban logs
- Check system logs for anomalies

### Weekly
- Review logwatch reports
- Check disk space (`df -h`)
- Review user accounts

### Monthly
- Run full system scan with ClamAV
- Run rkhunter check
- Run AIDE integrity check
- Review and update firewall rules
- Audit user access and permissions

### As Needed
- Apply security patches immediately
- Review and update security policies
- Test backup restoration
- Update SSL/TLS certificates

---

## Additional hardening scripts and tools

https://github.com/flaneurette/Auto-enable-UFW

https://github.com/flaneurette/Comprehensive-Fail2ban-Configuration/

https://github.com/flaneurette/IP-Block

https://github.com/flaneurette/Automated-Server-Backup

https://github.com/flaneurette/Tailscale-Monitor

https://github.com/flaneurette/Apache-Honeypot

https://github.com/flaneurette/Linux-Rat-Scan

https://github.com/flaneurette/htaccess-firewall

## Additional Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Security Guidelines](https://www.nist.gov/cyberframework)
- [OWASP Security Project](https://owasp.org/)
- [Ubuntu Security](https://ubuntu.com/security)
- [Debian Security](https://www.debian.org/security/)

---

**Warning**: Always test configurations in a staging environment before applying to production servers. Keep backups before making significant changes.

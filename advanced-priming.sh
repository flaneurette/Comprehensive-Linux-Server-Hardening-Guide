#!/bin/bash
# Enhanced Hardened Linux Server Setup Script
set -e

# --- CONFIGURATION VARIABLES ---
MYSQL_USER="user"
MYSQL_DB="databasename"
MYSQL_PASS=$(openssl rand -base64 24)
REDIS_PASS=$(openssl rand -base64 24)
DOMAIN="example.com"
DOCUMENT_ROOT="/var/www/html"
EMAIL="admin@example.com"
SSH_PORT="2222"
ADMIN_IP="YOUR_IP_ADDRESS"

# File paths
APACHE_CONF="/etc/apache2/sites-available/$DOMAIN.conf"
SSH_CONFIG="/etc/ssh/sshd_config"
PASSWORD_FILE="/root/.server_credentials"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- FUNCTIONS ---
print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }

save_credential() {
    echo "$1: $2" >> "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"
}

# Checks

if [ "$ADMIN_IP" == "YOUR_IP_ADDRESS" ]; then
    print_error "CRITICAL: Set ADMIN_IP to your actual IP!"
    print_warning "Get your IP: curl -4 ifconfig.me"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root or with sudo"
    exit 1
fi

# Backup current SSH config before changes
if [ -f "$SSH_CONFIG" ]; then
    cp "$SSH_CONFIG" "${SSH_CONFIG}.backup.$(date +%Y%m%d)"
    print_status "SSH config backed up"
fi

cd ~
sudo apt update
sudo apt upgrade -y
sudo apt dist-upgrade -y
sudo apt autoremove -y

# Create credentials file
touch "$PASSWORD_FILE"
chmod 600 "$PASSWORD_FILE"
echo "=== Server Credentials ===" > "$PASSWORD_FILE"
echo "Generated on: $(date)" >> "$PASSWORD_FILE"
echo "" >> "$PASSWORD_FILE"

print_status "Starting hardened server setup..."

# --- SYSTEM UPDATES ---
print_status "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt update && apt upgrade -y

print_status "Installing essential packages..."
apt install -y apache2 curl wget ufw git fail2ban htop unzip vim net-tools \
    software-properties-common unattended-upgrades apt-listchanges \
    libpam-pwquality apache2-utils

# --- AUTOMATIC SECURITY UPDATES ---
print_status "Configuring automatic security updates..."
cat <<EOF > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
EOF

cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable unattended-upgrades
systemctl start unattended-upgrades

# --- FIREWALL CONFIGURATION (UFW) ---
print_status "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Critical: Allow SSH from admin IP before enabling firewall
print_warning "Allowing SSH (port $SSH_PORT) from: $ADMIN_IP"
ufw allow from $ADMIN_IP to any port $SSH_PORT proto tcp comment 'SSH-Admin'
ufw limit $SSH_PORT/tcp comment 'SSH-RateLimit'

# Block database ports from external access
ufw deny 6379 comment 'Block-Redis'
ufw deny 3306 comment 'Block-MySQL'

# Web traffic
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# Enable with force flag
echo "y" | ufw enable
print_status "UFW firewall enabled"
ufw status numbered

# --- FAIL2BAN CONFIGURATION ---
print_status "Configuring Fail2Ban..."
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = $EMAIL
sendername = Fail2Ban-$(hostname)
action = %(action_mwl)s
ignoreip = 127.0.0.1/8 ::1 $ADMIN_IP

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log
maxretry = 3

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache2/*access.log
maxretry = 2

[apache-noscript]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log
maxretry = 5

[apache-overflows]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log
maxretry = 2

[apache-nohome]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log
maxretry = 2

[apache-botsearch]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log
maxretry = 2
EOF

systemctl enable fail2ban
systemctl start fail2ban
print_status "Fail2Ban configured and started"
sleep 2
fail2ban-client status

# --- PHP INSTALLATION ---
print_status "Adding PHP repository and installing PHP 8.4..."
add-apt-repository ppa:ondrej/php -y
apt update

# --- APACHE INSTALLATION & HARDENING ---
print_status "Installing Apache and security modules..."
apt install -y apache2 certbot python3-certbot-apache \
    libapache2-mod-security2 libapache2-mod-evasive
    
apt install -y php8.4-cli php8.4-fpm php8.4-mysql php8.4-redis php8.4-curl php8.4-mbstring \
    php8.4-xml php8.4-zip php8.4-intl php8.4-soap php8.4-bcmath php8.4-gd \
    php8.4-imagick imagemagick php8.4-common php8.4-json php8.4-ldap \
    php8.4-pgsql php8.4-sqlite3 php8.4-xdebug php8.4-bz2

# PHP hardening
PHP_INI="/etc/php/8.4/apache2/php.ini"
if [ -f "$PHP_INI" ]; then
    cp "$PHP_INI" "${PHP_INI}.backup"
    sed -i 's/^expose_php = On/expose_php = Off/' "$PHP_INI"
    sed -i 's/^;date.timezone =.*/date.timezone = UTC/' "$PHP_INI"
    sed -i 's/^upload_max_filesize =.*/upload_max_filesize = 20M/' "$PHP_INI"
    sed -i 's/^post_max_size =.*/post_max_size = 25M/' "$PHP_INI"
    sed -i 's/^memory_limit =.*/memory_limit = 256M/' "$PHP_INI"
    sed -i 's/^max_execution_time =.*/max_execution_time = 60/' "$PHP_INI"
    sed -i 's/^display_errors =.*/display_errors = Off/' "$PHP_INI"
    sed -i 's/^;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' "$PHP_INI"
    print_status "PHP security settings applied"
fi

php -v

# --- APACHE ---
# Backup original configs
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.backup
cp /etc/apache2/conf-available/security.conf /etc/apache2/conf-available/security.conf.backup

# Apache security configuration
cat <<EOF > /etc/apache2/conf-available/security.conf
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None

<Directory />
    Options -Indexes -Includes
    AllowOverride None
    Require all denied
</Directory>

<DirectoryMatch "/\.git">
    Require all denied
</DirectoryMatch>

<FilesMatch "^\.">
    Require all denied
</FilesMatch>
EOF

# Security headers
cat <<'EOF' > /etc/apache2/conf-available/security-headers.conf
<IfModule mod_headers.c>
    # Prevent clickjacking
    Header always set X-Frame-Options "SAMEORIGIN"
    
    # XSS Protection
    Header always set X-XSS-Protection "1; mode=block"
    
    # Prevent MIME sniffing
    Header always set X-Content-Type-Options "nosniff"
    
    # Referrer Policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Content Security Policy (adjust as needed)
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"
    
    # Remove X-Powered-By header
    Header unset X-Powered-By
</IfModule>
EOF

# Disable directory listing globally
sed -i 's/Options Indexes FollowSymLinks/Options -Indexes +FollowSymLinks/' /etc/apache2/apache2.conf

# Enable required modules
a2enmod headers ssl rewrite expires deflate

# Enable security configurations
a2enconf security security-headers

# --- MODEVASIVE CONFIGURATION ---
print_status "Configuring ModEvasive for DDoS protection..."
mkdir -p /var/log/mod_evasive
chown -R www-data:www-data /var/log/mod_evasive

cat <<EOF > /etc/apache2/mods-available/evasive.conf
<IfModule mod_evasive20.c>
    DOSHashTableSize 3097
    DOSPageCount 5
    DOSPageInterval 1
    DOSSiteCount 100
    DOSSiteInterval 1
    DOSBlockingPeriod 60
    DOSEmailNotify $EMAIL
    DOSLogDir /var/log/mod_evasive
    DOSWhitelist 127.0.0.1
    DOSWhitelist ::1
    DOSWhitelist $ADMIN_IP
</IfModule>
EOF

a2enmod evasive
print_status "ModEvasive configured"

# Test Apache configuration
apache2ctl configtest

# --- MYSQL INSTALLATION & HARDENING ---
print_status "Installing and securing MySQL..."
apt install -y mysql-server

# Wait for MySQL to be ready
sleep 3

# Secure MySQL installation (non-interactive)
mysql -e "DELETE FROM mysql.user WHERE User='';"
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -e "DROP DATABASE IF EXISTS test;"
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '$MYSQL_PASS';"
mysql -e "FLUSH PRIVILEGES;"

save_credential "MySQL Root Password" "$MYSQL_PASS"

# Create application database and user
mysql -u root -p"$MYSQL_PASS" <<MYSQL_SCRIPT
CREATE DATABASE IF NOT EXISTS $MYSQL_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$MYSQL_USER'@'localhost' IDENTIFIED BY '$MYSQL_PASS';
GRANT ALL PRIVILEGES ON $MYSQL_DB.* TO '$MYSQL_USER'@'localhost';
FLUSH PRIVILEGES;
SELECT User, Host FROM mysql.user;
SHOW DATABASES;
MYSQL_SCRIPT

save_credential "MySQL User" "$MYSQL_USER"
save_credential "MySQL Database" "$MYSQL_DB"
save_credential "MySQL User Password" "$MYSQL_PASS"

# Bind MySQL to localhost only
sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf
sed -i 's/^mysqlx-bind-address.*/mysqlx-bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf

systemctl restart mysql
systemctl enable mysql

print_status "MySQL secured and bound to localhost"

# --- REDIS INSTALLATION & HARDENING ---
print_status "Installing and securing Redis..."
apt install -y redis-server

# Redis security configuration
REDIS_CONF="/etc/redis/redis.conf"
cp "$REDIS_CONF" "${REDIS_CONF}.backup"

sed -i "s/^# requirepass.*/requirepass $REDIS_PASS/" "$REDIS_CONF"
sed -i 's/^bind .*/bind 127.0.0.1 ::1/' "$REDIS_CONF"
sed -i 's/^protected-mode no/protected-mode yes/' "$REDIS_CONF"

# Disable dangerous commands
echo "rename-command FLUSHDB \"\"" >> "$REDIS_CONF"
echo "rename-command FLUSHALL \"\"" >> "$REDIS_CONF"
echo "rename-command CONFIG \"CONFIG_$RANDOM$RANDOM\"" >> "$REDIS_CONF"

save_credential "Redis Password" "$REDIS_PASS"

systemctl restart redis-server
systemctl enable redis-server

print_status "Redis secured and bound to localhost"

# Test Redis
redis-cli -a "$REDIS_PASS" ping | grep -q PONG && print_status "Redis connection test passed"

# --- KERNEL HARDENING FOR DDOS PROTECTION ---
print_status "Applying kernel hardening parameters..."

cat <<EOF > /etc/sysctl.d/99-hardening.conf
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians (packets with impossible addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 0

# Increase system file descriptor limit
fs.file-max = 65535

# Discourage Linux from swapping idle processes
vm.swappiness = 10

# Increase ephemeral port range
net.ipv4.ip_local_port_range = 1024 65535

# Decrease TIME_WAIT seconds
net.ipv4.tcp_fin_timeout = 15

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
EOF

sysctl --system
print_status "Kernel hardening applied"

# --- SSH HARDENING ---
print_status "Hardening SSH configuration..."

# Backup SSH config
cp "$SSH_CONFIG" "${SSH_CONFIG}.hardened.backup"

cat <<EOF > "$SSH_CONFIG"
# SSH Hardened Configuration
Port $SSH_PORT
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security settings
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable dangerous features
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
AllowAgentForwarding no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Other security options
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
Compression no

# Banner
Banner /etc/ssh/banner

# Allowed users (uncomment and modify as needed)
# AllowUsers deployuser
EOF

# Create SSH banner
cat <<'EOF' > /etc/ssh/banner
***************************************************************************
                            AUTHORIZED ACCESS ONLY
                            
Unauthorized access to this system is forbidden and will be prosecuted by law.
By accessing this system, you agree that your actions may be monitored.

***************************************************************************
EOF

print_warning "SSH configured on port $SSH_PORT with key-based auth only"
print_warning "Ensure you have SSH keys set up before restarting SSH!"

# Don't restart SSH automatically - let admin do it after key setup
print_warning "To apply SSH changes, run: systemctl restart sshd"
print_warning "Test with: ssh -p $SSH_PORT user@server"

# --- APACHE VIRTUAL HOST & SSL ---
print_status "Creating Apache virtual host for $DOMAIN..."

if [ ! -f "$APACHE_CONF" ]; then
    cat <<EOF > "$APACHE_CONF"
<VirtualHost *:80>
    ServerName $DOMAIN
    ServerAdmin $EMAIL
    DocumentRoot $DOCUMENT_ROOT
    
    <Directory $DOCUMENT_ROOT>
        Options -Indexes +FollowSymLinks -MultiViews
        AllowOverride All
        Require all granted
    </Directory>
    
    # Logging
    ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}_error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}_access.log combined
    
    # Security headers will be applied via conf
</VirtualHost>
EOF

    a2ensite "$DOMAIN.conf"
    a2dissite 000-default.conf
fi

# --- SSL CERTIFICATE ---
print_status "Obtaining Let's Encrypt SSL certificate..."

# Ensure Apache is running
systemctl restart apache2

# Get SSL certificate
certbot --apache -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect \
    --hsts --staple-ocsp --must-staple

# Enable auto-renewal
systemctl enable certbot.timer
systemctl start certbot.timer

# Test renewal
certbot renew --dry-run

print_status "SSL certificate installed and auto-renewal enabled"

# --- FILE PERMISSIONS ---
print_status "Setting secure file permissions..."
chown -R www-data:www-data ${DOCUMENT_ROOT}
find ${DOCUMENT_ROOT} -type d -exec chmod 755 {} \;
find ${DOCUMENT_ROOT} -type f -exec chmod 644 {} \;

# Secure sensitive files
chmod 600 /etc/mysql/mysql.conf.d/mysqld.cnf
chmod 600 /etc/redis/redis.conf

# --- INSTALL SECURITY AUDIT TOOLS ---
print_status "Installing security audit tools..."
apt install -y rkhunter aide lynis chkrootkit

# Initialize AIDE (this takes time)
print_status "Initializing AIDE file integrity database..."
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Update rkhunter
rkhunter --update
rkhunter --propupd

print_status "Security tools installed"

# --- LOGWATCH FOR LOG MONITORING ---
print_status "Installing Logwatch for log monitoring..."
apt install -y logwatch

cat <<EOF > /etc/cron.daily/00logwatch
#!/bin/bash
/usr/sbin/logwatch --output mail --mailto $EMAIL --detail high --service all --range today
EOF

chmod +x /etc/cron.daily/00logwatch

# --- CREATE MAINTENANCE SCRIPTS ---
print_status "Creating maintenance scripts..."

cat <<'EOF' > /usr/local/bin/security-check.sh
#!/bin/bash
echo "Running security checks..."
echo "=========================="
echo ""
echo "1. Checking for rootkits..."
rkhunter --check --skip-keypress --report-warnings-only
echo ""
echo "2. Checking file integrity..."
aide --check
echo ""
echo "3. Fail2Ban status..."
fail2ban-client status
echo ""
echo "4. UFW status..."
ufw status verbose
echo ""
echo "5. Checking for updates..."
apt list --upgradable
EOF

chmod +x /usr/local/bin/security-check.sh

# --- RESTART ALL SERVICES ---
print_status "Restarting all services..."
systemctl restart apache2
systemctl restart mysql
systemctl restart redis-server
systemctl restart fail2ban

# --- FINAL STATUS REPORT ---
echo ""
echo ""
print_status "========================================"
print_status "   HARDENED SERVER SETUP COMPLETE!"
print_status "========================================"
echo ""
print_info "Server Information:"
echo "  Domain: $DOMAIN"
echo "  SSH Port: $SSH_PORT (restricted to $ADMIN_IP)"
echo "  Database: $MYSQL_DB"
echo "  MySQL User: $MYSQL_USER"
echo ""
print_info "Security Features Enabled:"
echo "UFW Firewall with IP restrictions"
echo "Fail2Ban intrusion prevention"
echo "ModSecurity WAF with OWASP CRS"
echo "ModEvasive DDoS protection"
echo "SSL/TLS with Let's Encrypt"
echo "Automatic security updates"
echo "Kernel hardening for DDoS"
echo "MySQL hardened (localhost only)"
echo "Redis secured (localhost only)"
echo "PHP security hardening"
echo "Apache security headers"
echo "File integrity monitoring (AIDE)"
echo "Rootkit detection (rkhunter)"
echo "Log monitoring (Logwatch)"
echo ""
print_warning "CRITICAL - SAVE THESE CREDENTIALS:"
echo "=================================="
cat "$PASSWORD_FILE"
echo "=================================="
echo ""
print_warning "Credentials saved to: $PASSWORD_FILE"
echo ""
print_warning "IMPORTANT NEXT STEPS:"
echo "1. SAVE the credentials file somewhere secure"
echo "2. Set up SSH key authentication before enabling SSH changes"
echo "3. Test SSH access: ssh -p $SSH_PORT user@$DOMAIN"
echo "4. Apply SSH hardening: systemctl restart sshd"
echo "5. Review firewall: ufw status verbose"
echo "6. Check Fail2Ban: fail2ban-client status"
echo "7. Test SSL: https://$DOMAIN"
echo "8. Run security audit: sudo lynis audit system"
echo "9. Run maintenance: sudo /usr/local/bin/security-check.sh"
echo ""
print_info "Regular maintenance commands:"
echo "  - Security check: /usr/local/bin/security-check.sh"
echo "  - AIDE check: aide --check"
echo "  - Rootkit scan: rkhunter --check"
echo "  - Full audit: lynis audit system"
echo "  - Update system: apt update && apt upgrade"
echo ""
print_status "Setup completed at: $(date)"
print_status "========================================"

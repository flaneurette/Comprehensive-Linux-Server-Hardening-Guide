#!/bin/bash
set -e

# --- CONFIGURATION ---
MYSQL_USER="user"
MYSQL_DB="databasename"
MYSQL_PASS="changeme"
REDIS_PASS=$(openssl rand -base64 24)
DOMAIN="domain.com"            # Replace with your actual domain
DOCUMENT_ROOT="/var/www/html"
EMAIL="admin@yourdomain.com"   # Certbot notifications
APACHE_CONF="/etc/apache2/sites-available/$DOMAIN.conf"

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err() { echo -e "${RED}[ERROR]${NC} $1"; }

# --- SYSTEM UPDATE ---
info "Updating system..."
apt update && apt upgrade -y

# --- ESSENTIAL PACKAGES ---
info "Installing essential packages..."
apt install -y curl ufw git fail2ban htop unzip software-properties-common \
    ca-certificates lsb-release apt-transport-https

# --- FIREWALL ---
info "Configuring UFW..."
ufw allow OpenSSH
ufw allow 'Apache Full'
ufw deny 6379
ufw --force enable
ufw status

# --- FAIL2BAN ---
info "Enabling Fail2Ban..."
systemctl enable fail2ban
systemctl start fail2ban

# --- PHP 8.4 ---
info "Adding PHP 8.4 repository..."
add-apt-repository ppa:ondrej/php -y
apt update

info "Installing PHP 8.4 and extensions..."
apt install -y apache2 certbot python3-certbot-apache \
    php8.4-cli php8.4-fpm php8.4-mysql php8.4-redis php8.4-curl php8.4-mbstring \
    php8.4-xml php8.4-zip php8.4-intl php8.4-soap php8.4-bcmath php8.4-gd \
    php8.4-imagick imagemagick php8.4-common php8.4-json php8.4-ldap \
    php8.4-pgsql php8.4-sqlite3 php8.4-xdebug php8.4-bz2

systemctl restart apache2

info "Installed PHP version: $(php -v | head -n1)"
info "Checking installed PHP modules..."
php -m | grep -E 'mysqli|redis|curl|mbstring|xml|zip|intl|soap|bcmath|gd|opcache|imagick|xdebug'

# --- MYSQL ---
info "Installing MySQL..."
DEBIAN_FRONTEND=noninteractive apt install -y mysql-server

info "Securing MySQL..."
mysql <<MYSQL_SCRIPT
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '$MYSQL_PASS';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

info "Creating application database and user..."
mysql -u root -p"$MYSQL_PASS" <<MYSQL_SCRIPT
CREATE DATABASE IF NOT EXISTS $MYSQL_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$MYSQL_USER'@'localhost' IDENTIFIED BY '$MYSQL_PASS';
GRANT ALL PRIVILEGES ON $MYSQL_DB.* TO '$MYSQL_USER'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

# --- REDIS ---
info "Installing Redis..."
apt install -y redis-server

info "Securing Redis..."
REDIS_CONF="/etc/redis/redis.conf"
cp "$REDIS_CONF" "${REDIS_CONF}.backup"
sed -i "s/^# requirepass .*/requirepass $REDIS_PASS/" "$REDIS_CONF"
sed -i 's/^bind .*/bind 127.0.0.1 ::1/' "$REDIS_CONF"
sed -i 's/^protected-mode no/protected-mode yes/' "$REDIS_CONF"
echo "rename-command FLUSHDB \"\"" >> "$REDIS_CONF"
echo "rename-command FLUSHALL \"\"" >> "$REDIS_CONF"
systemctl restart redis-server
systemctl enable redis-server

info "Redis password saved: $REDIS_PASS"

# --- APACHE VIRTUAL HOST ---
if [ ! -f "$APACHE_CONF" ]; then
    info "Creating Apache virtual host for $DOMAIN..."
    tee "$APACHE_CONF" > /dev/null <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot $DOCUMENT_ROOT

    <Directory $DOCUMENT_ROOT>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}_error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}_access.log combined
</VirtualHost>
EOF
    a2ensite "$DOMAIN.conf"
    a2dissite 000-default.conf
    systemctl reload apache2
fi

# --- CERTBOT SSL ---
info "Installing Let's Encrypt SSL..."
certbot --apache -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect
systemctl enable certbot.timer
systemctl start certbot.timer

# --- APACHE MODULES ---
a2enmod rewrite headers expires
systemctl restart apache2

# --- FILE PERMISSIONS ---
chown -R www-data:www-data "$DOCUMENT_ROOT"
find "$DOCUMENT_ROOT" -type d -exec chmod 755 {} \;
find "$DOCUMENT_ROOT" -type f -exec chmod 644 {} \;

info "Setup complete!"
echo "Domain: $DOMAIN"
echo "MySQL Database: $MYSQL_DB"
echo "MySQL User: $MYSQL_USER"
echo "MySQL Password: $MYSQL_PASS"
echo "Redis Password: $REDIS_PASS"

#!/bin/bash

# Exit on error
sudo set -e

# --- Variables ---
MYSQL_USER="user"
MYSQL_DB="databasename"
MYSQL_PASS="changeme" 
REDIS_SERVICE="redis-server"
DOMAIN="domain.com"        # Replace with your actual domain
EMAIL="admin@yourdomain.com"   # Email for renewal notices
APACHE_CONF="/etc/apache2/sites-available/$DOMAIN.conf"

echo "Updating system..."
sudo apt update && sudo apt upgrade -y

echo "Installing essential packages..."
sudo apt install -y curl ufw git fail2ban htop unzip software-properties-common

echo "Configuring UFW firewall..."
sudo ufw allow 22
sudo ufw deny 6379
sudo ufw allow OpenSSH
sudo ufw allow 'Apache Full'
sudo ufw --force enable

sudo apt update && sudo apt upgrade -y

echo "Configuring Fail2Ban..."
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

echo "Installing PHP packages..."
sudo apt install -y software-properties-common ca-certificates lsb-release apt-transport-https
sudo add-apt-repository ppa:ondrej/php -y

sudo apt update && sudo apt upgrade -y

echo "Installing Apache and PHP..."
sudo apt install -y apache2 certbot python3-certbot-apache php-cli php-mysql php-redis php-curl php-mbstring php-xml php-zip php-intl php-soap php-bcmath php-gd
sudo apt install -y imagemagick php-common php-imagick php-json php-ldap php-pgsql php-sqlite3 php-xdebug php-bz2

sudo systemctl restart apache2

sudo apache2 -v
sudo php -v

sudo php -m | grep -E 'mysqli|redis|curl|mbstring|xml|zip|intl|soap|bcmath|gd|opcache|imagick|xdebug'

echo "Apache with PHP and extensions installed successfully!"

echo "Installing MySQL..."
sudo DEBIAN_FRONTEND=noninteractive apt install -y mysql-server

echo "Securing MySQL installation..."
sudo mysql_secure_installation <<EOF

y
$MYSQL_PASS
$MYSQL_PASS
y
y
y
y
EOF

echo "Creating MySQL user and database..."
sudo mysql -u root -p"$MYSQL_PASS" <<MYSQL_SCRIPT
CREATE DATABASE $MYSQL_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '$MYSQL_USER'@'localhost' IDENTIFIED BY '$MYSQL_PASS';
GRANT ALL PRIVILEGES ON $MYSQL_DB.* TO '$MYSQL_USER'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT


# Do this manually to prevent errors!
#	echo "Securing SSH (disabling password login)..."
#	sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
#	sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
#	systemctl restart sshd

sudo apt update && sudo apt upgrade -y

echo "Chowning var/www/html"

sudo chown -R www-data:www-data /var/www/html

# REDIS
echo "Installing Redis..."
sudo apt update
sudo apt install -y redis

sudo apt update

# CERTBOT
echo "Installing Let's Encrypt SSL with Certbot for Apache..."
sudo apt install -y certbot python3-certbot-apache

if [ ! -f "$APACHE_CONF" ]; then
	echo "Creating Apache virtual host for $DOMAIN..."
	sudo cat <<EOF > $APACHE_CONF
<VirtualHost *:80>
	ServerName $DOMAIN
	DocumentRoot /var/www/html

	ErrorLog \${APACHE_LOG_DIR}/error.log
	CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
	sudo a2ensite $DOMAIN
	sudo systemctl reload apache2
fi

sudo certbot --apache -d $DOMAIN --non-interactive --agree-tos -m $EMAIL

sudo systemctl status certbot.timer > /dev/null 2>&1 || {
	echo "Enabling Certbot timer for auto-renewal..."
	sudo systemctl enable certbot.timer
	sudo systemctl start certbot.timer
}

echo "SSL certificate has been installed and configured for $DOMAIN"

sudo a2enmod rewrite
sudo a2enmod headers
sudo a2enmod expires
sudo systemctl restart apache2

echo "Setup complete!"
echo "Your MySQL database '$MYSQL_DB' and user '$MYSQL_USER' are ready."





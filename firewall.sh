#!/bin/bash

# Block everything, except for user-defined IP addresses and public ports.

# Your private allowed IPs (home, work, etc)
ALLOWED_IPS=("105.1.2.3" "105.1.2.4")

# Allowed Ports for above IPs
PORTS=(22 993 587 995)

# Allowed Public ports
PUBLIC_PORTS=(80 443 25)

# Install netfilter-persistent if not installed

apt remove -y ufw
apt install -y netfilter-persistent

sleep 3

# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- Allow your IPs on specified ports ---
for ip in "${ALLOWED_IPS[@]}"; do
  for port in "${PORTS[@]}"; do
    iptables -I INPUT 1 -p tcp -s "$ip" --dport "$port" -j ACCEPT
  done
done

# --- Optional: allow ping ---
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# --- Allow public services ---
for port in "${PUBLIC_PORTS[@]}"; do
  iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
done

# Save rules
iptables-save > /etc/iptables/rules.v4
netfilter-persistent save

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Manually check your iptables rules:${NC}\n"

echo -e "1. List rules with line numbers:"
echo -e "   ${GREEN}iptables -L INPUT --line-numbers -n -v${NC}\n"

echo -e "2. Look for a line like:"
echo -e "   ${RED}ACCEPT  0  --  0.0.0.0/0  0.0.0.0/0${NC}\n"

echo -e "3. If it exists, delete that rule using its line number, e.g.:"
echo -e "   ${GREEN}iptables -D INPUT 10${NC}  # Replace 10 with the actual number"


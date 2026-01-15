#!/bin/bash
# IPv6 ONLY!
# To generate a random IPv6 address on your block:
# ip=$(printf "<YourClientIPv6block>:%04x:%04x:%04x:%04x" \
# $((RANDOM % 65536)) \
# $((RANDOM % 65536)) \
# $((RANDOM % 65536)) \
# $((RANDOM % 65536)))
# echo $ip

# Block everything, except for user-defined IP addresses and public ports.

# Your private allowed IPs (home, work, etc) MUST be IPv6!
ALLOWED_IPS=("::/0" "::/0")

# Allowed Ports for above IPs
PORTS=(22 993 587 995)

# Allowed Public ports
PUBLIC_PORTS=(80 443 25)

# Install netfilter-persistent if not installed

apt remove -y ufw
apt install -y netfilter-persistent

sleep 3

# Flush existing rules
ip6tables -F
ip6tables -X

# Default policies
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT

# Allow loopback
ip6tables -A INPUT -i lo -j ACCEPT

# Allow established connections
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- Allow your IPs on specified ports ---
for ip in "${ALLOWED_IPS[@]}"; do
  for port in "${PORTS[@]}"; do
    ip6tables -I INPUT 1 -p tcp -s "$ip" --dport "$port" -j ACCEPT
  done
done

# --- Optional: allow ping ---
ip6tables -A INPUT -p icmpv6 -j ACCEPT
ip6tables -A OUTPUT -p icmpv6 -j ACCEPT

# --- Allow public services ---
for port in "${PUBLIC_PORTS[@]}"; do
  ip6tables -A INPUT -p tcp --dport "$port" -j ACCEPT
done

# Save rules
ip6tables-save > /etc/iptables/rules.v6
netfilter-persistent save

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Manually check your ip6tables rules:${NC}\n"

echo -e "1. List rules with line numbers:"
echo -e "   ${GREEN}ip6tables -L INPUT --line-numbers -n -v${NC}\n"

echo -e "2. Look for a line like:"
echo -e "   ${RED}ACCEPT  0  --  0.0.0.0/0  0.0.0.0/0${NC}\n"

echo -e "3. If it exists, delete that rule using its line number, e.g.:"
echo -e "   ${GREEN}ip6tables -D INPUT 10${NC}  # Replace 10 with the actual number"

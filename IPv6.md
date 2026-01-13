# Disable IPv6

This very well deserves a seperate document. Few sysadmins update their `iptables6`, because it's hard. They have to convert all IPv4 to IPv6. No-one likes doing that. Attackers know this, and they will scan IPv6, often without the admin realizing.

Unless you want to maintain iptables6 (and few ever do it), it is better to **disable ipv6** on your server globally. This cuts the attack surface in half. 

Run:

`sudo nano /etc/sysctl.d/99-custom.conf`

Add:

```
net.ipv6.conf.all.disable_ipv6 = 1
# Disables IPv6 on ALL network interfaces (current and future)

net.ipv6.conf.default.disable_ipv6 = 1  
# Disables IPv6 on any NEW interfaces that get created

net.ipv6.conf.lo.disable_ipv6 = 1
# Disables IPv6 on loopback (localhost)
# Some apps use ::1 (IPv6 localhost), this breaks that
```

Save it, then run:

`sudo sysctl --system`

`systemctl apache2 restart`

`systemctl postfix restart`

`systemctl dovecot restart`


# Check it

```
# 1. Immediate checks
ip -6 addr show                    # Should be empty
netstat -tlnp | grep tcp6          # Should be empty
ping6 ::1                          # Should fail

# 2. Service checks (5 minutes)
systemctl status apache2           # Should be active
systemctl status postfix           # Should be active  
systemctl status dovecot           # Should be active

# 3. External access test (5 minutes)
curl -4 https://domain   # Should work
ssh -4 user@ip # Should work
# Test email send/receive

# 4. Monitor logs (30 minutes)
journalctl -f | grep -i "error\|fail\|fatal"
# Watch for any service failures

# 5. If all good after 30 mins
# IPv6 disabled successfully 
# Keep monitoring casually for 24 hours
```

# If it breaks

```
# 1. Comment out the lines in /etc/sysctl.conf
sudo nano /etc/sysctl.conf
# Add # in front of the disable_ipv6 lines

# 2. Re-enable immediately (without reboot)
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0
sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0

# 3. Restart networking
sudo systemctl restart networking

# 4. Restart affected services
sudo systemctl restart apache2
# etc.

# 5. Verify IPv6 is back
ip -6 addr show
# Should show addresses again
```

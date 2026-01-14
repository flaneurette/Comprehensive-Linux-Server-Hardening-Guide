# Disable IPv6

This very well deserves a seperate document. Few sysadmins update their `iptables6`, because it's hard. They have to convert all IPv4 to IPv6. No-one likes doing that. Attackers know this, and they will scan IPv6, often without the admin realizing.

Unless you want to maintain iptables6 (and few ever do it), it is better to **disable ipv6** on your server globally. This cuts the attack surface in half. 

If you don't think it is an issue, run `netstat` and watch `tcp6` connections. You probably have them. They are IPv6 scanners, probing ports, or DDossing you with SYN floods. They assume no-one configures the IPv6 firewall, and honestly, few admins ever do.

So it is better to drop IPv6 all together.

For maximum reliability, use a **systemd service** to disable IPv6 on all interfaces at boot. This works even on cloud VPS servers that attempt to force IPv6 via RA/DHCPv6.

Create file:

`sudo nano /etc/systemd/system/disable-ipv6.service`

Add:

```
[Unit]
Description=Disable IPv6 on all interfaces
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/sysctl -w net.ipv6.conf.all.disable_ipv6=1
ExecStart=/usr/sbin/sysctl -w net.ipv6.conf.default.disable_ipv6=1
ExecStart=/usr/sbin/sysctl -w net.ipv6.conf.lo.disable_ipv6=1
# This mail fail on some systems, if you get errors, comment this line:
ExecStart=/usr/sbin/sysctl -w net.ipv6.conf.ens6.disable_ipv6=1
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Then run this to survive reboots:

```
sudo systemctl daemon-reload
sudo systemctl enable disable-ipv6.service
sudo systemctl start disable-ipv6.service
ip -6 addr show
```

Also run:

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

**REBOOT** to see if it survives, it should: `sudo reboot`

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

# If rebooting breaks.

`sudo nano /etc/default/grub`

Set:

`GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"`

Then:

```
sudo update-grub
sudo reboot
```

# If everything breaks

```
# 1. Comment out the lines in /etc/sysctl.conf or/and /etc/sysctl.d/99-custom.conf
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


# Re-enable IPv6

```
sudo rm -f /etc/sysctl.d/99-custom.conf
sudo sysctl --system
sudo systemctl disable disable-ipv6.service
sudo systemctl stop disable-ipv6.service
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0
sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0
sudo sysctl -w net.ipv6.conf.ens6.disable_ipv6=0
```

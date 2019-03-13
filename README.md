Scripts to generate captures exploring TCP reassembly.

On macOS to block TCP reset packets being sent from the host running these
scripts add the following rule to `/etc.pf.conf`:

```
block drop proto tcp from <source> to <destination> flags R/R
```

Then enable the firewall by running `sudo pfctl -e`. To reapply the rules in
`/etc/pf.conf` run `sudo pfctl -f /etc/pf.conf`.

On Linux:

```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <source> -d <destination> -j DROP
```

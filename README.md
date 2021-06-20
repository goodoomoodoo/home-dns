# Home DNS

## Getting started with Ubuntu Server

1. Disable ```systemd-resolve``` by modifying ```/etc/systemd/resolved.conf```
- Set ```DNS``` to your preferred DNS server (i.e. 8.8.8.8)
- Set ```DNSStubListener``` to no

2. Create symbolic links and reboot
```bash
$ sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
```

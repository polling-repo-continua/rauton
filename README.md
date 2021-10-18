# Rauton
Bug Bounty Recon Automation Tool

![ScreenShot](https://i.imgur.com/VCVWtQf.png)


## Features :
- Take Screenshots from subdomains ([Gowitness](https://github.com/sensepost/gowitness))
- Get title and headers from subdomains ([Gowitness](https://github.com/sensepost/gowitness))
- General info about company and CIDRs
- Network scan ([Nmap](https://github.com/nmap/nmap))
- HTTP scan ([Nmap](https://github.com/nmap/nmap))
- Get Wayback links and Grouping and separate vulnerable links with [Unfurl](https://github.com/tomnomnom/unfurl) and [GF](https://github.com/tomnomnom/gf)
- Full scan with [Nuclei](https://github.com/projectdiscovery/nuclei)
- Dirsearching with [Dirsearch](https://github.com/maurosoria/dirsearch)
- Scan ssl with [SSLScan](https://github.com/rbsec/sslscan)
- Get all host IPs from subdomains

## Installation :
1. Clone the repository with `git clone https://github.com/Huntinex/rauton`
2. Run installation file `./install.sh`
3. Edit the script `CONFIG` section and enter your `dirsearch_wordlist_path` .

## Usage :
For single domains use :
```bash
./rauton.sh -single apple.com
# or (default mode is single)
./rauton.sh apple.com
```
And for wildcard domains use :
```bash
./rauton.sh -wild apple.com
```
---
Thanks : @silver_stone3

**If you like tool please support me !**

# HackTheBox_Beginner_Cheat_Sheet
HackTheBox: Beginner Cheat Sheet

## This template is for:

- Beginners looking to start HackTheBox
- Players looking to solve easy boxes
- Players who want to have a more organised methodology

## How to use this template:

- Make a copy
- Delete sections you don’t need (like this one)
- As you learn more techniques, checks, and tools, add them to your version
- For each box you do, check items off as you go
- If you want to follow me or contribute: https://linktr.ee/appsecexplained
- Good luck! 🚀

# Simple Methodology Checklist

Below are the **minimum steps and checks** to work through when attacking a target.  
Very often, one of these steps will reveal or fully solve the current stage.

---

## Enumeration

- [ ] Nmap scans
- [ ] Service fingerprinting
  - [ ] Banner grabbing
  - [ ] Searchsploit & Google version checks
- [ ] Web recon
  - [ ] Web stack & technologies
  - [ ] Subdomains
  - [ ] Endpoints
  - [ ] Parameters
  - [ ] Injection points
  - [ ] Framework / CMS versions
- [ ] Additional enumeration
  - [ ] SNMP
  - [ ] NFS shares
  - [ ] SMB
  - [ ] FTP
  - [ ] DNS zone transfer
  - [ ] SMTP
  - [ ] LDAP

---

## Foothold

- [ ] Low-hanging fruit
  - [ ] Anonymous FTP
  - [ ] SMB shares
  - [ ] Default credentials
- [ ] Search for known exploits
- [ ] Credential attacks
  - [ ] Password reuse across services
  - [ ] Brute-force
- [ ] Web attacks
  - [ ] Command injection
  - [ ] File uploads
  - [ ] SQL injection
  - [ ] Other common attacks
  - [ ] Known framework / CMS exploits

---

## Privilege Escalation

- [ ] Whoami
- [ ] `sudo -l`
- [ ] Host OS & version
- [ ] Existing users
- [ ] Groups & privileges
- [ ] Environment variables
- [ ] Files & directories
  - [ ] SSH keys
  - [ ] Credentials in logs
  - [ ] Suspicious binaries
  - [ ] Backups
  - [ ] Command history
  - [ ] Home directories
  - [ ] `/opt`
  - [ ] DB creds in config files
  - [ ] World-readable/writeable sensitive files
  - [ ] SAM & SYSTEM (Windows)
- [ ] LinPEAS / WinPEAS
- [ ] Suspicious or unusual services
- [ ] pspy
- [ ] Kernel exploits

---

# Key Resources

- **PayloadsAllTheThings**  
  https://github.com/swisskyrepo/PayloadsAllTheThings

- **HackTricks**  
  https://book.hacktricks.xyz

- **Exploit-DB**  
  https://www.exploit-db.com

- **GTFOBins**  
  https://gtfobins.github.io

- **LOLBAS** (Living-Off-The-Land Binaries & Scripts)  
  https://lolbas-project.github.io

- **PEASS-ng (LinPEAS / WinPEAS)**  
  https://github.com/peass-ng/PEASS-ng

- **SecLists**  
  https://github.com/danielmiessler/SecLists

- **revshells.com** (Reverse shell generator)  
  https://www.revshells.com

- **Pentestmonkey Reverse Shell Cheat Sheet**  
  https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

---

# Box List (Starting Out)

### First 5 — follow IppSec walkthroughs

- [ ] Lame
- [ ] Active
- [ ] Shocker
- [ ] Grandpa
- [ ] Swagshop

### Next — timed (~45 mins). Peek walkthroughs only if stuck.

- [ ] Networked
- [ ] Granny
- [ ] Legacy
- [ ] Optimum
- [ ] Mirai
- [ ] Doctor
- [ ] Netmon
- [ ] Scriptkiddie
- [ ] Tabby
- [ ] Heist

---

# Commands & Tools Reference

> **Note:** Some commands were AI-generated for speed. They were reviewed but may not be 100% perfect.

---

## Enumeration

### Nmap Scans

```bash
nmap -A <target> -oN scan.initial
nmap -p- -A <target> -T4 -oN scan.full
nmap -p- -sU --top-ports 200 <target> -oN scan.udp

```

## Service Fingerprinting

### Banner Grabbing

```bash
nc -nv <target> 80 (then type HEAD / HTTP/1.0)

curl -sv http://<target>/ -o /dev/null

openssl s_client -connect <target>:443 -servername <target> | head

```

### Searchsploit / Google Version Checks

- searchsploit "Apache Tomcat 7.0.88"
- searchsploit --nmap scan.initial
- Google-fu: 
```bash
" <service> <version> exploit "
```

## Web Recon

### Web Stack & Technologies

- whatweb -a 3 http://<target>
- httpx -tech-detect -title -status -ip -o tech.txt
- Browser add-on: Wappalyzer


## Subdomains
```bash

ffuf -u http://<target> -H "Host: FUZZ.<target>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 4242

feroxbuster --vhost -u http://<target> -w subdomains.txt

```

## Endpoints / Directories

```bash

ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,204,301,302,307,401,403

dirsearch -u http://<target> -e php,txt,bak

```

## Parameters

- `arjun -u http://<target>/search.php`
- `paramspider -d <target-domain>`


## Injection points

### 

- Manual probe in Burp Repeater: `test' "$IFS$(id)` etc.
- `wfuzz -u http://<target>/page.php?id=FUZZ -w /usr/share/wordlists/others/sql.txt --hc 404`

### Framework / CMS versions

- **WordPress:** `wpscan --url http://<target> --enumerate ap,at,tt,u --api-token <token>`
- **Drupal:** `droopescan scan drupal -u http://<target>`
- **Joomla:** `joomscan --url http://<target>`

### Additional enumeration

| Item | Linux / cross-platform | Windows flavour |
| --- | --- | --- |
| **SNMP** | `snmpwalk -v2c -c public <target> 1` | — |
| **NFS shares** | `showmount -e <target>` → `mount -t nfs <target>:/share /mnt` | — |
| **SMB** | `smbclient -L //<target> -N` (no pass) / `enum4linux -a <target>` / `smbmap -H <target>` | `net view \\<target>` |
| **FTP** | `ftp <target>` (try `anonymous`) / `lftp ftp://anonymous@<target>` | Windows built-in `ftp` |
| **DNS zone transfer** | `dig axfr @ns1.<domain> <domain>` / `host -l <domain> ns1.<domain>` | `nslookup -type=any l <domain> ns1.<domain>` |
| **SMTP (user enum)** | `swaks --to user@<target> --server <target> --quit` / `nc <target> 25` then `VRFY root` | `telnet <target> 25` |
| **LDAP** | `ldapsearch -x -h <target> -b "dc=corp,dc=htb,dc=local"` | `ldapsearch.exe` from WSL or ported binaries |


## Foothold

### Low-hanging fruit

| Check | Handy commands |
| --- | --- |
| Anonymous FTP | `ftp <target>` → `anonymous / <blank>` |
| List SMB shares | `smbclient -L //<target> -N` |
| Default logins | `nmap --script http-default-accounts -p80,8080 <target>` / `hydra -L users.txt -P passwords.txt <target> http-get /admin` |

### Search for known exploits

- `searchsploit -m 49283` (download exploit)
- `msfconsole -q` → `search CVE-2021-41773` → `use exploit/multi/http/apache_path_traversal`

### Credential attacks

- **Password reuse / spray:** `crackmapexec smb <target> -u users.txt -p "Summer2024"`
- **Brute-force:** `hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://<target>`
- **Hash-crack:** `john --wordlist=rockyou.txt hash.txt`

### Web attacks

| Vector | Go-to snippet |
| --- | --- |
| Command injection | `curl -G "http://<target>/ping?ip=127.0.0.1;id"` |
| File uploads | `curl -F "file=@shell.php" http://<target>/upload.php` then browse `/uploads/shell.php` |
| SQLi | `sqlmap -u "http://<target>/item.php?id=1" --batch --current-db` |
| Other (LFI/RFI) | `curl "http://<target>/index.php?page=../../../../etc/passwd"` |
| CMS exploit | `wpscan --url http://<target> --enumerate vp --api-token <token>` then `searchsploit <vuln>` |


## Privilege Escalation

### Quick recon

```bash
whoami          # Windows: whoami /all
id              # Linux
sudo -l         # Linux
systeminfo      # Windows OS & patch level
uname -a        # Linux kernel
```

### Users / groups / env

- `cat /etc/passwd` | `net user /domain`
- `groups` | `whoami /groups`
- `env` / `printenv` | `set`


### Files & directories (pick & mix)

```bash
find / -perm -4000 -type f 2>/dev/null      # SUIDs
grep -Ri "password" /home /opt 2>/dev/null  # creds
ls -la /root /home/*/.*_history            # histories
```

- SSH keys → `cat ~/.ssh/id_rsa`
- SAM & SYSTEM → `reg save HKLM\\SAM sam` + `reg save HKLM\\SYSTEM system`

### Automated enum

- `./linpeas.sh -a` | `winpeas.exe cmd > winpeas.txt`
- `./pspy64` (watch cron / processes)

### Suspicious services

- `systemctl list-units --type=service` (Linux)
- `sc queryex type=service` / `wmic service get name,pathname,startmode` (Windows)

### Kernel exploits

- `uname -r` → if **< 4.8** consider DirtyCow (`searchsploit dirtycow`)
- `windows-exploit-suggester.py --systeminfo systeminfo.txt` (classic)

*If you spot `sudo NOPASSWD`*, consult **GTFOBins**.

*If you find `SeImpersonatePrivilege`*, drop **PrintSpoofer/Incognito/JuicyPotato**.






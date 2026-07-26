# Standing up a Windows target for HackPit (VMware + WinRM)

HackPit drives a Windows/AD box **you** run in VMware Workstation. HackPit never owns the VM
— start / snapshot / revert stay in VMware; HackPit only connects over WinRM and runs
commands. This guide gets a VM up, enables WinRM for a local account over HTTP:5985, and
smoke-tests it before you wire it into HackPit.

You (the operator) run these steps — the agent cannot install an OS (it is an interactive
GUI). Everything below is copy-paste.

> **Safety framing.** Only ever point HackPit at a VM (or lab/domain) you own or are
> authorized to test. WinRM over HTTP with NTLM is fine for a local lab VM on a NAT network;
> do not expose 5985 to an untrusted network.

---

## 1. Get a Windows VM (easiest first)

**Option A — Windows 11 dev environment (a single client, quickest).**
Microsoft ships a free, pre-built evaluation VM (90-day) that already includes VMware images.

1. Go to Microsoft's "Windows 11 development environment" download page (search:
   *"Windows 11 dev environment VMware"* → aka.ms / Microsoft Dev Home downloads).
2. Download the **VMware** edition (a `.zip` containing a `.ovf`/`.vmdk` set, ~20 GB).
3. Unzip it somewhere with room to spare.

A single Windows client is enough to prove the WinRM backend end to end (run PowerShell,
PowerView against a live AD later, Rubeus, etc.). A full domain controller is a later step.

**Option B — Windows Server eval (if you want a real Domain Controller for CRTP/OSCP AD).**

1. Download the **Windows Server 2022 evaluation ISO** from the Microsoft Evaluation Center
   (180-day eval, free).
2. In VMware: **File → New Virtual Machine → Installer disc image (ISO)** → pick the ISO →
   install Standard (Desktop Experience).
3. After install, promote it to a DC if you want a domain:
   ```powershell
   Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
   Install-ADDSForest -DomainName "corp.local" -InstallDNS -Force
   ```
   (The box reboots as the DC for `corp.local`. Create a lab user + a few ACL edges to
   exercise the AD attack-path graph live.)

---

## 2. Open it in VMware Workstation, networking = NAT

VMware Workstation / Player: `"C:\Program Files (x86)\VMware\VMware Workstation\vmplayer.exe"`.

1. **Option A:** *Open a Virtual Machine* → select the unzipped `.ovf`. **Option B:** you
   already created the VM in step 1.
2. Open **VM → Settings → Network Adapter**:
   - **NAT** (default) is simplest — the VM gets a `192.168.x.y` address on VMware's NAT net,
     and the HackPit host (uvicorn on 127.0.0.1) can reach it directly. **Use NAT unless you
     have a reason not to.**
   - **Bridged** also works (the VM gets an address on your LAN) — use it if you want other
     LAN hosts to reach the VM too.
3. Power on the VM and log in.

---

## 3. Enable WinRM inside the VM (local account, NTLM over HTTP:5985)

Open **PowerShell as Administrator** *inside the VM* and run:

```powershell
# 1. Turn on PS Remoting + the WinRM service (starts + sets the listener + firewall rule).
Enable-PSRemoting -Force

# 2. A NAT/bridged adapter often reads as a "Public" network, and Enable-PSRemoting skips
#    the firewall rule on Public profiles. Flip the connection profile to Private...
Get-NetConnectionProfile
Set-NetConnectionProfile -InterfaceAlias "Ethernet0" -NetworkCategory Private
#    (use the InterfaceAlias that Get-NetConnectionProfile printed; VMware NICs are often
#     "Ethernet0". If it refuses, just open the firewall port directly in step 3.)

# 3. Make sure the HTTP listener (5985) is allowed through the firewall for any profile:
New-NetFirewallRule -DisplayName "WinRM HTTP-In 5985" -Name "WinRM-HTTP-In-5985" `
  -Protocol TCP -LocalPort 5985 -Direction Inbound -Action Allow

# 4. Allow NTLM auth so a LOCAL account authenticates without Kerberos/domain:
Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true
#    (Negotiate = NTLM/Kerberos. Do NOT enable Basic — HackPit uses NTLM, which is safer and
#     works for local accounts over HTTP.)

# 5. If you will connect as a LOCAL admin account (not a domain user), Windows' remote UAC
#    token filtering blocks it over the network. Allow it:
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System `
  -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force

# 6. Confirm the listener is up:
winrm enumerate winrm/config/listener
```

You want to see a `Transport = HTTP`, `Port = 5985` listener bound to `*` (or the VM's IP).

> **Domain accounts** (Option B / a real domain): skip steps 4–5 — a domain user over
> Kerberos/NTLM works once WinRM is on. NTLM/Negotiate is still what HackPit uses, so a
> domain user + password (or `ntlm-hash` for pass-the-hash) both work.

### Find the VM's IP

Still inside the VM:

```powershell
ipconfig
```

Note the IPv4 address of the VMware adapter (e.g. `192.168.153.130` for NAT). That is the
**host** you will put in the HackPit profile.

---

## 4. Smoke-test WinRM from the HackPit host → the VM

Back on **your host** (where HackPit runs). Two easy checks:

**a) Port reachable?**
```powershell
Test-NetConnection 192.168.153.130 -Port 5985
```
`TcpTestSucceeded : True` means the firewall/listener are good.

**b) Can you authenticate + run a command?** (from an elevated PowerShell on the host)
```powershell
$cred = Get-Credential            # enter the VM's local user, e.g. .\hackpit  (or DOMAIN\user)
Invoke-Command -ComputerName 192.168.153.130 -Credential $cred `
  -Authentication Negotiate -ScriptBlock { whoami; hostname }
```
If that prints the VM's username + hostname, WinRM is working end to end and HackPit will too.

> If (b) fails with an access-denied / TrustedHosts error, add the VM to your host's WinRM
> TrustedHosts (host side, elevated):
> ```powershell
> Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.153.130" -Concatenate -Force
> ```
> (HackPit's own client uses pywinrm, which does not consult TrustedHosts — this is only for
> the PowerShell `Invoke-Command` smoke test.)

---

## 5. Wire it into HackPit

1. **Install the live WinRM dependency** (once) into the backend venv:
   ```
   .venv/Scripts/python.exe -m pip install -r backend/requirements-winrm.txt
   ```
   (The app and the whole test suite run without this — it is only needed to drive a real box.)

2. Start HackPit (backend + frontend) as usual, open the cockpit, and follow **⊞ windows
   targets** (or browse `/windows`).

3. **Add a target:**
   - **name**: e.g. `DC01 — corp.local` (just a label)
   - **host**: the VM IP from step 3 (`192.168.153.130`)
   - **port**: `5985`
   - **username**: the VM account (local `hackpit`, or `DOMAIN\user`)
   - **domain**: the AD domain if any (e.g. `corp.local`), else blank
   - **auth**: `password` (type it) or `NTLM hash` for pass-the-hash (paste the NT hash)
   - **secret**: the password or hash — it is stored write-only and never shown again

4. Click **test** on the saved target. A green `✓ reached … — <user>` means HackPit can
   drive the box.

5. Now every cockpit command with that profile selected — and every AD attack-path abuse you
   pick "run on: <that target>" — runs as PowerShell **on the VM over WinRM**, through the
   same gates (approve-each + the danger red-confirm). Switching VMs is just picking a
   different profile.

---

## Troubleshooting

| symptom | fix |
|---|---|
| `Test-NetConnection … 5985` fails | firewall rule (step 3.3) / listener (`winrm quickconfig`) |
| auth denied as a **local** admin | `LocalAccountTokenFilterPolicy = 1` (step 3.5) |
| `Basic auth` errors | you want **Negotiate/NTLM**, not Basic — step 3.4; HackPit uses NTLM |
| pass-the-hash rejected | confirm the account, and that the box allows NTLM; paste the **NT** hash (HackPit sends it as `LM:NT`) |
| profile `test` says "pywinrm not installed" | run step 5.1 |

See `WINDOWS-EXECUTION.md` for how the driver works under the hood.

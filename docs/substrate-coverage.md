# Substrate coverage — do the catalogued tools actually run?

Measured against the live sandbox image (`hackpit-kali-sandbox`, profile `no-new-privileges` + `CapDrop: ALL`) by invoking each catalogued tool with a trivial call (`--version` / `--help`). A tool that does not run is reported as not-running with the reason — never counted as covered.

## Headline

- **97 of 104 catalogued Linux tools actually execute** (93.3%) in this image under its real profile.
- installed but does not run (landmine / caps): **2**
- catalogued but not installed: **5**
- resolved under an alias (package name != binary): **11**
- Windows-only entries (not applicable to a Linux sandbox): **6**


## Installed but does NOT run (setcap / no-new-privileges landmine)

| tool | category | resolved as | reason |
|---|---|---|---|
| Empire | persistence | powershell-empire (aliased) | no-new-privileges / setcap landmine (output: 'no new privileges') |
| amass | recon | amass | no-new-privileges / setcap landmine (output: 'no new privileges') |

## Catalogued but NOT installed

| tool | category | resolved as | reason |
|---|---|---|---|
| ghidra | binary |  | not installed (no candidate binary resolved on PATH) |
| kube-hunter | cloud |  | not installed (no candidate binary resolved on PATH) |
| prowler | cloud |  | not installed (no candidate binary resolved on PATH) |
| scoutsuite | cloud |  | not installed (no candidate binary resolved on PATH) |
| subwiz | recon |  | not installed (no candidate binary resolved on PATH) |

## Runs (executed under the live profile)

| tool | category | resolved as | probe |
|---|---|---|---|
| gdb | binary | gdb | `--version` exit 0 |
| radare2 | binary | radare2 | `--version` exit 0 |
| strings | binary | strings | `--version` exit 0 |
| Sliver | c2 | sliver-server (aliased) | `--version` exit 1 |
| cloud_enum | cloud | cloud_enum | `--version` exit 0 |
| s3scanner | cloud | s3scanner | `--version` exit 0 |
| trivy | cloud | trivy | `--version` exit 0 |
| hashcat | credentials | hashcat | `--version` exit 0 |
| john | credentials | john | `--version` exit 1 |
| responder | credentials | responder | `--version` exit 0 |
| ScareCrow | evasion | ScareCrow | `--version` exit 2 |
| dnscat2 | evasion | dnscat2-server (aliased) | `--version` exit 0 |
| donut | evasion | donut | `--version` exit 2 |
| iodine | evasion | iodine | `--version` exit 2 |
| msfconsole | exploitation | msfconsole | `--version` exit 0 |
| msfvenom | exploitation | msfvenom | `--version` exit 1 |
| searchsploit | exploitation | searchsploit | `--version` exit 2 |
| GetNPUsers.py | network-ad | impacket-GetNPUsers (aliased) | `--version` exit 2 |
| GetUserSPNs.py | network-ad | impacket-GetUserSPNs (aliased) | `--version` exit 2 |
| bloodhound-python | network-ad | bloodhound-python | `--version` exit 2 |
| bloodyAD | network-ad | bloodyAD | `--version` exit 2 |
| certipy | network-ad | certipy | `--version` exit 0 |
| enum4linux-ng | network-ad | enum4linux-ng | `--version` exit 2 |
| evil-winrm | network-ad | evil-winrm | `--version` exit 0 |
| getTGT.py | network-ad | impacket-getTGT (aliased) | `--version` exit 2 |
| hydra | network-ad | hydra | `--version` exit 255 |
| kerbrute | network-ad | kerbrute | `--version` exit 1 |
| ldapdomaindump | network-ad | ldapdomaindump | `--version` exit 2 |
| ldapsearch | network-ad | ldapsearch | `--version` exit 1 |
| mssqlclient.py | network-ad | impacket-mssqlclient (aliased) | `--version` exit 2 |
| netexec | network-ad | netexec | `--version` exit 1 |
| ntlmrelayx.py | network-ad | impacket-ntlmrelayx (aliased) | `--version` exit 2 |
| psexec.py | network-ad | impacket-psexec (aliased) | `--version` exit 2 |
| secretsdump.py | network-ad | impacket-secretsdump (aliased) | `--version` exit 2 |
| smbexec.py | network-ad | impacket-smbexec (aliased) | `--version` exit 2 |
| smbmap | network-ad | smbmap | `--version` exit 2 |
| wmiexec.py | network-ad | impacket-wmiexec (aliased) | `--version` exit 2 |
| dorks_hunter | osint | dorks_hunter | `--version` exit 2 |
| gitdorks_go | osint | gitdorks_go | `--version` exit 2 |
| github-subdomains | osint | github-subdomains | `--version` exit 2 |
| gitlab-subdomains | osint | gitlab-subdomains | `--version` exit 2 |
| msftrecon | osint | msftrecon | `--version` exit 2 |
| trufflehog | osint | trufflehog | `--version` exit 0 |
| weevely | persistence | weevely | `--version` exit 1 |
| linpeas | privesc | linpeas | `--version` exit 0 |
| asnmap | recon | asnmap | `--version` exit 0 |
| assetfinder | recon | assetfinder | `--version` exit 2 |
| csprecon | recon | csprecon | `--version` exit 2 |
| dnsrecon | recon | dnsrecon | `--version` exit 0 |
| dnsvalidator | recon | dnsvalidator | `--version` exit 2 |
| dnsx | recon | dnsx | `--version` exit 0 |
| fierce | recon | fierce | `--version` exit 2 |
| gotator | recon | gotator | `--version` exit 0 |
| httpx | recon | httpx | `--version` exit 2 |
| mapcidr | recon | mapcidr | `--version` exit 0 |
| masscan | recon | masscan | `--version` exit 1 |
| massdns | recon | massdns | `--version` exit 0 |
| naabu | recon | naabu | `--version` exit 0 |
| nmap | recon | nmap | `--version` exit 0 |
| puredns | recon | puredns | `--version` exit 0 |
| regulator | recon | regulator | `--version` exit 1 |
| rustscan | recon | rustscan | `--version` exit 0 |
| shodan | recon | shodan | `--version` exit 2 |
| subfinder | recon | subfinder | `--version` exit 0 |
| theHarvester | recon | theHarvester | `--version` exit 2 |
| tlsx | recon | tlsx | `--version` exit 0 |
| SSTImap | web | SSTImap | `--version` exit 0 |
| arjun | web | arjun | `--version` exit 2 |
| commix | web | commix | `--version` exit 0 |
| crlfuzz | web | crlfuzz | `--version` exit 2 |
| dalfox | web | dalfox | `--version` exit 1 |
| dirsearch | web | dirsearch | `--version` exit 0 |
| feroxbuster | web | feroxbuster | `--version` exit 0 |
| ffuf | web | ffuf | `--version` exit 2 |
| gau | web | gau | `--version` exit 0 |
| getjs | web | getjs | `--version` exit 2 |
| gf | web | gf | `--version` exit 2 |
| gobuster | web | gobuster | `--version` exit 0 |
| hakrawler | web | hakrawler | `--version` exit 2 |
| jsluice | web | jsluice | `--version` exit 2 |
| jwt_tool | web | jwt_tool | `--version` exit 2 |
| katana | web | katana | `--version` exit 0 |
| nikto | web | nikto | `--version` exit 0 |
| nomore403 | web | nomore403 | `--version` exit 0 |
| nuclei | web | nuclei | `--version` exit 0 |
| paramspider | web | paramspider | `--version` exit 2 |
| qsreplace | web | qsreplace | `--version` exit 2 |
| sqlmap | web | sqlmap | `--version` exit 0 |
| sslscan | web | sslscan | `--version` exit 0 |
| subjs | web | subjs | `--version` exit 0 |
| testssl.sh | web | testssl.sh | `--version` exit 0 |
| unfurl | web | unfurl | `--version` exit 2 |
| wafw00f | web | wafw00f | `--version` exit 0 |
| waybackurls | web | waybackurls | `--version` exit 2 |
| wfuzz | web | wfuzz | `--version` exit 0 |
| whatweb | web | whatweb | `--version` exit 0 |
| wpscan | web | wpscan | `--version` exit 0 |

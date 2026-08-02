# fix-vmnet8.ps1 — restore the HOST's route to the VMware NAT network (VMnet8).
#
# WHY: the Windows/AD lab VM (build #9) sits on VMware's NAT subnet 192.168.13.0/24, with the
# DC at 192.168.13.140. The host's "VMware Network Adapter VMnet8" is supposed to hold
# 192.168.13.1 — VMware's own C:\ProgramData\VMware\vmnetdhcp.conf reserves exactly that
# address for it. When that adapter falls back to an APIPA address (169.254.x.x/16) the host
# has NO route to 192.168.13.0/24 and every reach to the DC fails (ping and TCP/5985 both
# dead). HackPit cannot drive the box until this is fixed.
#
# This is the companion to dc_prereq_probe.py: the probe tells you the DC is unreachable,
# this fixes the most common host-side cause. It is the operator's own machine, not a target —
# it touches no sandbox, no gate and no engagement.
#
# Needs an ELEVATED PowerShell (changing an interface address requires Administrator).
#
# Self-verifying: it prints PASS/FAIL per step and finishes by actually testing TCP/5985 to
# the domain controller, so a green run is evidence rather than an assumption.
#
# Usage (elevated):
#   powershell -ExecutionPolicy Bypass -File docker\proof\fix-vmnet8.ps1
#   powershell -ExecutionPolicy Bypass -File docker\proof\fix-vmnet8.ps1 -DC 192.168.13.150

[CmdletBinding()]
param(
    # The host adapter VMware assigns to its NAT network.
    [string]$Alias = 'VMware Network Adapter VMnet8',
    # The address VMware reserves for that adapter (vmnetdhcp.conf).
    [string]$WantIP = '192.168.13.1',
    [int]$Prefix = 24,
    # The lab domain controller this is all in aid of reaching.
    [string]$DC = '192.168.13.140',
    # Defaults beside this script so the transcript survives the elevated window closing.
    # NEVER hardcode an operator's home directory here — this repo is public.
    [string]$LogPath = (Join-Path $PSScriptRoot 'fix-vmnet8.log')
)

$ErrorActionPreference = 'Stop'

try { Start-Transcript -Path $LogPath -Force | Out-Null } catch {}

function Say($ok, $msg) {
    if ($ok) { Write-Host "PASS  $msg" -ForegroundColor Green }
    else { Write-Host "FAIL  $msg" -ForegroundColor Red }
}

# 0. Elevation check — fail fast with a clear message rather than a cryptic access denied.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "FAIL  not elevated - right-click PowerShell -> Run as Administrator, then re-run this script" -ForegroundColor Red
    exit 1
}
Say $true 'running elevated'

# 1. Show what the adapter looks like before we touch it.
Write-Host "`n--- before ---" -ForegroundColor Cyan
Get-NetIPAddress -InterfaceAlias $Alias -AddressFamily IPv4 |
    Select-Object IPAddress, PrefixLength, PrefixOrigin | Format-Table -AutoSize | Out-String | Write-Host

# 2. Drop the APIPA address and assign the address VMware reserves for this adapter.
#    Only 169.254.* (link-local) addresses are removed - a real address is left alone.
Get-NetIPAddress -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -like '169.254.*' } |
    ForEach-Object {
        Remove-NetIPAddress -InterfaceAlias $Alias -IPAddress $_.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "      removed APIPA $($_.IPAddress)"
    }

$already = Get-NetIPAddress -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -eq $WantIP }
if (-not $already) {
    New-NetIPAddress -InterfaceAlias $Alias -IPAddress $WantIP -PrefixLength $Prefix | Out-Null
}
$now = Get-NetIPAddress -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
       Where-Object { $_.IPAddress -eq $WantIP }
Say ([bool]$now) "$Alias holds $WantIP/$Prefix"

# 3. Bounce VMware's NAT + DHCP services so the NAT gateway re-binds to the restored subnet.
foreach ($svc in 'VMnetDHCP', 'VMware NAT Service') {
    try { Restart-Service -Name $svc -Force; Say $true "restarted $svc" }
    catch { Say $false "restart $svc - $($_.Exception.Message)" }
}

# 4. Prove it: route to the NAT subnet, then the DC's WinRM port.
Write-Host "`n--- after ---" -ForegroundColor Cyan
Get-NetIPAddress -InterfaceAlias $Alias -AddressFamily IPv4 |
    Select-Object IPAddress, PrefixLength, PrefixOrigin | Format-Table -AutoSize | Out-String | Write-Host

$ping = Test-Connection -ComputerName $DC -Count 2 -Quiet -ErrorAction SilentlyContinue
Say $ping "ICMP reaches the DC at $DC  (a Windows firewall may drop ping even when WinRM works - the next check is the one that matters)"

$tcp = Test-NetConnection $DC -Port 5985 -WarningAction SilentlyContinue
Say $tcp.TcpTestSucceeded "TCP/5985 (WinRM) reaches the DC at $DC"

if ($tcp.TcpTestSucceeded) {
    Write-Host "`nRESULT: the host can reach the domain controller. HackPit's live tasks can run." -ForegroundColor Green
    try { Stop-Transcript | Out-Null } catch {}
    exit 0
} else {
    Write-Host "`nRESULT: still unreachable. Check that the VM is powered on and that its adapter is still NAT" -ForegroundColor Red
    Write-Host "        (inside the VM: ipconfig - confirm it still holds $DC)." -ForegroundColor Red
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}

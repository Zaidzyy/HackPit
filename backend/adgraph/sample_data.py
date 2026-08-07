"""A small, self-contained synthetic BloodHound collection — a GOAD-style domain with a real
multi-hop ACL route to Domain Admins. Used by the tests and available to the UI as a demo so
the AD graph renders end-to-end with NO live AD lab.

The route (owned low-priv `tywin` → Domain Admins):

    tywin --ForceChangePassword--> jaime --GenericWrite--> joffrey --WriteDacl--> tyrion
          --AddSelf--> [Small Council] --GenericAll--> [Domain Admins]      (== win)

plus a parallel Kerberoast/DCSync flavour:  a `svc_sql` SPN account and an `AddMember` edge,
and `cersei` who is already a Domain Admin (so the group is populated and high-value).

The shape is faithful to bloodhound-python v5 output (per-type files with a `meta` block, ACEs
on the target object, `Members` on the group). SIDs use the documented well-known RIDs so
high-value detection (Domain Admins = RID 512) fires exactly as it would on a real domain.
"""

from __future__ import annotations

DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"


def _u(rid: str, name: str) -> str:
    return f"{DOMAIN_SID}-{rid}"


# principals
TYWIN = _u("1104", "tywin")
JAIME = _u("1105", "jaime")
JOFFREY = _u("1106", "joffrey")
TYRION = _u("1107", "tyrion")
CERSEI = _u("1108", "cersei")
SVC_SQL = _u("1109", "svc_sql")
# AD CS enrollees — low-priv principals whose ESC route to DA the certipy sample adds.
HODOR = _u("1110", "hodor")   # can WRITE a template (ESC4) -> reconfigure -> ESC1
BRAN = _u("1111", "bran")     # a direct ESC1 enrollee + a CA officer (ESC7)
SMALL_COUNCIL = _u("1120", "small council")
DOMAIN_ADMINS = f"{DOMAIN_SID}-512"
DC01 = _u("1001", "dc01")
WKSTN01 = _u("1130", "wkstn01")  # the coerced/relayed machine for ESC8


def _user(sid: str, short: str, **props) -> dict:
    p = {"name": f"{short.upper()}@SEVENKINGDOMS.LOCAL", "domain": "SEVENKINGDOMS.LOCAL",
         "enabled": True}
    p.update(props)
    return {
        "ObjectIdentifier": sid,
        "PrimaryGroupSID": f"{DOMAIN_SID}-513",
        "Properties": p,
        "Aces": [],
        "AllowedToDelegate": [],
        "SPNTargets": [],
        "HasSIDHistory": [],
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def _ace(principal: str, right: str, ptype: str = "User", inherited: bool = False) -> dict:
    return {"PrincipalSID": principal, "PrincipalType": ptype, "RightName": right,
            "IsInherited": inherited}


def sample_collection() -> dict:
    """The combined collection mapping (type -> BloodHound file object)."""
    # --- users, each carrying the ACE that the NEXT hop abuses --------------- #
    jaime = _user(JAIME, "jaime")
    jaime["Aces"].append(_ace(TYWIN, "ForceChangePassword"))  # tywin -> jaime

    joffrey = _user(JOFFREY, "joffrey")
    joffrey["Aces"].append(_ace(JAIME, "GenericWrite"))       # jaime -> joffrey

    tyrion = _user(TYRION, "tyrion")
    tyrion["Aces"].append(_ace(JOFFREY, "WriteDacl"))         # joffrey -> tyrion

    svc_sql = _user(SVC_SQL, "svc_sql",
                    hasspn=True, serviceprincipalnames=["MSSQLSvc/dc01.sevenkingdoms.local:1433"])
    svc_sql["Aces"].append(_ace(TYRION, "GenericAll"))        # tyrion -> svc_sql (side branch)

    tywin = _user(TYWIN, "tywin")
    cersei = _user(CERSEI, "cersei")  # already a Domain Admin (member below)
    # AD CS enrollees — no ACL edges of their own; their only route to DA is the ESC chain the
    # certipy sample synthesizes (so the BloodHound-only graph is byte-identical for the old tests).
    hodor = _user(HODOR, "hodor")
    bran = _user(BRAN, "bran")

    users = [tywin, jaime, joffrey, tyrion, cersei, svc_sql, hodor, bran]

    # --- groups ------------------------------------------------------------- #
    small_council = {
        "ObjectIdentifier": SMALL_COUNCIL,
        "Properties": {"name": "SMALL COUNCIL@SEVENKINGDOMS.LOCAL",
                       "domain": "SEVENKINGDOMS.LOCAL", "highvalue": False},
        "Members": [],
        # tyrion can AddSelf to Small Council (an ACE on the group)
        "Aces": [_ace(TYRION, "AddSelf", ptype="User")],
        "IsDeleted": False,
    }
    domain_admins = {
        "ObjectIdentifier": DOMAIN_ADMINS,
        "Properties": {"name": "DOMAIN ADMINS@SEVENKINGDOMS.LOCAL",
                       "domain": "SEVENKINGDOMS.LOCAL", "highvalue": True},
        # cersei is a real DA; Small Council has GenericAll over the group (the final hop)
        "Members": [{"ObjectIdentifier": CERSEI, "ObjectType": "User"}],
        "Aces": [_ace(SMALL_COUNCIL, "GenericAll", ptype="Group")],
        "IsDeleted": False,
    }

    # --- computer (a DC), with a session for flavour ------------------------ #
    dc01 = {
        "ObjectIdentifier": DC01,
        "Properties": {"name": "DC01.SEVENKINGDOMS.LOCAL", "domain": "SEVENKINGDOMS.LOCAL",
                       "operatingsystem": "Windows Server 2019", "highvalue": True},
        "Aces": [],
        "AllowedToDelegate": [],
        "AllowedToAct": [],
        "Sessions": {"Results": [{"UserSID": CERSEI, "ComputerSID": DC01}], "Collected": True},
        "LocalAdmins": {"Results": [{"ObjectIdentifier": DOMAIN_ADMINS, "ObjectType": "Group"}],
                        "Collected": True},
        "RemoteDesktopUsers": {"Results": [], "Collected": True},
        "PSRemoteUsers": {"Results": [], "Collected": True},
        "DcomUsers": {"Results": [], "Collected": True},
        "PrimaryGroupSID": f"{DOMAIN_SID}-516",
        "IsDeleted": False,
    }

    # --- domain (with a DCSync ACE for a defender-relevant final flavour) ---- #
    domain = {
        "ObjectIdentifier": DOMAIN_SID,
        "Properties": {"name": "SEVENKINGDOMS.LOCAL", "domain": "SEVENKINGDOMS.LOCAL",
                       "highvalue": True},
        # Domain Admins hold both replication rights => a synthesized DCSync edge
        "Aces": [_ace(DOMAIN_ADMINS, "GetChanges", ptype="Group"),
                 _ace(DOMAIN_ADMINS, "GetChangesAll", ptype="Group")],
        "Trusts": [],
        "ChildObjects": [{"ObjectIdentifier": DC01, "ObjectType": "Computer"}],
        "Links": [],
        "IsDeleted": False,
    }

    # a workstation — the machine ESC8 coerces + relays to the CA's web enrollment.
    wkstn01 = {
        "ObjectIdentifier": WKSTN01,
        "Properties": {"name": "WKSTN01.SEVENKINGDOMS.LOCAL", "domain": "SEVENKINGDOMS.LOCAL",
                       "operatingsystem": "Windows 11", "highvalue": False},
        "Aces": [], "AllowedToDelegate": [], "AllowedToAct": [],
        "Sessions": {"Results": [], "Collected": True},
        "LocalAdmins": {"Results": [], "Collected": True},
        "RemoteDesktopUsers": {"Results": [], "Collected": True},
        "PSRemoteUsers": {"Results": [], "Collected": True},
        "DcomUsers": {"Results": [], "Collected": True},
        "PrimaryGroupSID": f"{DOMAIN_SID}-515",
        "IsDeleted": False,
    }

    def _file(mtype: str, data: list[dict]) -> dict:
        return {"data": data, "meta": {"methods": 46, "type": mtype, "count": len(data),
                                       "version": 5}}

    return {
        "users": _file("users", users),
        "groups": _file("groups", [small_council, domain_admins]),
        "computers": _file("computers", [dc01, wkstn01]),
        "domains": _file("domains", [domain]),
        "gpos": _file("gpos", []),
        "ous": _file("ous", []),
        "containers": _file("containers", []),
    }


def sample_certipy() -> dict:
    """A synthetic ``certipy find -json`` for the SAME domain — a deliberately vulnerable AD CS
    deployment covering ESC1/ESC2/ESC3/ESC4/ESC6/ESC7/ESC8. Folded into the sample graph
    (parser.ingest_certipy) so ``/cockpit/ad`` renders an ESC route with NO live CA.

    The headline route the screenshot shows (from HODOR): ``hodor --ESC4--> VulnTemplate
    --ESC1--> Domain Admins`` — a low-priv user who can rewrite a template's config, reconfigures
    it to be SAN-abusable, then enrols a Domain Admin certificate. No real domain, CA, or account
    names — all synthetic.
    """
    dom = "SEVENKINGDOMS.LOCAL"
    ca = "SEVENKINGDOMS-CA"
    return {
        "Certificate Authorities": {
            "0": {
                "CA Name": ca,
                "DNS Name": "dc01.sevenkingdoms.local",
                "Web Enrollment": "Enabled",           # ESC8 surface
                "User Specified SAN": "Enabled",        # EDITF_ATTRIBUTESUBJECTALTNAME2 -> ESC6
                "Manage CA Principals": [f"{dom}\\bran"],       # ESC7
                "Relay Sources": ["WKSTN01.SEVENKINGDOMS.LOCAL"],  # ESC8 (operator-chosen source)
                "[!] Vulnerabilities": {"ESC6": "User Specified SAN is enabled",
                                        "ESC7": "bran has Manage CA",
                                        "ESC8": "Web Enrollment is enabled without HTTPS/EPA"},
            }
        },
        "Certificate Templates": {
            # ESC4 demo — HODOR can rewrite this template's config; not yet ESC1 (no ESS), so the
            # only route through it is reconfigure-then-abuse.
            "0": {
                "Template Name": "VulnTemplate",
                "Enabled": True,
                "Extended Key Usage": ["Client Authentication"],
                "Enrollee Supplies Subject": False,
                "Requires Manager Approval": False,
                "Enrollment Rights": [f"{dom}\\Domain Users"],
                "Object Control Permissions": {"Write Owner Principals": [f"{dom}\\hodor"]},
                "Certificate Authorities": [ca],
                "[!] Vulnerabilities": {"ESC4": "hodor has dangerous write permissions"},
            },
            # a directly ESC1-vulnerable template (enrollee-supplied SAN + client auth + enrol).
            "1": {
                "Template Name": "UserAuthESC1",
                "Enabled": True,
                "Extended Key Usage": ["Client Authentication"],
                "Enrollee Supplies Subject": True,
                "Requires Manager Approval": False,
                "Enrollment Rights": [f"{dom}\\bran", f"{dom}\\Domain Users"],
                "Certificate Authorities": [ca],
                "[!] Vulnerabilities": {"ESC1": "Enrollee supplies subject + client auth"},
            },
            # client-auth but NOT enrollee-supplied-SAN — abusable ONLY because the CA EDITF flag
            # is set (ESC6), not on its own.
            "2": {
                "Template Name": "WorkstationAuth",
                "Enabled": True,
                "Extended Key Usage": ["Client Authentication"],
                "Enrollee Supplies Subject": False,
                "Requires Manager Approval": False,
                "Enrollment Rights": [f"{dom}\\Domain Computers"],
                "Certificate Authorities": [ca],
            },
            # Any-Purpose EKU (ESC2).
            "3": {
                "Template Name": "AnyPurpose",
                "Enabled": True,
                "Extended Key Usage": ["Any Purpose"],
                "Enrollee Supplies Subject": False,
                "Requires Manager Approval": False,
                "Enrollment Rights": [f"{dom}\\Domain Users"],
                "Certificate Authorities": [ca],
                "[!] Vulnerabilities": {"ESC2": "Any Purpose EKU"},
            },
            # Enrollment Agent template (ESC3).
            "4": {
                "Template Name": "EnrollmentAgent",
                "Enabled": True,
                "Extended Key Usage": ["Certificate Request Agent"],
                "Requires Manager Approval": False,
                "Enrollment Rights": [f"{dom}\\bran"],
                "Certificate Authorities": [ca],
                "[!] Vulnerabilities": {"ESC3": "Certificate Request Agent EKU"},
            },
        },
    }


# The canonical owned start + the high-value target for the demo/tests.
OWNED_START = TYWIN
HIGH_VALUE_TARGET = DOMAIN_ADMINS
# The AD CS demo's owned start — a low-priv user who reaches DA via the ESC chain (ESC4 -> ESC1).
ESC_SAMPLE_START = HODOR

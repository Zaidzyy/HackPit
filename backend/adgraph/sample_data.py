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
SMALL_COUNCIL = _u("1120", "small council")
DOMAIN_ADMINS = f"{DOMAIN_SID}-512"
DC01 = _u("1001", "dc01")


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

    users = [tywin, jaime, joffrey, tyrion, cersei, svc_sql]

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

    def _file(mtype: str, data: list[dict]) -> dict:
        return {"data": data, "meta": {"methods": 46, "type": mtype, "count": len(data),
                                       "version": 5}}

    return {
        "users": _file("users", users),
        "groups": _file("groups", [small_council, domain_admins]),
        "computers": _file("computers", [dc01]),
        "domains": _file("domains", [domain]),
        "gpos": _file("gpos", []),
        "ous": _file("ous", []),
        "containers": _file("containers", []),
    }


# The canonical owned start + the high-value target for the demo/tests.
OWNED_START = TYWIN
HIGH_VALUE_TARGET = DOMAIN_ADMINS

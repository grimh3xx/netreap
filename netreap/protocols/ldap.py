"""Enumeracao de Active Directory via LDAP (Impacket).

Precisa de um DC real para validacao ponta-a-ponta — teste em LAB.
"""

from __future__ import annotations

from impacket.ldap import ldap, ldapasn1

from netreap.creds import Credential

# samAccountType para contas de usuario normais
_SAM_USER = "805306368"
# userAccountControl: DONT_REQ_PREAUTH
_UAC_NO_PREAUTH = "4194304"


def base_dn(ad_domain: str) -> str:
    return ",".join(f"DC={part}" for part in ad_domain.split("."))


def connect(host: str, ad_domain: str, cred: Credential, timeout: int = 5):
    base = base_dn(ad_domain)
    conn = ldap.LDAPConnection(f"ldap://{host}", base, host)
    conn.login(cred.username, cred.password, ad_domain,
               cred.lmhash, cred.nthash)
    return conn, base


def _search(conn, base: str, flt: str, attrs: list[str]) -> list[dict]:
    sc = ldap.SimplePagedResultsControl(size=1000)
    rows: list[dict] = []
    results = conn.search(searchBase=base, searchFilter=flt,
                          attributes=attrs, sizeLimit=0,
                          searchControls=[sc])
    for item in results:
        if not isinstance(item, ldapasn1.SearchResultEntry):
            continue
        row: dict = {}
        for attr in item["attributes"]:
            name = str(attr["type"])
            vals = [str(v) for v in attr["vals"]]
            row[name] = vals[0] if len(vals) == 1 else vals
        rows.append(row)
    return rows


def enum_users(conn, base: str) -> list[dict]:
    return _search(conn, base, f"(samAccountType={_SAM_USER})",
                   ["sAMAccountName", "description"])


def enum_groups(conn, base: str) -> list[dict]:
    return _search(conn, base, "(objectClass=group)",
                   ["sAMAccountName", "description"])


def kerberoastable(conn, base: str) -> list[dict]:
    flt = (f"(&(samAccountType={_SAM_USER})(servicePrincipalName=*)"
           f"(!(cn=krbtgt)))")
    return _search(conn, base, flt, ["sAMAccountName", "servicePrincipalName"])


def asreproastable(conn, base: str) -> list[dict]:
    flt = (f"(&(samAccountType={_SAM_USER})"
           f"(userAccountControl:1.2.840.113556.1.4.803:={_UAC_NO_PREAUTH}))")
    return _search(conn, base, flt, ["sAMAccountName"])

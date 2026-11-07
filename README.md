# netreap

Ferramenta enxuta de **enumeração e post-exploitation de rede** (SMB / LDAP /
Active Directory), escrita em **Python + [Impacket](https://github.com/fortra/impacket)** —
uma alternativa leve e com **saída JSON limpa** ao
[CrackMapExec / NetExec](https://github.com/Pennyw0rth/NetExec).

> ⚠️ **Uso autorizado apenas.** Pentest com escopo definido, laboratórios e
> CTF. Rode somente contra sistemas que você tem **permissão explícita** para
> testar. O uso não autorizado é crime. A responsabilidade é inteiramente sua.

## Por que existe / o que faz melhor

- **Saída JSON-lines nativa** (`-o out.json`) — cada resultado é um registro,
  fácil de pipar pra `jq`, Elastic, planilha, etc.
- **Concorrência** sobre CIDR/faixas/arquivos de alvo.
- **Spraying com consciência de lockout**: ao detectar `account_locked_out`,
  para de tentar aquela conta (evita travar usuários reais). Use
  `--continue-on-lockout` só se souber o que está fazendo.
- **Pass-the-hash** nativo (`-H`).
- Código pequeno e modular — cada protocolo é um arquivo em
  `netreap/protocols/`.

## Módulos (v1)

**SMB**
- Host info (SO, domínio, SMB signing, dialeto)
- Autenticação / **password spraying** (lista/arquivo de users e senhas) + PtH
- Marca **`(Pwn3d!)`** quando a credencial é admin local
- Enum de **shares**, **usuários** (SAMR), **sessões** (SRVSVC), **política de senha**
- **Execução de comando** (`-x`, via serviço SVCCTL)
- **Dump de credenciais**: `--sam`, `--lsa`, `--ntds` (via secretsdump da Impacket)

**LDAP / AD**
- Enum de **usuários** e **grupos**
- **Kerberoastáveis** (contas com SPN)
- **AS-REP roastáveis** (sem pré-autenticação)

## Instalação

```bash
git clone https://github.com/grimh3xx/netreap
cd netreap
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Uso

```bash
# Host info + spraying numa /24
netreap smb 10.0.0.0/24 -u administrator -p 'Senha123!' -d CORP

# Enumerar shares/usuarios/politica onde a credencial for valida
netreap smb 10.0.0.10 -u svc -p pass -d CORP --shares --users --pass-pol

# Pass-the-hash e execucao de comando
netreap smb 10.0.0.10 -u admin -H 31d6...089c0 -d CORP -x "whoami /all"

# Dump de SAM/LSA (admin local) com saida JSON
netreap smb 10.0.0.10 -u admin -p pass --local-auth --sam --lsa -o loot.json

# AD enum via LDAP: kerberoastaveis e asrep-roastaveis
netreap ldap 10.0.0.1 -u user -p pass --ad-domain corp.local --kerberoast --asreproast
```

Alvos aceitam IP, CIDR (`10.0.0.0/24`), faixa (`10.0.0.1-50`), hostname e
`@arquivo`. `-u`/`-p`/`-H` aceitam um valor ou um **arquivo** (uma entrada por
linha), permitindo spraying.

## Estado dos módulos / testes

Este repositório tem testes (`pytest`) para a lógica pura — parsing de
credenciais e hashes, expansão de alvos (CIDR/faixa/arquivo), base DN de LDAP —
e **smoke tests** de CLI e tratamento de erro de conexão.

> **Importante:** os módulos que falam DCE-RPC/LDAP com um Windows/DC real
> (enum via SAMR/SRVSVC, `-x`, secretsdump, LDAP) foram escritos sobre as APIs
> da Impacket mas **ainda não foram validados ponta-a-ponta contra um Active
> Directory** — faça isso num **laboratório autorizado** antes de usar em
> engajamento. PRs com resultados de lab são bem-vindos.

## Desenvolvimento

```bash
pip install -e . pytest
pytest -q
```

## Licença

MIT. Veja [LICENSE](LICENSE).

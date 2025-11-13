# ghostSPN

`ghostSPN` is a Python utility for identifying "ghost" Service Principal Names (SPNs) in Active Directory. It helps defenders uncover stale or orphaned SPNs that attackers can abuse for Kerberos-based privilege escalation.

## Features
- Enumerates SPNs via LDAP with paging and filtering optimizations.
- Flags high-risk services (HTTP, MSSQL, TERMSRV, and more).
- Optional DNS resolution checks with caching to reduce false positives.
- Parallel host lookups and AD correlation to confirm legitimate targets.

## Installation
- **pipx (recommended)**
  ```
  pipx install git+https://github.com/mverschu/ghostSPN.git
  ```

## Usage
Provide valid Active Directory credentials and target information. The most common invocation is:
```
python3 ghostSPN.py --server DC01 --domain corp.local --username corp\\admin --password Pass123
```

For LDAPS environments enforcing channel binding, use a UPN-style username together with `--use-ssl`:
```
python3 ghostSPN.py --server dc01.corp.local --use-ssl --username admin@corp.local --password Pass123 --no-verify
```

Useful options:
- `--use-ssl` and `--no-verify` to control LDAPS.
- `--quick-mode` to enable all speed optimizations.
- `--check-dns` to resolve hostnames and cache known results.
- `--output results.csv` to export findings.

Run `ghostspn --help` (or `python3 ghostSPN.py --help`) for the complete list of arguments.

## Output
The script prints severity-grouped tables of potential ghost SPNs. When `--output` is supplied, results are written as CSV or JSON depending on the file extension.

